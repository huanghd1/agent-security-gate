/**
 * End-to-end proof of the checkpoint semantics.
 *
 * Scenario: a 5-step plan. The process is killed with SIGKILL-equivalent
 * (taskkill /T /F) while step 3 is mid-flight — after its side effect landed,
 * before the step was recorded as finished. That is THE ambiguous window, and
 * every "resume" implementation has to answer for it.
 *
 * Expected behaviour, asserted below:
 *   run 1  killed during s3
 *   run 2  s1,s2 skipped by checkpoint; s3 REFUSED (effect + in flight)
 *   run 3  --accept-partial: s3 re-runs (duplicating its effect, on purpose),
 *          then s4, s5 complete
 *
 * Step effect counts are asserted too, so "it resumed" cannot be faked by
 * silently re-running everything.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from '../../src/store.ts';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const work = join(root, '.e2e');
const dbPath = join(work, 'gate.db');
const effectsPath = join(work, 'effects.log');
const RUN_ID = 'e2e-resume';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function reset(): void {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true });
}

function manifest(): void {
  const mark = (id: string): string =>
    `node -e "require('fs').appendFileSync('effects.log','${id}\\n')"`;
  const slow = `node -e "require('fs').appendFileSync('effects.log','s3\\n'); setTimeout(function(){}, 8000)"`;

  writeFileSync(
    join(work, 'pipeline.json'),
    JSON.stringify(
      {
        name: 'demo-resume',
        steps: [
          { id: 's1', cmd: mark('s1'), mode: 'effect' },
          { id: 's2', cmd: mark('s2'), mode: 'effect' },
          { id: 's3', cmd: slow, mode: 'effect' },
          { id: 's4', cmd: mark('s4'), mode: 'effect' },
          { id: 's5', cmd: mark('s5'), mode: 'effect' },
        ],
      },
      null,
      2,
    ),
  );
}

function spawnCli(args: string[]): ChildProcess {
  return spawn(process.execPath, [join(root, 'src/cli.ts'), ...args], {
    cwd: work,
    env: { ...process.env, AGENT_GATE_DB: dbPath },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
}

function collect(child: ChildProcess): { out: () => string } {
  let buf = '';
  child.stdout?.on('data', (d: Buffer) => {
    buf += d.toString('utf8');
  });
  child.stderr?.on('data', (d: Buffer) => {
    buf += d.toString('utf8');
  });
  return { out: () => buf };
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  }
}

function effects(): Map<string, number> {
  const counts = new Map<string, number>();
  if (!existsSync(effectsPath)) return counts;
  for (const line of readFileSync(effectsPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (t) counts.set(t, (counts.get(t) ?? 0) + 1);
  }
  return counts;
}

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`  ${ok ? '✓' : '✗'} ${label}${detail ? `  — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

async function main(): Promise<void> {
  reset();
  manifest();

  console.log('\n=== 阶段 1：启动 5 步流水线，在 s3 执行中强杀 ===');
  const run1 = spawnCli(['run', join(work, 'pipeline.json'), '--run', RUN_ID, '--approver', 'scripted', '--decisions', 'approve,approve,approve']);
  const c1 = collect(run1);

  // Wait until s3 has written its effect but is still sleeping inside the step.
  let killed = false;
  for (let i = 0; i < 200; i++) {
    if (effects().has('s3')) {
      killTree(run1);
      killed = true;
      break;
    }
    await sleep(100);
  }
  await new Promise<void>((r) => run1.once('close', () => r()));
  check('确实在 s3 执行期间被杀', killed);
  console.log(`    已产生的副作用: ${[...effects().entries()].map(([k, v]) => `${k}×${v}`).join(', ') || '(无)'}`);

  console.log('\n=== 阶段 2：用同一 run id 恢复 ===');
  const run2 = spawnCli(['run', join(work, 'pipeline.json'), '--run', RUN_ID, '--approver', 'scripted', '--decisions', 'approve,approve,approve']);
  const c2 = collect(run2);
  const code2 = await new Promise<number | null>((r) => run2.once('close', (c) => r(c)));
  const out2 = c2.out();
  console.log(out2.trimEnd().replace(/^/gm, '    '));

  check('s1、s2 被检查点跳过（没有重跑）', (effects().get('s1') ?? 0) === 1 && (effects().get('s2') ?? 0) === 1);
  check('s3 被拒绝自动重跑，退出码 4', code2 === 4, `实际 ${code2}`);
  check('s4、s5 完全没有执行', !effects().has('s4') && !effects().has('s5'));
  check('明确说明是"副作用可能已部分落地"', out2.includes('拒绝自动重跑'));

  console.log('\n=== 阶段 3：显式 --accept-partial 放行 ===');
  const run3 = spawnCli([
    'run',
    join(work, 'pipeline.json'),
    '--run',
    RUN_ID,
    '--approver',
    'scripted',
    '--decisions',
    'approve,approve,approve,approve',
    '--accept-partial',
  ]);
  const c3 = collect(run3);
  const code3 = await new Promise<number | null>((r) => run3.once('close', (c) => r(c)));
  console.log(c3.out().trimEnd().replace(/^/gm, '    '));

  const final = effects();
  check('整体成功，退出码 0', code3 === 0, `实际 ${code3}`);
  check('s1 恰好执行 1 次', (final.get('s1') ?? 0) === 1, `${final.get('s1') ?? 0} 次`);
  check('s3 执行 2 次（这是显式接受重放的代价，不是 bug）', (final.get('s3') ?? 0) === 2, `${final.get('s3') ?? 0} 次`);
  check('s4、s5 各 1 次', (final.get('s4') ?? 0) === 1 && (final.get('s5') ?? 0) === 1);

  console.log('\n=== 阶段 4：审计链校验 ===');
  const store = new Store(dbPath);
  const verify = store.verify(RUN_ID);
  const events = store.events(RUN_ID);
  check('哈希链完整', verify.ok, `${verify.total} 条事件`);
  const types = events.reduce<Record<string, number>>((acc, e) => {
    acc[e.type] = (acc[e.type] ?? 0) + 1;
    return acc;
  }, {});
  console.log(`    事件构成: ${Object.entries(types).map(([k, v]) => `${k}=${v}`).join(' ')}`);

  // Tamper check: rewrite a stored payload behind the store's back and re-verify.
  const tdb = join(work, 'tamper.db');
  const s1 = new Store(tdb);
  s1.ensureRun('t');
  s1.append('t', 'cmd_decided', { cmd: 'ls -la', tier: 'allow' });
  s1.append('t', 'cmd_result', { code: 0 });
  const clean = s1.verify('t');
  s1.close();
  check('未篡改时链完整', clean.ok);

  const { DatabaseSync } = await import('node:sqlite');
  const raw = new DatabaseSync(tdb);
  raw.prepare('UPDATE events SET payload = ? WHERE seq = 1').run('{"cmd":"rm -rf /","tier":"allow"}');
  raw.close();

  const s2 = new Store(tdb);
  const after = s2.verify('t');
  s2.close();
  check(
    '篡改后 verify 精确定位到断链行',
    !after.ok && after.brokenAt?.seq === 1,
    `brokenAt.seq=${after.brokenAt?.seq}`,
  );

  console.log(`\n${failures === 0 ? '✓ 全部断言通过' : `✗ ${failures} 条断言失败`}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

void main();
