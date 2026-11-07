#!/usr/bin/env node
/**
 * agent-gate CLI.
 *
 * Exit codes are part of the contract, because the primary consumer is another
 * program (the agent's shell wrapper, or CI):
 *
 *   0  allowed / executed successfully
 *   1  runtime error
 *   2  needs a human (confirm tier) — for `check`
 *   3  hard-denied (deny tier)
 *   4  a human withheld approval, or it timed out
 *
 * `check` is the seam a coding agent should call before every tool use: it is
 * cheap (no execution) and gives a stable verdict.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { classify, describe } from './classify.ts';
import { Store, defaultDbPath } from './store.ts';
import { makeApprover, type Approver, type ApproverKind } from './approval.ts';import { newRunId, runOne, runPipeline } from './pipeline.ts';
import { buildReport, formatReport } from './report.ts';
import { RULES } from './rules.ts';
import type { Manifest } from './types.ts';

type Args = { _: string[]; flags: Map<string, string | true> };

function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        out.flags.set(a.slice(2, eq), a.slice(eq + 1));
        continue;
      }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        out.flags.set(key, next);
        i++;
      } else {
        out.flags.set(key, true);
      }
      continue;
    }
    out._.push(a);
  }
  return out;
}

const flagStr = (a: Args, k: string): string | undefined => {
  const v = a.flags.get(k);
  return typeof v === 'string' ? v : undefined;
};
const flagNum = (a: Args, k: string): number | undefined => {
  const v = flagStr(a, k);
  return v === undefined ? undefined : Number(v);
};
const flagBool = (a: Args, k: string): boolean => a.flags.get(k) === true || a.flags.get(k) === 'true';

const USAGE = `agent-gate — 给自治 Agent 装一个会拒绝的刹车

用法:
  agent-gate check <command>            只判定，不执行（CI 用，退出码 0/2/3）
  agent-gate explain <command>          判定 + 命中的规则与理由
  agent-gate exec <command>             判定 → 审批 → 执行，写审计
  agent-gate run <manifest.json>        多步流水线，支持崩溃后 resume
  agent-gate report [runId]             复盘：想干什么、拦了什么、规则该怎么调
  agent-gate runs                       列出历史运行
  agent-gate verify [runId]             校验审计链哈希
  agent-gate rules                      列出规则目录

通用参数:
  --db <path>           审计库位置（默认 ./.agent-gate/gate.db）
  --run <id>            复用/指定 run id
  --json                机器可读输出

exec / run 参数:
  --approver <kind>     deny-all(默认) | terminal | web | scripted | auto-approve
  --decisions a,b,c     scripted 模式的决策队列，a=approve d=deny
  --timeout <ms>        人工审批超时，默认 300000；超时即拒绝
  --exec-timeout <ms>   单条命令超时，默认 120000
  --accept-partial      显式放行"崩溃时正在执行的 effect 步"，危险，谨慎
`;

function openStore(a: Args): Store {
  return new Store(flagStr(a, 'db') ?? defaultDbPath());
}

function buildApprover(a: Args): Approver {
  const kind = (flagStr(a, 'approver') ?? 'deny-all') as ApproverKind;
  const decisions = (flagStr(a, 'decisions') ?? '').split(',').filter(Boolean);
  return makeApprover(kind, {
    timeoutMs: flagNum(a, 'timeout'),
    decisions,
  });
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const a = parseArgs(argv);
  const cmd = a._[0];

  if (!cmd || cmd === 'help' || cmd === '--help') {
    process.stdout.write(USAGE);
    return 0;
  }

  switch (cmd) {
    case 'check': {
      const target = a._.slice(1).join(' ');
      if (!target) {
        process.stderr.write('缺少命令\n');
        return 1;
      }
      const v = classify(target);
      if (flagBool(a, 'json')) {
        process.stdout.write(`${JSON.stringify(v)}\n`);
      } else {
        process.stdout.write(`${v.tier}\t${v.risk}\t${v.ruleIds.join(',')}\n`);
      }
      if (v.tier === 'deny') return 3;
      if (v.tier === 'confirm') return 2;
      return 0;
    }

    case 'explain': {
      const target = a._.slice(1).join(' ');
      if (!target) {
        process.stderr.write('缺少命令\n');
        return 1;
      }
      const v = classify(target);
      process.stdout.write(`${describe(v)}\n`);
      if (v.matches.length > 0) {
        process.stdout.write('\n');
        for (const m of v.matches) process.stdout.write(`· ${m.ruleId}\n  ${m.why}\n`);
      }
      return 0;
    }

    case 'exec': {
      const target = a._.slice(1).join(' ');
      if (!target) {
        process.stderr.write('缺少命令\n');
        return 1;
      }
      const store = openStore(a);
      const runId = flagStr(a, 'run') ?? newRunId();
      const approver = buildApprover(a);

      const res = await runOne({
        cmd: target,
        runId,
        stepId: flagStr(a, 'step') ?? `exec-${Date.now().toString(36)}`,
        manifest: { name: 'exec', steps: [] },
        approver,
        store,
        cwd: process.cwd(),
        acceptPartial: flagBool(a, 'accept-partial'),
        approvalTimeoutMs: flagNum(a, 'timeout'),
        execTimeoutMs: flagNum(a, 'exec-timeout'),
        log: (l) => process.stderr.write(`${l}\n`),
      });

      await approver.close?.();
      if (res.stdout) process.stdout.write(res.stdout);
      if (res.stderr) process.stderr.write(res.stderr);
      store.close();

      if (res.ok) return 0;
      const st = res.outcome.state;
      if (st === 'denied') return res.outcome.tier === 'deny' ? 3 : 4;
      if (st === 'failed') return 1;
      return 4;
    }

    case 'run': {
      const file = a._[1];
      if (!file) {
        process.stderr.write('缺少 manifest 路径\n');
        return 1;
      }
      const manifest = JSON.parse(readFileSync(resolve(file), 'utf8')) as Manifest;
      if (!manifest.steps || !Array.isArray(manifest.steps)) {
        process.stderr.write('manifest 缺少 steps[]\n');
        return 1;
      }
      const store = openStore(a);
      const runId = flagStr(a, 'run') ?? newRunId();
      const approver = buildApprover(a);

      process.on('SIGINT', () => {
        store.append(runId, 'run_aborted', { reason: 'SIGINT' });
        process.stderr.write('\n[中断] 已记录 run_aborted，下次运行同一 run id 可从断点恢复\n');
        process.exit(130);
      });

      const res = await runPipeline({
        runId,
        manifest,
        approver,
        store,
        cwd: process.cwd(),
        acceptPartial: flagBool(a, 'accept-partial'),
        approvalTimeoutMs: flagNum(a, 'timeout'),
        execTimeoutMs: flagNum(a, 'exec-timeout'),
        log: (l) => process.stdout.write(`${l}\n`),
      });

      await approver.close?.();
      store.close();

      if (flagBool(a, 'json')) process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
      if (res.ok) return 0;
      if (res.stoppedBecause?.includes('denied')) return 3;
      return 4;
    }

    case 'report': {
      const store = openStore(a);
      const runId = a._[1] ?? flagStr(a, 'run');
      const report = buildReport(store, { runId });
      store.close();
      if (flagBool(a, 'json')) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      else process.stdout.write(`${formatReport(report)}\n`);
      return report.chain.ok ? 0 : 1;
    }

    case 'runs': {
      const store = openStore(a);
      const runs = store.listRuns(50);
      store.close();
      if (runs.length === 0) process.stdout.write('（还没有运行记录）\n');
      for (const r of runs) {
        process.stdout.write(
          `${r.id}  ${new Date(r.createdAt).toISOString().slice(0, 19).replace('T', ' ')}  ${r.label}\n`,
        );
      }
      return 0;
    }

    case 'verify': {
      const store = openStore(a);
      const runId = a._[1] ?? flagStr(a, 'run');
      const res = store.verify(runId);
      store.close();
      if (res.ok) {
        process.stdout.write(`✓ 审计链完好（${res.total} 条事件）\n`);
        return 0;
      }
      process.stdout.write(`✗ 审计链在第 ${res.brokenAt?.seq} 条处断裂（run ${res.brokenAt?.runId}）\n`);
      return 1;
    }

    case 'rules': {
      const tiers: Array<'deny' | 'confirm' | 'log'> = ['deny', 'confirm', 'log'];
      for (const t of tiers) {
        const list = RULES.filter((r) => r.tier === t);
        process.stdout.write(`\n${t.toUpperCase()} (${list.length})\n`);
        for (const r of list) process.stdout.write(`  ${r.id.padEnd(22)} ${r.title}\n`);
      }
      process.stdout.write(`\n合计 ${RULES.length} 条规则\n`);
      return 0;
    }

    default:
      process.stderr.write(`未知命令: ${cmd}\n\n${USAGE}`);
      return 1;
  }
}

main()
  .then((code) => {
    // Set exitCode instead of calling process.exit(): on Windows, exit() can
    // truncate buffered stdout when the consumer is a pipe.
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`[agent-gate] ${(err as Error).stack ?? String(err)}\n`);
    process.exitCode = 1;
  });
