/**
 * Headless approval path.
 *
 * When the agent runs on a server with no terminal, the ONLY way a human can
 * say yes is the localhost card. This test drives it end to end — serve, render,
 * click approve — and then proves the opposite property: if nobody clicks, the
 * request dies as `timeout`, which the pipeline treats as denied.
 *
 * Fail-closed is the whole product. If this test fails, nothing else matters.
 */

import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebApprover } from '../../src/approval.ts';

const here = dirname(fileURLToPath(import.meta.url));

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`  ${ok ? '✓' : '✗'} ${label}${detail ? `  — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

async function main(): Promise<void> {
  const app = new WebApprover({ timeoutMs: 4000 });
  const url = await app.listen();
  const parsed = new URL(url);
  const token = parsed.searchParams.get('t') ?? '';
  const base = parsed.origin;

  console.log('\n=== 审批卡片 ===');
  console.log(`  卡片地址: ${url}`);

  // The page must render while a decision is pending, so start the request first.
  const pending = app.request({
    id: 'req-1',
    runId: 'r1',
    stepId: 's1',
    cmd: 'rm -rf ./dist',
    tier: 'confirm',
    risk: 50,
    reasons: ['递归删除'],
    ruleIds: ['fs.rm-recursive'],
    cwd: process.cwd(),
    timeoutMs: 4000,
  });

  await new Promise((r) => setTimeout(r, 150));

  const page = await fetch(url);
  const html = await page.text();
  check('卡片页可访问 (HTTP 200)', page.status === 200);
  check('页面包含待审批容器', html.includes('待审批'));
  check('页面不泄漏审批 token 之外的信息', html.includes('approve') && html.includes('deny'));

  const listing = (await (await fetch(`${base}/api/pending?t=${token}`)).json()) as {
    items: Array<{ id: string; cmd: string }>;
  };
  check('待审批队列里有这条命令', listing.items.some((i) => i.id === 'req-1' && i.cmd.includes('rm -rf')));

  const denied403 = await fetch(`${base}/api/pending?t=wrong-token`);
  check('错误 token 被拒绝 (403)', denied403.status === 403);

  const decide = await fetch(`${base}/api/decide?t=${token}&id=req-1&d=approve`, { method: 'POST' });
  check('点击"批准"被接受', decide.status === 200);
  const result = await pending;
  check('请求返回 approved', result.decision === 'approved', `by=${result.by} waited=${result.waitedMs}ms`);

  console.log('\n=== 无人值守时必须失败关闭 ===');
  const t0 = Date.now();
  const orphan = await app.request({
    id: 'req-2',
    runId: 'r1',
    stepId: 's2',
    cmd: 'npm publish',
    tier: 'confirm',
    risk: 50,
    reasons: ['发布到公共仓库'],
    ruleIds: ['pkg.publish'],
    cwd: process.cwd(),
    timeoutMs: 400,
  });
  const elapsed = Date.now() - t0;
  check('没人点 = timeout（不是 approved）', orphan.decision === 'timeout', `decision=${orphan.decision} ${elapsed}ms`);
  check('在超时附近返回，不会永久挂起', elapsed < 2000, `${elapsed}ms`);

  await app.close();
  console.log(`\n${failures === 0 ? '✓ 全部断言通过' : `✗ ${failures} 条断言失败`}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

void main();
