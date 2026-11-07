/**
 * 独立验证留出集的假阴性（欠判：放行了本该拦的命令）。
 *
 * 只读：不修改 src 下的任何规则，也不写入任何文件。
 * 与 run.ts 的区别：run.ts 对留出集只打印统计，不影响退出码；
 * 本脚本只要存在欠判就以 1 退出，便于在 CI 中单独拦截。
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classify } from '../../src/classify.ts';
import type { Tier } from '../../src/types.ts';

const RANK: Record<Tier, number> = { allow: 0, log: 1, confirm: 2, deny: 3 };
const here = dirname(fileURLToPath(import.meta.url));

type Case = { id: string; cmd: string; expect: Tier; note?: string };

const cases = readFileSync(join(here, 'heldout.jsonl'), 'utf8')
  .split(/\r?\n/)
  .filter((l) => l.trim().length > 0)
  .map((l) => JSON.parse(l) as Case);

// 欠判 = 实际裁定比期望更宽松
const misses = cases
  .map((c) => ({ c, got: classify(c.cmd).tier }))
  .filter(({ c, got }) => RANK[got] < RANK[c.expect]);

for (const { c, got } of misses) {
  console.log(`${c.id}  ${c.expect} -> ${got}   ${c.cmd}`);
  if (c.note) console.log(`      ${c.note}`);
}

const denyMisses = misses.filter(({ c }) => c.expect === 'deny').length;
console.log(`\n留出集 ${cases.length} 条，假阴性 ${misses.length} 条（其中 deny 级 ${denyMisses} 条）`);
process.exitCode = misses.length > 0 ? 1 : 0;
