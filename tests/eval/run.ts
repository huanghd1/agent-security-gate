/**
 * Evaluation harness.
 *
 * Two distinct datasets, because they answer different questions:
 *
 *   cases.jsonl       — the policy *spec*. If this regresses, a rule change
 *                       broke an intention we already agreed on.
 *   adversarial.jsonl — an outside attempt to beat the gate. Written without
 *                       looking at the rule source: alternative syntax,
 *                       obfuscation, and "looks dangerous but is benign"
 *                       probes to measure false positives.
 *
 * The metric that matters is direction, not accuracy:
 *   UNDER  (predicted less strict than intended) — the gate failed open. Bad.
 *   OVER   (predicted stricter)                 — noise. Bad, but survivable.
 *
 * A single perfect score on your own corpus means you wrote the test to match
 * the code. Which is why the adversarial set exists and why it is allowed to
 * fail loudly.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classify } from '../../src/classify.ts';
import type { Tier } from '../../src/types.ts';

type Case = {
  id: string;
  cmd: string;
  expect: Tier;
  cat?: string;
  kind?: string;
  note?: string;
};

const RANK: Record<string, number> = { allow: 0, log: 1, confirm: 2, deny: 3 };
const here = dirname(fileURLToPath(import.meta.url));

function load(file: string): Case[] {
  return readFileSync(join(here, file), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Case);
}

type Row = {
  c: Case;
  got: Tier;
  ruleIds: string[];
  obf: number;
  delta: number; // >0 => over (stricter), <0 => under (looser)
};

function run(cases: Case[]): Row[] {
  return cases.map((c) => {
    const v = classify(c.cmd);
    return { c, got: v.tier, ruleIds: v.ruleIds, obf: v.obfuscation, delta: RANK[v.tier]! - RANK[c.expect]! };
  });
}

function summarize(label: string, rows: Row[]): { exact: number; under: number; over: number } {
  const exact = rows.filter((r) => r.delta === 0).length;
  const under = rows.filter((r) => r.delta < 0).length;
  const over = rows.filter((r) => r.delta > 0).length;
  const pct = ((exact / rows.length) * 100).toFixed(1);

  console.log(`\n=== ${label} (${rows.length} 条) ===`);
  console.log(`精确 ${exact}/${rows.length} (${pct}%)   欠判 ${under}   过判 ${over}`);

  if (under > 0) {
    console.log('\n  欠判 —— 放过了本该拦的（危险方向）:');
    for (const r of rows.filter((x) => x.delta < 0)) {
      console.log(`    ${r.c.id}  ${r.c.expect} -> ${r.got}   ${r.c.cmd}`);
      if (r.c.note) console.log(`          ${r.c.note}`);
    }
  }
  if (over > 0) {
    console.log('\n  过判 —— 拦了不该拦的（噪声方向）:');
    for (const r of rows.filter((x) => x.delta > 0)) {
      console.log(`    ${r.c.id}  ${r.c.expect} -> ${r.got}   ${r.c.cmd}`);
      if (r.c.note) console.log(`          ${r.c.note}`);
      console.log(`          命中: ${r.ruleIds.join(', ')}`);
    }
  }
  return { exact, under, over };
}

function perCategory(rows: Row[]): void {
  const cats = new Map<string, { total: number; ok: number }>();
  for (const r of rows) {
    const k = r.c.cat ?? r.c.kind ?? '?';
    const e = cats.get(k) ?? { total: 0, ok: 0 };
    e.total += 1;
    if (r.delta === 0) e.ok += 1;
    cats.set(k, e);
  }
  console.log('\n  按类别:');
  for (const [k, v] of [...cats.entries()].sort()) {
    const bar = '█'.repeat(Math.round((v.ok / v.total) * 20));
    console.log(`    ${k.padEnd(14)} ${String(v.ok).padStart(2)}/${String(v.total).padEnd(2)} ${bar}`);
  }
}

function main(): number {
  const spec = run(load('cases.jsonl'));
  const adv = run(load('adversarial.jsonl'));

  const s1 = summarize('策略回归集 cases.jsonl', spec);
  perCategory(spec);

  const s2 = summarize('对抗集 adversarial.jsonl', adv);
  const held = run(load('heldout.jsonl'));
  const s3 = summarize('留出集 heldout.jsonl（写完后只跑一次，未据此调规则）', held);

  const evasions = adv.filter((r) => r.c.kind === 'evasion');
  const fps = adv.filter((r) => r.c.kind === 'fp-probe');
  console.log(`\n  绕过尝试: ${evasions.filter((r) => r.delta === 0).length}/${evasions.length} 被正确拦下`);
  console.log(`  误报探针: ${fps.filter((r) => r.delta === 0).length}/${fps.length} 没有被误伤`);

  const total = spec.length + adv.length;
  const exact = s1.exact + s2.exact;
  console.log(`\n训练/调优过的语料: ${exact}/${total} (${((exact / total) * 100).toFixed(1)}%)`);
  console.log(
    `留出集（真实泛化指标）: ${s3.exact}/${held.length} (${((s3.exact / held.length) * 100).toFixed(1)}%)`,
  );

  // Hard gate: no expected-deny case may end up below `confirm`.
  const unsafe = [...spec, ...adv].filter((r) => r.c.expect === 'deny' && RANK[r.got]! < RANK.confirm!);
  if (unsafe.length > 0) {
    console.log(`\n❌ ${unsafe.length} 条 expect=deny 的命令只拿到了 confirm 或更低（未到达硬拦截）`);
    return 1;
  }
  console.log('\n✓ 调优语料中所有 expect=deny 的用例都至少被拦在 confirm 及以上');
  return 0;
}

process.exitCode = main();
