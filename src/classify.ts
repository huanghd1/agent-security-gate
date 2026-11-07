/**
 * Classifier: normalized command -> verdict.
 *
 * Contract: `classify` never throws and never silently downgrades. If a rule
 * itself fails (bad regex, unexpected shape), that is treated as `confirm`,
 * not `allow` — a broken rule must fail closed like everything else here.
 */

import { normalize } from './normalize.ts';
import { RULES } from './rules.ts';
import { TIER_RANK, maxTier } from './types.ts';
import type { Match, Norm, Tier, Verdict } from './types.ts';

export function classifyNorm(n: Norm): Verdict {
  const matches: Match[] = [];

  for (const rule of RULES) {
    try {
      if (rule.test(n)) {
        matches.push({ ruleId: rule.id, tier: rule.tier, title: rule.title, why: rule.why });
      }
    } catch (err) {
      // Fail closed: a rule that cannot decide is a reason to ask a human.
      matches.push({
        ruleId: `${rule.id}:error`,
        tier: 'confirm',
        title: `规则异常：${rule.id}`,
        why: `规则执行失败（${(err as Error).message}），按不可判定处理。`,
      });
    }
  }

  let tier: Tier = 'allow';
  for (const m of matches) tier = maxTier(tier, m.tier);

  // Sort: worst first, so the first `why` a human reads is the real reason.
  matches.sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier] || a.ruleId.localeCompare(b.ruleId));

  const reasons = [...new Set(matches.map((m) => m.title))];
  const risk = Math.min(100, TIER_RANK[tier] * 25 + Math.round(n.obfuscation * 20));

  return {
    tier,
    matches,
    ruleIds: matches.map((m) => m.ruleId),
    reasons,
    obfuscation: n.obfuscation,
    signals: n.signals,
    programs: n.programs,
    risk,
  };
}

export function classify(raw: string): Verdict {
  return classifyNorm(normalize(raw));
}

/** Human-readable multi-line explanation, used by `agent-gate explain`. */
export function describe(v: Verdict): string {
  const lines: string[] = [];
  lines.push(`裁定: ${v.tier.toUpperCase()}   风险: ${v.risk}/100   混淆度: ${v.obfuscation}`);
  lines.push(`程序: ${v.programs.join(', ') || '(none)'}`);
  if (v.matches.length === 0) {
    lines.push('命中规则: 无');
  } else {
    lines.push('命中规则:');
    for (const m of v.matches) lines.push(`  [${m.tier}] ${m.ruleId} — ${m.title}`);
  }
  if (v.signals.length > 0) lines.push(`信号: ${v.signals.join(', ')}`);
  return lines.join('\n');
}
