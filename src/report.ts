/**
 * Post-hoc analysis: "what did the agent actually want to do, and what did we
 * block?" — plus rule tuning hints.
 *
 * The tuning part is the reason this file exists. A static rule set rots: too
 * many false positives and humans start clicking approve without reading, at
 * which point the gate is decorative. So the gateway measures its own noise and
 * suggests which rules to demote. The human still decides; the data just makes
 * the decision cheap.
 */

import type { Store } from './store.ts';
import type { Tier } from './types.ts';
import { RULES_BY_ID } from './rules.ts';

export type RuleStat = {
  ruleId: string;
  tier: Tier;
  fired: number;
  approved: number;
  denied: number;
  auto: number;
  /** approved / (approved + denied); null when never needed a human. */
  approvalRate: number | null;
};

export type BlockedItem = {
  runId: string;
  stepId: string;
  cmd: string;
  tier: Tier;
  ruleIds: string[];
  decision: string;
  ts: number;
};

export type ReportSummary = {
  scope: string;
  runs: number;
  commands: number;
  byTier: Record<Tier, number>;
  rules: RuleStat[];
  blocked: BlockedItem[];
  medianApprovalMs: number | null;
  suggestions: string[];
  /** Programs seen in commands that matched no rule at all — the blind spots. */
  uncovered: Array<{ program: string; count: number }>;
  chain: { ok: boolean; total: number; brokenAt?: { seq: number; runId: string } };
};

const EMPTY_TIERS = (): Record<Tier, number> => ({ allow: 0, log: 0, confirm: 0, deny: 0 });

function median(nums: number[]): number | null {
  if (nums.length === 0) return null;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? Math.round(((s[mid - 1]! + s[mid]!) / 2) * 10) / 10 : s[mid]!;
}

export function buildReport(store: Store, opts: { runId?: string } = {}): ReportSummary {
  const runIds = opts.runId ? [opts.runId] : store.listRuns(500).map((r) => r.id);

  const byTier = EMPTY_TIERS();
  const rules = new Map<string, RuleStat>();
  const blocked: BlockedItem[] = [];
  const approvalWaits: number[] = [];
  const uncovered = new Map<string, number>();
  let commands = 0;

  for (const runId of runIds) {
    const events = store.events(runId);
    // (stepId -> last classification) so a retried step counts once per attempt.
    const pending = new Map<string, { tid: string[]; tier: Tier }>();

    for (const ev of events) {
      const stepId = typeof ev.payload.stepId === 'string' ? ev.payload.stepId : '';

      if (ev.type === 'cmd_decided') {
        const tier = (typeof ev.payload.tier === 'string' ? ev.payload.tier : 'allow') as Tier;
        const ids = Array.isArray(ev.payload.ruleIds) ? (ev.payload.ruleIds as string[]) : [];
        const cmd = typeof ev.payload.cmd === 'string' ? ev.payload.cmd : '';
        commands += 1;
        byTier[tier] = (byTier[tier] ?? 0) + 1;
        pending.set(stepId, { tid: ids, tier });

        for (const id of ids) {
          // The rule's OWN tier, not the command's verdict: a `log` rule that
          // happened to sit inside a `deny` command is still a log rule, and
          // mislabelling it here would poison the tuning advice.
          const declared = RULES_BY_ID.get(id)?.tier ?? tier;
          const st =
            rules.get(id) ?? { ruleId: id, tier: declared, fired: 0, approved: 0, denied: 0, auto: 0, approvalRate: null };
          st.fired += 1;
          st.tier = declared;
          rules.set(id, st);
        }

        // A command that tripped zero rules is, by definition, invisible to the
        // gate. Counting those programs is how the tool admits its own blind
        // spots instead of implying full coverage.
        if (ids.length === 0) {
          const progs = Array.isArray(ev.payload.programs) ? (ev.payload.programs as string[]) : [];
          for (const p of progs) uncovered.set(p, (uncovered.get(p) ?? 0) + 1);
        }

        if (tier === 'deny') {
          for (const id of ids) {
            const st = rules.get(id);
            if (st && st.tier !== 'log') st.denied += 1;
          }
          blocked.push({ runId, stepId, cmd, tier, ruleIds: ids, decision: 'hard-deny', ts: ev.ts });
        } else if (tier === 'allow' || tier === 'log') {
          for (const id of ids) {
            const st = rules.get(id);
            if (st) st.auto += 1;
          }
        }
      }

      if (ev.type === 'cmd_approved') {
        const decision = typeof ev.payload.decision === 'string' ? ev.payload.decision : 'denied';
        const waited = typeof ev.payload.waitedMs === 'number' ? ev.payload.waitedMs : 0;
        const entry = pending.get(stepId);
        approvalWaits.push(waited);
        for (const id of entry?.tid ?? []) {
          const st = rules.get(id);
          if (!st) continue;
          if (decision === 'approved') st.approved += 1;
          else st.denied += 1;
        }
        if (decision !== 'approved' && entry) {
          const cmdEv = [...events].reverse().find((e) => e.type === 'cmd_decided' && e.payload.stepId === stepId);
          blocked.push({
            runId,
            stepId,
            cmd: typeof cmdEv?.payload.cmd === 'string' ? cmdEv.payload.cmd : '',
            tier: entry.tier,
            ruleIds: entry.tid,
            decision,
            ts: ev.ts,
          });
        }
      }
    }
  }

  for (const st of rules.values()) {
    const decided = st.approved + st.denied;
    st.approvalRate = decided > 0 ? Math.round((st.approved / decided) * 1000) / 1000 : null;
  }

  const med = median(approvalWaits);
  const sorted = [...rules.values()].sort((a, b) => b.fired - a.fired);

  return {
    scope: opts.runId ?? `all runs (${runIds.length})`,
    runs: runIds.length,
    commands,
    byTier,
    rules: sorted,
    blocked,
    medianApprovalMs: med,
    suggestions: suggest(sorted, byTier, commands, med),
    uncovered: [...uncovered.entries()]
      .map(([program, count]) => ({ program, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    chain: store.verify(opts.runId),
  };
}

function suggest(rules: RuleStat[], byTier: Record<Tier, number>, commands: number, med: number | null): string[] {
  const out: string[] = [];

  for (const r of rules) {
    if (r.tier === 'confirm' && r.approved + r.denied >= 3 && (r.approvalRate ?? 0) >= 0.9) {
      out.push(
        `降级建议：${r.ruleId} 已被人工确认 ${r.approved + r.denied} 次，通过率 ${Math.round((r.approvalRate ?? 0) * 100)}%。` +
          ` 摩擦大于保护 —— 考虑 tier → log。`,
      );
    }
    if (r.tier === 'confirm' && r.denied > 0) {
      out.push(`保留：${r.ruleId} 真实拦下过 ${r.denied} 次，这个规则在干活。`);
    }
    if (r.tier === 'confirm' && r.fired === 0) {
      out.push(`僵尸规则：${r.ruleId} 在 ${commands} 条命令里一次都没命中，检查它是否写得太窄。`);
    }
    if (r.tier === 'deny' && r.fired > 0) {
      out.push(`硬拦截：${r.ruleId} 拦下 ${r.fired} 次，属于不可协商项，不要因为"烦"而放宽。`);
    }
  }

  const confirmRate = commands === 0 ? 0 : byTier.confirm / commands;
  if (commands >= 10 && confirmRate > 0.15) {
    out.push(
      `噪声偏高：${Math.round(confirmRate * 100)}% 的命令需要人工确认。超过 15% 时人会开始无脑点"批准"，` +
        `先修规则，别加人。`,
    );
  }
  if (med !== null && med > 60_000) {
    out.push(`人工确认中位耗时 ${(med / 1000).toFixed(1)}s —— 阻塞式审批已经在拖慢流程，考虑改成异步卡片。`);
  }
  if (commands > 0 && byTier.allow === commands) {
    out.push('提示：全部放行。要么环境很安全，要么规则没覆盖到真实风险面。');
  }

  return out;
}

export function formatReport(r: ReportSummary): string {
  const lines: string[] = [];
  const pct = (n: number) => (r.commands ? `${Math.round((n / r.commands) * 100)}%` : '0%');

  lines.push(`范围: ${r.scope}   命令: ${r.commands}   运行: ${r.runs}`);
  lines.push(
    `分级: allow ${r.byTier.allow} (${pct(r.byTier.allow)}) · log ${r.byTier.log} · confirm ${r.byTier.confirm} · deny ${r.byTier.deny}`,
  );
  lines.push(`人工确认中位耗时: ${r.medianApprovalMs === null ? '-' : `${(r.medianApprovalMs / 1000).toFixed(1)}s`}`);
  lines.push(`审计链: ${r.chain.ok ? `完好（${r.chain.total} 条事件）` : `❌ 在第 ${r.chain.brokenAt?.seq} 条处断裂`}`);

  if (r.rules.length > 0) {
    lines.push('');
    lines.push('规则命中排行:');
    const w = Math.max(...r.rules.map((x) => x.ruleId.length), 10);
    for (const x of r.rules.slice(0, 15)) {
      const rate = x.approvalRate === null ? '  -  ' : `${String(Math.round(x.approvalRate * 100)).padStart(3)}%`;
      lines.push(
        `  ${x.ruleId.padEnd(w)}  ${x.tier.padEnd(7)} ×${String(x.fired).padStart(3)}  通过率 ${rate}  (批准 ${x.approved} / 拒绝 ${x.denied})`,
      );
    }
  }

  if (r.blocked.length > 0) {
    lines.push('');
    lines.push(`被拦下的动作 (${r.blocked.length}):`);
    for (const b of r.blocked.slice(0, 10)) {
      lines.push(`  [${b.decision}] ${b.tier}  ${b.cmd.length > 70 ? `${b.cmd.slice(0, 70)}…` : b.cmd}`);
      lines.push(`      ${b.ruleIds.join(', ')}`);
    }
  }

  if (r.uncovered.length > 0) {
    lines.push('');
    lines.push('盲区自查（这些程序从未命中任何规则 —— 网关对它们等于不存在）:');
    for (const u of r.uncovered) lines.push(`  ${u.program.padEnd(14)} ×${u.count}`);
  }

  if (r.suggestions.length > 0) {
    lines.push('');
    lines.push('规则调优建议:');
    for (const s of r.suggestions) lines.push(`  · ${s}`);
  }

  return lines.join('\n');
}
