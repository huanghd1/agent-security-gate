/**
 * Multi-step runner with crash-safe checkpointing.
 *
 * The interesting part is not "run some commands". It is what happens when the
 * process dies in the middle of one.
 *
 * State is derived entirely from the event log, not from memory, so a resumed
 * run sees exactly what a fresh observer would see:
 *
 *   step_finished exists          -> skip it, it already happened once
 *   step_started without finished -> IN FLIGHT, and we cannot know whether the
 *                                    side effect landed
 *
 * That third case is where most "agent resume" implementations quietly corrupt
 * state: they re-run the step and hope. Here the mode decides:
 *
 *   readonly    -> safe to replay, always
 *   idempotent  -> safe to replay by contract (the step says so)
 *   effect      -> NOT safe. Refuse, and make a human say `--accept-partial`.
 *
 * The refusal is the feature. Silently re-running a partially-applied write is
 * how you get double-charged customers and duplicated records.
 */

import { createHash, randomUUID } from 'node:crypto';
import { classify } from './classify.ts';
import { execShell } from './exec.ts';
import type { Approver } from './approval.ts';
import { WebApprover } from './approval.ts';
import type { Store } from './store.ts';
import type { Manifest, StepDef, StepMode, Tier } from './types.ts';

export type RunOptions = {
  runId: string;
  manifest: Manifest;
  approver: Approver;
  store: Store;
  cwd?: string;
  acceptPartial?: boolean;
  approvalTimeoutMs?: number;
  execTimeoutMs?: number;
  log?: (line: string) => void;
};

export type StepState = {
  started: boolean;
  finished: boolean;
  finishedCode?: number | null;
};

export type StepOutcome = {
  id: string;
  state:
    | 'ran'
    | 'skipped'
    | 'replayed'
    | 'blocked-partial'
    | 'denied'
    | 'failed'
    | 'partial-accepted'
    | 'disabled';
  detail?: string;
  tier?: Tier;
  code?: number | null;
  durationMs?: number;
  waitMs?: number;
};

export type RunResult = {
  ok: boolean;
  runId: string;
  outcomes: StepOutcome[];
  stoppedBecause?: string;
};

const idemKey = (runId: string, stepId: string, cmd: string): string =>
  createHash('sha256').update(`${runId}\u0000${stepId}\u0000${cmd}`).digest('hex').slice(0, 16);

export function newRunId(): string {
  const d = new Date();
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `run-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}-${randomUUID().slice(0, 4)}`;
}

/** Rebuilds per-step state from the log. Pure; no side effects. */
export function deriveState(store: Store, runId: string): Map<string, StepState> {
  const state = new Map<string, StepState>();
  for (const ev of store.events(runId)) {
    const stepId = typeof ev.payload.stepId === 'string' ? ev.payload.stepId : null;
    if (!stepId) continue;
    const s = state.get(stepId) ?? { started: false, finished: false };
    if (ev.type === 'cmd_decided') s.started = true;
    if (ev.type === 'step_finished') {
      s.finished = true;
      s.finishedCode = typeof ev.payload.code === 'number' ? ev.payload.code : null;
    }
    state.set(stepId, s);
  }
  return state;
}

export async function runPipeline(opts: RunOptions): Promise<RunResult> {
  const { runId, manifest, approver, store } = opts;
  const cwd = opts.cwd ?? process.cwd();
  const log = opts.log ?? (() => {});
  const approvalTimeoutMs = opts.approvalTimeoutMs ?? 300_000;
  const execTimeoutMs = opts.execTimeoutMs ?? 120_000;
  const outcomes: StepOutcome[] = [];

  const prior = store.events(runId);
  const firstBoot = !prior.some((e) => e.type === 'run_started');
  const state = deriveState(store, runId);

  store.ensureRun(runId, { cwd, label: manifest.name, meta: { steps: manifest.steps.length } });
  if (firstBoot) {
    store.append(runId, 'run_started', { name: manifest.name, cwd, totalSteps: manifest.steps.length });
  } else {
    log(`[resume] ${runId} 已有 ${prior.length} 条事件，从断点继续`);
  }

  const finish = (ok: boolean, stoppedBecause?: string): RunResult => {
    store.append(runId, 'run_finished', { ok, stoppedBecause: stoppedBecause ?? null, outcomes: outcomes.length });
    return { ok, runId, outcomes, stoppedBecause };
  };

  for (const step of manifest.steps) {
    const mode: StepMode = step.mode ?? 'effect';
    const s = state.get(step.id);

    if (step.disabled) {
      outcomes.push({ id: step.id, state: 'disabled' });
      log(`  ⊘ ${step.id}  disabled`);
      continue;
    }

    if (s?.finished) {
      outcomes.push({ id: step.id, state: 'skipped', code: s.finishedCode ?? null });
      log(`  ⏭ ${step.id}  已完成（跳过）`);
      store.append(runId, 'step_state', { stepId: step.id, state: 'skipped', reason: 'checkpoint' });
      continue;
    }

    if (s?.started && !s.finished) {
      // The crash window. This is the whole point of the exercise.
      if (mode === 'effect' && !opts.acceptPartial) {
        store.append(runId, 'step_state', {
          stepId: step.id,
          state: 'inflight-blocked',
          mode,
          reason: 'effect step was in flight when the process died; side effect may be partially applied',
        });
        outcomes.push({ id: step.id, state: 'blocked-partial', detail: 'effect 步在崩溃时处于执行中，无法判断副作用是否已落地' });
        log(`  ⛔ ${step.id}  上次执行中断，副作用可能已部分生效 —— 拒绝自动重跑`);
        log(`     确认后可用 --accept-partial 放行（或将此步标记为 idempotent）`);
        return finish(false, `step ${step.id} blocked: ambiguous partial side effect`);
      }
      if (mode === 'effect') {
        store.append(runId, 'step_state', { stepId: step.id, state: 'partial-accepted', mode });
        outcomes.push({ id: step.id, state: 'partial-accepted' });
        log(`  ⚠ ${step.id}  --accept-partial 已显式放行中断步`);
      } else {
        store.append(runId, 'step_state', { stepId: step.id, state: 'replayed', mode });
        outcomes.push({ id: step.id, state: 'replayed' });
        log(`  ↻ ${step.id}  中断但模式为 ${mode}，可安全重放`);
      }
    }

    const verdict = classify(step.cmd);
    const key = idemKey(runId, step.id, step.cmd);

    store.append(runId, 'cmd_decided', {
      stepId: step.id,
      cmd: step.cmd,
      tier: verdict.tier,
      risk: verdict.risk,
      ruleIds: verdict.ruleIds,
      reasons: verdict.reasons,
      obfuscation: verdict.obfuscation,
      programs: verdict.programs,
      idemKey: key,
      mode,
    });

    if (verdict.tier === 'deny') {
      store.append(runId, 'step_state', { stepId: step.id, state: 'denied', reason: 'hard deny' });
      outcomes.push({ id: step.id, state: 'denied', tier: 'deny', detail: verdict.ruleIds.join(',') });
      log(`  ⛔ ${step.id}  DENY  ${verdict.reasons.join(' / ')}`);
      return finish(false, `step ${step.id} hard-denied by ${verdict.ruleIds.join(',')}`);
    }

    if (verdict.tier === 'confirm') {
      if (approver instanceof WebApprover) {
        const url = await approver.listen();
        log(`  🌐 审批卡片: ${url}`);
      }
      const res = await approver.request({
        id: `${runId}:${step.id}`,
        runId,
        stepId: step.id,
        cmd: step.cmd,
        tier: verdict.tier,
        risk: verdict.risk,
        reasons: verdict.reasons,
        ruleIds: verdict.ruleIds,
        cwd,
        timeoutMs: approvalTimeoutMs,
      });
      store.append(runId, 'cmd_approved', {
        stepId: step.id,
        decision: res.decision,
        by: res.by,
        waitedMs: res.waitedMs,
        note: res.note ?? null,
      });

      if (res.decision !== 'approved') {
        store.append(runId, 'step_state', { stepId: step.id, state: 'denied', reason: res.decision });
        outcomes.push({ id: step.id, state: 'denied', tier: 'confirm', waitMs: res.waitedMs, detail: res.decision });
        log(`  ⛔ ${step.id}  未获批准（${res.decision}）`);
        return finish(false, `step ${step.id} not approved (${res.decision})`);
      }
      log(`  ✔ ${step.id}  已批准（${res.by}，等待 ${res.waitedMs}ms）`);
    }

    const startedAt = Date.now();
    const result = await execShell(step.cmd, {
      cwd: step.cwd ? (step.cwd.startsWith('/') || /^[a-zA-Z]:/.test(step.cwd) ? step.cwd : `${cwd}/${step.cwd}`) : cwd,
      timeoutMs: execTimeoutMs,
    });
    const durationMs = Date.now() - startedAt;

    store.append(runId, 'cmd_result', {
      stepId: step.id,
      code: result.code,
      durationMs,
      timedOut: result.timedOut,
      truncated: result.truncated,
      stdoutTail: result.stdout.slice(-2000),
      stderrTail: result.stderr.slice(-2000),
    });

    const okCode = result.code === 0;
    store.append(runId, 'step_finished', { stepId: step.id, code: result.code, ok: okCode });

    outcomes.push({
      id: step.id,
      state: okCode ? 'ran' : 'failed',
      tier: verdict.tier,
      code: result.code,
      durationMs,
    });
    log(`  ${okCode ? '✓' : '✗'} ${step.id}  exit=${result.code}  ${durationMs}ms  [${verdict.tier}]`);

    if (!okCode) {
      return finish(false, `step ${step.id} exited with ${result.code}`);
    }
  }

  for (const o of outcomes) {
    if (o.state === 'ran' || o.state === 'partial-accepted' || o.state === 'replayed') {
      store.append(runId, 'step_state', { stepId: o.id, state: 'finished-ok' });
    }
  }

  log(`[done] ${runId}  ${outcomes.filter((o) => o.state === 'ran').length} 步执行`);
  return finish(true);
}

/** Single command through the same gate — the `agent-gate exec` path. */
export async function runOne(
  opts: RunOptions & { cmd: string; stepId?: string },
): Promise<{ ok: boolean; outcome: StepOutcome; stdout: string; stderr: string }> {
  const step: StepDef = { id: opts.stepId ?? 'exec', cmd: opts.cmd, mode: 'effect' };
  const manifest: Manifest = { name: 'exec', steps: [step] };

  // Reuse the pipeline so the trace shape is identical between both entry points.
  const before = opts.store.events(opts.runId).length;
  const res = await runPipeline({ ...opts, manifest });

  const events = opts.store.events(opts.runId).slice(before);
  const last = [...events].reverse().find((e) => e.type === 'cmd_result');
  return {
    ok: res.ok,
    outcome: res.outcomes[0] ?? { id: step.id, state: 'denied' },
    stdout: typeof last?.payload.stdoutTail === 'string' ? last.payload.stdoutTail : '',
    stderr: typeof last?.payload.stderrTail === 'string' ? last.payload.stderrTail : '',
  };
}
