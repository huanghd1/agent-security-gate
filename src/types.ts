/**
 * Shared types for agent-gate.
 *
 * Design note: the type surface is deliberately small and serializable.
 * Everything that crosses a process boundary (trace rows, approval requests,
 * CLI --json output) is plain JSON, so the store and the UI never need to
 * agree on classes.
 */

/** Ordered by severity. `max()` over rules decides the verdict. */
export type Tier = 'allow' | 'log' | 'confirm' | 'deny';

export const TIER_RANK: Record<Tier, number> = {
  allow: 0,
  log: 1,
  confirm: 2,
  deny: 3,
};

export const RANK_TIER: Tier[] = ['allow', 'log', 'confirm', 'deny'];

export function maxTier(a: Tier, b: Tier): Tier {
  return TIER_RANK[a] >= TIER_RANK[b] ? a : b;
}

/** How a single shell segment was joined to the next one. */
export type Op = '&&' | '||' | ';' | '|' | '&' | null;

export type Segment = {
  /** Raw text of this segment, trimmed. */
  raw: string;
  /** argv[0] is the *effective* program after wrapper unwrapping. */
  argv: string[];
  /** Basename, lowercased, .exe stripped, wrapper programs removed. */
  program: string;
  /** Programs we stripped while unwrapping (`sudo`, `env`, `nohup`, ...). */
  wrappers: string[];
  /** Operator that joins this segment to the next. */
  nextOp: Op;
  /** True when this segment came from descending into inline code (`-c`, `$( )`). */
  inline: boolean;
};

export type Norm = {
  raw: string;
  lower: string;
  segments: Segment[];
  /** Every program in the chain, in order (deduped, lowercased). */
  programs: string[];
  /** Redirect targets, e.g. `> out.txt` -> ["out.txt"]. */
  redirects: string[];
  /** Depth of `$( )`, backticks and `${ }` nesting. */
  nesting: number;
  /** Base64/hex-ish opaque blobs found in the command. */
  encodedBlobs: string[];
  /** 0..1 — how much this command tries to hide what it does. */
  obfuscation: number;
  /** Human-readable reasons behind the obfuscation score. */
  signals: string[];
};

export type Rule = {
  id: string;
  tier: Tier;
  title: string;
  /** Longer explanation that ends up in the audit trail. */
  why: string;
  test: (n: Norm) => boolean;
};

export type Match = { ruleId: string; tier: Tier; title: string; why: string };

export type Verdict = {
  tier: Tier;
  matches: Match[];
  ruleIds: string[];
  /** Sorted by severity, deduped. */
  reasons: string[];
  obfuscation: number;
  signals: string[];
  programs: string[];
  /** 0..100 display score; monotonic in tier, nudged by obfuscation. */
  risk: number;
};

export type ApprovalDecision = 'approved' | 'denied' | 'timeout';

export type ApprovalResult = {
  decision: ApprovalDecision;
  /** Who/what decided: `terminal:tty`, `scripted`, `web:127.0.0.1`, `policy`. */
  by: string;
  /** Wall clock spent waiting. Streaming it lets you reason about human latency. */
  waitedMs: number;
  note?: string;
};

export type ExecResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  signal: string | null;
  /** True when stdout/stderr were truncated to the store limit. */
  truncated: boolean;
};

export type StepMode = 'readonly' | 'idempotent' | 'effect';

export type StepDef = {
  id: string;
  cmd: string;
  mode?: StepMode;
  cwd?: string;
  /** Skip classification and go straight to deny (used by tests). */
  disabled?: boolean;
};

export type Manifest = {
  name: string;
  steps: StepDef[];
};
