/**
 * Append-only event store (SQLite, `node:sqlite`, zero deps).
 *
 * Two properties matter more than query speed here:
 *
 * 1. **Crash safety.** Every state transition is one row, written before the
 *    next action starts. Killing the process at any point leaves a readable
 *    history — no "in-memory state was lost" ambiguity.
 *
 * 2. **Tamper evidence.** Rows are hash-chained (`prev_hash` + payload). Editing
 *    history after the fact breaks the chain, and `agent-gate verify` points at
 *    the first broken row. This is cheap and it changes the conversation from
 *    "trust the log" to "check the log".
 *
 * Redaction happens before `append`, so plaintext secrets never reach disk.
 */

import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { redactDeep } from './redact.ts';

const GENESIS = '0'.repeat(64);

export type EventRow = {
  seq: number;
  runId: string;
  ts: number;
  type: string;
  payload: Record<string, unknown>;
  prevHash: string;
  hash: string;
};

export type RunRow = {
  id: string;
  createdAt: number;
  cwd: string;
  label: string;
  meta: Record<string, unknown>;
};

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

export function defaultDbPath(cwd = process.cwd()): string {
  return process.env.AGENT_GATE_DB ?? join(cwd, '.agent-gate', 'gate.db');
}

export class Store {
  readonly path: string;
  #db: DatabaseSync;
  #lastHash = new Map<string, string>();

  constructor(path = defaultDbPath()) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        cwd TEXT NOT NULL,
        label TEXT NOT NULL,
        meta TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        type TEXT NOT NULL,
        payload TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, seq);
    `);
  }

  close(): void {
    this.#db.close();
  }

  // --- runs ---------------------------------------------------------------

  ensureRun(id: string, opts: { cwd?: string; label?: string; meta?: Record<string, unknown> } = {}): RunRow {
    const existing = this.getRun(id);
    if (existing) return existing;
    const row: RunRow = {
      id,
      createdAt: Date.now(),
      cwd: opts.cwd ?? process.cwd(),
      label: opts.label ?? id,
      meta: opts.meta ?? {},
    };
    this.#db
      .prepare('INSERT INTO runs (id, created_at, cwd, label, meta) VALUES (?, ?, ?, ?, ?)')
      .run(row.id, row.createdAt, row.cwd, row.label, JSON.stringify(row.meta));
    return row;
  }

  getRun(id: string): RunRow | null {
    const r = this.#db.prepare('SELECT * FROM runs WHERE id = ?').get(id) as
      | { id: string; created_at: number; cwd: string; label: string; meta: string }
      | undefined;
    if (!r) return null;
    return {
      id: r.id,
      createdAt: r.created_at,
      cwd: r.cwd,
      label: r.label,
      meta: safeJson(r.meta),
    };
  }

  listRuns(limit = 20): RunRow[] {
    const rows = this.#db
      .prepare('SELECT * FROM runs ORDER BY created_at DESC LIMIT ?')
      .all(limit) as Array<{ id: string; created_at: number; cwd: string; label: string; meta: string }>;
    return rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      cwd: r.cwd,
      label: r.label,
      meta: safeJson(r.meta),
    }));
  }

  // --- events -------------------------------------------------------------

  /** Appends one event. Redaction happens here so no caller can forget it. */
  append(runId: string, type: string, payload: Record<string, unknown>): { seq: number; hash: string } {
    const { value: clean } = redactDeep(payload);
    const body = JSON.stringify(clean);
    const prev = this.#lastHashOf(runId);
    const ts = Date.now();
    const hash = sha256([prev, runId, String(ts), type, body].join('\n'));

    const info = this.#db
      .prepare('INSERT INTO events (run_id, ts, type, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)')
      .run(runId, ts, type, body, prev, hash);

    this.#lastHash.set(runId, hash);
    return { seq: Number(info.lastInsertRowid), hash };
  }

  #lastHashOf(runId: string): string {
    const cached = this.#lastHash.get(runId);
    if (cached) return cached;
    const row = this.#db
      .prepare('SELECT hash FROM events WHERE run_id = ? ORDER BY seq DESC LIMIT 1')
      .get(runId) as { hash: string } | undefined;
    const h = row?.hash ?? GENESIS;
    this.#lastHash.set(runId, h);
    return h;
  }

  events(runId: string): EventRow[] {
    const rows = this.#db.prepare('SELECT * FROM events WHERE run_id = ? ORDER BY seq').all(runId) as Array<{
      seq: number;
      run_id: string;
      ts: number;
      type: string;
      payload: string;
      prev_hash: string;
      hash: string;
    }>;
    return rows.map((r) => ({
      seq: r.seq,
      runId: r.run_id,
      ts: r.ts,
      type: r.type,
      payload: safeJson(r.payload),
      prevHash: r.prev_hash,
      hash: r.hash,
    }));
  }

  /** Recomputes the whole chain; returns the first row that does not match. */
  verify(runId?: string): { ok: boolean; total: number; brokenAt?: { seq: number; runId: string } } {
    const rows = (runId
      ? this.#db.prepare('SELECT * FROM events WHERE run_id = ? ORDER BY seq').all(runId)
      : this.#db.prepare('SELECT * FROM events ORDER BY seq').all()) as Array<{
      seq: number;
      run_id: string;
      ts: number;
      type: string;
      payload: string;
      prev_hash: string;
      hash: string;
    }>;

    const last = new Map<string, string>();
    for (const r of rows) {
      const prev = last.get(r.run_id) ?? GENESIS;
      const expect = sha256([prev, r.run_id, String(r.ts), r.type, r.payload].join('\n'));
      if (r.prev_hash !== prev || r.hash !== expect) {
        return { ok: false, total: rows.length, brokenAt: { seq: r.seq, runId: r.run_id } };
      }
      last.set(r.run_id, r.hash);
    }
    return { ok: true, total: rows.length };
  }
}

function safeJson(s: string): Record<string, unknown> {
  try {
    const v = JSON.parse(s);
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
