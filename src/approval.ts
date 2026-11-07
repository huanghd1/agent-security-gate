/**
 * Approval layer — where the human actually enters the loop.
 *
 * The single most important property in this file is **fail-closed**:
 *
 *   timeout            -> denied
 *   no TTY             -> denied (a CI box has no human; do not guess)
 *   malformed decision -> denied
 *   approver throws    -> denied
 *   server never opened-> denied
 *
 * Everything else is convenience. A gate that fails open is worse than no gate,
 * because it manufactures false confidence.
 *
 * Four approvers are provided:
 *   deny-all   — the default. Useless by design; you must opt in.
 *   terminal   — a y/N prompt with a countdown.
 *   web        — a localhost card UI, for when the agent runs headless.
 *   scripted   — a queue of decisions, for tests and CI. This is the "fake
 *                human" that makes a human-in-the-loop system testable at all.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { ApprovalResult, Tier } from './types.ts';

export type ApprovalRequest = {
  id: string;
  runId: string;
  stepId?: string;
  cmd: string;
  tier: Tier;
  risk: number;
  reasons: string[];
  ruleIds: string[];
  cwd: string;
  timeoutMs: number;
};

export type Approver = {
  readonly name: string;
  request(req: ApprovalRequest): Promise<ApprovalResult>;
  close?(): Promise<void> | void;
};

const DENY = (by: string, waitedMs = 0, note?: string): ApprovalResult => ({
  decision: 'timeout',
  by,
  waitedMs,
  note: note ?? 'fail-closed',
});

/** Nothing gets through. The default when no approver is configured. */
export function denyAll(): Approver {
  return {
    name: 'deny-all',
    request: () => Promise.resolve(DENY('deny-all', 0, '没有配置审批人，默认拒绝')),
  };
}

/** A fake human: pops decisions off a queue. `undefined` when exhausted -> deny. */
export function scripted(decisions: Array<'approved' | 'denied'>, name = 'scripted'): Approver {
  const queue = [...decisions];
  return {
    name,
    request: () => {
      const next = queue.shift();
      if (!next) return Promise.resolve(DENY(name, 0, '决策队列已耗尽'));
      return Promise.resolve({ decision: next, by: `${name}:${queue.length} left`, waitedMs: 5 });
    },
  };
}

export function terminal(timeoutMs = 120_000): Approver {
  return {
    name: 'terminal',
    async request(req: ApprovalRequest): Promise<ApprovalResult> {
      // No TTY means no human. Do not block for two minutes pretending otherwise.
      if (!process.stdin.isTTY) return DENY('terminal:no-tty', 0, '当前进程没有 TTY，无法人工确认');

      const started = Date.now();
      const { createInterface } = await import('node:readline/promises');
      const rl = createInterface({ input: process.stdin, output: process.stdout });

      const ask = (async () => {
        const ans = await rl.question(`\n  ⚠ ${req.cmd}\n  ${req.reasons.join(' / ')}\n  批准执行？[y/N] `);
        return ans.trim().toLowerCase();
      })();

      const timer = new Promise<'__timeout'>((r) => setTimeout(() => r('__timeout'), Math.max(1, req.timeoutMs || timeoutMs)));

      try {
        const winner = await Promise.race([ask, timer]);
        const waitedMs = Date.now() - started;
        if (winner === '__timeout') return DENY('terminal', waitedMs, '等待超时');
        return { decision: winner === 'y' || winner === 'yes' ? 'approved' : 'denied', by: 'terminal:tty', waitedMs };
      } catch {
        return DENY('terminal:error', Date.now() - started, '读取输入失败');
      } finally {
        rl.close();
        ask.catch(() => {});
      }
    },
  };
}

/**
 * Localhost approval card. Survives a headless agent: the URL is printed to
 * stderr, the human opens it, clicks, and the blocked call resumes.
 */
export class WebApprover implements Approver {
  readonly name = 'web';
  #server: Server | null = null;
  #token = randomBytes(12).toString('hex');
  #pending = new Map<
    string,
    { req: ApprovalRequest; resolve: (r: ApprovalResult) => void; timer: NodeJS.Timeout; startedAt: number }
  >();
  #url = '';
  #defaultTimeout: number;

  constructor(opts: { timeoutMs?: number; port?: number } = {}) {
    this.#defaultTimeout = opts.timeoutMs ?? 120_000;
    this.#port = opts.port ?? 0;
  }
  #port: number;

  get url(): string {
    return this.#url;
  }

  async listen(): Promise<string> {
    if (this.#server) return this.#url;
    const server = createServer((req, res) => this.#handle(req, res));
    this.#server = server;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.#port, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : this.#port;
    this.#url = `http://127.0.0.1:${port}/?t=${this.#token}`;
    return this.#url;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    await this.listen();
    const started = Date.now();
    const id = req.id;

    return await new Promise<ApprovalResult>((resolve) => {
      const timer = setTimeout(() => {
        this.#settle(id, DENY('web:timeout', Date.now() - started, '等待超时'));
      }, Math.max(1, req.timeoutMs || this.#defaultTimeout));

      this.#pending.set(id, { req, resolve, timer, startedAt: started });
    });
  }

  #settle(id: string, result: ApprovalResult): void {
    const entry = this.#pending.get(id);
    if (!entry) return;
    this.#pending.delete(id);
    clearTimeout(entry.timer);
    entry.resolve(result);
  }

  #authorized(url: URL): boolean {
    return url.searchParams.get('t') === this.#token;
  }

  #handle(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (!this.#authorized(url)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }).end('forbidden');
      return;
    }

    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(this.#page());
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/pending') {
      const items = [...this.#pending.entries()].map(([id, e]) => ({
        id,
        cmd: e.req.cmd,
        tier: e.req.tier,
        risk: e.req.risk,
        reasons: e.req.reasons,
        ruleIds: e.req.ruleIds,
        cwd: e.req.cwd,
        stepId: e.req.stepId ?? null,
      }));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ items }));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/decide') {
      const id = url.searchParams.get('id') ?? '';
      const d = url.searchParams.get('d');
      if (!this.#pending.has(id) || (d !== 'approve' && d !== 'deny')) {
        res.writeHead(400).end(JSON.stringify({ ok: false }));
        return;
      }
      const entry = this.#pending.get(id);
      const waitedMs = entry ? Date.now() - entry.startedAt : 0;
      this.#settle(id, {
        decision: d === 'approve' ? 'approved' : 'denied',
        by: 'web:127.0.0.1',
        waitedMs,
      });
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404).end('not found');
  }

  #page(): string {
    return `<!doctype html><html lang="zh"><meta charset="utf-8">
<title>agent-gate · 审批</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;
        --red:#f85149;--amber:#d29922;--green:#3fb950;--blue:#58a6ff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;padding:24px}
  h1{font-size:15px;font-weight:600;letter-spacing:.02em;margin:0 0 4px}
  .sub{color:var(--dim);font-size:12px;margin-bottom:20px}
  .empty{color:var(--dim);border:1px dashed var(--line);border-radius:10px;padding:28px;text-align:center}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
  .card.hi{border-color:var(--red)}
  .row{display:flex;gap:10px;align-items:center;margin-bottom:10px}
  .badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid}
  .badge.deny{color:var(--red);border-color:var(--red)}
  .badge.confirm{color:var(--amber);border-color:var(--amber)}
  .badge.log{color:var(--blue);border-color:var(--blue)}
  .risk{margin-left:auto;color:var(--dim);font-size:12px}
  pre{background:#010409;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;
      white-space:pre-wrap;word-break:break-all;margin:0 0 10px;font-size:13px}
  ul{margin:0 0 12px;padding-left:18px;color:var(--dim);font-size:12px}
  .btns{display:flex;gap:8px}
  button{font:inherit;font-size:13px;padding:8px 18px;border-radius:8px;border:1px solid var(--line);
         background:#21262d;color:var(--fg);cursor:pointer}
  button.ok{border-color:var(--green);color:var(--green)}
  button.no{border-color:var(--red);color:var(--red)}
  button:hover{filter:brightness(1.3)}
  .meta{color:var(--dim);font-size:11px;margin-top:8px}
</style>
<h1>agent-gate · 待审批</h1>
<div class="sub">每一行都是一个被拦下的、不可回滚的动作。超时 = 拒绝。</div>
<div id="list"><div class="empty">没有待审批项</div></div>
<script>
const T = new URLSearchParams(location.search).get('t') || '';
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function decide(id, d){
  await fetch('/api/decide?t='+encodeURIComponent(T)+'&id='+encodeURIComponent(id)+'&d='+d, {method:'POST'});
  load();
}
function render(items){
  const el = document.getElementById('list');
  if (!items.length){ el.innerHTML = '<div class="empty">没有待审批项</div>'; return; }
  el.innerHTML = items.map(it => \`
    <div class="card \${it.tier === 'deny' ? 'hi' : ''}">
      <div class="row">
        <span class="badge \${esc(it.tier)}">\${esc(it.tier)}</span>
        <span class="meta">\${esc(it.stepId || it.id)}</span>
        <span class="risk">risk \${it.risk}/100</span>
      </div>
      <pre>\${esc(it.cmd)}</pre>
      <ul>\${it.reasons.map(r => '<li>'+esc(r)+'</li>').join('')}</ul>
      <div class="btns">
        <button class="ok" onclick="decide('\${esc(it.id)}','approve')">批准</button>
        <button class="no" onclick="decide('\${esc(it.id)}','deny')">拒绝</button>
      </div>
      <div class="meta">\${esc(it.ruleIds.join(', '))} · cwd \${esc(it.cwd)}</div>
    </div>\`).join('');
}
let last = '';
async function load(){
  try{
    const r = await fetch('/api/pending?t='+encodeURIComponent(T));
    const j = await r.json();
    const sig = JSON.stringify(j.items);
    if (sig !== last){ last = sig; render(j.items); }
  }catch(e){}
}
load(); setInterval(load, 800);
</script></html>`;
    }

  async close(): Promise<void> {
    for (const [id] of this.#pending) this.#settle(id, DENY('web:shutdown', 0, '审批服务关闭'));
    const s = this.#server;
    this.#server = null;
    if (s) await new Promise<void>((r) => s.close(() => r()));
  }
}

export type ApproverKind = 'deny-all' | 'terminal' | 'web' | 'scripted' | 'auto-approve';

/**
 * `auto-approve` exists for CI and for demos, and it is deliberately loud about
 * what it is. It is never the default, and every use is written into the trace.
 */
export function makeApprover(kind: ApproverKind, opts: { timeoutMs?: number; decisions?: string[]; port?: number } = {}): Approver {
  switch (kind) {
    case 'terminal':
      return terminal(opts.timeoutMs);
    case 'web':
      return new WebApprover({ timeoutMs: opts.timeoutMs, port: opts.port });
    case 'scripted':
      return scripted((opts.decisions ?? []).map((d) => (d === 'approve' || d === 'approved' ? 'approved' : 'denied')));
    case 'auto-approve':
      return {
        name: 'auto-approve',
        request: () => Promise.resolve({ decision: 'approved', by: 'auto-approve:EXPLICIT', waitedMs: 0, note: '显式关闭人工确认' }),
      };
    case 'deny-all':
    default:
      return denyAll();
  }
}
