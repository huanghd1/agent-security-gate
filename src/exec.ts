/**
 * Command execution.
 *
 * Deliberately dumb: the gate already decided *whether* to run this. This
 * module only has to run it correctly and never hang forever. The one subtle
 * requirement is that a timeout must kill the whole process TREE — on Windows
 * `taskkill /T`, on POSIX the process group — otherwise a shell that spawned
 * grandchildren leaves orphans behind after the gate reports "timed out".
 */

import { spawn } from 'node:child_process';
import type { ExecResult } from './types.ts';

const MAX_STREAM = 256 * 1024;

export type ExecOptions = {
  cwd?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
};

function killTree(child: ReturnType<typeof spawn>): void {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    return;
  }
  try {
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    try {
      child.kill('SIGKILL');
    } catch {
      /* already gone */
    }
  }
}

export function execShell(cmd: string, opts: ExecOptions = {}): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const started = Date.now();

  return new Promise<ExecResult>((resolve) => {
    let stdout = '';
    let stderr = '';
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const child = spawn(cmd, {
      cwd: opts.cwd ?? process.cwd(),
      env: opts.env ?? process.env,
      shell: true,
      windowsHide: true,
      detached: process.platform !== 'win32',
    });

    const take = (cur: string, chunk: Buffer): string => {
      if (cur.length >= MAX_STREAM) {
        truncated = true;
        return cur;
      }
      const next = cur + chunk.toString('utf8');
      if (next.length > MAX_STREAM) {
        truncated = true;
        return next.slice(0, MAX_STREAM);
      }
      return next;
    };

    child.stdout?.on('data', (d: Buffer) => {
      stdout = take(stdout, d);
    });
    child.stderr?.on('data', (d: Buffer) => {
      stderr = take(stderr, d);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, timeoutMs);

    const settle = (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code,
        stdout,
        stderr,
        durationMs: Date.now() - started,
        timedOut,
        signal: signal ?? null,
        truncated,
      });
    };

    child.on('error', (err: Error) => {
      stderr += `\n[spawn error] ${err.message}`;
      settle(null, null);
    });
    child.on('close', (code, signal) => settle(code, signal));
  });
}
