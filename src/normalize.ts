/**
 * Shell command normalization.
 *
 * Why this exists at all: a regex over the raw string is trivially bypassed
 * (`echo cm0gLXJmIC8= | base64 -d | sh`). The gateway therefore does not ask
 * "does this string contain `rm -rf /`". It asks "what will actually execute",
 * which means it has to tokenize, unwrap privileged wrappers, and *descend*
 * into inline code (`sh -c "..."`, `$(...)`, backticks).
 *
 * The output is a flat `Segment[]`: nested inline code is appended to the same
 * list, so every rule stays a simple "is there a segment such that ...".
 *
 * Known limit, stated up front: this is a static approximation. It cannot see
 * through `eval "$(cat payload.sh)"` where the payload lives in a file, nor
 * through a network fetch whose response is executed later. That is exactly
 * why obfuscation is scored separately and treated as a signal in itself —
 * we detect the *act of hiding*, not only the hidden content.
 */

import type { Norm, Op, Segment } from './types.ts';

const WRAPPERS = new Set([
  'sudo', 'sudoedit', 'doas', 'env', 'nohup', 'time', 'nice', 'command',
  'exec', 'runas', 'setsid', 'stdbuf', 'builtin', 'start-process',
]);

export const INTERPRETERS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash',
  'pwsh', 'powershell', 'cmd',
  'node', 'deno', 'bun', 'python', 'python3', 'python2', 'perl', 'ruby', 'php',
  'iex', 'invoke-expression',
]);

export const DOWNLOADERS = new Set([
  'curl', 'wget', 'iwr', 'invoke-webrequest', 'invoke-restmethod',
  'aria2c', 'start-bitstransfer', 'fetch', 'http', 'xh', 'curlie',
]);

/** Flags that mean "the next token is code to run inline". */
const INLINE_FLAGS = new Set(['-c', '-e', '--eval', '-command', '-enc', '-encodedcommand', '/c', '/k']);

const MAX_SEGMENTS = 64;
const MAX_DEPTH = 3;

type RawSeg = { text: string; nextOp: Op };

/** Splits a command line on shell operators, quote-aware. */
function splitOps(raw: string): RawSeg[] {
  const segs: RawSeg[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  let i = 0;

  const close = (op: Op, isFinal = false) => {
    const text = cur.trim();
    cur = '';
    if (text) {
      segs.push({ text, nextOp: op });
    } else if (!isFinal && segs.length > 0) {
      // Trailing operator (`cmd &`) still belongs to the previous segment.
      segs[segs.length - 1]!.nextOp = op;
    }
  };

  while (i < raw.length) {
    const ch = raw[i]!;

    if (quote) {
      cur += ch;
      if (ch === '\\' && quote === '"') {
        cur += raw[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      i++;
      continue;
    }

    if (ch === '\\') {
      cur += ch + (raw[i + 1] ?? '');
      i += 2;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      i++;
      continue;
    }

    if (ch === '&' && raw[i + 1] === '&') {
      close('&&');
      i += 2;
      continue;
    }
    if (ch === '|' && raw[i + 1] === '|') {
      close('||');
      i += 2;
      continue;
    }
    if (ch === '|') {
      close('|');
      i++;
      continue;
    }
    if (ch === ';' || ch === '\n' || ch === '\r') {
      close(';');
      i++;
      continue;
    }
    if (ch === '&') {
      close('&');
      i++;
      continue;
    }

    cur += ch;
    i++;
  }

  close(null, true);
  return segs;
}

/** Splits one segment into argv tokens, quote-aware, keeping redirects aside. */
function tokenizeSegment(text: string): { argv: string[]; redirects: string[] } {
  const argv: string[] = [];
  const redirects: string[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  let expectRedirect = false;
  let i = 0;

  const flush = () => {
    if (!cur) return;
    if (expectRedirect) {
      redirects.push(cur);
      expectRedirect = false;
    } else if (/^(?:[12]?>>?|[12]?>|<)$/.test(cur)) {
      // Bare operator token without a glued target; the target follows.
      expectRedirect = true;
    } else if (cur.startsWith('>') && cur.length > 1) {
      redirects.push(cur.slice(cur.startsWith('>>') ? 2 : 1));
    } else if (cur.startsWith('<') && cur.length > 1) {
      // input redirect: recorded for visibility, harmless for classification
      redirects.push(cur.slice(1));
    } else {
      argv.push(cur);
    }
    cur = '';
  };

  while (i < text.length) {
    const ch = text[i]!;

    if (quote) {
      cur += ch;
      if (ch === '\\' && quote === '"') {
        cur += text[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      i++;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      i++;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      flush();
      i++;
      continue;
    }

    cur += ch;
    i++;
  }
  flush();

  return { argv: argv.map(canonicalToken), redirects };
}

function stripQuotes(s: string): string {
  const t = s.trim();
  if (t.length >= 2) {
    const a = t[0];
    const b = t[t.length - 1];
    if ((a === '"' && b === '"') || (a === "'" && b === "'")) return t.slice(1, -1);
  }
  return t;
}

/**
 * Decodes bash ANSI-C quoting: `$'\x72\x6d'` is literally `rm`.
 *
 * This matters because it is the cheapest way to hide a program name from any
 * matcher that looks at the string: `$'\x72\x6d' -rf /` reads as gibberish and
 * executes as `rm -rf /`. Decoding here means the rest of the pipeline never
 * has to know this trick exists — canonicalization beats pattern matching.
 */
function decodeAnsiC(body: string): string {
  return body.replace(/\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)/g, (_, esc: string) => {
    if (esc.startsWith('x') && esc.length === 3) return String.fromCharCode(parseInt(esc.slice(1), 16));
    if (/^[0-7]{1,3}$/.test(esc)) return String.fromCharCode(parseInt(esc, 8));
    const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"', '0': '\0', a: '\x07', b: '\b', f: '\f', v: '\v' };
    return map[esc] ?? esc;
  });
}

/** Quote-aware canonicalization: strips outer quotes, decodes `$'...'`. */
function canonicalToken(s: string): string {
  const t = s.trim();
  const ansi = /^\$'([\s\S]*)'$/.exec(t);
  if (ansi) return decodeAnsiC(ansi[1]!);
  return stripQuotes(t);
}

export function basename(p: string): string {
  const clean = p.replace(/^["']|["']$/g, '');
  const parts = clean.split(/[\\/]/);
  return (parts[parts.length - 1] ?? clean).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '');
}

/** Strips `sudo`, `env FOO=1`, `nice -n 5`, ... so rules see the real program. */
function unwrap(argv: string[]): { argv: string[]; wrappers: string[] } {
  const out = [...argv];
  const wrappers: string[] = [];
  for (let guard = 0; guard < 6 && out.length > 0; guard++) {
    const prog = basename(out[0]!);
    if (!WRAPPERS.has(prog)) break;
    wrappers.push(prog);
    out.shift();

    // Skip this wrapper's own flags and, for `env`, its VAR=VAL assignments.
    while (out.length > 0) {
      const tok = out[0]!;
      if (prog === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
        out.shift();
        continue;
      }
      if (tok.startsWith('-')) {
        const carriesValue = /^-(u|g|n|C|d|S|p)$/.test(tok);
        out.shift();
        if (carriesValue && out.length > 0) out.shift();
        continue;
      }
      break;
    }
  }
  return { argv: out, wrappers };
}

function toSegment(text: string, nextOp: Op, inline: boolean): Segment | null {
  const { argv: rawArgv } = tokenizeSegment(text);
  if (rawArgv.length === 0) return null;
  const { argv, wrappers } = unwrap(rawArgv);
  if (argv.length === 0) return null;
  return {
    raw: text,
    argv,
    // `c""url` is `curl` to the shell. Strip intra-word quotes before matching,
    // otherwise quote-splicing defeats every program-name rule at once.
    program: basename(argv[0]!.replace(/["']/g, '')),
    wrappers,
    nextOp,
    inline,
  };
}

/** Flags whose payload is genuinely shell code (so descending always pays). */
const SHELL_PROGRAMS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash',
  'pwsh', 'powershell', 'cmd', 'iex', 'invoke-expression',
]);

/**
 * `node -e "console.log(1)"` is not shell code. Descending into every
 * interpreter payload produces garbage "programs" (`console.log(1)`) and
 * pollutes the trace. So: always descend for shells; for other interpreters
 * only when the payload actually talks to the OS.
 */
function worthDescending(program: string, payload: string): boolean {
  if (SHELL_PROGRAMS.has(program)) return true;
  return /(curl|wget|rm\s+-rf|child_process|execSync|exec\(|spawn|system\(|subprocess|os\.system|popen|urlopen|urllib|requests\.|\|\s*(?:sh|bash|pwsh|python)\b)/i.test(
    payload,
  );
}

/**
 * A descended fragment is only a "command" if its argv[0] looks like one.
 * `console.log(1)` and `x = 1` are code, not programs — keep them out of the
 * program list (rules match on real programs).
 */
function looksLikeCommand(argv: string[]): boolean {
  const head = argv[0] ?? '';
  if (!head) return false;
  return !/[(){};=]/.test(head) && !head.includes(' ');
}

/** Finds `$(...)`, backtick and `sh -c "..."` payloads worth descending into. */
function extractInline(text: string): string[] {
  const found: string[] = [];
  let m: RegExpExecArray | null;

  const sub = /\$\(([^()]{1,400})\)/g;
  while ((m = sub.exec(text))) found.push(m[1]!);

  const bt = /`([^`]{1,400})`/g;
  while ((m = bt.exec(text))) found.push(m[1]!);

  return found;
}

function countNesting(text: string): number {
  const sub = (text.match(/\$\(/g) ?? []).length;
  const bt = (text.match(/`/g) ?? []).length;
  const brace = (text.match(/\$\{/g) ?? []).length;
  return sub + Math.floor(bt / 2) + brace;
}

function findEncodedBlobs(text: string): string[] {
  const blobs: string[] = [];
  const b64 = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let m: RegExpExecArray | null;
  while ((m = b64.exec(text))) blobs.push(m[0]!);
  return blobs;
}

/**
 * Builds the canonical form. `depth` guards against adversarial nesting.
 */
export function normalize(raw: string, depth = 0): Norm {
  const segments: Segment[] = [];
  const redirects: string[] = [];
  const signals: string[] = [];
  const queue: Array<{ text: string; depth: number; inline: boolean }> = [
    { text: raw, depth, inline: false },
  ];
  let nesting = countNesting(raw);
  const encodedBlobs = findEncodedBlobs(raw);

  while (queue.length > 0 && segments.length < MAX_SEGMENTS) {
    const job = queue.shift()!;
    if (job.depth > MAX_DEPTH) {
      signals.push('nesting-limit');
      continue;
    }

    for (const s of splitOps(job.text)) {
      const seg = toSegment(s.text, s.nextOp, job.inline);
      if (!seg) continue;
      if (job.inline && !looksLikeCommand(seg.argv)) {
        signals.push('code-fragment');
        continue;
      }
      segments.push(seg);
      redirects.push(...tokenizeSegment(s.text).redirects);

      // Descend into inline code: `sh -c "..."`, `node -e "..."`.
      if (INTERPRETERS.has(seg.program)) {
        for (let k = 1; k < seg.argv.length; k++) {
          const tok = seg.argv[k]!;
          const payload = seg.argv[k + 1];
          if (INLINE_FLAGS.has(tok.toLowerCase()) && payload && worthDescending(seg.program, payload)) {
            queue.push({ text: payload, depth: job.depth + 1, inline: true });
            signals.push(`inline-code:${seg.program}`);
            break;
          }
        }
      }

      // Descend into command substitution.
      for (const inner of extractInline(s.text)) {
        queue.push({ text: inner, depth: job.depth + 1, inline: true });
        signals.push('command-substitution');
      }
    }
  }

  if (segments.length >= MAX_SEGMENTS) signals.push('segment-limit');

  const programs = [...new Set(segments.map((s) => s.program).filter(Boolean))];
  const lower = raw.toLowerCase();

  const obf = scoreObfuscation(segments, raw, nesting, encodedBlobs);
  signals.push(...obf.signals);

  return {
    raw,
    lower,
    segments,
    programs,
    redirects,
    nesting: Math.max(nesting, depth),
    encodedBlobs,
    obfuscation: obf.score,
    signals: [...new Set(signals)],
  };
}

/**
 * Obfuscation score: how hard is this command trying not to be read?
 *
 * This is the single most useful thing the gateway does. Content detection
 * always has a hole; *concealment* is a much stronger signal and much cheaper
 * to detect reliably. A command that decodes a blob and pipes it to a shell is
 * suspicious regardless of what the blob contains.
 */
function scoreObfuscation(
  segments: Segment[],
  raw: string,
  nesting: number,
  blobs: string[],
): { score: number; signals: string[] } {
  let score = 0;
  const signals: string[] = [];

  const boost = (v: number, why: string) => {
    score += v;
    signals.push(why);
  };

  // download | interpreter — the canonical supply-chain RCE shape.
  for (let i = 0; i < segments.length - 1; i++) {
    const a = segments[i]!;
    const b = segments[i + 1]!;
    if (a.nextOp === '|' && DOWNLOADERS.has(a.program) && INTERPRETERS.has(b.program)) {
      boost(1, 'download-piped-to-interpreter');
    }
  }

  // decode | interpreter — same shape, payload hidden in base64/hex.
  for (let i = 0; i < segments.length - 1; i++) {
    const a = segments[i]!;
    const b = segments[i + 1]!;
    const decodes =
      (a.program === 'base64' && a.argv.some((x) => /^-(d|D|-decode)$/.test(x))) ||
      (a.program === 'xxd' && a.argv.includes('-r')) ||
      (a.program === 'certutil' && a.argv.some((x) => /^-decode/i.test(x))) ||
      (a.program === 'openssl' && a.argv.includes('-d'));
    if (decodes) boost(a.nextOp === '|' && INTERPRETERS.has(b.program) ? 0.9 : 0.55, 'decode-payload');
  }

  if (segments.some((s) => s.program === 'eval')) boost(0.5, 'eval');
  if (segments.some((s) => s.program === 'alias' || s.program === 'function')) boost(0.25, 'alias-redefinition');
  if (segments.some((s) => INTERPRETERS.has(s.program) && s.argv.some((a) => INLINE_FLAGS.has(a.toLowerCase()))))
    boost(0.45, 'inline-interpreter');

  if (blobs.length > 0) boost(0.4, 'opaque-blob');
  if (/\\x[0-9a-f]{2}/i.test(raw)) boost(0.25, 'hex-escapes');
  if (nesting >= 4) boost(0.35, 'deep-nesting');
  else if (nesting >= 2) boost(0.2, 'nesting');

  // `curl -s url -o f && chmod +x f && ./f` — staged payload, no pipe needed.
  const staged = segments.some(
    (s, i) =>
      DOWNLOADERS.has(s.program) &&
      s.argv.some((a) => /^(-o|--output|-outfile|-destination)$/i.test(a)) &&
      segments.slice(i + 1).some((t) => t.program === 'chmod' || /^\.\//.test(t.argv[0] ?? '')),
  );
  if (staged) boost(0.7, 'staged-payload');

  return { score: Math.min(1, Math.round(score * 100) / 100), signals };
}
