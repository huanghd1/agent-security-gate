/**
 * Redaction layer.
 *
 * The audit trail is only useful if it can be shared (in a PR, a ticket, a
 * support bundle). That means secrets must never reach the store in the first
 * place — redacting on read is too late, because the plaintext is already on
 * disk. So: redact BEFORE hashing, before insert, before every log line.
 */

const RULES: Array<{ name: string; re: RegExp; repl: string }> = [
  // Well-known token shapes.
  { name: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, repl: '«REDACTED_PRIVATE_KEY»' },
  { name: 'aws-akid', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, repl: '«REDACTED_AWS_KEY_ID»' },
  { name: 'github-pat', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, repl: '«REDACTED_GH_TOKEN»' },
  { name: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g, repl: '«REDACTED_API_KEY»' },
  { name: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, repl: '«REDACTED_SLACK_TOKEN»' },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, repl: '«REDACTED_JWT»' },
  // Generic `KEY=value` / `Authorization: Bearer ...` in either case.
  {
    name: 'kv-secret',
    re: /\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*)\s*=\s*("([^"]*)"|'([^']*)'|\S+)/gi,
    repl: '$1=«REDACTED»',
  },
  { name: 'bearer', re: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}/gi, repl: '$1 «REDACTED»' },
  // Credentials embedded in URLs: https://user:pass@host
  { name: 'url-cred', re: /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi, repl: '$1«REDACTED»@' },
  // CLI flags that take a secret as the next token.
  { name: 'cli-flag', re: /(--(?:password|passwd|token|api-key|apikey|secret|client-secret)[= ])(?:"[^"]*"|'[^']*'|\S+)/gi, repl: '$1«REDACTED»' },
];

export type Redaction = { text: string; hits: string[] };

/** Redacts a single string. Returns the hit names so the trace can record "we saw a secret here". */
export function redact(input: string): Redaction {
  let text = input;
  const hits: string[] = [];
  for (const rule of RULES) {
    if (!rule.re.test(text)) {
      // RegExp with /g keeps lastIndex between calls — reset defensively.
      rule.re.lastIndex = 0;
      continue;
    }
    rule.re.lastIndex = 0;
    hits.push(rule.name);
    text = text.replace(rule.re, rule.repl);
    rule.re.lastIndex = 0;
  }
  return { text, hits };
}

/** Deep-redacts every string in a JSON-ish value. Keys are preserved. */
export function redactDeep<T>(value: T): { value: T; hits: string[] } {
  const hits = new Set<string>();
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const r = redact(v);
      for (const h of r.hits) hits.add(h);
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = walk(val);
      return out;
    }
    return v;
  };
  return { value: walk(value) as T, hits: [...hits] };
}
