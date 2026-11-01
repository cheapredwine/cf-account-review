/**
 * Redaction helpers — shared by all collectors (TS) and mirrored in the
 * PowerShell and bash collectors. See docs/data-policy.md for the full rules.
 */
import { createHash } from "node:crypto";
import { REDACTED } from "./schema.js";


/** Hash an ID deterministically (first 16 hex chars of SHA-256). */
export function hashId(value: string): string {
  return `h${createHash("sha256").update(value).digest("hex").slice(0, 16)}`;
}

/** Hash every 32-hex Cloudflare ID embedded in an API path. */
export function hashIdsInPath(path: string): string {
  return path.replace(/\b[0-9a-f]{32}\b/g, (m) => hashId(m));
}

/** Redact DNS record content (origin IPs / CNAME targets) unless authorized. */
export function redactDnsContent(content: string | undefined | null): string | undefined {
  if (content === undefined || content === null) return undefined;
  return REDACTED;
}

/**
 * Redact origin references inside WAF/rule expressions while keeping the rule
 * readable: replaces IPs, emails, and internal-looking hostnames. Public
 * hostnames are left as-is (they are already visible in DNS).
 */
const IP_PATTERN = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const PRIVATE_HOST_PATTERN =
  /\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|internal\.[a-z]{2,}|origin\.[-a-z0-9.]+)\b/gi;

export function redactExpression(expression: string | undefined): string | undefined {
  if (!expression) return expression;
  let out = expression.replace(EMAIL_PATTERN, REDACTED);
  out = out.replace(IP_PATTERN, REDACTED);
  out = out.replace(PRIVATE_HOST_PATTERN, REDACTED);
  return out;
}

/** Email addresses never leave a collection. */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
export function redactEmails(text: string): string {
  return text.replace(EMAIL_PATTERN, REDACTED);
}

/** Detect accidental secrets before an output file is finalized. */
const SECRET_PATTERNS: { pattern: RegExp; severity: "fail" | "warn" }[] = [
  { pattern: /Bearer\s+[A-Za-z0-9._-]+/i, severity: "fail" },
  { pattern: /\b[A-Za-z0-9_-]{64,}\b/, severity: "fail" }, // opaque token-length strings
  { pattern: /\b[A-Za-z0-9_-]{40}\b/, severity: "warn" }, // could be a token or an ID
  { pattern: /(?:api[_-]?key|api[_-]?token|password|credential)\s*[:=]\s*\S+/gi, severity: "fail" },
];

export interface SecretScanHit {
  sample: string;
  index: number;
  severity: "fail" | "warn";
}

export function scanForSecrets(text: string): SecretScanHit[] {
  const hits: SecretScanHit[] = [];
  for (const { pattern, severity } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = pattern.exec(text)) !== null && count < 5) {
      hits.push({ sample: match[0] ?? "", index: match.index, severity });
      count++;
    }
  }
  return hits;
}
