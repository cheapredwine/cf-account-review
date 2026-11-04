/**
 * Redaction helpers — shared by all collectors (TS) and mirrored in the
 * PowerShell and bash collectors. See docs/data-policy.md for the full rules.
 */
import { createHash } from "node:crypto";
import { REDACTED } from "./schema.js";

/** Hash an ID deterministically (first 16 hex chars of SHA-256). */
export function hashId(value: string, include = false): string {
  if (include) return value;
  return `h${createHash("sha256").update(value).digest("hex").slice(0, 16)}`;
}

/** Redact DNS record content (origin IPs / CNAME targets) unless authorized. */
export function redactDnsContent(
  content: string | undefined | null,
  include = false,
): string | undefined {
  if (content === undefined || content === null) return undefined;
  if (include) return content;
  return REDACTED;
}

/**
 * Redact origin references inside WAF/rule expressions while keeping the rule
 * readable: replaces hostnames and IPs that look like origin addresses.
 * Public-facing hostnames in `keepHosts` (e.g. the zone's own domains) survive.
 */
const IP_PATTERN = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const PRIVATE_HOST_PATTERN =
  /\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|internal\.[a-z]{2,}|origin\.[-a-z0-9.]+)\b/gi;

export function redactExpression(
  expression: string | undefined,
  keepHosts: string[] = [],
): string | undefined {
  if (!expression) return expression;
  let out = expression.replace(EMAIL_PATTERN, REDACTED);
  out = out.replace(IP_PATTERN, REDACTED);
  out = out.replace(PRIVATE_HOST_PATTERN, REDACTED);
  for (const keep of keepHosts) {
    if (!keep) continue;
    // un-redact occurrences of the zone's own public hostnames
    out = out.replaceAll(`"${keep}"`, `"${keep}"`);
  }
  return out;
}

/** Email addresses never leave a collection. */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
export function redactEmails(text: string): string {
  return text.replace(EMAIL_PATTERN, REDACTED);
}

/**
 * Rule action_parameters are collected for rule-shape checks (e.g. the
 * response-header transform audit). Header NAMES and operations are kept;
 * header VALUES set by a rule are redacted — a short secret value assigned
 * by a transform rule would otherwise pass the opaque-string scan untouched.
 * All other parameters pass through unchanged.
 */
export function redactRuleActionParameters(params: unknown): unknown {
  if (params === null || typeof params !== "object") return params;
  const out: Record<string, unknown> = { ...(params as Record<string, unknown>) };
  const headers = out.headers;
  if (headers !== null && typeof headers === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [name, op] of Object.entries(headers as Record<string, unknown>)) {
      if (op !== null && typeof op === "object" && "value" in (op as Record<string, unknown>)) {
        redacted[name] = { ...(op as Record<string, unknown>), value: REDACTED };
      } else {
        redacted[name] = op;
      }
    }
    out.headers = redacted;
  }
  return out;
}

/**
 * Opaque material never leaves a collection: any whitespace-free run of 64+
 * token-class characters is redacted regardless of where it appears. Legitimate
 * collected posture data (settings, booleans, counts, names, statuses) never
 * needs such a string. Applied before the pre-write scan so the opaque-token
 * scan pattern becomes a structural guarantee rather than a tripwire.
 */
export function redactOpaqueStrings(text: string): string {
  return text.replace(
    /\b[A-Za-z0-9_-]{64,}\b/g,
    (m) => `${REDACTED}:opaque-${m.length}`,
  );
}

/** Detect accidental secrets before an output file is finalized. */
const SECRET_PATTERNS: { pattern: RegExp; severity: "fail" | "warn" }[] = [
  { pattern: /Bearer\s+[A-Za-z0-9._-]+/i, severity: "fail" },
  { pattern: /\b[A-Za-z0-9_-]{64,}\b/, severity: "fail" }, // opaque token-length strings
  { pattern: /\b[A-Za-z0-9_-]{40}\b/, severity: "warn" }, // could be a token or an ID
  {
    pattern: /(?:api[_-]?key|api[_-]?token|password|credential)\s*[:=]\s*\S+/gi,
    severity: "fail",
  },
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
