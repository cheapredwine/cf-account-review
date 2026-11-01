/**
 * Summarizers — turn raw Cloudflare API objects into the minimal, policy-safe
 * shapes the collection schema allows. Pure functions, no I/O.
 *
 * Used by Mode A and compiled into the Mode B single binary; mirrored in
 * collectors/sh/collect-config.sh (python assembler). Keep the two in step —
 * tests/collector-parity.test.ts and tests/web-security.test.ts pin the behavior.
 *
 * Design rule: a summarizer only ever emits enumerations, counts, booleans,
 * numbers, and identifiers that are public Cloudflare constants (managed
 * ruleset names, header names, phase names). Free text, IPs, hostnames inside
 * values, header VALUES, and customer IDs never pass through.
 */

/** Publicly documented managed ruleset IDs → stable short names (fallback when
 * the zone's ruleset list is unreadable). */
export const KNOWN_MANAGED_RULESETS: Record<string, string> = {
  efb7b8c949ac4650a09736fc376e9aee: "Cloudflare Managed Ruleset",
  "4814384a9e5d4991b9815dcfc25d2f1f": "Cloudflare OWASP Core Ruleset",
  c2e184081120413c86c3ab7e14069605: "Cloudflare Exposed Credentials Check Ruleset",
  "4d21379b4f9f4bb088e0729962c8b3cf": "DDoS L7 ruleset",
};

/** Short canonical keys the analyzer matches on. */
export function managedRulesetKey(name: string | undefined): string | undefined {
  if (!name) return undefined;
  const n = name.toLowerCase();
  if (n.includes("owasp")) return "owasp";
  if (n.includes("exposed credentials")) return "exposed_credentials";
  if (n.includes("ddos")) return "ddos_l7";
  if (n.includes("cloudflare managed")) return "cloudflare_managed";
  if (n.includes("sensitive data")) return "sensitive_data_detection";
  return "other_managed";
}

function rec(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function bool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

export interface ActionParametersSummary {
  /** For action=execute: canonical key of the executed ruleset. */
  executes?: string;
  overrides?: {
    enabled?: boolean;
    action?: string;
    sensitivityLevel?: string;
    disabledCategories: string[];
    rulesDisabled: number;
    rulesActionOverridden: number;
    /** Lowest OWASP-style anomaly score threshold set on any rule override. */
    scoreThreshold?: number;
  };
  skip?: {
    currentRuleset: boolean;
    rulesets: number;
    rules: number;
    phases: string[];
    products: string[];
  };
  ratelimit?: {
    characteristics: string[];
    period?: number;
    requestsPerPeriod?: number;
    scorePerPeriod?: number;
    mitigationTimeout?: number;
    requestsToOrigin?: boolean;
    hasCountingExpression: boolean;
  };
  /** Header transform rules: header names (lowercased) and operation only. */
  headers?: { name: string; operation: string }[];
  /** Cache rules: whether the rule marks matching requests cache-eligible. */
  cache?: { eligible?: boolean };
}

/**
 * Summarize a ruleset rule's action_parameters (plus the rule-level
 * `ratelimit` object, which the Rulesets API keeps beside — not inside —
 * action_parameters). `rulesetNames` maps raw ruleset IDs (from the zone's
 * /rulesets list) to their names, so execute rules resolve without hard-coding
 * IDs; KNOWN_MANAGED_RULESETS is the fallback.
 */
export function summarizeActionParameters(
  action: string | undefined,
  raw: unknown,
  rulesetNames: Record<string, string> = {},
  ratelimitRaw?: unknown,
): ActionParametersSummary | undefined {
  const ap = rec(raw);
  if (Object.keys(ap).length === 0 && ratelimitRaw === undefined) return undefined;
  const out: ActionParametersSummary = {};

  if (action === "execute") {
    const id = str(ap.id) ?? "";
    out.executes = managedRulesetKey(rulesetNames[id] ?? KNOWN_MANAGED_RULESETS[id]) ?? "custom_or_unknown";
    const ov = rec(ap.overrides);
    if (Object.keys(ov).length > 0) {
      const categories = arr(ov.categories).map(rec);
      const rules = arr(ov.rules).map(rec);
      const thresholds = rules.map((r) => num(r.score_threshold)).filter((n): n is number => n !== undefined);
      out.overrides = {
        enabled: bool(ov.enabled),
        action: str(ov.action),
        sensitivityLevel: str(ov.sensitivity_level),
        disabledCategories: categories
          .filter((c) => c.enabled === false)
          .map((c) => str(c.category) ?? "")
          .filter((c) => c.length > 0)
          .slice(0, 50),
        rulesDisabled: rules.filter((r) => r.enabled === false).length,
        rulesActionOverridden: rules.filter((r) => typeof r.action === "string").length,
        scoreThreshold: thresholds.length > 0 ? Math.min(...thresholds) : undefined,
      };
    }
  }

  if (action === "skip") {
    const rulesObj = rec(ap.rules);
    out.skip = {
      currentRuleset: ap.ruleset === "current",
      rulesets: arr(ap.rulesets).length,
      rules: Object.values(rulesObj).reduce<number>((n, v) => n + arr(v).length, 0),
      phases: arr(ap.phases).map(String).slice(0, 20),
      products: arr(ap.products).map(String).slice(0, 20),
    };
  }

  if (ratelimitRaw !== undefined && ratelimitRaw !== null) {
    const rl = rec(ratelimitRaw);
    out.ratelimit = {
      characteristics: arr(rl.characteristics).map(String).slice(0, 10),
      period: num(rl.period),
      requestsPerPeriod: num(rl.requests_per_period),
      scorePerPeriod: num(rl.score_per_period),
      mitigationTimeout: num(rl.mitigation_timeout),
      requestsToOrigin: bool(rl.requests_to_origin),
      hasCountingExpression: typeof rl.counting_expression === "string" && rl.counting_expression.length > 0,
    };
  }

  if (ap.headers !== undefined) {
    const headers = rec(ap.headers);
    out.headers = Object.entries(headers)
      .slice(0, 50)
      .map(([name, cfg]) => ({ name: name.toLowerCase(), operation: str(rec(cfg).operation) ?? "unknown" }));
  }

  if (action === "set_cache_settings" && typeof ap.cache === "boolean") {
    out.cache = { eligible: ap.cache };
  }

  return Object.keys(out).length > 0 ? out : undefined;
}

/** IP Access Rules: mode/target always; value only for non-identifying targets. */
export function summarizeIpAccessRule(raw: unknown): { mode?: string; target?: string; value?: string; scope?: string } {
  const r = rec(raw);
  const cfg = rec(r.configuration);
  const target = str(cfg.target);
  const keepValue = target === "country" || target === "asn";
  return {
    mode: str(r.mode),
    target,
    value: keepValue ? str(cfg.value) : "[redacted]",
    scope: str(rec(r.scope).type),
  };
}

/** Page rule action IDs whose values are enumerations safe to keep. */
const PAGE_RULE_ENUM_ACTIONS = new Set([
  "security_level",
  "ssl",
  "cache_level",
  "browser_check",
  "waf",
  "always_use_https",
  "automatic_https_rewrites",
  "email_obfuscation",
  "rocket_loader",
  "disable_security",
  "disable_apps",
  "disable_performance",
  "cache_deception_armor",
]);

/** Page rules: status + action ids, enumerated values only; URL targets dropped. */
export function summarizePageRule(raw: unknown): { status?: string; actions: { id: string; value?: string }[] } {
  const r = rec(raw);
  return {
    status: str(r.status),
    actions: arr(r.actions)
      .map(rec)
      .map((a) => {
        const id = str(a.id) ?? "";
        const v = a.value;
        const value = PAGE_RULE_ENUM_ACTIONS.has(id) && (typeof v === "string" || typeof v === "boolean") ? String(v) : undefined;
        return { id, value };
      })
      .filter((a) => a.id.length > 0),
  };
}

/** Bot management: allow-listed configuration keys only. */
const BOT_KEYS = [
  "fight_mode",
  "enable_js",
  "sbfm_definitely_automated",
  "sbfm_likely_automated",
  "sbfm_verified_bots",
  "sbfm_static_resource_protection",
  "optimize_wordpress",
  "ai_bots_protection",
  "crawler_protection",
  "is_robots_txt_managed",
  "using_latest_model",
  "auto_update_model",
  "suppress_session_score",
] as const;

export function summarizeBotManagement(raw: unknown): Record<string, string | boolean> | undefined {
  const r = rec(raw);
  if (Object.keys(r).length === 0) return undefined;
  const out: Record<string, string | boolean> = {};
  for (const k of BOT_KEYS) {
    const v = r[k];
    if (typeof v === "string" || typeof v === "boolean") out[k] = v;
  }
  return out;
}

/** Managed transforms: id + enabled for request and response sides. */
export function summarizeManagedHeaders(
  raw: unknown,
): { request: { id: string; enabled: boolean }[]; response: { id: string; enabled: boolean }[] } | undefined {
  const r = rec(raw);
  if (Object.keys(r).length === 0) return undefined;
  const pick = (v: unknown) =>
    arr(v)
      .map(rec)
      .map((h) => ({ id: str(h.id) ?? "", enabled: h.enabled === true }))
      .filter((h) => h.id.length > 0);
  return { request: pick(r.managed_request_headers), response: pick(r.managed_response_headers) };
}

/** Zone plan → canonical tier, tolerant of "Enterprise Website", "Pro Plan", legacy_id, etc. */
export function normalizePlan(planName: string | undefined, legacyId?: string): "free" | "pro" | "business" | "enterprise" | undefined {
  for (const candidate of [legacyId, planName]) {
    if (!candidate) continue;
    const p = candidate.toLowerCase();
    if (p.includes("enterprise")) return "enterprise";
    if (p.includes("business")) return "business";
    if (p.includes("pro")) return "pro";
    if (p.includes("free")) return "free";
  }
  return undefined;
}
