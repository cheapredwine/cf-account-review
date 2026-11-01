/**
 * Findings engine — evaluates the YAML rulebook against a Collection.
 *
 * Verdicts: pass | warn | fail | manual | na
 * Invariant: incomplete or unreadable evidence can never "pass".
 *
 * Readability (schema 1.1): an omitted list field means "could not read";
 * an empty array means "read, nothing there". Phase entrypoints carry an
 * explicit present/absent/unreadable status. 1.0 collections (no phaseStatus)
 * treat a missing entrypoint as unreadable.
 */
import type { Collection, PhaseEntrypoint, Zone } from "../schema.js";
import { normalizePlan } from "../summarize.js";

export type Verdict = "pass" | "warn" | "fail" | "manual" | "na";
type Tier = "any" | "pro-plus" | "business-plus" | "enterprise";
type Account = Collection["accounts"][number];
type Rule = NonNullable<PhaseEntrypoint["rules"]>[number];

export interface Check {
  id: string;
  name: string;
  domain: string;
  severity: "high" | "medium" | "low";
  type: string;
  /** "zone" (default) evaluates per zone; "account" evaluates once. */
  scope?: "zone" | "account";
  applies?: { planTier?: Tier };
  evidence: string;
  params: Record<string, unknown>;
  warnIf?: string[];
  remediation: string;
  citation: string;
}

export interface Finding {
  check: Check;
  scope: string; // "account" or zone name
  verdict: Verdict;
  detail: string;
}

type Result = { verdict: Verdict; detail: string };

const PLAN_ORDER = { free: 0, pro: 1, business: 2, enterprise: 3 } as const;

/** true / false, or undefined when the zone's plan is unknown. */
export function planAtLeast(zone: Pick<Zone, "plan" | "planLegacyId">, tier: Tier): boolean | undefined {
  if (tier === "any") return true;
  const plan = normalizePlan(zone.plan, zone.planLegacyId);
  if (!plan) return undefined;
  const need = PLAN_ORDER[tier === "pro-plus" ? "pro" : tier === "business-plus" ? "business" : "enterprise"];
  return PLAN_ORDER[plan] >= need;
}

// ---------------------------------------------------------------- helpers

function settingValue(zone: Zone, settingId: string, nested?: string): { value: unknown; readable: boolean } {
  const setting = zone.settings?.[settingId];
  if (!setting) return { value: undefined, readable: false };
  let v: unknown = setting.value;
  if (nested) {
    for (const part of nested.split(".")) {
      if (typeof v !== "object" || v === null) return { value: undefined, readable: false };
      v = (v as Record<string, unknown>)[part];
    }
  }
  return { value: v, readable: v !== undefined };
}

type PhaseState = { state: "present"; rules: Rule[] } | { state: "absent" | "unreadable"; rules: [] };

export function phase(zone: Zone, name: string): PhaseState {
  const ep = zone.phaseEntrypoints?.[name];
  if (ep) return { state: "present", rules: ep.rules ?? [] };
  const st = zone.phaseStatus?.[name];
  if (st === "absent") return { state: "absent", rules: [] };
  return { state: "unreadable", rules: [] };
}

const enabled = (r: Rule) => r.enabled !== false;
const expr = (r: Rule) => (r.expression ?? "").trim();
const ENFORCING = new Set(["block", "challenge", "managed_challenge", "js_challenge"]);

/** An expression that matches (nearly) all traffic. */
function isBroadExpression(e: string): boolean {
  const x = e.trim().toLowerCase();
  if (x === "" || x === "true" || x === "(true)") return true;
  // host-only conditions are still "everything on this hostname"
  return /^\(?\s*http\.host\s+(eq|in|contains|wildcard)\s+[^)]*\)?$/.test(x);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Account-level list field across all accounts; unreadable if any account lacks it. */
function accountList<K extends keyof Account>(
  c: Collection,
  key: K,
): { readable: boolean; items: NonNullable<Account[K]> extends (infer T)[] ? T[] : never } {
  type Item = NonNullable<Account[K]> extends (infer T)[] ? T[] : never;
  if (c.accounts.length === 0) return { readable: false, items: [] as unknown as Item };
  const readable = c.accounts.every((a) => Array.isArray(a[key]));
  const items = c.accounts.flatMap((a) => (Array.isArray(a[key]) ? (a[key] as unknown[]) : [])) as unknown as Item;
  return { readable, items };
}

/** Enterprise account-level WAF: a root ruleset in the managed phase may cover this zone. */
function accountLevelManagedWaf(c: Collection): boolean {
  return c.accounts.some((a) => (a.accountRulesets ?? []).some((r) => r.phase === "http_request_firewall_managed" && r.kind === "root"));
}

function managedExecutions(zone: Zone, key: string): Rule[] {
  return phase(zone, "http_request_firewall_managed").rules.filter(
    (r) => r.action === "execute" && r.actionParameters?.executes === key,
  );
}

// ---------------------------------------------------------------- evaluators

type Evaluator = (check: Check, zone: Zone | null, collection: Collection) => Result;

const evaluators: Record<string, Evaluator> = {
  // -------------------------------------------------- generic zone setting
  zone_setting: (check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const settingId = String(check.params.settingId ?? "");
    const nested = check.params.nested as { path?: string; expect?: unknown } | undefined;
    const miss = (check.params.missVerdict as Verdict | undefined) ?? "fail";
    const { value, readable } = settingValue(zone, settingId, nested?.path);
    if (!readable) {
      return { verdict: "manual", detail: `setting "${settingId}" was not readable for this zone (scope gap or plan restriction)` };
    }
    const sv = String(value);
    if (check.params.expectOneOf) {
      const allowed = (check.params.expectOneOf as unknown[]).map(String);
      if (allowed.includes(sv)) return { verdict: "pass", detail: `value: ${sv}` };
      if (check.warnIf?.map(String).includes(sv)) {
        return { verdict: "warn", detail: `value: ${sv} (acceptable but not recommended)` };
      }
      return { verdict: miss, detail: `value: ${sv} (expected one of: ${allowed.join(", ")})` };
    }
    const expect = nested?.expect ?? check.params.expect;
    if (expect !== undefined) {
      const ok = typeof expect === "boolean" ? value === expect : sv === String(expect);
      return ok ? { verdict: "pass", detail: `value: ${sv}` } : { verdict: miss, detail: `value: ${sv} (expected: ${String(expect)})` };
    }
    return { verdict: "manual", detail: "check misconfigured: no expectation defined" };
  },

  zone_active: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    if (zone.paused === true) {
      return { verdict: "fail", detail: "zone is PAUSED — traffic bypasses Cloudflare; no WAF, DDoS, bot, or TLS policy applies" };
    }
    if (zone.paused === undefined || !zone.status) return { verdict: "manual", detail: "zone status not readable" };
    if (zone.status !== "active") return { verdict: "warn", detail: `zone status is "${zone.status}" (not active)` };
    return { verdict: "pass", detail: `active${zone.type ? `, ${zone.type} setup` : ""}` };
  },

  // -------------------------------------------------- WAF
  waf_managed: (check, zone, c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const key = String(check.params.ruleset ?? "cloudflare_managed");
    const ph = phase(zone, "http_request_firewall_managed");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "managed rules phase not readable (scope gap)" };
    if (ph.state === "absent") {
      return accountLevelManagedWaf(c)
        ? { verdict: "manual", detail: "no zone-level deployment, but an account-level managed WAF ruleset exists — confirm its expression covers this zone" }
        : { verdict: "fail", detail: "no managed rulesets deployed on this zone" };
    }
    const executes = ph.rules.filter((r) => r.action === "execute");
    const identified = executes.some((r) => r.actionParameters?.executes !== undefined);
    if (!identified) {
      // 1.0 collection: cannot tell which ruleset is executed.
      return executes.some(enabled)
        ? { verdict: "manual", detail: `${plural(executes.length, "managed ruleset execution")} found; ruleset identity not collected (schema 1.0) — re-collect` }
        : { verdict: "fail", detail: "no enabled managed ruleset executions" };
    }
    const target = managedExecutions(zone, key);
    if (target.length === 0) return { verdict: "fail", detail: `${key} ruleset is not deployed` };
    const live = target.filter(enabled);
    if (live.length === 0) return { verdict: "fail", detail: `${key} ruleset is deployed but the execute rule is disabled` };
    const ov = live[0]?.actionParameters?.overrides;
    if (ov?.enabled === false) return { verdict: "fail", detail: `${key} deployed but every rule disabled via ruleset-level override` };
    if (ov?.action === "log") return { verdict: "fail", detail: `${key} deployed in log-only mode (ruleset-level action override = log)` };
    const notes: string[] = [];
    if (ov && ov.rulesDisabled > 0) notes.push(`${plural(ov.rulesDisabled, "rule")} individually disabled`);
    if (ov && ov.disabledCategories.length > 0) notes.push(`categories disabled: ${ov.disabledCategories.slice(0, 5).join(", ")}`);
    return { verdict: "pass", detail: `${key} deployed and enforcing${notes.length ? ` (${notes.join("; ")})` : ""}` };
  },

  waf_owasp: (check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_request_firewall_managed");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "managed rules phase not readable (scope gap)" };
    const execs = managedExecutions(zone, "owasp").filter(enabled);
    if (execs.length === 0) {
      const identified = ph.rules.some((r) => r.actionParameters?.executes !== undefined);
      if (ph.state === "present" && !identified) return { verdict: "manual", detail: "ruleset identity not collected (schema 1.0)" };
      return { verdict: "warn", detail: "OWASP Core Ruleset not deployed" };
    }
    const ov = execs[0]?.actionParameters?.overrides;
    if (ov?.enabled === false) return { verdict: "warn", detail: "OWASP deployed but disabled via override" };
    if (ov?.action === "log") return { verdict: "warn", detail: "OWASP deployed in log-only mode" };
    const maxThreshold = Number(check.params.maxScoreThreshold ?? 60);
    if (ov?.scoreThreshold !== undefined && ov.scoreThreshold > maxThreshold) {
      return { verdict: "warn", detail: `OWASP anomaly threshold ${ov.scoreThreshold} is above ${maxThreshold} (very low sensitivity)` };
    }
    return {
      verdict: "pass",
      detail: `OWASP enforcing (action: ${ov?.action ?? "ruleset default"}, threshold: ${ov?.scoreThreshold ?? "default"})`,
    };
  },

  custom_rules: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_request_firewall_custom");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "custom rules phase not readable (scope gap)" };
    const live = ph.rules.filter(enabled);
    if (live.length === 0) return { verdict: "warn", detail: "no enabled custom rules" };
    const enforcing = live.filter((r) => r.action && ENFORCING.has(r.action));
    if (enforcing.length === 0) {
      return { verdict: "warn", detail: `${plural(live.length, "custom rule")}, none block or challenge (log/skip only)` };
    }
    return { verdict: "pass", detail: `${plural(live.length, "enabled custom rule")}, ${enforcing.length} enforcing` };
  },

  broad_skip_audit: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const custom = phase(zone, "http_request_firewall_custom");
    const managed = phase(zone, "http_request_firewall_managed");
    if (custom.state === "unreadable" && managed.state === "unreadable") {
      return { verdict: "manual", detail: "custom and managed phases not readable" };
    }
    const findings: string[] = [];
    for (const r of custom.rules.filter(enabled)) {
      if (r.action !== "skip" || !isBroadExpression(expr(r))) continue;
      const sk = r.actionParameters?.skip;
      const what = sk
        ? [
            sk.currentRuleset ? "remaining custom rules" : "",
            sk.phases.length ? `phases ${sk.phases.join("/")}` : "",
            sk.products.length ? `products ${sk.products.join("/")}` : "",
          ]
            .filter(Boolean)
            .join(", ")
        : "unknown scope";
      findings.push(`custom skip on ${expr(r) || "<all traffic>"} → ${what}`);
    }
    for (const r of managed.rules.filter(enabled)) {
      if (r.action !== "skip" || !isBroadExpression(expr(r))) continue;
      const sk = r.actionParameters?.skip;
      const what = sk ? (sk.rules > 0 ? `${plural(sk.rules, "managed rule")}` : sk.rulesets > 0 ? `${plural(sk.rulesets, "managed ruleset")}` : "remaining managed rules") : "unknown scope";
      findings.push(`WAF exception on ${expr(r) || "<all traffic>"} → ${what}`);
    }
    const partial = custom.state === "unreadable" || managed.state === "unreadable";
    if (findings.length > 0) return { verdict: "warn", detail: findings.slice(0, 3).join("; ") + (findings.length > 3 ? ` (+${findings.length - 3} more)` : "") };
    if (partial) return { verdict: "manual", detail: "one of custom/managed phases not readable; no broad skips in the readable one" };
    return { verdict: "pass", detail: "no site-wide skip rules or WAF exceptions" };
  },

  leaked_credentials: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const lc = zone.leakedCredentialChecks;
    if (!lc || lc.enabled === undefined) return { verdict: "manual", detail: "leaked credentials detection status not readable" };
    return lc.enabled
      ? { verdict: "pass", detail: "leaked credentials detection enabled" }
      : { verdict: "warn", detail: "leaked credentials detection disabled" };
  },

  ip_access_allowlist: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const rules = zone.ipAccessRuleSummary;
    if (!rules) return { verdict: "manual", detail: "IP access rules not readable (or 1.0 collection)" };
    const allow = rules.filter((r) => r.mode === "whitelist");
    if (allow.length === 0) return { verdict: "pass", detail: `${plural(rules.length, "IP access rule")}, none allowlist` };
    const broad = allow.filter((r) => r.target === "country" || r.target === "asn");
    if (broad.length > 0) {
      return {
        verdict: "fail",
        detail: `${plural(broad.length, "country/ASN allowlist rule")} bypass all security products for entire networks: ${broad
          .slice(0, 5)
          .map((r) => `${r.target}=${r.value}`)
          .join(", ")}`,
      };
    }
    return { verdict: "warn", detail: `${plural(allow.length, "IP/range allowlist rule")} bypass WAF, rate limiting, bots and DDoS for those sources` };
  },

  page_rule_security: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const prs = zone.pageRuleSummary;
    if (!prs) return { verdict: "manual", detail: "page rules not readable (or 1.0 collection)" };
    const active = prs.filter((p) => p.status !== "disabled");
    const bad: string[] = [];
    for (const p of active) {
      for (const a of p.actions) {
        if (a.id === "disable_security") bad.push("disable_security");
        if (a.id === "security_level" && (a.value === "off" || a.value === "essentially_off")) bad.push(`security_level=${a.value}`);
        if (a.id === "ssl" && (a.value === "off" || a.value === "flexible")) bad.push(`ssl=${a.value}`);
        if (a.id === "waf" && a.value === "off") bad.push("waf=off");
        if (a.id === "browser_check" && a.value === "off") bad.push("browser_check=off");
      }
    }
    if (bad.length > 0) return { verdict: "fail", detail: `active page rules weaken security: ${[...new Set(bad)].join(", ")}` };
    if (active.length > 0) return { verdict: "pass", detail: `${plural(active.length, "active page rule")}, none weaken security (plan migration to Rules)` };
    return { verdict: "pass", detail: "no active page rules" };
  },

  // -------------------------------------------------- rate limiting
  ratelimit_login: (check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_ratelimit");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "rate limiting phase not readable — cannot confirm login protection" };
    const loginPaths = ((check.params.loginPaths as string[]) ?? []).map((p) => p.toLowerCase());
    const matching = ph.rules.filter((r) => enabled(r) && loginPaths.some((p) => expr(r).toLowerCase().includes(p)));
    if (matching.length === 0) {
      return { verdict: "fail", detail: `no rate limiting rule matches login paths (${loginPaths.join(", ")})` };
    }
    const enforcing = matching.filter((r) => r.action && ENFORCING.has(r.action));
    if (enforcing.length === 0) return { verdict: "warn", detail: "login rate limiting rule exists but only logs" };
    const rl = enforcing[0]?.actionParameters?.ratelimit;
    const params = rl
      ? ` (${rl.requestsPerPeriod ?? "?"} req / ${rl.period ?? "?"}s by ${rl.characteristics.filter((c) => c !== "cf.colo.id").join("+") || "?"}, timeout ${rl.mitigationTimeout ?? "?"}s)`
      : "";
    return { verdict: "pass", detail: `login path rate limited${params}` };
  },

  ratelimit_present: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_ratelimit");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "rate limiting phase not readable" };
    const live = ph.rules.filter(enabled);
    if (live.length === 0) return { verdict: "warn", detail: "no rate limiting rules" };
    const enforcing = live.filter((r) => r.action && ENFORCING.has(r.action));
    if (enforcing.length === 0) return { verdict: "warn", detail: `${plural(live.length, "rate limiting rule")}, all log-only` };
    return { verdict: "pass", detail: `${plural(enforcing.length, "enforcing rate limiting rule")}` };
  },

  legacy_ratelimit: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    if (!Array.isArray(zone.legacyRateLimits)) return { verdict: "manual", detail: "legacy rate limits not readable" };
    const live = (zone.legacyRateLimits as { disabled?: boolean }[]).filter((r) => r?.disabled !== true);
    if (live.length === 0) return { verdict: "pass", detail: "no active legacy rate-limit rules" };
    return { verdict: "warn", detail: `${plural(live.length, "legacy rate-limit rule")} still active` };
  },

  // -------------------------------------------------- bots
  bot_baseline: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const plan = normalizePlan(zone.plan, zone.planLegacyId);
    const custom = phase(zone, "http_request_firewall_custom");
    const usesBmScore = custom.rules.some((r) => enabled(r) && expr(r).includes("cf.bot_management.score") && r.action && ENFORCING.has(r.action));
    if (plan === "enterprise" && usesBmScore) {
      return { verdict: "pass", detail: "Enterprise Bot Management: enforcing custom rules on bot score" };
    }
    const bm = zone.botManagement as Record<string, unknown> | undefined;
    if (!bm || Object.keys(bm).length === 0) return { verdict: "manual", detail: "bot management settings not readable" };
    if (plan === "free" || plan === undefined) {
      if (bm.fight_mode === true) return { verdict: "pass", detail: "Bot Fight Mode on" };
      if (plan === "free") return { verdict: "warn", detail: "Bot Fight Mode off" };
    }
    const def = bm.sbfm_definitely_automated;
    if (typeof def === "string") {
      if (def === "allow") {
        return { verdict: "warn", detail: `Super Bot Fight Mode: definitely-automated traffic allowed${plan === "enterprise" ? " and no bot-score custom rules" : ""}` };
      }
      return { verdict: "pass", detail: `Super Bot Fight Mode: definitely automated → ${def}, likely automated → ${String(bm.sbfm_likely_automated ?? "n/a")}` };
    }
    if (bm.fight_mode === true) return { verdict: "pass", detail: "Bot Fight Mode on" };
    return { verdict: "warn", detail: "no bot mitigation found (no SBFM action, no Bot Fight Mode, no bot-score rules)" };
  },

  bot_verified_exclusion: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_request_firewall_custom");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "custom rules phase not readable" };
    const blocks = ph.rules.filter(
      (r) => enabled(r) && r.action && ENFORCING.has(r.action) && expr(r).includes("cf.bot_management.score"),
    );
    if (blocks.length === 0) return { verdict: "na", detail: "no enforcing bot-score rules to evaluate" };
    const missing = blocks.filter((r) => !expr(r).includes("verified_bot"));
    if (missing.length > 0) {
      return { verdict: "warn", detail: `${plural(missing.length, "bot-score rule")} block/challenge without a verified_bot exclusion` };
    }
    return { verdict: "pass", detail: `${plural(blocks.length, "bot-score rule")}, all exclude verified bots` };
  },

  bot_enforcement: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "http_request_firewall_custom");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "custom rules phase not readable" };
    const botRules = ph.rules.filter((r) => enabled(r) && expr(r).includes("cf.bot_management"));
    if (botRules.length === 0) return { verdict: "warn", detail: "no custom rules use Bot Management signals" };
    const enforcing = botRules.filter((r) => r.action && ENFORCING.has(r.action));
    if (enforcing.length === 0) {
      return { verdict: "fail", detail: `${plural(botRules.length, "Bot Management rule")}, zero enforce (skip/log only)` };
    }
    return { verdict: "pass", detail: `${plural(enforcing.length, "Bot Management rule")} enforce` };
  },

  turnstile: (_check, _zone, c) => {
    const { readable, items } = accountList(c, "turnstileWidgets");
    if (!readable) return { verdict: "manual", detail: "Turnstile widgets not readable" };
    if (items.length === 0) return { verdict: "na", detail: "no Turnstile widgets" };
    const unbound = items.filter((w) => !w.domains || w.domains.length === 0);
    if (unbound.length > 0) return { verdict: "warn", detail: `${plural(unbound.length, "widget")} with no domains bound` };
    return { verdict: "pass", detail: `${plural(items.length, "widget")} with domains bound` };
  },

  // -------------------------------------------------- DDoS
  ddos_not_disabled: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const ph = phase(zone, "ddos_l7");
    if (ph.state === "unreadable") return { verdict: "manual", detail: "HTTP DDoS (ddos_l7) phase not readable" };
    if (ph.state === "absent") return { verdict: "pass", detail: "no overrides — HTTP DDoS managed ruleset at defaults" };
    const problems: string[] = [];
    let lowered = false;
    for (const r of ph.rules) {
      if (r.action !== "execute") continue;
      const ov = r.actionParameters?.overrides;
      if (r.enabled === false) problems.push("execute rule disabled");
      if (ov?.enabled === false) problems.push("ruleset disabled via override");
      if (ov?.action === "log") problems.push("ruleset set to log");
      if (ov?.sensitivityLevel === "eoff") problems.push("sensitivity essentially off");
      if (ov?.sensitivityLevel === "low") lowered = true;
      if (ov && ov.rulesDisabled > 0) problems.push(`${plural(ov.rulesDisabled, "rule")} disabled`);
    }
    if (problems.length > 0) return { verdict: "fail", detail: [...new Set(problems)].join("; ") };
    if (lowered) return { verdict: "warn", detail: "HTTP DDoS sensitivity lowered to low" };
    return { verdict: "pass", detail: "HTTP DDoS overrides present, protections not weakened" };
  },

  // -------------------------------------------------- DNS / origin
  caa_present: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const dns = zone.dnsRecords;
    if (!dns) return { verdict: "manual", detail: "DNS records not readable" };
    const caa = dns.filter((d) => d.type.toUpperCase() === "CAA");
    if (caa.length === 0) return { verdict: "warn", detail: "no CAA records published" };
    return { verdict: "pass", detail: `${plural(caa.length, "CAA record")}` };
  },

  email_records: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const dns = zone.dnsRecords;
    if (!dns) return { verdict: "manual", detail: "DNS records not readable" };
    const hasMx = dns.some((d) => d.type.toUpperCase() === "MX");
    const hasTxt = dns.some((d) => d.type.toUpperCase() === "TXT");
    if (!hasMx) return { verdict: hasTxt ? "pass" : "warn", detail: hasTxt ? "no MX; TXT present (confirm null SPF / reject DMARC manually)" : "no MX and no TXT — publish null SPF and reject DMARC to prevent spoofing" };
    if (!hasTxt) return { verdict: "warn", detail: "MX present but no TXT records (SPF/DMARC missing)" };
    return { verdict: "pass", detail: "MX and TXT present (SPF/DMARC content not exported — confirm manually)" };
  },

  dns_origin_exposure: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const dns = zone.dnsRecords;
    if (!dns) return { verdict: "manual", detail: "DNS records not readable" };
    const web = dns.filter((d) => ["A", "AAAA", "CNAME"].includes(d.type.toUpperCase()) && !d.name.startsWith("_"));
    const proxied = web.filter((d) => d.proxied === true);
    if (proxied.length === 0) return { verdict: "na", detail: "no proxied records — Cloudflare's web security stack is not in the path" };
    const exposed = web.filter((d) => d.proxied === false);
    if (exposed.length === 0) return { verdict: "pass", detail: `all ${plural(web.length, "A/AAAA/CNAME record")} proxied` };
    const names = [...new Set(exposed.map((d) => d.name))];
    return {
      verdict: "warn",
      detail: `${plural(exposed.length, "DNS-only A/AAAA/CNAME record")} next to ${proxied.length} proxied — confirm none resolve to a protected origin: ${names.slice(0, 5).join(", ")}${names.length > 5 ? ", …" : ""}`,
    };
  },

  authenticated_origin_pulls_enabled: (_check, zone) => {
    const aop = zone?.authenticatedOriginPulls;
    if (!aop || aop.enabled === undefined) return { verdict: "manual", detail: "Authenticated Origin Pulls status not readable" };
    if (aop.enabled) return { verdict: "pass", detail: "Authenticated Origin Pulls enabled" };
    return { verdict: "warn", detail: "Authenticated Origin Pulls off — origin must otherwise be locked down (Tunnel, or firewall allowing only Cloudflare IPs)" };
  },

  zone_level_aop_preferred: (_check, zone) => {
    const aop = zone?.authenticatedOriginPulls;
    if (!aop || aop.enabled === undefined) return { verdict: "manual", detail: "Authenticated Origin Pulls status not readable" };
    if (!aop.enabled) return { verdict: "na", detail: "AOP not enabled" };
    if (aop.hasZoneLevelCert === undefined) return { verdict: "manual", detail: "zone-level AOP certificates not readable" };
    if (!aop.hasZoneLevelCert) return { verdict: "warn", detail: "global (shared) AOP certificate only; zone-level certificate recommended" };
    return { verdict: "pass", detail: `zone-level AOP with ${plural(aop.certCount ?? 0, "certificate")}` };
  },

  // -------------------------------------------------- client side / headers / cache
  page_shield_enabled: (_check, zone) => {
    const ps = zone?.pageShield;
    if (!ps || ps.enabled === undefined) return { verdict: "manual", detail: "Page Shield status not readable" };
    return ps.enabled ? { verdict: "pass", detail: "Page Shield enabled" } : { verdict: "fail", detail: "Page Shield disabled" };
  },

  security_headers: (check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const mh = zone.managedHeaders;
    const ph = phase(zone, "http_response_headers_transform");
    if (!mh && ph.state === "unreadable") return { verdict: "manual", detail: "managed transforms and response header rules not readable" };
    const wanted = ((check.params.headers as string[]) ?? []).map((h) => h.toLowerCase());
    const set = new Set<string>();
    if (mh?.response.some((h) => h.id === "add_security_headers" && h.enabled)) {
      ["x-content-type-options", "x-frame-options", "referrer-policy"].forEach((h) => set.add(h));
    }
    for (const r of ph.rules.filter(enabled)) {
      for (const h of r.actionParameters?.headers ?? []) if (h.operation === "set" || h.operation === "add") set.add(h.name);
    }
    const poweredByRemoved = mh?.response.some((h) => h.id === "remove_x-powered-by_header" && h.enabled) ?? false;
    const missing = wanted.filter((h) => !set.has(h));
    const tail = poweredByRemoved ? "" : "; X-Powered-By not stripped at the edge";
    if (missing.length === 0) return { verdict: "pass", detail: `security headers set at the edge${tail}` };
    return {
      verdict: "warn",
      detail: `not set at the edge: ${missing.join(", ")} (fine if the origin sets them — verify)${tail}`,
    };
  },

  html_cache_check: (_check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const prs = zone.pageRuleSummary;
    const cache = phase(zone, "http_request_cache_settings");
    if (!prs && cache.state === "unreadable") return { verdict: "manual", detail: "page rules and cache rules not readable" };
    const issues: string[] = [];
    for (const p of prs ?? []) {
      if (p.status === "disabled") continue;
      if (p.actions.some((a) => a.id === "cache_level" && a.value === "cache_everything")) issues.push("page rule: Cache Everything");
    }
    for (const r of cache.rules.filter(enabled)) {
      if (r.actionParameters?.cache?.eligible === true && isBroadExpression(expr(r))) issues.push(`cache rule eligible on ${expr(r) || "<all traffic>"}`);
    }
    if (issues.length > 0) {
      return { verdict: "warn", detail: `${issues.slice(0, 3).join("; ")} — confirm authenticated/personalized responses bypass cache (cache deception risk)` };
    }
    const partial = !prs || cache.state === "unreadable";
    if (partial) return { verdict: "manual", detail: "no site-wide HTML caching in readable data; page rules or cache rules not readable" };
    return { verdict: "pass", detail: "no site-wide cache-everything rules" };
  },

  // -------------------------------------------------- certificates
  cert_expiry: (check, zone) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const packs = zone.certificatePacks;
    if (!packs || packs.length === 0) return { verdict: "manual", detail: "certificate packs not readable (or none present)" };
    const customPacks = packs.filter((p) => !(p.type === "advanced" && p.certificateAuthority === "lets_encrypt") && p.type !== "universal");
    if (customPacks.length === 0) return { verdict: "pass", detail: "only auto-renewing certificates found" };
    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    const warnMs = Number(check.params.warnDays ?? 90) * day;
    const failMs = Number(check.params.failDays ?? 30) * day;
    const expiring = customPacks
      .filter((p) => p.expiresOn)
      .map((p) => new Date(p.expiresOn as string).getTime())
      .sort((a, b) => a - b);
    const failing = expiring.filter((t) => t - now < failMs);
    const warning = expiring.filter((t) => t - now >= failMs && t - now < warnMs);
    if (failing.length > 0) {
      return { verdict: "fail", detail: `${plural(failing.length, "certificate")} expiring within ${check.params.failDays ?? 30} days (soonest: ${Math.floor(((failing[0] ?? now) - now) / day)} days)` };
    }
    if (warning.length > 0) {
      return { verdict: "warn", detail: `${plural(warning.length, "certificate")} expiring within ${check.params.warnDays ?? 90} days (soonest: ${Math.floor(((warning[0] ?? now) - now) / day)} days)` };
    }
    return { verdict: "pass", detail: `${plural(customPacks.length, "custom certificate")}, all valid > ${check.params.warnDays ?? 90} days` };
  },

  // -------------------------------------------------- account-scoped (non web-security profile)
  access_apps: (_check, _zone, c) => {
    const { readable, items } = accountList(c, "accessApps");
    if (!readable) return { verdict: "manual", detail: "Access applications not readable" };
    if (items.length === 0) return { verdict: "na", detail: "no Access applications" };
    const missing = items.filter((a) => a.hasPolicies === false);
    const bypass = items.filter((a) => (a.policyDecisions ?? []).includes("bypass"));
    if (missing.length > 0 || bypass.length > 0) {
      return { verdict: "fail", detail: `${plural(missing.length, "app")} without policies, ${plural(bypass.length, "app")} with a bypass decision` };
    }
    return { verdict: "pass", detail: `${plural(items.length, "Access app")}, all with policies and no bypass` };
  },

  access_idps: (_check, _zone, c) => {
    const { readable, items } = accountList(c, "accessIdentityProviders");
    if (!readable) return { verdict: "manual", detail: "identity providers not readable" };
    if (items.length === 0) return { verdict: "warn", detail: "no IdPs configured — Access falls back to One-time PIN" };
    if (items.every((p) => p.type === "onetimepin")) return { verdict: "warn", detail: "only One-time PIN IdP configured" };
    return { verdict: "pass", detail: `${plural(items.length, "IdP")} configured` };
  },

  account_setting_flag: (check, _zone, c) => {
    const flag = String(check.params.flag ?? "");
    if (c.accounts.length === 0) return { verdict: "manual", detail: "no accounts collected" };
    for (const account of c.accounts) {
      const value = (account as unknown as Record<string, unknown>)[flag];
      if (value === null || value === undefined) return { verdict: "manual", detail: `"${flag}" not readable for an account` };
      if (value !== check.params.expect) return { verdict: "fail", detail: `"${flag}" is ${String(value)} (expected ${String(check.params.expect)})` };
    }
    return { verdict: "pass", detail: `"${flag}" meets expectation across ${plural(c.accounts.length, "account")}` };
  },

  token_expiry: (_check, _zone, c) => {
    const { readable, items } = accountList(c, "apiTokens");
    if (!readable) return { verdict: "manual", detail: "token inventory not readable" };
    const active = items.filter((t) => t.status === "active" || t.status === undefined);
    if (active.length === 0) return { verdict: "na", detail: "no active API tokens" };
    const noExpiry = active.filter((t) => !t.expiresOn);
    if (noExpiry.length > 0) return { verdict: "warn", detail: `${plural(noExpiry.length, "active token")} with no expiration` };
    return { verdict: "pass", detail: `${plural(active.length, "active token")}, all with expiry` };
  },

  zombie_workers: (check, _zone, c) => {
    const scripts = accountList(c, "workersScripts");
    const routesReadable = c.zones.length > 0 && c.zones.every((z) => Array.isArray(z.workersRoutes));
    const routes = c.zones.flatMap((z) => z.workersRoutes ?? []);
    if (!scripts.readable || !routesReadable) return { verdict: "manual", detail: "Workers scripts or routes not readable" };
    if (check.params.mode === "dangling-routes") {
      const names = new Set(scripts.items.map((s) => s.scriptName).filter(Boolean));
      const dangling = routes.filter((r) => r.script && !names.has(r.script));
      if (dangling.length > 0) return { verdict: "warn", detail: `${plural(dangling.length, "route")} reference scripts not in the inventory` };
      return { verdict: "pass", detail: "all routes reference existing scripts" };
    }
    if (scripts.items.length === 0) return { verdict: "na", detail: "no Workers scripts" };
    const zombies = scripts.items.filter((s) => s.scriptName && !routes.some((r) => r.script === s.scriptName));
    if (zombies.length > 0) {
      return { verdict: "warn", detail: `${plural(zombies.length, "script")} with no route on any audited zone (custom domains / workers.dev not checked)` };
    }
    return { verdict: "pass", detail: `${plural(scripts.items.length, "script")}, all routed` };
  },

  lb_pool_health: (check, _zone, c) => {
    const { readable, items } = accountList(c, "loadBalancerPools");
    if (!readable) return { verdict: "manual", detail: "load balancer pools not readable" };
    if (items.length === 0) return { verdict: "na", detail: "no load balancer pools" };
    const minOrigins = Number(check.params.minOrigins ?? 2);
    const single = items.filter((p) => (p.origins?.length ?? 0) < minOrigins);
    if (single.length > 0) return { verdict: "fail", detail: `${plural(single.length, "pool")} with fewer than ${minOrigins} origins — no failover` };
    return { verdict: "pass", detail: `${plural(items.length, "pool")}, all with ${minOrigins}+ origins` };
  },

  lb_monitor_health: (check, _zone, c) => {
    const { readable, items } = accountList(c, "loadBalancerMonitors");
    if (!readable) return { verdict: "manual", detail: "load balancer monitors not readable" };
    if (items.length === 0) return { verdict: "na", detail: "no load balancer monitors" };
    const max = Number(check.params.maxIntervalSeconds ?? 60);
    const slow = items.filter((m) => (m.interval ?? 0) > max);
    if (slow.length > 0) return { verdict: "warn", detail: `${plural(slow.length, "monitor")} with interval > ${max}s` };
    return { verdict: "pass", detail: `${plural(items.length, "monitor")}, all ≤ ${max}s` };
  },

  aig_gateway: (check, _zone, c) => {
    const { readable, items } = accountList(c, "aiGateways");
    if (!readable) return { verdict: "manual", detail: "AI Gateway inventory not readable" };
    if (items.length === 0) return { verdict: "na", detail: "no AI Gateway gateways" };
    const field = String(check.params.field);
    const miss = (check.params.missVerdict as Verdict | undefined) ?? "warn";
    const bad = items.filter((g) => {
      if (field === "rateLimiting") return !g.rateLimitingLimit || !g.rateLimitingInterval;
      const v = (g as Record<string, unknown>)[field];
      return v !== true;
    });
    const label = String(check.params.label ?? field);
    if (bad.length > 0) return { verdict: miss, detail: `${plural(bad.length, "gateway")} without ${label}` };
    return { verdict: "pass", detail: `${plural(items.length, "gateway")}, all with ${label}` };
  },

  tunnel_access_gap: (_check, _zone, c) => {
    const tunnels = accountList(c, "cfdTunnels");
    if (!tunnels.readable) return { verdict: "manual", detail: "tunnels not readable" };
    if (tunnels.items.length === 0) return { verdict: "na", detail: "no Cloudflare Tunnels" };
    const hostnames = tunnels.items.flatMap((t) => t.publicHostnames ?? []);
    if (hostnames.length === 0) return { verdict: "pass", detail: `${plural(tunnels.items.length, "tunnel")}, no public hostnames` };
    const apps = accountList(c, "accessApps");
    if (!apps.readable) return { verdict: "manual", detail: "tunnels expose public hostnames but Access apps not readable" };
    const protectedDomains = new Set<string>();
    for (const app of apps.items) {
      if (app.domain) protectedDomains.add(app.domain.toLowerCase());
      for (const d of app.selfHostedDomains ?? []) protectedDomains.add(d.toLowerCase());
    }
    const unprotected = hostnames.filter((h) => !protectedDomains.has(h.toLowerCase()));
    if (unprotected.length > 0) {
      return { verdict: "fail", detail: `${plural(unprotected.length, "public tunnel hostname")} without an Access app: ${unprotected.slice(0, 3).join(", ")}${unprotected.length > 3 ? ", …" : ""}` };
    }
    return { verdict: "pass", detail: `${plural(hostnames.length, "public tunnel hostname")}, all behind Access` };
  },
};

export const EVALUATOR_TYPES = Object.keys(evaluators);

export function evaluate(collection: Collection, checks: Check[]): Finding[] {
  const findings: Finding[] = [];
  for (const check of checks) {
    const evaluator = evaluators[check.type];
    if (!evaluator) {
      findings.push({ check, scope: "all", verdict: "manual", detail: `unknown check type "${check.type}"` });
      continue;
    }
    if (check.scope === "account") {
      findings.push({ check, scope: "account", ...evaluator(check, null, collection) });
      continue;
    }
    if (collection.zones.length === 0) {
      findings.push({ check, scope: "account", verdict: "manual", detail: "no zones collected" });
      continue;
    }
    const tier = check.applies?.planTier ?? "any";
    for (const zone of collection.zones) {
      const ok = planAtLeast(zone, tier);
      if (ok === false) {
        findings.push({ check, scope: zone.name, verdict: "na", detail: `zone plan (${zone.plan ?? "unknown"}) below check tier (${tier})` });
        continue;
      }
      const res = evaluator(check, zone, collection);
      // Unknown plan + a pass is fine (evidence was read); but annotate.
      findings.push({ check, scope: zone.name, ...res, detail: ok === undefined ? `${res.detail} [plan unknown]` : res.detail });
    }
  }
  return findings;
}

/** Filter a rulebook by profile (list of domains). Unknown profile → error. */
export function selectProfile(checks: Check[], profiles: Record<string, string[]>, profile: string): Check[] {
  if (profile === "all") return checks;
  const domains = profiles[profile];
  if (!domains) throw new Error(`unknown profile "${profile}" (available: all, ${Object.keys(profiles).join(", ")})`);
  return checks.filter((c) => domains.includes(c.domain));
}
