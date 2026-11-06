/**
 * Findings engine — evaluates the YAML rulebook against a Collection.
 *
 * Verdicts: pass | warn | fail | manual | na
 * Invariant: incomplete or unreadable evidence can never "pass".
 */
import type { Collection, Zone } from "../schema.js";

export type Verdict = "pass" | "warn" | "fail" | "manual" | "na";

export interface Check {
  id: string;
  name: string;
  domain: string;
  tier: "lite" | "full"; // Binary checks (lite) vs contextual/SE-assisted checks (full)
  severity: "high" | "medium" | "low";
  type: string;
  applies?: { planTier?: "any" | "pro-plus" | "business-plus" | "enterprise" };
  evidence: string;
  params: Record<string, unknown>;
  warnIf?: string[];
  remediation: string;
  citation: string;
  compliance?: string[]; // SOC 2 TSC codes, PCI DSS requirements
}

export interface Finding {
  check: Check;
  scope: string; // "account" or zone name
  verdict: Verdict;
  detail: string;
}

const PLAN_ORDER: Record<string, number> = {
  free: 0,
  pro: 1,
  business: 2,
  enterprise: 3,
};

/**
 * Reduce a zone plan display name to its tier. The API returns names such as
 * "Enterprise Website", "Business Website", "Pro Plan" or "Free Website"
 * (legacy_id is not collected), so the tier is the first known tier word in
 * the name rather than an exact match — an exact match silently treated every
 * Enterprise zone as Free and marked all tiered checks `na`.
 */
export function planTier(plan: string | undefined): string | undefined {
  if (!plan) return undefined;
  const words = plan.toLowerCase().split(/[^a-z]+/);
  return words.find((w) => w in PLAN_ORDER);
}

export function planAtLeast(plan: string | undefined, tier: string): boolean {
  if (tier === "any") return true;
  const planKey = planTier(plan);
  if (planKey === undefined) return false;
  const need = PLAN_ORDER[tier.replace("-plus", "")] ?? 0;
  const have = PLAN_ORDER[planKey] ?? 0;
  if (tier.endsWith("-plus")) return have >= need;
  return planKey === tier;
}

/** Rule-level overrides on an `execute` rule (managed ruleset deployments). */
function executeOverrides(r: { action?: string; action_parameters?: unknown }) {
  if (r.action !== "execute") return undefined;
  const ap = r.action_parameters;
  if (typeof ap !== "object" || ap === null) return undefined;
  const ov = (ap as Record<string, unknown>).overrides;
  if (typeof ov !== "object" || ov === null) return undefined;
  const o = ov as Record<string, unknown>;
  return {
    enabled: typeof o.enabled === "boolean" ? o.enabled : undefined,
    action: typeof o.action === "string" ? o.action : undefined,
  };
}

/** True when the rule is on AND, for execute rules, its managed ruleset is not
 *  switched off wholesale via `overrides.enabled: false`. */
function ruleEffectivelyEnabled(r: {
  enabled?: boolean;
  action?: string;
  action_parameters?: unknown;
}): boolean {
  if (r.enabled === false) return false;
  return executeOverrides(r)?.enabled !== false;
}

function settingValue(
  zone: Zone,
  settingId: string,
  nested?: string,
): { value: unknown; readable: boolean } {
  const setting = zone.settings?.[settingId];
  if (!setting) return { value: undefined, readable: false };
  let v: unknown = setting.value;
  if (nested) {
    for (const part of nested.split(".")) {
      if (typeof v !== "object" || v === null)
        return { value: undefined, readable: false };
      v = (v as Record<string, unknown>)[part];
    }
  }
  return { value: v, readable: v !== undefined };
}

function rules(zone: Zone, phase: string) {
  return zone.phaseEntrypoints?.[phase]?.rules ?? undefined;
}

type Evaluator = (
  check: Check,
  zone: Zone | null,
  collection: Collection,
) => { verdict: Verdict; detail: string };

const evaluators: Record<string, Evaluator> = {
  response_header_transform: (_check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const rs = rules(zone, "http_response_headers_transform");
    if (rs === undefined) {
      return {
        verdict: "manual",
        detail:
          "response header transform phase not readable (not deployed, or scope gap)",
      };
    }
    const securityHeaders = [
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
    ];
    // Response header transform rules use action "rewrite"; removal is
    // action_parameters.headers.<name>.operation = "remove" (per the
    // response-header-modification docs).
    const stripping = rs.filter((r) => {
      const rule = r as {
        action?: string;
        enabled?: boolean;
        action_parameters?: {
          headers?: Record<string, { operation?: string }>;
        };
      };
      if (rule.action !== "rewrite" || rule.enabled === false) return false;
      const headers = rule.action_parameters?.headers ?? {};
      return Object.entries(headers).some(
        ([name, op]) =>
          securityHeaders.includes(name.toLowerCase()) &&
          String(op?.operation ?? "").toLowerCase() === "remove",
      );
    });
    if (stripping.length > 0) {
      return {
        verdict: "fail",
        detail: `${stripping.length} response transform rule(s) remove security headers (CSP/HSTS/XFO/XCTO)`,
      };
    }
    if (rs.length === 0) {
      return {
        verdict: "na",
        detail: "no edge response-header transforms configured",
      };
    }
    return {
      verdict: "pass",
      detail: "response transforms do not strip security headers",
    };
  },
  zone_setting: (check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const settingId = String(check.params.settingId ?? "");
    const nested = check.params.nested as
      | { path?: string; expect?: unknown }
      | undefined;
    const { value, readable } = settingValue(zone, settingId, nested?.path);
    if (!readable) {
      return {
        verdict: "manual",
        detail: `setting "${settingId}" was not readable for this zone (scope gap or plan restriction)`,
      };
    }
    if (check.params.expectOneOf) {
      const allowed = (check.params.expectOneOf as string[]).map(String);
      const sv = String(value);
      if (allowed.includes(sv))
        return { verdict: "pass", detail: `value: ${sv}` };
      if (check.warnIf && check.warnIf.map(String).includes(sv)) {
        return {
          verdict: "warn",
          detail: `value: ${sv} (acceptable but not recommended)`,
        };
      }
      return {
        verdict: "fail",
        detail: `value: ${sv} (expected one of: ${allowed.join(", ")})`,
      };
    }
    if (check.params.expect !== undefined) {
      const ok =
        typeof check.params.expect === "boolean"
          ? value === check.params.expect
          : String(value) === String(check.params.expect);
      return ok
        ? { verdict: "pass", detail: `value matches expectation` }
        : {
            verdict: "fail",
            detail: `value: ${String(value)} (expected: ${String(check.params.expect)})`,
          };
    }
    return {
      verdict: "manual",
      detail: "check misconfigured: no expectation defined",
    };
  },

  phase_present: (check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const phase = String(check.params.phase ?? "");
    const rs = rules(zone, phase);
    if (rs === undefined) {
      return {
        verdict: "manual",
        detail: `phase ${phase} not readable (no ruleset deployed, or scope gap)`,
      };
    }
    const enabledRules = rs.filter(ruleEffectivelyEnabled);
    if (enabledRules.length === 0) {
      return {
        verdict: "fail",
        detail: `phase ${phase} has no enabled rules (rule-level or override-level disabled)`,
      };
    }
    if (check.params.requireEnabledExecuteRule) {
      const execute = enabledRules.filter((r) => r.action === "execute");
      if (execute.length === 0) {
        return {
          verdict: "fail",
          detail: `no enabled "execute" rule deploys a managed ruleset in ${phase}`,
        };
      }
      const logOnly = execute.filter(
        (r) => executeOverrides(r)?.action === "log",
      );
      if (logOnly.length === execute.length) {
        return {
          verdict: "warn",
          detail: `all ${execute.length} managed ruleset deployment(s) in ${phase} are overridden to log only`,
        };
      }
    }
    if (check.params.warnIfNoBlockingAction) {
      const blocking = enabledRules.some(
        (r) => r.action && !["log", "skip"].includes(r.action),
      );
      if (!blocking) {
        return {
          verdict: "warn",
          detail:
            "custom rules exist but none take a blocking/challenging action",
        };
      }
    }
    return {
      verdict: "pass",
      detail: `${enabledRules.length} enabled rule(s) in ${phase}`,
    };
  },

  broad_skip_audit: (_check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const rs = rules(zone, "http_request_firewall_custom");
    if (rs === undefined)
      return { verdict: "manual", detail: "custom rules phase not readable" };
    const broad = rs.filter(
      (r) =>
        r.enabled !== false &&
        r.action === "skip" &&
        (!r.expression ||
          r.expression.trim() === "true" ||
          r.expression.includes("*")),
    );
    if (broad.length > 0) {
      return {
        verdict: "warn",
        detail: `${broad.length} skip rule(s) with site-wide or missing expressions`,
      };
    }
    return { verdict: "pass", detail: "no site-wide skip rules found" };
  },

  ratelimit_login: (check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const phase = String(check.params.phase ?? "http_ratelimit");
    const rs = rules(zone, phase);
    if (rs === undefined) {
      return {
        verdict: "manual",
        detail: `phase ${phase} not readable — cannot confirm login protection`,
      };
    }
    const loginPaths = (check.params.loginPaths as string[]) ?? [];
    const hasLogin = rs.some((r) => {
      if (r.enabled === false) return false;
      const expr = (r.expression ?? "").toLowerCase();
      return loginPaths.some((p) => expr.includes(p));
    });
    return hasLogin
      ? { verdict: "pass", detail: "rate limiting rule covers a login path" }
      : {
          verdict: "fail",
          detail: `no rate limiting rule matches login paths (${loginPaths.join(", ")})`,
        };
  },

  // legacy_ratelimit evaluator removed with CF-RL-002: keeping it would turn
  // absent data into a vacuous "pass" (fail-closed violation).

  bot_rules: (_check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const rs = rules(zone, "http_request_firewall_custom");
    if (rs === undefined)
      return {
        verdict: "manual",
        detail: "custom rules phase not readable — bot posture unverifiable",
      };
    const botRules = rs.filter((r) =>
      (r.expression ?? "").includes("bot_management"),
    );
    if (botRules.length === 0) {
      return {
        verdict: "warn",
        detail: "no custom rules use bot management signals",
      };
    }
    const skipping = botRules.filter(
      (r) => r.action === "skip" && r.enabled !== false,
    );
    const enforced = botRules.filter(
      (r) => r.action && r.action !== "skip" && r.enabled !== false,
    );
    if (enforced.length === 0 && skipping.length > 0) {
      return {
        verdict: "fail",
        detail: `bot management rules only skip (${skipping.length}) — zero enforcement`,
      };
    }
    if (enforced.length === 0)
      return {
        verdict: "manual",
        detail: "bot rules exist but none are enabled — confirm intent",
      };
    // verified-bot exclusion check on block/challenge actions
    const missingExclusion = enforced.filter(
      (r) =>
        (r.action === "block" ||
          r.action === "challenge" ||
          r.action === "managed_challenge") &&
        (r.expression ?? "").includes("score") &&
        !(r.expression ?? "").includes("verified_bot"),
    );
    if (missingExclusion.length > 0) {
      return {
        verdict: "warn",
        detail: `${missingExclusion.length} bot-score rule(s) with block/challenge but no verified_bot exclusion`,
      };
    }
    return {
      verdict: "pass",
      detail: `${enforced.length} bot rule(s) enforce with sensible exclusions`,
    };
  },

  turnstile: (_check, _zone, collection) => {
    const widgets = collection.accounts.flatMap(
      (a) => a.turnstileWidgets ?? [],
    );
    if (widgets.length === 0) {
      return {
        verdict: "manual",
        detail:
          "no Turnstile widgets found (or Turnstile not in use — confirm intent)",
      };
    }
    const unbound = widgets.filter((w) => !w.domains || w.domains.length === 0);
    if (unbound.length > 0) {
      return {
        verdict: "warn",
        detail: `${unbound.length} widget(s) have no domains bound`,
      };
    }
    return {
      verdict: "pass",
      detail: `${widgets.length} widget(s) with domains bound`,
    };
  },

  access_apps: (_check, _zone, collection) => {
    const apps = collection.accounts.flatMap((a) => a.accessApps ?? []);
    if (apps.length === 0) {
      return {
        verdict: "manual",
        detail: "no Access applications found (or Access not in use)",
      };
    }
    const missing = apps.filter((a) => a.hasPolicies === false);
    const bypass = apps.filter((a) =>
      (a.policyDecisions ?? []).includes("bypass"),
    );
    if (missing.length > 0 || bypass.length > 0) {
      return {
        verdict: "fail",
        detail: `${missing.length} app(s) without policies, ${bypass.length} app(s) with a bypass decision`,
      };
    }
    return {
      verdict: "pass",
      detail: `${apps.length} Access app(s), all with policies and no bypass`,
    };
  },

  access_idps: (_check, _zone, collection) => {
    const idps = collection.accounts.flatMap(
      (a) => a.accessIdentityProviders ?? [],
    );
    if (idps.length === 0) {
      return {
        verdict: "warn",
        detail: "no IdPs configured — Access falls back to One-time PIN",
      };
    }
    const onlyOtp = idps.every((p) => p.type === "onetimepin");
    if (onlyOtp)
      return { verdict: "warn", detail: "only One-time PIN IdP configured" };
    return { verdict: "pass", detail: `${idps.length} IdP(s) configured` };
  },

  account_setting_flag: (check, _zone, collection) => {
    const flag = String(check.params.flag ?? "");
    const expect = check.params.expect;
    for (const account of collection.accounts) {
      const value = (account as unknown as Record<string, unknown>)[flag];
      if (value === null || value === undefined) {
        return {
          verdict: "manual",
          detail: `flag "${flag}" not readable for this account`,
        };
      }
      if (value !== expect) {
        return {
          verdict: "fail",
          detail: `flag "${flag}" is ${String(value)} (expected ${String(expect)})`,
        };
      }
    }
    return {
      verdict: "pass",
      detail: `flag "${flag}" meets expectation across accounts`,
    };
  },

  token_expiry: (_check, _zone, collection) => {
    const tokens = collection.accounts.flatMap((a) => a.apiTokens ?? []);
    if (tokens.length === 0)
      return { verdict: "manual", detail: "token inventory not readable" };
    const active = tokens.filter(
      (t) => t.status === "active" || t.status === undefined,
    );
    const noExpiry = active.filter((t) => !t.expiresOn);
    if (noExpiry.length > 0) {
      return {
        verdict: "warn",
        detail: `${noExpiry.length} active token(s) with no expiration`,
      };
    }
    return {
      verdict: "pass",
      detail: `${active.length} active token(s) all have expiry`,
    };
  },

  caa_present: (_check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const dns = zone.dnsRecords;
    if (!dns || dns.length === 0)
      return { verdict: "manual", detail: "DNS records not readable" };
    const caa = dns.filter((d) => d.type.toUpperCase() === "CAA");
    if (caa.length === 0)
      return { verdict: "warn", detail: "no CAA records published" };
    return { verdict: "pass", detail: `${caa.length} CAA record(s)` };
  },

  email_records: (_check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const dns = zone.dnsRecords;
    if (!dns || dns.length === 0)
      return { verdict: "manual", detail: "DNS records not readable" };
    const hasMx = dns.some((d) => d.type.toUpperCase() === "MX");
    const hasTxt = dns.some((d) => d.type.toUpperCase() === "TXT");
    if (!hasMx)
      return {
        verdict: "pass",
        detail: "no MX records — zone does not receive mail",
      };
    if (!hasTxt)
      return {
        verdict: "warn",
        detail:
          "MX present but no TXT records (check SPF/DMARC manually — TXT content not exported)",
      };
    return { verdict: "pass", detail: "MX and TXT records present" };
  },

  zombie_workers: (check, _c, collection) => {
    const scripts: NonNullable<
      Collection["accounts"][number]["workersScripts"]
    > = collection.accounts.flatMap((a) => a.workersScripts ?? []);
    const routes: NonNullable<Collection["zones"][number]["workersRoutes"]> =
      collection.zones.flatMap((z) => z.workersRoutes ?? []);
    const scriptNames = new Set(
      scripts.map((s) => s.scriptName).filter((n): n is string => !!n),
    );
    if (scripts.length === 0 && routes.length > 0) {
      return {
        verdict: "manual",
        detail: "routes exist but scripts not readable (token scope gap)",
      };
    }
    if (check.id === "CF-WRK-001") {
      const zombies = scripts.filter(
        (s) => s.scriptName && !routes.some((r) => r.script === s.scriptName),
      );
      if (zombies.length > 0 && routes.length === 0) {
        return {
          verdict: "warn",
          detail: `${zombies.length} script(s) with no route on any audited zone`,
        };
      }
      if (zombies.length > 0) {
        return {
          verdict: "warn",
          detail: `${zombies.length} script(s) not referenced by any collected route`,
        };
      }
      return {
        verdict: "pass",
        detail: `${scripts.length} script(s), all referenced by routes`,
      };
    }
    // CF-WRK-002: routes referencing unknown scripts
    const dangling = routes.filter(
      (r) => r.script && !scriptNames.has(r.script),
    );
    if (dangling.length > 0) {
      return {
        verdict: "manual",
        detail: `${dangling.length} route(s) reference scripts outside the readable inventory`,
      };
    }
    return { verdict: "pass", detail: "all routes reference readable scripts" };
  },

  cert_expiry: (check, zone, _c) => {
    if (!zone) return { verdict: "na", detail: "no zone in scope" };
    const packs = zone.certificatePacks;
    if (!packs || packs.length === 0) {
      return {
        verdict: "manual",
        detail: "certificate packs not readable (or no custom certificates)",
      };
    }
    const customPacks = packs.filter(
      (p) =>
        !(p.type === "advanced" && p.certificateAuthority === "lets_encrypt"),
    );
    if (customPacks.length === 0) {
      return {
        verdict: "pass",
        detail: "only universal certificates found (auto-renew)",
      };
    }
    const now = Date.now();
    const warnMs = (check.params.warnDays as number) * 24 * 60 * 60 * 1000;
    const failMs = (check.params.failDays as number) * 24 * 60 * 60 * 1000;
    const expiring = customPacks
      .filter((p) => p.expiresOn)
      .map((p) => ({
        ...p,
        expiresMs: new Date(p.expiresOn!).getTime(),
      }));
    const failing = expiring.filter((p) => p.expiresMs - now < failMs);
    const warning = expiring.filter(
      (p) => p.expiresMs - now >= failMs && p.expiresMs - now < warnMs,
    );
    if (failing.length > 0) {
      const days = Math.floor(
        ((failing[0]?.expiresMs ?? now) - now) / (24 * 60 * 60 * 1000),
      );
      return {
        verdict: "fail",
        detail: `${failing.length} certificate(s) expiring within 30 days (soonest: ${days} days)`,
      };
    }
    if (warning.length > 0) {
      const days = Math.floor(
        ((warning[0]?.expiresMs ?? now) - now) / (24 * 60 * 60 * 1000),
      );
      return {
        verdict: "warn",
        detail: `${warning.length} certificate(s) expiring within 90 days (soonest: ${days} days)`,
      };
    }
    return {
      verdict: "pass",
      detail: `${customPacks.length} custom certificate(s), all valid for >90 days`,
    };
  },

  lb_pool_health: (check, _zone, collection) => {
    const pools = collection.accounts.flatMap((a) => a.loadBalancerPools ?? []);
    if (pools.length === 0) {
      return {
        verdict: "manual",
        detail: "no load balancer pools found (or not readable)",
      };
    }
    const minOrigins = (check.params.minOrigins as number) ?? 2;
    const singleOrigin = pools.filter(
      (p) => (p.origins?.length ?? 0) < minOrigins,
    );
    if (singleOrigin.length > 0) {
      return {
        verdict: "fail",
        detail: `${singleOrigin.length} pool(s) have fewer than ${minOrigins} origin(s) — no failover`,
      };
    }
    return {
      verdict: "pass",
      detail: `${pools.length} pool(s), all have ${minOrigins}+ origins`,
    };
  },

  lb_monitor_health: (check, _zone, collection) => {
    const monitors = collection.accounts.flatMap(
      (a) => a.loadBalancerMonitors ?? [],
    );
    if (monitors.length === 0) {
      return {
        verdict: "manual",
        detail: "no load balancer monitors found (or not readable)",
      };
    }
    const maxInterval = (check.params.maxIntervalSeconds as number) ?? 60;
    const slow = monitors.filter((m) => (m.interval ?? 0) > maxInterval);
    if (slow.length > 0) {
      return {
        verdict: "warn",
        detail: `${slow.length} monitor(s) have interval >${maxInterval}s (may miss outages quickly)`,
      };
    }
    return {
      verdict: "pass",
      detail: `${monitors.length} monitor(s), all with interval <=${maxInterval}s`,
    };
  },

  aig_rate_limiting: (_check, _zone, collection) => {
    const gateways = collection.accounts.flatMap((a) => a.aiGateways ?? []);
    if (gateways.length === 0) {
      return { verdict: "na", detail: "no AI Gateway gateways found" };
    }
    const noRateLimit = gateways.filter(
      (g) => !g.rateLimitingLimit || !g.rateLimitingInterval,
    );
    if (noRateLimit.length > 0) {
      return {
        verdict: "fail",
        detail: `${noRateLimit.length} gateway(s) without rate limiting configured`,
      };
    }
    return {
      verdict: "pass",
      detail: `${gateways.length} gateway(s), all have rate limiting configured`,
    };
  },

  aig_authentication: (_check, _zone, collection) => {
    const gateways = collection.accounts.flatMap((a) => a.aiGateways ?? []);
    if (gateways.length === 0) {
      return { verdict: "na", detail: "no AI Gateway gateways found" };
    }
    const noAuth = gateways.filter((g) => g.authentication === false);
    if (noAuth.length > 0) {
      return {
        verdict: "fail",
        detail: `${noAuth.length} gateway(s) without authentication enabled`,
      };
    }
    return {
      verdict: "pass",
      detail: `${gateways.length} gateway(s), all have authentication enabled`,
    };
  },

  aig_logging: (_check, _zone, collection) => {
    const gateways = collection.accounts.flatMap((a) => a.aiGateways ?? []);
    if (gateways.length === 0) {
      return { verdict: "na", detail: "no AI Gateway gateways found" };
    }
    const noLogs = gateways.filter((g) => g.collectLogs === false);
    if (noLogs.length > 0) {
      return {
        verdict: "warn",
        detail: `${noLogs.length} gateway(s) without log collection enabled`,
      };
    }
    return {
      verdict: "pass",
      detail: `${gateways.length} gateway(s), all have log collection enabled`,
    };
  },

  aig_dlp: (_check, _zone, collection) => {
    const gateways = collection.accounts.flatMap((a) => a.aiGateways ?? []);
    if (gateways.length === 0) {
      return { verdict: "na", detail: "no AI Gateway gateways found" };
    }
    const noDlp = gateways.filter(
      (g) => g.dlpEnabled === false || g.dlpEnabled === undefined,
    );
    if (noDlp.length > 0) {
      return {
        verdict: "warn",
        detail: `${noDlp.length} gateway(s) without DLP policies configured`,
      };
    }
    return {
      verdict: "pass",
      detail: `${gateways.length} gateway(s), all have DLP policies configured`,
    };
  },

  aig_guardrails: (_check, _zone, collection) => {
    const gateways = collection.accounts.flatMap((a) => a.aiGateways ?? []);
    if (gateways.length === 0) {
      return { verdict: "na", detail: "no AI Gateway gateways found" };
    }
    const noGuardrails = gateways.filter(
      (g) => g.guardrailsConfigured !== true,
    );
    if (noGuardrails.length > 0) {
      return {
        verdict: "warn",
        detail: `${noGuardrails.length} gateway(s) without guardrails configured`,
      };
    }
    return {
      verdict: "pass",
      detail: `${gateways.length} gateway(s), all have guardrails configured`,
    };
  },

  page_shield_enabled: (_check, zone) => {
    if (!zone?.pageShield) {
      return { verdict: "manual", detail: "Page Shield data not collected" };
    }
    if (zone.pageShield.enabled === false) {
      return { verdict: "fail", detail: "Page Shield disabled" };
    }
    if (zone.pageShield.enabled === true) {
      return { verdict: "pass", detail: "Page Shield enabled" };
    }
    return {
      verdict: "manual",
      detail: "Page Shield enablement status unknown",
    };
  },

  authenticated_origin_pulls_enabled: (_check, zone) => {
    if (!zone?.authenticatedOriginPulls) {
      return {
        verdict: "manual",
        detail: "Authenticated Origin Pulls data not collected",
      };
    }
    if (zone.authenticatedOriginPulls.enabled === false) {
      return { verdict: "fail", detail: "Authenticated Origin Pulls disabled" };
    }
    if (zone.authenticatedOriginPulls.enabled === true) {
      return { verdict: "pass", detail: "Authenticated Origin Pulls enabled" };
    }
    return { verdict: "manual", detail: "AOP enablement status unknown" };
  },

  zone_level_aop_preferred: (_check, zone) => {
    if (!zone?.authenticatedOriginPulls) {
      return {
        verdict: "manual",
        detail: "Authenticated Origin Pulls data not collected",
      };
    }
    if (zone.authenticatedOriginPulls.enabled === false) {
      return { verdict: "na", detail: "AOP not enabled" };
    }
    if (zone.authenticatedOriginPulls.hasZoneLevelCert === false) {
      return {
        verdict: "warn",
        detail:
          "Using global AOP only (shared certificate); zone-level cert recommended",
      };
    }
    return {
      verdict: "pass",
      detail: `Zone-level AOP with ${zone.authenticatedOriginPulls.certCount ?? 0} certificate(s)`,
    };
  },

  ddos_not_disabled: (_check, zone) => {
    if (!zone?.phaseEntrypoints) {
      return { verdict: "manual", detail: "Rulesets not collected" };
    }
    const ddosPhase = zone.phaseEntrypoints["ddos_l7"];
    if (!ddosPhase) {
      // The ddos_l7 entrypoint 404s when no override ruleset exists. That is
      // only a pass if the (readable) ruleset list agrees no zone-kind
      // ddos_l7 ruleset is deployed — otherwise it was a scope gap.
      if (!zone.rulesets) {
        return {
          verdict: "manual",
          detail: "DDoS L7 phase not readable and zone ruleset list not collected",
        };
      }
      const overrideRuleset = zone.rulesets.find(
        (r) => r.phase === "ddos_l7" && r.kind === "zone",
      );
      if (overrideRuleset) {
        return {
          verdict: "manual",
          detail:
            "a DDoS override ruleset exists but its rules were not readable",
        };
      }
      return {
        verdict: "pass",
        detail: "no HTTP DDoS override ruleset deployed — managed protection at defaults",
      };
    }
    const neutered = (ddosPhase.rules ?? []).filter((r) => {
      if (r.action !== "execute") return false;
      const ov = executeOverrides(r);
      return (
        r.enabled === false || ov?.enabled === false || ov?.action === "log"
      );
    });
    if (neutered.length > 0) {
      return {
        verdict: "fail",
        detail: `${neutered.length} HTTP DDoS managed ruleset deployment(s) disabled or set to log via override`,
      };
    }
    return {
      verdict: "pass",
      detail: "HTTP DDoS managed rulesets deployed with overrides that keep mitigation active",
    };
  },

  html_cache_check: (_check, zone) => {
    if (!zone?.settings) {
      return { verdict: "manual", detail: "Zone settings not collected" };
    }
    const cacheLevel = zone.settings.cache_level?.value;
    if (cacheLevel === "aggressive") {
      return {
        verdict: "warn",
        detail: "cache_level set to 'aggressive' (caches HTML by default)",
      };
    }
    return {
      verdict: "pass",
      detail: `cache_level is '${String(cacheLevel ?? "basic")}' (HTML not cached by default)`,
    };
  },

  tunnel_access_gap: (_check, _zone, collection) => {
    const tunnels = collection.accounts.flatMap((a) => a.cfdTunnels ?? []);
    if (tunnels.length === 0) {
      return { verdict: "na", detail: "no Cloudflare Tunnels found" };
    }

    const publicHostnames = tunnels.flatMap((t) => t.publicHostnames ?? []);
    if (publicHostnames.length === 0) {
      return {
        verdict: "pass",
        detail: `${tunnels.length} tunnel(s), no public hostnames configured`,
      };
    }

    const accessApps = collection.accounts.flatMap((a) => a.accessApps ?? []);
    const protectedDomains = new Set<string>();

    for (const app of accessApps) {
      if (app.domain) protectedDomains.add(app.domain.toLowerCase());
      for (const selfHosted of app.selfHostedDomains ?? []) {
        protectedDomains.add(selfHosted.toLowerCase());
      }
    }

    const unprotected = publicHostnames.filter(
      (h) => !protectedDomains.has(h.toLowerCase()),
    );
    if (unprotected.length > 0) {
      return {
        verdict: "fail",
        detail: `${unprotected.length} public tunnel hostname(s) without Access protection: ${unprotected.slice(0, 3).join(", ")}${unprotected.length > 3 ? "..." : ""}`,
      };
    }

    return {
      verdict: "pass",
      detail: `${publicHostnames.length} public tunnel hostname(s), all protected by Access`,
    };
  },
};

/** Filter checks to the given named domains (the rulebook's `domain` field).
 * Used to scope a run to the categories the operator chooses; pass nothing
 * to include every check. */
export function filterChecksByDomains(
  checks: Check[],
  domains: Iterable<string>,
): Check[] {
  const wanted = new Set(domains);
  if (wanted.size === 0) return checks;
  return checks.filter((c) => wanted.has(c.domain));
}

export interface FindingDiff {
  check: string;
  scope: string;
  name: string;
  before: Verdict;
  after: Verdict;
  /** new | resolved | changed */
  kind: "new" | "resolved" | "changed";
  detail: string;
}

/** Diff two evaluation runs over the same rulebook, keyed by (check id, scope). */
export function diffFindings(
  before: Finding[],
  after: Finding[],
): FindingDiff[] {
  const key = (f: Finding) => `${f.check.id}|${f.scope}`;
  const beforeMap = new Map(before.map((f) => [key(f), f]));
  const afterMap = new Map(after.map((f) => [key(f), f]));
  const diffs: FindingDiff[] = [];
  for (const [k, f] of afterMap) {
    const old = beforeMap.get(k);
    if (!old) {
      diffs.push({
        check: f.check.id,
        scope: f.scope,
        name: f.check.name,
        before: "na",
        after: f.verdict,
        kind: "new",
        detail: f.detail,
      });
    } else if (old.verdict !== f.verdict) {
      diffs.push({
        check: f.check.id,
        scope: f.scope,
        name: f.check.name,
        before: old.verdict,
        after: f.verdict,
        kind: "changed",
        detail: f.detail,
      });
    }
  }
  for (const [k, f] of beforeMap) {
    if (!afterMap.has(k)) {
      diffs.push({
        check: f.check.id,
        scope: f.scope,
        name: f.check.name,
        before: f.verdict,
        after: "na",
        kind: "resolved",
        detail: f.detail,
      });
    }
  }
  return diffs;
}

export function evaluate(collection: Collection, checks: Check[]): Finding[] {
  const findings: Finding[] = [];
  for (const check of checks) {
    const evaluator = evaluators[check.type];
    if (!evaluator) {
      findings.push({
        check,
        scope: "all",
        verdict: "manual",
        detail: `unknown check type "${check.type}"`,
      });
      continue;
    }
    const tier = check.applies?.planTier ?? "any";
    if (tier !== "any") {
      // account-level checks run once; zone checks run per zone
      if (
        [
          "turnstile",
          "access_apps",
          "access_idps",
          "account_setting_flag",
          "token_expiry",
          "zombie_workers",
          "lb_pool_health",
          "lb_monitor_health",
          "aig_rate_limiting",
          "aig_authentication",
          "aig_logging",
          "aig_dlp",
          "aig_guardrails",
          "tunnel_access_gap",
        ].includes(check.type)
      ) {
        const res = evaluator(check, null, collection);
        findings.push({ check, scope: "account", ...res });
      } else {
        for (const zone of collection.zones) {
          if (!planAtLeast(zone.plan, tier)) {
            findings.push({
              check,
              scope: zone.name,
              verdict: "na",
              detail: `zone plan (${zone.plan ?? "unknown"}) below check tier (${tier})`,
            });
            continue;
          }
          const res = evaluator(check, zone, collection);
          findings.push({ check, scope: zone.name, ...res });
        }
      }
    } else {
      if (
        [
          "turnstile",
          "access_apps",
          "access_idps",
          "account_setting_flag",
          "token_expiry",
          "zombie_workers",
          "lb_pool_health",
          "lb_monitor_health",
          "aig_rate_limiting",
          "aig_authentication",
          "aig_logging",
          "aig_dlp",
          "aig_guardrails",
          "tunnel_access_gap",
        ].includes(check.type)
      ) {
        const res = evaluator(check, null, collection);
        findings.push({ check, scope: "account", ...res });
      } else {
        if (collection.zones.length === 0) {
          findings.push({
            check,
            scope: "account",
            verdict: "manual",
            detail: "no zones collected",
          });
        } else {
          for (const zone of collection.zones) {
            const res = evaluator(check, zone, collection);
            findings.push({ check, scope: zone.name, ...res });
          }
        }
      }
    }
  }
  return findings;
}
