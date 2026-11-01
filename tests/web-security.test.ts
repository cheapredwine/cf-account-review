/**
 * Web security stack: fixture tests for the v0.2 checks and the regressions
 * found reviewing v0.1 (plan normalization, fail-open evidence, ddos_l7).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { evaluate, planAtLeast, selectProfile, type Check } from "../src/analyzer/engine.js";
import { renderMarkdown } from "../src/analyzer/report.js";
import { collectionSchema, type Collection } from "../src/schema.js";
import {
  normalizePlan,
  summarizeActionParameters,
  summarizeBotManagement,
  summarizeIpAccessRule,
  summarizePageRule,
} from "../src/summarize.js";

const ROOT = new URL("..", import.meta.url).pathname;
const doc = parse(readFileSync(join(ROOT, "findings", "checks.yaml"), "utf8")) as {
  checks: Check[];
  profiles: Record<string, string[]>;
};
const checks = doc.checks;

function coll(zone: Record<string, unknown>, accounts: unknown[] = []): Collection {
  return collectionSchema.parse({
    schemaVersion: "1.1",
    collectedAt: new Date().toISOString(),
    collector: "api",
    collectorVersion: "0.2.0",
    tokenStatus: "active",
    accounts,
    zones: [{ name: "example.com", plan: "Enterprise Website", status: "active", paused: false, ...zone }],
    collectionErrors: [],
  });
}

function verdict(c: Collection, id: string): string | undefined {
  return evaluate(c, checks).find((f) => f.check.id === id && f.scope !== "all")?.verdict;
}

describe("plan normalization (v0.1 regression)", () => {
  it("real API plan names map to tiers", () => {
    expect(normalizePlan("Enterprise Website")).toBe("enterprise");
    expect(normalizePlan("Business Plan")).toBe("business");
    expect(normalizePlan("Pro Plan")).toBe("pro");
    expect(normalizePlan("Free Website")).toBe("free");
    expect(normalizePlan(undefined, "enterprise")).toBe("enterprise");
    expect(normalizePlan(undefined)).toBeUndefined();
  });

  it("Enterprise Website zones are NOT treated as below pro-plus", () => {
    expect(planAtLeast({ plan: "Enterprise Website" }, "pro-plus")).toBe(true);
    expect(planAtLeast({ plan: "Free Website" }, "pro-plus")).toBe(false);
    expect(planAtLeast({ plan: undefined }, "business-plus")).toBeUndefined();
    const v = verdict(coll({ phaseStatus: { http_request_firewall_managed: "absent" } }), "CF-WAF-001");
    expect(v).toBe("fail"); // v0.1 reported "na" here
  });
});

describe("fail-closed evidence (v0.1 regressions)", () => {
  it("unreadable legacy rate limits are manual, not pass", () => {
    expect(verdict(coll({}), "CF-RL-002")).toBe("manual");
    expect(verdict(coll({ legacyRateLimits: [] }), "CF-RL-002")).toBe("pass");
  });
  it("unreadable tunnels / gateways are manual, not na", () => {
    expect(verdict(coll({}, [{}]), "CF-TUNNEL-001")).toBe("manual");
    expect(verdict(coll({}, [{}]), "CF-AIG-001")).toBe("manual");
    expect(verdict(coll({}, [{ cfdTunnels: [] }]), "CF-TUNNEL-001")).toBe("na");
  });
  it("no check passes on a bare zone", () => {
    const findings = evaluate(coll({}), checks).filter((f) => f.scope === "example.com");
    const passes = findings.filter((f) => f.verdict === "pass").map((f) => f.check.id);
    expect(passes).toEqual(["CF-ZONE-001"]); // status/paused were provided
  });
});

describe("WAF", () => {
  const managed = (rules: unknown[]) =>
    coll({ phaseEntrypoints: { http_request_firewall_managed: { phase: "http_request_firewall_managed", rules } } });

  it("account-level managed WAF (Enterprise) turns a zone 'absent' into manual, not fail", () => {
    const c = coll({ phaseStatus: { http_request_firewall_managed: "absent" } }, [
      { accountRulesets: [{ name: "root", kind: "root", phase: "http_request_firewall_managed" }] },
    ]);
    expect(verdict(c, "CF-WAF-001")).toBe("manual");
  });

  it("managed ruleset in log-only or disabled via override fails", () => {
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "cloudflare_managed", overrides: { action: "log" } } }]), "CF-WAF-001")).toBe("fail");
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "cloudflare_managed", overrides: { enabled: false } } }]), "CF-WAF-001")).toBe("fail");
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "owasp" } }]), "CF-WAF-001")).toBe("fail");
  });

  it("OWASP: absent warns, log-only warns, blocking passes, very-low sensitivity warns", () => {
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "cloudflare_managed" } }]), "CF-WAF-004")).toBe("warn");
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "owasp", overrides: { action: "log" } } }]), "CF-WAF-004")).toBe("warn");
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "owasp", overrides: { action: "block", scoreThreshold: 40 } } }]), "CF-WAF-004")).toBe("pass");
    expect(verdict(managed([{ action: "execute", actionParameters: { executes: "owasp", overrides: { scoreThreshold: 80 } } }]), "CF-WAF-004")).toBe("warn");
  });

  it("broad WAF exception in the managed phase warns", () => {
    const c = managed([
      { action: "skip", expression: "true", actionParameters: { skip: { rulesets: 1 } } },
      { action: "execute", actionParameters: { executes: "cloudflare_managed" } },
    ]);
    c.zones[0]!.phaseStatus = { http_request_firewall_custom: "absent" };
    expect(verdict(c, "CF-WAF-003")).toBe("warn");
  });

  it("host-only skip in custom rules counts as broad", () => {
    const c = coll({
      phaseEntrypoints: {
        http_request_firewall_custom: {
          phase: "http_request_firewall_custom",
          rules: [{ action: "skip", expression: 'http.host eq "api.example.com"', actionParameters: { skip: { phases: ["http_request_firewall_managed"] } } }],
        },
      },
      phaseStatus: { http_request_firewall_managed: "absent" },
    });
    expect(verdict(c, "CF-WAF-003")).toBe("warn");
  });

  it("IP access rules: country allowlist fails, IP allowlist warns, blocks pass", () => {
    expect(verdict(coll({ ipAccessRuleSummary: [{ mode: "whitelist", target: "country", value: "US" }] }), "CF-WAF-006")).toBe("fail");
    expect(verdict(coll({ ipAccessRuleSummary: [{ mode: "whitelist", target: "ip", value: "[redacted]" }] }), "CF-WAF-006")).toBe("warn");
    expect(verdict(coll({ ipAccessRuleSummary: [{ mode: "block", target: "ip" }] }), "CF-WAF-006")).toBe("pass");
    expect(verdict(coll({}), "CF-WAF-006")).toBe("manual");
  });

  it("page rule disabling security fails", () => {
    expect(verdict(coll({ pageRuleSummary: [{ status: "active", actions: [{ id: "disable_security" }] }] }), "CF-WAF-007")).toBe("fail");
    expect(verdict(coll({ pageRuleSummary: [{ status: "disabled", actions: [{ id: "disable_security" }] }] }), "CF-WAF-007")).toBe("pass");
  });

  it("security level: off fails, under_attack warns", () => {
    const sl = (v: string) => coll({ settings: { security_level: { id: "security_level", value: v } } });
    expect(verdict(sl("essentially_off"), "CF-WAF-008")).toBe("fail");
    expect(verdict(sl("under_attack"), "CF-WAF-008")).toBe("warn");
    expect(verdict(sl("medium"), "CF-WAF-008")).toBe("pass");
  });

  it("leaked credentials: off warns, on passes, unreadable manual", () => {
    expect(verdict(coll({ leakedCredentialChecks: { enabled: false } }), "CF-WAF-005")).toBe("warn");
    expect(verdict(coll({ leakedCredentialChecks: { enabled: true } }), "CF-WAF-005")).toBe("pass");
    expect(verdict(coll({}), "CF-WAF-005")).toBe("manual");
  });
});

describe("rate limiting, bots, DDoS", () => {
  it("login rate limit that only logs warns", () => {
    const c = coll({
      phaseEntrypoints: { http_ratelimit: { phase: "http_ratelimit", rules: [{ action: "log", expression: 'http.request.uri.path eq "/login"' }] } },
    });
    expect(verdict(c, "CF-RL-001")).toBe("warn");
  });

  it("absent ratelimit phase: login check fails (readable, nothing deployed)", () => {
    expect(verdict(coll({ phaseStatus: { http_ratelimit: "absent" } }), "CF-RL-001")).toBe("fail");
  });

  it("bot baseline per plan", () => {
    expect(verdict(coll({ plan: "Free Website", botManagement: { fight_mode: false } }), "CF-BOT-003")).toBe("warn");
    expect(verdict(coll({ plan: "Free Website", botManagement: { fight_mode: true } }), "CF-BOT-003")).toBe("pass");
    expect(verdict(coll({ plan: "Business Plan", botManagement: { sbfm_definitely_automated: "allow" } }), "CF-BOT-003")).toBe("warn");
    expect(verdict(coll({ plan: "Business Plan", botManagement: { sbfm_definitely_automated: "managed_challenge" } }), "CF-BOT-003")).toBe("pass");
    expect(verdict(coll({ plan: "Business Plan" }), "CF-BOT-003")).toBe("manual");
  });

  it("Enterprise bot-score checks are na below Enterprise", () => {
    expect(verdict(coll({ plan: "Business Plan" }), "CF-BOT-002")).toBe("na");
  });

  it("HTTP DDoS: absent = defaults pass; eoff/log fail; low warns; unreadable manual", () => {
    const d = (overrides: Record<string, unknown>) =>
      coll({ phaseEntrypoints: { ddos_l7: { phase: "ddos_l7", rules: [{ action: "execute", actionParameters: { executes: "ddos_l7", overrides } }] } } });
    expect(verdict(coll({ phaseStatus: { ddos_l7: "absent" } }), "CF-DDOS-001")).toBe("pass");
    expect(verdict(coll({}), "CF-DDOS-001")).toBe("manual");
    expect(verdict(d({ sensitivityLevel: "eoff" }), "CF-DDOS-001")).toBe("fail");
    expect(verdict(d({ action: "log" }), "CF-DDOS-001")).toBe("fail");
    expect(verdict(d({ sensitivityLevel: "low" }), "CF-DDOS-001")).toBe("warn");
  });
});

describe("origin exposure, headers, zone state", () => {
  it("grey-clouded A next to proxied records warns and names them", () => {
    const c = coll({
      dnsRecords: [
        { type: "A", name: "www.example.com", proxied: true },
        { type: "A", name: "direct.example.com", proxied: false },
        { type: "TXT", name: "example.com", proxied: false },
      ],
    });
    const f = evaluate(c, checks).find((x) => x.check.id === "CF-DNS-004");
    expect(f?.verdict).toBe("warn");
    expect(f?.detail).toContain("direct.example.com");
  });

  it("all proxied passes; nothing proxied is na", () => {
    expect(verdict(coll({ dnsRecords: [{ type: "A", name: "www.example.com", proxied: true }] }), "CF-DNS-004")).toBe("pass");
    expect(verdict(coll({ dnsRecords: [{ type: "A", name: "www.example.com", proxied: false }] }), "CF-DNS-004")).toBe("na");
  });

  it("security headers via managed transform pass; none warns", () => {
    const on = coll({ managedHeaders: { request: [], response: [{ id: "add_security_headers", enabled: true }] } });
    expect(verdict(on, "CF-HDR-001")).toBe("pass");
    const off = coll({ managedHeaders: { request: [], response: [] }, phaseStatus: { http_response_headers_transform: "absent" } });
    expect(verdict(off, "CF-HDR-001")).toBe("warn");
  });

  it("security headers via response header transform rule pass", () => {
    const c = coll({
      managedHeaders: { request: [], response: [] },
      phaseEntrypoints: {
        http_response_headers_transform: {
          phase: "http_response_headers_transform",
          rules: [{ action: "rewrite", expression: "true", actionParameters: { headers: [{ name: "x-content-type-options", operation: "set" }, { name: "x-frame-options", operation: "set" }] } }],
        },
      },
    });
    expect(verdict(c, "CF-HDR-001")).toBe("pass");
  });

  it("paused zone fails", () => {
    expect(verdict(coll({ paused: true }), "CF-ZONE-001")).toBe("fail");
  });
});

describe("summarizers keep only policy-safe fields", () => {
  it("execute rule resolves managed ruleset by name, then by known ID", () => {
    expect(summarizeActionParameters("execute", { id: "abc" }, { abc: "Cloudflare OWASP Core Ruleset" })?.executes).toBe("owasp");
    expect(summarizeActionParameters("execute", { id: "efb7b8c949ac4650a09736fc376e9aee" })?.executes).toBe("cloudflare_managed");
    expect(summarizeActionParameters("execute", { id: "unknown" })?.executes).toBe("custom_or_unknown");
  });

  it("overrides summary captures disable/log/threshold, not rule IDs", () => {
    const s = summarizeActionParameters("execute", {
      id: "4814384a9e5d4991b9815dcfc25d2f1f",
      overrides: {
        action: "log",
        categories: [{ category: "paranoia-level-3", enabled: false }],
        rules: [{ id: "6179ae15870a4bb7b2d480d4843b323c", score_threshold: 40 }, { id: "x", enabled: false }],
      },
    });
    expect(s?.overrides).toMatchObject({ action: "log", disabledCategories: ["paranoia-level-3"], rulesDisabled: 1, scoreThreshold: 40 });
    expect(JSON.stringify(s)).not.toContain("6179ae15");
  });

  it("ratelimit summary drops the counting expression text", () => {
    // rule.ratelimit sits beside action_parameters in the Rulesets API
    const s = summarizeActionParameters("block", { response: { status_code: 429 } }, {}, {
      characteristics: ["ip.src", "cf.colo.id"], period: 60, requests_per_period: 5, mitigation_timeout: 600, counting_expression: 'http.response.code eq 401 and ip.src eq 10.1.2.3',
    });
    expect(s?.ratelimit).toMatchObject({ period: 60, requestsPerPeriod: 5, hasCountingExpression: true });
    expect(JSON.stringify(s)).not.toContain("10.1.2.3");
  });

  it("header transforms keep names, never values", () => {
    const s = summarizeActionParameters("rewrite", { headers: { "X-Api-Key": { operation: "set", value: "sk-secret" } } });
    expect(s?.headers).toEqual([{ name: "x-api-key", operation: "set" }]);
    expect(JSON.stringify(s)).not.toContain("sk-secret");
  });

  it("IP access rule: IP values redacted, country kept, notes dropped", () => {
    expect(summarizeIpAccessRule({ mode: "whitelist", notes: "ops@example.com", configuration: { target: "ip", value: "203.0.113.9" }, scope: { type: "zone" } })).toEqual({
      mode: "whitelist",
      target: "ip",
      value: "[redacted]",
      scope: "zone",
    });
    expect(summarizeIpAccessRule({ mode: "block", configuration: { target: "country", value: "XX" } }).value).toBe("XX");
  });

  it("page rule: URL target and forwarding URLs dropped", () => {
    const s = summarizePageRule({
      status: "active",
      targets: [{ constraint: { value: "internal.example.com/*" } }],
      actions: [{ id: "forwarding_url", value: { url: "https://origin.example.com" } }, { id: "security_level", value: "essentially_off" }],
    });
    expect(JSON.stringify(s)).not.toContain("example.com");
    expect(s.actions).toContainEqual({ id: "security_level", value: "essentially_off" });
  });

  it("bot management keeps allow-listed keys only", () => {
    expect(summarizeBotManagement({ fight_mode: true, some_future_field: "x", sbfm_likely_automated: "allow" })).toEqual({
      fight_mode: true,
      sbfm_likely_automated: "allow",
    });
  });
});

describe("profiles and report", () => {
  it("web-security profile excludes zero-trust and platform checks", () => {
    const ws = selectProfile(checks, doc.profiles, "web-security");
    expect(ws.some((c) => c.id === "CF-WAF-001")).toBe(true);
    expect(ws.some((c) => c.domain === "zero-trust" || c.domain === "ai-gateway")).toBe(false);
    expect(() => selectProfile(checks, doc.profiles, "nope")).toThrow();
  });

  it("every check type has an evaluator and every domain is in some profile", () => {
    const covered = new Set(Object.values(doc.profiles).flat());
    for (const c of checks) {
      expect(covered.has(c.domain), `${c.id} domain ${c.domain} not in any profile`).toBe(true);
      expect(evaluate(coll({}), [c]).every((f) => !f.detail.startsWith("unknown check type")), c.id).toBe(true);
    }
  });

  it("report renders the posture matrix and top issues", () => {
    const c = coll({ paused: true, phaseStatus: { http_request_firewall_managed: "absent" } });
    const md = renderMarkdown(c, evaluate(c, selectProfile(checks, doc.profiles, "web-security")), { profile: "web-security" });
    expect(md).toContain("## Web security posture by zone");
    expect(md).toContain("## Top issues");
    expect(md).toContain("CF-ZONE-001");
  });

  it("committed fixture validates and analyzes", () => {
    const raw = JSON.parse(readFileSync(join(ROOT, "tests", "fixtures", "web-security-collection.json"), "utf8")) as unknown;
    const parsed = collectionSchema.parse(raw);
    const findings = evaluate(parsed, checks);
    expect(findings.length).toBeGreaterThan(30);
  });

  it("rejects a 2.x collection", () => {
    expect(
      collectionSchema.safeParse({ schemaVersion: "2.0", collectedAt: new Date().toISOString(), collector: "api", collectorVersion: "x", tokenStatus: "active" }).success,
    ).toBe(false);
  });
});
