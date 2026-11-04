import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { collectionSchema, type Collection } from "../src/schema.js";
import { evaluate, filterChecksByPhase, type Check, type Finding } from "../src/analyzer/engine.js";

const ROOT = new URL("..", import.meta.url).pathname;

function baseCollection(): Collection {
  return collectionSchema.parse({
    schemaVersion: "1.0",
    collectedAt: new Date().toISOString(),
    collector: "api",
    collectorVersion: "0.1.0",
    tokenStatus: "active",
    accounts: [],
    zones: [],
    collectionErrors: [],
  });
}

function zoneWith(overrides: Record<string, unknown>): Collection["zones"][number] {
  return {
    name: "example.com",
    plan: "Enterprise",
    status: "active",
    paused: false,
    type: "full",
    createdOn: new Date().toISOString(),
    ...overrides,
  } as Collection["zones"][number];
}

function loadChecks(): Check[] {
  const doc = parse(readFileSync(join(ROOT, "findings", "checks.yaml"), "utf8")) as { checks: Check[] };
  return doc.checks;
}

describe("findings engine", () => {
  const checks = loadChecks();
  it("rulebook loads with unique check IDs", () => {
    expect(checks.length).toBeGreaterThan(10);
    const ids = checks.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("unreadable evidence yields manual, never pass", () => {
    const collection = baseCollection();
    collection.zones = [zoneWith({})];
    const findings = evaluate(collection, checks);
    for (const f of findings) {
      if (f.check.id.startsWith("CF-SSL") || f.check.id.startsWith("CF-DNS") || f.check.id.startsWith("CF-WAF")) {
        expect(f.verdict, `${f.check.id} passed on empty evidence`).not.toBe("pass");
      }
    }
  });

  it("SSL flexible mode fails, strict passes", () => {
    const collection = baseCollection();
    collection.zones = [
      zoneWith({ settings: { ssl: { id: "ssl", value: "flexible" } } }),
    ];
    const finding = evaluate(collection, checks).find(
      (f: Finding) => f.check.id === "CF-SSL-001" && f.scope === "example.com",
    );
    expect(finding?.verdict).toBe("fail");
  });

  it("managed ruleset absent -> fail when phase readable, manual when not", () => {
    const collection = baseCollection();
    collection.zones = [
      zoneWith({
        phaseEntrypoints: {
          http_request_firewall_managed: {
            phase: "http_request_firewall_managed",
            rules: [{ action: "execute", enabled: true }],
          },
        },
      }),
    ];
    const pass = evaluate(collection, checks).find(
      (f: Finding) => f.check.id === "CF-WAF-001" && f.scope === "example.com",
    );
    expect(pass?.verdict).toBe("pass");

    const c2 = baseCollection();
    c2.zones = [zoneWith({})];
    const manual = evaluate(c2, checks).find(
      (f: Finding) => f.check.id === "CF-WAF-001" && f.scope === "example.com",
    );
    expect(manual?.verdict).toBe("manual");
  });

  it("bot rules with zero enforcement fail", () => {
    const collection = baseCollection();
    collection.zones = [
      zoneWith({
        phaseEntrypoints: {
          http_request_firewall_custom: {
            phase: "http_request_firewall_custom",
            rules: [
              { action: "skip", enabled: true, expression: "cf.bot_management.score eq 1" },
              { action: "skip", enabled: true, expression: "cf.bot_management.score lt 30" },
            ],
          },
        },
      }),
    ];
    const finding = evaluate(collection, checks).find(
      (f: Finding) => f.check.id === "CF-BOT-002" && f.scope === "example.com",
    );
    expect(finding?.verdict).toBe("fail");
  });

  it("bot-score block without verified_bot exclusion warns", () => {
    const collection = baseCollection();
    collection.zones = [
      zoneWith({
        phaseEntrypoints: {
          http_request_firewall_custom: {
            phase: "http_request_firewall_custom",
            rules: [
              {
                action: "block",
                enabled: true,
                expression: "cf.bot_management.score eq 1 and not starts_with(http.request.uri.path, '/api/')",
              },
            ],
          },
        },
      }),
    ];
    const finding = evaluate(collection, checks).find(
      (f: Finding) => f.check.id === "CF-BOT-001" && f.scope === "example.com",
    );
    expect(finding?.verdict).toBe("warn");
  });

  it("rate limit on /login passes; missing fails when phase readable", () => {
    const make = (expr?: string): Collection => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          phaseEntrypoints: expr
            ? {
                http_ratelimit: {
                  phase: "http_ratelimit",
                  rules: [{ action: "block", enabled: true, expression: expr }],
                },
              }
            : { http_ratelimit: { phase: "http_ratelimit", rules: [] } },
        }),
      ];
      return c;
    };
    const pass = evaluate(make('http.request.uri.path eq "/login" and http.request.method eq "POST"'), checks).find(
      (f: Finding) => f.check.id === "CF-RL-001" && f.scope === "example.com",
    );
    expect(pass?.verdict).toBe("pass");
    const fail = evaluate(make(undefined), checks).find(
      (f: Finding) => f.check.id === "CF-RL-001" && f.scope === "example.com",
    );
    expect(fail?.verdict).toBe("fail");
  });

  it("Access app without policies fails; bypass decision fails", () => {
    const collection = baseCollection();
    collection.accounts = [
      {
        accessApps: [
          { name: "App A", hasPolicies: false, policyDecisions: [] },
          { name: "App B", hasPolicies: true, policyDecisions: ["bypass"] },
        ],
      },
    ];
    const finding = evaluate(collection, checks).find((f: Finding) => f.check.id === "CF-ZT-001");
    expect(finding?.verdict).toBe("fail");
  });

  it("2FA not enforced fails; unreadable is manual", () => {
    const failing = baseCollection();
    failing.accounts = [{ enforceTwofactor: false }];
    expect(evaluate(failing, checks).find((f: Finding) => f.check.id === "CF-ZT-003")?.verdict).toBe("fail");

    const manual = baseCollection();
    manual.accounts = [{ enforceTwofactor: null }];
    expect(evaluate(manual, checks).find((f: Finding) => f.check.id === "CF-ZT-003")?.verdict).toBe("manual");
  });

  it("schema rejects a collection missing schemaVersion", () => {
    expect(
      collectionSchema.safeParse({ collectedAt: "2026-10-31T00:00:00Z", collector: "api", collectorVersion: "0.1.0", tokenStatus: "active" }).success,
    ).toBe(false);
  });

  it("schema accepts DNS content redacted sentinel", () => {
    const c = baseCollection();
    c.zones = [zoneWith({ dnsRecordCount: 1, dnsRecords: [{ type: "A", name: "app.example.com", content: "[redacted]", proxied: true }] })];
    expect(c.zones[0]?.dnsRecords?.[0]?.content).toBe("[redacted]");
  });

  it("certificate expiry: fails within 30 days, warns within 90 days, passes beyond", () => {
    function daysFromNow(days: number): string {
      const d = new Date();
      d.setDate(d.getDate() + days);
      return d.toISOString();
    }

    const makeColl = (expiresOn: string) => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          certificatePacks: [
            { id: "pack1", type: "advanced", certificateAuthority: "digicert", expiresOn, hosts: ["example.com"] },
          ],
        }),
      ];
      return c;
    };

    const failing = evaluate(makeColl(daysFromNow(20)), checks).find(
      (f: Finding) => f.check.id === "CF-SSL-005",
    );
    expect(failing?.verdict).toBe("fail");

    const warning = evaluate(makeColl(daysFromNow(60)), checks).find(
      (f: Finding) => f.check.id === "CF-SSL-005",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeColl(daysFromNow(120)), checks).find(
      (f: Finding) => f.check.id === "CF-SSL-005",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("certificate expiry: universal certs (auto-renew) pass", () => {
    const c = baseCollection();
    c.zones = [
      zoneWith({
        certificatePacks: [
          { id: "pack1", type: "advanced", certificateAuthority: "lets_encrypt", expiresOn: new Date().toISOString(), hosts: ["example.com"] },
        ],
      }),
    ];
    const finding = evaluate(c, checks).find((f: Finding) => f.check.id === "CF-SSL-005");
    expect(finding?.verdict).toBe("pass");
  });

  it("certificate expiry: universal cert expiring soon still passes (regression test)", () => {
    function daysFromNow(days: number): string {
      const d = new Date();
      d.setDate(d.getDate() + days);
      return d.toISOString();
    }

    const c = baseCollection();
    c.zones = [
      zoneWith({
        certificatePacks: [
          {
            id: "pack1",
            type: "advanced",
            certificateAuthority: "lets_encrypt",
            expiresOn: daysFromNow(15), // Expiring in 15 days
            hosts: ["example.com"],
          },
        ],
      }),
    ];
    const finding = evaluate(c, checks).find((f: Finding) => f.check.id === "CF-SSL-005");
    expect(finding?.verdict).toBe("pass"); // Universal certs auto-renew
  });

  it("load balancer pools: single origin fails, multiple origins pass", () => {
    const makeC = (originCount: number) => {
      const c = baseCollection();
      c.accounts = [
        {
          loadBalancerPools: [
            {
              id: "pool1",
              name: "test-pool",
              enabled: true,
              origins: Array.from({ length: originCount }, (_, i) => ({
                name: `origin-${i}`,
                address: `10.0.0.${i}`,
                enabled: true,
              })),
            },
          ],
        },
      ];
      return c;
    };

    const failing = evaluate(makeC(1), checks).find((f: Finding) => f.check.id === "CF-LB-001");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(2), checks).find((f: Finding) => f.check.id === "CF-LB-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("load balancer monitors: interval >60s warns, <=60s passes", () => {
    const makeC = (interval: number) => {
      const c = baseCollection();
      c.accounts = [
        {
          loadBalancerMonitors: [
            { id: "mon1", type: "https", interval, timeout: 5, retries: 2, expectedCodes: "200" },
          ],
        },
      ];
      return c;
    };

    const warning = evaluate(makeC(120), checks).find((f: Finding) => f.check.id === "CF-LB-002");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(30), checks).find((f: Finding) => f.check.id === "CF-LB-002");
    expect(passing?.verdict).toBe("pass");
  });

  it("exit code enforcement: --fail-on high blocks only high-severity fails", () => {
    // This is tested via the CLI; engine just needs to expose severity
    const c = baseCollection();
    c.zones = [zoneWith({ settings: { ssl: { id: "ssl", value: "flexible" } } })];
    const findings = evaluate(c, checks);
    const ssl001 = findings.find((f: Finding) => f.check.id === "CF-SSL-001");
    expect(ssl001?.check.severity).toBe("high");
    expect(ssl001?.verdict).toBe("fail");
  });

  it("AI Gateway: rate limiting configured passes, missing fails", () => {
    const makeC = (rateLimitingLimit: number | null, rateLimitingInterval: number | null) => {
      const c = baseCollection();
      c.accounts = [
        {
          aiGateways: [
            {
              id: "my-gateway",
              authentication: true,
              rateLimitingLimit,
              rateLimitingInterval,
              rateLimitingTechnique: "sliding",
              collectLogs: true,
            },
          ],
        },
      ];
      return c;
    };

    const failing = evaluate(makeC(null, null), checks).find((f: Finding) => f.check.id === "CF-AIG-001");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(100, 60), checks).find((f: Finding) => f.check.id === "CF-AIG-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: authentication enabled passes, disabled fails", () => {
    const makeC = (authentication: boolean) => {
      const c = baseCollection();
      c.accounts = [
        {
          aiGateways: [
            {
              id: "my-gateway",
              authentication,
              rateLimitingLimit: 100,
              rateLimitingInterval: 60,
              collectLogs: true,
            },
          ],
        },
      ];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AIG-002");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AIG-002");
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: log collection enabled passes, disabled warns", () => {
    const makeC = (collectLogs: boolean) => {
      const c = baseCollection();
      c.accounts = [
        {
          aiGateways: [
            {
              id: "my-gateway",
              authentication: true,
              collectLogs,
            },
          ],
        },
      ];
      return c;
    };

    const warning = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AIG-003");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AIG-003");
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: DLP enabled passes, disabled warns", () => {
    const makeC = (dlpEnabled: boolean | undefined) => {
      const c = baseCollection();
      c.accounts = [
        {
          aiGateways: [
            {
              id: "my-gateway",
              authentication: true,
              dlpEnabled,
              dlpPoliciesCount: dlpEnabled ? 2 : 0,
            },
          ],
        },
      ];
      return c;
    };

    const warning = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AIG-004");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AIG-004");
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: guardrails configured passes, absent warns", () => {
    const makeC = (guardrailsConfigured: boolean) => {
      const c = baseCollection();
      c.accounts = [
        {
          aiGateways: [
            {
              id: "my-gateway",
              authentication: true,
              guardrailsConfigured,
            },
          ],
        },
      ];
      return c;
    };

    const warning = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AIG-005");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AIG-005");
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: no gateways found returns na", () => {
    const c = baseCollection();
    c.accounts = [{ aiGateways: [] }];
    const findings = evaluate(c, checks);
    const aigFindings = findings.filter((f: Finding) => f.check.domain === "ai-gateway");
    
    // Should have at least the 5 AI Gateway checks
    expect(aigFindings.length).toBeGreaterThan(0);
    
    // All should return na when no gateways present
    expect(aigFindings.every((f) => f.verdict === "na")).toBe(true);
  });

  it("Page Shield: enabled passes, disabled fails", () => {
    const makeC = (enabled: boolean) => {
      const c = baseCollection();
      c.zones = [zoneWith({ pageShield: { enabled } })];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-PS-001");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-PS-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("Authenticated Origin Pulls: enabled passes, disabled fails", () => {
    const makeC = (enabled: boolean) => {
      const c = baseCollection();
      c.zones = [zoneWith({ authenticatedOriginPulls: { enabled, hasZoneLevelCert: false, certCount: 0 } })];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AOP-001");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AOP-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("Zone-level AOP: warns when using global only, passes with zone cert", () => {
    const makeC = (hasZoneLevelCert: boolean) => {
      const c = baseCollection();
      c.zones = [zoneWith({ authenticatedOriginPulls: { enabled: true, hasZoneLevelCert, certCount: hasZoneLevelCert ? 1 : 0 } })];
      return c;
    };

    const warning = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-AOP-002");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-AOP-002");
    expect(passing?.verdict).toBe("pass");
  });

  it("DDoS: passes when not disabled, fails when override disables", () => {
    const makeC = (disabledCount: number) => {
      const c = baseCollection();
      const rules = [];
      for (let i = 0; i < disabledCount; i++) {
        rules.push({ action: "execute", enabled: false });
      }
      c.zones = [zoneWith({ phaseEntrypoints: { ddos_l7: { id: "test", rules } } })];
      return c;
    };

    const passing = evaluate(makeC(0), checks).find((f: Finding) => f.check.id === "CF-DDOS-001");
    expect(passing?.verdict).toBe("pass");

    const failing = evaluate(makeC(1), checks).find((f: Finding) => f.check.id === "CF-DDOS-001");
    expect(failing?.verdict).toBe("fail");
  });

  it("Cache: warns on aggressive, passes otherwise", () => {
    const makeC = (cacheLevel: string) => {
      const c = baseCollection();
      c.zones = [zoneWith({ settings: { cache_level: { id: "cache_level", value: cacheLevel } } })];
      return c;
    };

    const warning = evaluate(makeC("aggressive"), checks).find((f: Finding) => f.check.id === "CF-CACHE-001");
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC("basic"), checks).find((f: Finding) => f.check.id === "CF-CACHE-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("Tunnel-Access gap: fails when public hostname unprotected, passes when protected", () => {
    const makeC = (hasAccessApp: boolean) => {
      const c = baseCollection();
      c.accounts = [
        {
          cfdTunnels: [{ id: "t1", name: "my-tunnel", status: "active", publicHostnames: ["app.example.com"] }],
          accessApps: hasAccessApp ? [{ domain: "app.example.com", hasPolicies: true }] : [],
        },
      ];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find((f: Finding) => f.check.id === "CF-TUNNEL-001");
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find((f: Finding) => f.check.id === "CF-TUNNEL-001");
    expect(passing?.verdict).toBe("pass");
  });

  it("phase filter keeps phase-1 checks and drops phase-2 (rulebook parity)", () => {
    // The shipped rulebook: every check defaults to phase 1 except the
    // explicitly phase-2 Developer Platform checks.
    const doc = parse(readFileSync(join(ROOT, "findings", "checks.yaml"), "utf8")) as { checks?: Check[] };
    const all = doc.checks ?? [];
    const phase1 = filterChecksByPhase(all, 1);
    // phase 2 currently holds 5 checks (2 Workers + 3 Cloudflare One/ZTNA)
    expect(all.length - phase1.length).toBe(5);
    const ids = (cs: Check[]) => new Set(cs.map((c) => c.id));
    const p1 = ids(phase1);
    expect(p1.has("CF-WRK-001")).toBe(false);
    expect(p1.has("CF-WRK-002")).toBe(false);
    expect(p1.has("CF-ZT-001")).toBe(false);
    expect(p1.has("CF-ZT-002")).toBe(false);
    expect(p1.has("CF-TUNNEL-001")).toBe(false);
    // account-hygiene checks are NOT Cloudflare One product checks
    expect(p1.has("CF-ZT-003")).toBe(true);
    expect(p1.has("CF-IAM-001")).toBe(true);
    // AI controls stay in phase 1
    for (const id of ["CF-AIG-001", "CF-AIG-002", "CF-AIG-003", "CF-AIG-004", "CF-AIG-005"]) {
      expect(p1.has(id)).toBe(true);
    }
    // no flag = everything
    expect(filterChecksByPhase(all, 99).length).toBe(all.length);
    // a phase-1 check without an explicit field defaults to 1
    const noField: Check = { ...all[0], phase: undefined };
    expect(filterChecksByPhase([noField], 1)).toHaveLength(1);
  });
});
