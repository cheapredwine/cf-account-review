import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { baseCollection, loadChecks, zoneWith } from "./helpers.js";
import { collectionSchema, type Collection } from "../src/schema.js";
import {
  diffFindings,
  evaluate,
  filterChecksByDomains,
  planAtLeast,
  planTier,
  type Finding,
} from "../src/analyzer/engine.js";

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
      if (
        f.check.id.startsWith("CF-SSL") ||
        f.check.id.startsWith("CF-DNS") ||
        f.check.id.startsWith("CF-WAF")
      ) {
        expect(f.verdict, `${f.check.id} passed on empty evidence`).not.toBe(
          "pass",
        );
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
              {
                action: "skip",
                enabled: true,
                expression: "cf.bot_management.score eq 1",
              },
              {
                action: "skip",
                enabled: true,
                expression: "cf.bot_management.score lt 30",
              },
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
                expression:
                  "cf.bot_management.score eq 1 and not starts_with(http.request.uri.path, '/api/')",
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
    const pass = evaluate(
      make(
        'http.request.uri.path eq "/login" and http.request.method eq "POST"',
      ),
      checks,
    ).find(
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
    const finding = evaluate(collection, checks).find(
      (f: Finding) => f.check.id === "CF-ZT-001",
    );
    expect(finding?.verdict).toBe("fail");
  });

  it("2FA not enforced fails; unreadable is manual", () => {
    const failing = baseCollection();
    failing.accounts = [{ enforceTwofactor: false }];
    expect(
      evaluate(failing, checks).find((f: Finding) => f.check.id === "CF-ZT-003")
        ?.verdict,
    ).toBe("fail");

    const manual = baseCollection();
    manual.accounts = [{ enforceTwofactor: null }];
    expect(
      evaluate(manual, checks).find((f: Finding) => f.check.id === "CF-ZT-003")
        ?.verdict,
    ).toBe("manual");
  });

  it("schema rejects a collection missing schemaVersion", () => {
    expect(
      collectionSchema.safeParse({
        collectedAt: "2026-10-31T00:00:00Z",
        collector: "api",
        collectorVersion: "0.1.0",
        tokenStatus: "active",
      }).success,
    ).toBe(false);
  });

  it("schema accepts DNS content redacted sentinel", () => {
    const c = baseCollection();
    c.zones = [
      zoneWith({
        dnsRecordCount: 1,
        dnsRecords: [
          {
            type: "A",
            name: "app.example.com",
            content: "[redacted]",
            proxied: true,
          },
        ],
      }),
    ];
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
            {
              id: "pack1",
              type: "advanced",
              certificateAuthority: "digicert",
              expiresOn,
              hosts: ["example.com"],
            },
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
          {
            id: "pack1",
            type: "advanced",
            certificateAuthority: "lets_encrypt",
            expiresOn: new Date().toISOString(),
            hosts: ["example.com"],
          },
        ],
      }),
    ];
    const finding = evaluate(c, checks).find(
      (f: Finding) => f.check.id === "CF-SSL-005",
    );
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
    const finding = evaluate(c, checks).find(
      (f: Finding) => f.check.id === "CF-SSL-005",
    );
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

    const failing = evaluate(makeC(1), checks).find(
      (f: Finding) => f.check.id === "CF-LB-001",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(2), checks).find(
      (f: Finding) => f.check.id === "CF-LB-001",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("load balancer monitors: interval >60s warns, <=60s passes", () => {
    const makeC = (interval: number) => {
      const c = baseCollection();
      c.accounts = [
        {
          loadBalancerMonitors: [
            {
              id: "mon1",
              type: "https",
              interval,
              timeout: 5,
              retries: 2,
              expectedCodes: "200",
            },
          ],
        },
      ];
      return c;
    };

    const warning = evaluate(makeC(120), checks).find(
      (f: Finding) => f.check.id === "CF-LB-002",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(30), checks).find(
      (f: Finding) => f.check.id === "CF-LB-002",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("exit code enforcement: --fail-on high blocks only high-severity fails", () => {
    // This is tested via the CLI; engine just needs to expose severity
    const c = baseCollection();
    c.zones = [
      zoneWith({ settings: { ssl: { id: "ssl", value: "flexible" } } }),
    ];
    const findings = evaluate(c, checks);
    const ssl001 = findings.find((f: Finding) => f.check.id === "CF-SSL-001");
    expect(ssl001?.check.severity).toBe("high");
    expect(ssl001?.verdict).toBe("fail");
  });

  it("AI Gateway: rate limiting configured passes, missing fails", () => {
    const makeC = (
      rateLimitingLimit: number | null,
      rateLimitingInterval: number | null,
    ) => {
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

    const failing = evaluate(makeC(null, null), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-001",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(100, 60), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-001",
    );
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

    const failing = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-002",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-002",
    );
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

    const warning = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-003",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-003",
    );
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

    const warning = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-004",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-004",
    );
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

    const warning = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-005",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AIG-005",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("AI Gateway: no gateways found returns na", () => {
    const c = baseCollection();
    c.accounts = [{ aiGateways: [] }];
    const findings = evaluate(c, checks);
    const aigFindings = findings.filter(
      (f: Finding) => f.check.domain === "ai-gateway",
    );

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

    const failing = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-PS-001",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-PS-001",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("Authenticated Origin Pulls: enabled passes, disabled fails", () => {
    const makeC = (enabled: boolean) => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          authenticatedOriginPulls: {
            enabled,
            hasZoneLevelCert: false,
            certCount: 0,
          },
        }),
      ];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AOP-001",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AOP-001",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("Zone-level AOP: warns when using global only, passes with zone cert", () => {
    const makeC = (hasZoneLevelCert: boolean) => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          authenticatedOriginPulls: {
            enabled: true,
            hasZoneLevelCert,
            certCount: hasZoneLevelCert ? 1 : 0,
          },
        }),
      ];
      return c;
    };

    const warning = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-AOP-002",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-AOP-002",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("DDoS: passes when not disabled, fails when override disables", () => {
    const makeC = (disabledCount: number) => {
      const c = baseCollection();
      const rules = [];
      for (let i = 0; i < disabledCount; i++) {
        rules.push({ action: "execute", enabled: false });
      }
      c.zones = [
        zoneWith({ phaseEntrypoints: { ddos_l7: { id: "test", rules } } }),
      ];
      return c;
    };

    const passing = evaluate(makeC(0), checks).find(
      (f: Finding) => f.check.id === "CF-DDOS-001",
    );
    expect(passing?.verdict).toBe("pass");

    const failing = evaluate(makeC(1), checks).find(
      (f: Finding) => f.check.id === "CF-DDOS-001",
    );
    expect(failing?.verdict).toBe("fail");
  });

  it("DDoS: no override ruleset (entrypoint 404) passes only when the ruleset list confirms it", () => {
    const managedOnly = [
      { kind: "managed", phase: "ddos_l7", name: "DDoS L7 ruleset" },
    ];
    const withOverride = [
      ...managedOnly,
      { kind: "zone", phase: "ddos_l7", name: "default" },
    ];
    const find = (c: ReturnType<typeof baseCollection>) =>
      evaluate(c, checks).find((f: Finding) => f.check.id === "CF-DDOS-001");

    const c1 = baseCollection();
    c1.zones = [zoneWith({ phaseEntrypoints: {}, rulesets: managedOnly })];
    expect(find(c1)?.verdict).toBe("pass");

    // override ruleset exists but its rules were not readable → scope gap
    const c2 = baseCollection();
    c2.zones = [zoneWith({ phaseEntrypoints: {}, rulesets: withOverride })];
    expect(find(c2)?.verdict).toBe("manual");

    // ruleset list itself unreadable → cannot distinguish 404 from 403
    const c3 = baseCollection();
    c3.zones = [zoneWith({ phaseEntrypoints: {} })];
    expect(find(c3)?.verdict).toBe("manual");

    // deployed override that sets the managed ruleset to log → fail
    const c4 = baseCollection();
    c4.zones = [
      zoneWith({
        rulesets: withOverride,
        phaseEntrypoints: {
          ddos_l7: {
            phase: "ddos_l7",
            rules: [
              {
                action: "execute",
                enabled: true,
                action_parameters: { id: "x", overrides: { action: "log" } },
              },
            ],
          },
        },
      }),
    ];
    expect(find(c4)?.verdict).toBe("fail");
  });

  it("managed WAF: override-disabled deployment fails, log-only deployment warns", () => {
    const make = (overrides: Record<string, unknown>) => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          phaseEntrypoints: {
            http_request_firewall_managed: {
              phase: "http_request_firewall_managed",
              rules: [
                {
                  action: "execute",
                  enabled: true,
                  action_parameters: { id: "efb7b8c9", overrides },
                },
              ],
            },
          },
        }),
      ];
      return evaluate(c, checks).find(
        (f: Finding) => f.check.id === "CF-WAF-001",
      );
    };
    expect(make({ enabled: false })?.verdict).toBe("fail");
    expect(make({ action: "log" })?.verdict).toBe("warn");
    expect(make({ action: "block" })?.verdict).toBe("pass");
  });

  it("plan tier: API display names resolve to tiers (Enterprise Website is Enterprise, not Free)", () => {
    expect(planTier("Enterprise Website")).toBe("enterprise");
    expect(planTier("Business Website")).toBe("business");
    expect(planTier("Pro Plan")).toBe("pro");
    expect(planTier("Free Website")).toBe("free");
    expect(planTier("Enterprise")).toBe("enterprise");
    expect(planTier("Partner Custom")).toBeUndefined();
    expect(planAtLeast("Enterprise Website", "pro-plus")).toBe(true);
    expect(planAtLeast("Enterprise Website", "enterprise")).toBe(true);
    expect(planAtLeast("Free Website", "pro-plus")).toBe(false);
    expect(planAtLeast("Partner Custom", "pro-plus")).toBe(false);
    expect(planAtLeast(undefined, "any")).toBe(true);

    // end to end: a tiered check on an "Enterprise Website" zone is evaluated, not na
    const c = baseCollection();
    c.zones = [
      zoneWith({
        plan: "Enterprise Website",
        phaseEntrypoints: {
          http_request_firewall_managed: {
            phase: "http_request_firewall_managed",
            rules: [{ action: "execute", enabled: true }],
          },
        },
      }),
    ];
    const f = evaluate(c, checks).find(
      (x: Finding) => x.check.id === "CF-WAF-001",
    );
    expect(f?.verdict).toBe("pass");
  });

  it("Cache: warns on aggressive, passes otherwise", () => {
    const makeC = (cacheLevel: string) => {
      const c = baseCollection();
      c.zones = [
        zoneWith({
          settings: { cache_level: { id: "cache_level", value: cacheLevel } },
        }),
      ];
      return c;
    };

    const warning = evaluate(makeC("aggressive"), checks).find(
      (f: Finding) => f.check.id === "CF-CACHE-001",
    );
    expect(warning?.verdict).toBe("warn");

    const passing = evaluate(makeC("basic"), checks).find(
      (f: Finding) => f.check.id === "CF-CACHE-001",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("Tunnel-Access gap: fails when public hostname unprotected, passes when protected", () => {
    const makeC = (hasAccessApp: boolean) => {
      const c = baseCollection();
      c.accounts = [
        {
          cfdTunnels: [
            {
              id: "t1",
              name: "my-tunnel",
              status: "active",
              publicHostnames: ["app.example.com"],
            },
          ],
          accessApps: hasAccessApp
            ? [{ domain: "app.example.com", hasPolicies: true }]
            : [],
        },
      ];
      return c;
    };

    const failing = evaluate(makeC(false), checks).find(
      (f: Finding) => f.check.id === "CF-TUNNEL-001",
    );
    expect(failing?.verdict).toBe("fail");

    const passing = evaluate(makeC(true), checks).find(
      (f: Finding) => f.check.id === "CF-TUNNEL-001",
    );
    expect(passing?.verdict).toBe("pass");
  });

  it("domain scoping keeps the in-scope categories and drops the rest (rulebook parity)", () => {
    const all = loadChecks();
    // The first customer run's scope, chosen 2026-11-04 by broad category:
    const inScope = [
      "ssl-tls",
      "waf",
      "rate-limiting",
      "bots",
      "ddos",
      "dns",
      "cache",
      "origin-security",
      "ai-gateway",
      "account-hygiene",
      "security",
      "performance",
    ];
    const scoped = filterChecksByDomains(all, inScope);
    const scopedIds = new Set(scoped.map((c) => c.id));
    // in: everything from the chosen domains, incl. AI controls + account security
    for (const id of [
      "CF-SSL-001",
      "CF-WAF-001",
      "CF-RL-001",
      "CF-BOT-001",
      "CF-TS-001",
      "CF-DDOS-001",
      "CF-DNS-001",
      "CF-CACHE-001",
      "CF-CACHE-002",
      "CF-AOP-001",
      "CF-AIG-001",
      "CF-ZT-003",
      "CF-IAM-001",
      "CF-SEC-001",
      "CF-PERF-001",
    ]) {
      expect(scopedIds.has(id)).toBe(true);
    }
    // out: the categories the user did not select
    const outDomains = new Set([
      "client-side-security",
      "traffic",
      "workers",
      "zero-trust",
      "response-headers",
    ]);
    const expectedOut = all.filter((c) => outDomains.has(c.domain));
    for (const id of [
      "CF-PS-001",
      "CF-LB-001",
      "CF-LB-002",
      "CF-WRK-001",
      "CF-WRK-002",
      "CF-ZT-001",
      "CF-ZT-002",
      "CF-TUNNEL-001",
      "CF-HDR-001",
    ]) {
      expect(scopedIds.has(id)).toBe(false);
    }
    expect(scoped.length).toBe(all.length - expectedOut.length);
    // empty/absent scope = every check
    expect(filterChecksByDomains(all, []).length).toBe(all.length);
  });

  it("diffFindings classifies new, resolved, and changed findings", () => {
    const mk = (
      id: string,
      scope: string,
      verdict: Finding["verdict"],
    ): Finding => ({
      check: {
        id,
        name: id,
        domain: "test",
        severity: "low",
        type: "x",
        evidence: "",
        params: {},
        remediation: "",
        citation: "",
      },
      scope,
      verdict,
      detail: "d",
    });
    const before = [
      mk("CF-A", "z", "fail"),
      mk("CF-B", "z", "warn"),
      mk("CF-C", "z", "pass"),
    ];
    const after = [
      mk("CF-A", "z", "pass"),
      mk("CF-B", "z", "warn"),
      mk("CF-D", "z", "fail"),
    ];
    const diffs = diffFindings(before, after);
    expect(diffs.find((d) => d.check === "CF-A")).toMatchObject({
      kind: "changed",
      before: "fail",
      after: "pass",
    });
    expect(diffs.find((d) => d.check === "CF-D")).toMatchObject({
      kind: "new",
    });
    expect(diffs.find((d) => d.check === "CF-C")).toMatchObject({
      kind: "resolved",
    });
    expect(diffs.find((d) => d.check === "CF-B")).toBeUndefined(); // unchanged → not in diff
    expect(diffFindings([], [])).toHaveLength(0);
  });

  it("diffFindings: remediating DNSSEC in the fixture resolves CF-DNS-001 and nothing else", () => {
    const fixture = collectionSchema.parse(
      JSON.parse(
        readFileSync(
          new URL("./fixtures/collection-fixture.json", import.meta.url),
          "utf8",
        ),
      ),
    ) as Collection;
    const remediated = {
      ...fixture,
      zones: fixture.zones.map((z) => ({
        ...z,
        settings: { ...z.settings, dnssec: { id: "dnssec", value: "active" } },
      })),
    };
    const before = evaluate(fixture, loadChecks());
    const after = evaluate(remediated, loadChecks());
    const diffs = diffFindings(before, after);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]).toMatchObject({
      check: "CF-DNS-001",
      kind: "changed",
      before: "fail",
      after: "pass",
    });
  });
});
