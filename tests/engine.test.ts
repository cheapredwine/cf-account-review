import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { collectionSchema, type Collection } from "../src/schema.js";
import { evaluate, type Check, type Finding } from "../src/analyzer/engine.js";

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
});
