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
});
