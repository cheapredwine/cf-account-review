/**
 * CI smoke: a committed, deterministic fixture collection is analyzed against
 * the committed rulebook and compared finding-for-finding with a committed
 * golden file. A rulebook or evaluator regression therefore fails visibly in
 * `pnpm verify` — never silently.
 *
 * Regenerate the fixture + golden deliberately (after an intended rulebook or
 * schema change) with:
 *   FIXTURE=1 pnpm vitest run tests/smoke.test.ts
 * then review the golden diff like code.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { collectionSchema, type Collection } from "../src/schema.js";
import { evaluate, type Finding } from "../src/analyzer/engine.js";
import { baseCollection, loadChecks, zoneWith } from "./helpers.js";

const ROOT = new URL("..", import.meta.url).pathname;
const FIXTURE = join(ROOT, "tests", "fixtures", "collection-fixture.json");
const GOLDEN = join(ROOT, "tests", "fixtures", "golden-findings.json");

/** Deterministic synthetic account+zone exercising many check paths. */
function fixtureCollection(): Collection {
  const c = baseCollection();
  c.collectedAt = "2026-01-01T00:00:00.000Z";
  c.accounts = [
    {
      id: "h1a2b3c4d5e6f7a8",
      name: "Fixture Account",
      enforceTwofactor: false, // CF-ZT-003 fail
      settings: {},
      accountMembers: [
        { roleNames: ["Super Administrator - All Zones"], twofactorEnabled: true, status: "active" },
        { roleNames: ["Super Administrator - All Zones"], twofactorEnabled: false, status: "active" },
      ],
      apiTokens: [
        { status: "active", expiresOn: null, lastUsedOn: "2026-01-01T00:00:00Z", permissionGroupNames: ["Zone Read"] }, // CF-IAM-001 fail
        { status: "active", expiresOn: "2026-06-01T00:00:00Z", lastUsedOn: "2026-01-01T00:00:00Z", permissionGroupNames: ["DNS Read"] },
      ],
      loadBalancerPools: [
        { id: "h1111222233334444", name: "pool-single", enabled: true, origins: [{ name: "origin-1", address: "[redacted]", enabled: true }] }, // CF-LB-001 fail
      ],
      loadBalancerMonitors: [{ id: "h5555666677778888", type: "http", interval: 60, timeout: 5, retries: 2, expectedCodes: "200" }],
      accessApps: [
        { name: "admin-app", type: "self_hosted", domain: "admin.example.com", hasPolicies: true, policyDecisions: ["allow"] }, // CF-ZT-001 pass
      ],
      accessIdentityProviders: [{ name: "Google SaaS", type: "google" }], // CF-ZT-002 pass
      turnstileWidgets: [{ name: "login-widget", domains: ["example.com"], mode: "managed" }], // CF-TS-001 pass
      cfdTunnels: [
        { id: "htunnel00000001", name: "corp-tunnel", status: "active", publicHostnames: ["internal.example.com"] },
      ],
      workersScripts: [
        { id: "hscript0000001", scriptName: "orphan-api", routesBound: false }, // CF-WRK-001 fail
      ],
      storageInventory: { kvNamespaces: 2, d1Databases: 1, r2Buckets: 1 },
      aiGateways: [
        { id: "fixture-gateway", authentication: true, rateLimitingLimit: 10, rateLimitingInterval: 60, collectLogs: true, dlpEnabled: false, dlpPoliciesCount: 0, guardrailsConfigured: true }, // CF-AIG-004 fail, rest pass
      ],
    },
  ];
  c.zones = [
    zoneWith({
      name: "example.com",
      settings: {
        ssl: { id: "ssl", value: "strict" }, // CF-SSL-001 pass
        min_tls_version: { id: "min_tls_version", value: "1.2" }, // CF-SSL-002 pass
        security_header: { id: "security_header", value: { strict_transport_security: { enabled: true } } }, // CF-SSL-003 pass
        always_use_https: { id: "always_use_https", value: "on" }, // CF-SSL-004 pass
        dnssec: { id: "dnssec", value: "off" }, // CF-DNS-001 fail
      },
      phaseEntrypoints: {
        http_request_firewall_managed: {
          phase: "http_request_firewall_managed",
          rules: [{ action: "execute", enabled: true }], // CF-WAF-001 pass
        },
        http_request_firewall_custom: {
          phase: "http_request_firewall_custom",
          rules: [
            { action: "block", enabled: true, expression: 'http.request.uri.path contains "/admin"' }, // CF-WAF-002 pass
            { action: "skip", enabled: true, expression: "(http.user_agent contains \"bot\")" },
          ],
        },
        http_ratelimit: {
          phase: "http_ratelimit",
          rules: [{ action: "block", enabled: true, expression: 'http.request.uri.path contains "/login"' }], // CF-RL-001 pass
        },
      },
      dnsRecordCount: 5,
      dnsRecords: [
        { type: "CAA", name: "example.com", content: "[redacted]", proxied: false, ttl: 3600 }, // CF-DNS-002 pass
        { type: "MX", name: "example.com", content: "[redacted]", proxied: false, ttl: 3600 }, // CF-DNS-003
      ],
      certificatePacks: [
        { id: "hcert000000001", type: "custom", status: "active", expiresOn: "2026-01-11T00:00:00Z", hosts: ["example.com"] }, // CF-SSL-005 fail (10 days)
      ],
      workersRoutes: [], // routes empty -> CF-WRK-002 manual (script exists, unrouted)
      botManagement: {},
      authenticatedOriginPulls: { enabled: false }, // CF-AOP-001 fail
      pageShield: { enabled: false }, // CF-PS-001 fail
    }),
  ];
  return c;
}

interface GoldenFinding {
  check: string;
  scope: string;
  verdict: string;
}

function findingsKey(f: Finding): GoldenFinding {
  return { check: f.check.id, scope: f.scope, verdict: f.verdict };
}

describe("rulebook smoke (committed fixture vs golden)", () => {
  function loadFixture(): Collection | null {
    if (!existsSync(FIXTURE)) return null;
    return collectionSchema.parse(JSON.parse(readFileSync(FIXTURE, "utf8"))) as Collection;
  }

  it("generates the committed fixture + golden when FIXTURE=1 (manual regeneration)", () => {
    if (process.env.FIXTURE !== "1") return;
    const collection = fixtureCollection();
    const findings = evaluate(collection, loadChecks());
    const actual = findings.map(findingsKey);
    mkdirSync(join(ROOT, "tests", "fixtures"), { recursive: true });
    writeFileSync(FIXTURE, JSON.stringify(collection, null, 2) + "\n", { mode: 0o600 });
    writeFileSync(GOLDEN, JSON.stringify(actual, null, 2) + "\n", { mode: 0o600 });
    console.log(`fixture + golden regenerated (${actual.length} findings)`);
  });

  it("fixture is synthetic — no credential-shaped material committed", () => {
    const collection = loadFixture();
    expect(collection).not.toBeNull();
    const text = readFileSync(FIXTURE, "utf8");
    expect(text).not.toMatch(/Bearer\s+\S+/i);
    expect(text).not.toMatch(/[A-Za-z0-9_-]{64,}/);
  });

  it("findings match the golden file exactly", () => {
    const collection = loadFixture();
    expect(collection).not.toBeNull();
    const findings = evaluate(collection as Collection, loadChecks());
    const actual = findings.map(findingsKey);
    expect(existsSync(GOLDEN)).toBe(true);
    const golden: GoldenFinding[] = JSON.parse(readFileSync(GOLDEN, "utf8"));
    expect(actual).toEqual(golden);
  });
});
