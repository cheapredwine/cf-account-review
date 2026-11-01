/**
 * Collector data policy, end to end. The single collector (Mode A, also compiled
 * as the Mode B binary) runs against a fake Cloudflare API
 * (tests/fixtures/fake-api.json) via a stubbed fetch — no network. The fake API
 * plants sensitive values; none may appear in the output, and the web-security
 * evidence must come through intact.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { collect } from "../src/collect.js";
import { collectionSchema } from "../src/schema.js";

const ROOT = new URL("..", import.meta.url).pathname;
const FAKE_API = join(ROOT, "tests", "fixtures", "fake-api.json");
const api = JSON.parse(readFileSync(FAKE_API, "utf8")) as Record<string, { status: number; body: unknown }>;

function stubFetch(): void {
  vi.stubGlobal("fetch", async (input: URL | string) => {
    const url = new URL(String(input));
    const path = url.pathname.replace("/client/v4", "");
    const entry = api[path] ?? { status: 404, body: { success: false, errors: [{ message: "not found" }] } };
    return new Response(JSON.stringify(entry.body), { status: entry.status, headers: { "content-type": "application/json" } });
  });
}

const PLANTED_SECRETS = [
  "198.51.100.7", // LB origin address
  "198.51.100.9", // IP access rule value
  "192.0.2.10", // DNS content
  "203.0.113.4", // IP in a rule expression
  "Basic c2VjcmV0", // LB monitor auth header
  "noc@example.com",
  "abuse@example.com",
  "x@example.com",
  "bob@example.com",
  "jane@example.com",
  "ops@example.com",
  "s3cr3t", // response header transform value
  "internal.shop.example", // page rule target
  "origin.shop.example", // forwarding URL
  "0x4AAAAAAA", // Turnstile secret
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // raw account id
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // raw zone id
];

describe("collector data policy (fake API, no network)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("emits a schema-valid collection with no planted secrets and full web-security evidence", async () => {
    stubFetch();
    const parsed = collectionSchema.parse(JSON.parse(JSON.stringify(await collect("fake-token-for-tests"))));

    const text = JSON.stringify(parsed);
    for (const secret of [...PLANTED_SECRETS, "fake-token-for-tests"]) expect(text, `leaked: ${secret}`).not.toContain(secret);

    // Unreadable endpoints recorded, with IDs hashed.
    expect(parsed.collectionErrors.map((e) => e.path).sort()).toEqual([
      "/accounts/h3ba3f5f43b926026/r2/buckets",
      "/accounts/h3ba3f5f43b926026/rulesets",
      "/zones/hbdb339768bc5e4fe/rulesets/phases/http_request_cache_settings/entrypoint",
    ]);

    // Evidence survives summarization (v0.1's offline collectors dropped every
    // phase entrypoint; this pins that it reaches the analyzer now).
    const z = parsed.zones[0];
    expect(z?.phaseStatus).toMatchObject({ ddos_l7: "absent", http_request_cache_settings: "unreadable", http_request_firewall_managed: "present" });
    const managed = z?.phaseEntrypoints?.http_request_firewall_managed?.rules ?? [];
    expect(managed.map((r) => r.actionParameters?.executes)).toEqual(["cloudflare_managed", "owasp"]);
    expect(z?.phaseEntrypoints?.http_ratelimit?.rules?.[0]?.actionParameters?.ratelimit?.requestsPerPeriod).toBe(5);
    expect(z?.botManagement).toEqual({ enable_js: true, sbfm_definitely_automated: "allow" });
    expect(parsed.accounts[0]?.enforceTwofactor).toBe(false);
    expect(z?.ipAccessRuleSummary).toEqual([
      { mode: "whitelist", target: "ip", value: "[redacted]", scope: "zone" },
      { mode: "whitelist", target: "country", value: "US", scope: "zone" },
    ]);
  });
});
