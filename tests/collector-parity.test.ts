/**
 * Collector parity: Mode A (TS — also compiled as the Mode B binary) and the bash
 * script must produce the same
 * collection from the same API responses. Both run against a fake Cloudflare
 * API (tests/fixtures/fake-api.json): the TS collector via a stubbed fetch,
 * the bash collector via a fake `curl` on PATH. No network is used.
 *
 * Also asserts the data policy on the produced documents: none of the
 * sensitive values planted in the fake API may appear in either output.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
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

/** Drop nulls/undefined and volatile fields so the two collectors compare cleanly. */
function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) {
      if (val === null || val === undefined) continue;
      if (["collectedAt", "collector", "collectorVersion", "collectionErrors"].includes(k)) continue;
      out[k] = normalize(val);
    }
    return out;
  }
  return v;
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

function readOutput(dir: string): unknown {
  const file = readdirSync(dir).find((f) => f.endsWith(".json"));
  expect(file, `no collection written to ${dir}`).toBeDefined();
  return JSON.parse(readFileSync(join(dir, file as string), "utf8")) as unknown;
}

function runBash(): unknown {
  const out = mkdtempSync(join(tmpdir(), "cfar-parity-sh-"));
  const res = spawnSync("bash", [join(ROOT, "collectors", "sh", "collect-config.sh"), out], {
    env: { ...process.env, PATH: `${join(ROOT, "tests", "fixtures", "fake-curl")}:${process.env.PATH ?? ""}`, CF_API_TOKEN: "fake-token-for-tests", FAKE_API },
    encoding: "utf8",
  });
  expect(res.status, res.stderr).toBe(0);
  return readOutput(out);
}

describe("collector parity (fake API, no network)", () => {
  afterEach(() => vi.unstubAllGlobals());

  async function runTs() {
    stubFetch();
    const ts = await collect("fake-token-for-tests");
    vi.unstubAllGlobals();
    return collectionSchema.parse(JSON.parse(JSON.stringify(ts)));
  }

  it("TS and bash collectors emit equivalent, schema-valid, policy-clean collections", async () => {
    const tsParsed = await runTs();
    const bashParsed = collectionSchema.parse(runBash());

    expect(normalize(bashParsed)).toEqual(normalize(tsParsed));

    // Same unreadable endpoints recorded (order differs between collectors).
    const paths = (c: typeof tsParsed) => [...new Set(c.collectionErrors.map((e) => e.path))].sort();
    expect(paths(bashParsed)).toEqual(paths(tsParsed));

    // Data policy: nothing planted in the fake API leaks into either output.
    for (const text of [JSON.stringify(tsParsed), JSON.stringify(bashParsed)]) {
      for (const secret of PLANTED_SECRETS) expect(text, `leaked: ${secret}`).not.toContain(secret);
    }

    // Spot-check the web-security evidence actually made it through Mode B
    // (v0.1's bash collector silently dropped every phase entrypoint).
    const z = bashParsed.zones[0];
    expect(z?.phaseStatus).toMatchObject({ ddos_l7: "absent", http_request_cache_settings: "unreadable", http_request_firewall_managed: "present" });
    const managed = z?.phaseEntrypoints?.http_request_firewall_managed?.rules ?? [];
    expect(managed.map((r) => r.actionParameters?.executes)).toEqual(["cloudflare_managed", "owasp"]);
    expect(z?.phaseEntrypoints?.http_ratelimit?.rules?.[0]?.actionParameters?.ratelimit?.requestsPerPeriod).toBe(5);
    expect(z?.botManagement).toEqual({ enable_js: true, sbfm_definitely_automated: "allow" });
  });
});
