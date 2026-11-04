/**
 * Collector parity: Mode A (TS) and both Mode B collectors (bash, PowerShell)
 * must produce the same collection from the same API responses. All three run
 * against a fake Cloudflare API (tests/fixtures/fake-api.json): the TS
 * collector via a stubbed fetch, bash via a fake `curl` on PATH, PowerShell via
 * a shadowing `Invoke-RestMethod` function. No network is used.
 *
 * Also asserts the data policy on the produced documents: none of the
 * sensitive values planted in the fake API may appear in any output.
 *
 * Why this exists: the v0.1 Mode B collectors silently dropped every phase
 * entrypoint (bash wrapped single objects in a list that `obj()` rejected; PS
 * attached fields with Add-Member, which ConvertTo-Json ignores on hashtables),
 * so every WAF / rate-limit / bot / DDoS check was `manual` in offline mode
 * while the dogfood notes claimed parity. Structural equality here makes that
 * class of regression fail visibly.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { collect } from "../src/collect.js";
import { collectionSchema, type Collection } from "../src/schema.js";

const ROOT = new URL("..", import.meta.url).pathname;
const FAKE_API = join(ROOT, "tests", "fixtures", "fake-api.json");
const api = JSON.parse(readFileSync(FAKE_API, "utf8")) as Record<
  string,
  { status: number; body: unknown }
>;

function stubFetch(): void {
  vi.stubGlobal("fetch", async (input: URL | string) => {
    const url = new URL(String(input));
    const path = url.pathname.replace("/client/v4", "");
    const entry = api[path] ?? {
      status: 404,
      body: { success: false, errors: [{ message: "not found" }] },
    };
    return new Response(JSON.stringify(entry.body), {
      status: entry.status,
      headers: { "content-type": "application/json" },
    });
  });
}

/** Fields that legitimately differ per collector run. */
const VOLATILE = new Set([
  "collectedAt",
  "collector",
  "collectorVersion",
  "collectionErrors",
  "tool",
]);

/** Drop nulls/undefined and volatile fields so collectors compare structurally. */
function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) {
      if (val === null || val === undefined) continue;
      if (VOLATILE.has(k)) continue;
      const n = normalize(val);
      // an object that normalizes to {} carries no evidence either way
      if (n && typeof n === "object" && !Array.isArray(n) && Object.keys(n).length === 0) continue;
      out[k] = n;
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
  "0x4AAAAAAA", // Turnstile secret
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // raw account id
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // raw zone id
  "cccccccccccccccccccccccccccccccc", // raw tunnel id
];

function readOutput(dir: string): unknown {
  const file = readdirSync(dir).find((f) => f.endsWith(".json"));
  expect(file, `no collection written to ${dir}`).toBeDefined();
  return JSON.parse(readFileSync(join(dir, file as string), "utf8")) as unknown;
}

function runBash(): unknown {
  const out = mkdtempSync(join(tmpdir(), "cfar-parity-sh-"));
  const res = spawnSync(
    "bash",
    [join(ROOT, "collectors", "sh", "collect-config.sh"), out],
    {
      env: {
        ...process.env,
        PATH: `${join(ROOT, "tests", "fixtures", "fake-curl")}:${process.env.PATH ?? ""}`,
        CF_API_TOKEN: "fake-token-for-tests",
        FAKE_API,
      },
      encoding: "utf8",
    },
  );
  expect(res.status, res.stderr || res.stdout).toBe(0);
  return readOutput(out);
}

/** pwsh from $PWSH or PATH; undefined when PowerShell is not installed. */
function findPwsh(): string | undefined {
  const candidates = [process.env.PWSH, "pwsh"].filter(
    (c): c is string => !!c,
  );
  for (const c of candidates) {
    if (spawnSync(c, ["-NoProfile", "-Command", "exit 0"]).status === 0) {
      return c;
    }
  }
  return undefined;
}
const PWSH = findPwsh();

function runPwsh(pwsh: string): unknown {
  const out = mkdtempSync(join(tmpdir(), "cfar-parity-ps-"));
  const res = spawnSync(
    pwsh,
    [
      "-NoProfile",
      "-File",
      join(ROOT, "tests", "fixtures", "fake-pwsh-api.ps1"),
      join(ROOT, "collectors", "ps", "Collect-CFConfig.ps1"),
      out,
    ],
    {
      env: { ...process.env, CF_API_TOKEN: "fake-token-for-tests", FAKE_API },
      encoding: "utf8",
    },
  );
  expect(res.status, res.stderr || res.stdout).toBe(0);
  return readOutput(out);
}

const errorPaths = (c: Collection) =>
  [...new Set(c.collectionErrors.map((e) => e.path))].sort();

/** The evidence Mode B historically dropped must be present and identical. */
function expectEvidencePresent(c: Collection): void {
  const z = c.zones[0];
  expect(z?.plan).toBe("Enterprise Website");
  expect(Object.keys(z?.phaseEntrypoints ?? {}).sort()).toEqual([
    "http_ratelimit",
    "http_request_firewall_custom",
    "http_request_firewall_managed",
    "http_response_headers_transform",
  ]);
  const managed = z?.phaseEntrypoints?.http_request_firewall_managed?.rules ?? [];
  expect(managed.map((r) => r.action)).toEqual(["execute", "execute"]);
  expect(z?.botManagement).toMatchObject({ enable_js: true });
  expect(z?.pageShield).toMatchObject({ enabled: true });
  expect(z?.authenticatedOriginPulls).toMatchObject({ enabled: false });
  expect(z?.settings?.ssl?.value).toBe("full");
  expect(Array.isArray(z?.ipAccessRules)).toBe(true);
  expect(Array.isArray(z?.pageRules)).toBe(true);
  const a = c.accounts[0];
  expect(a?.enforceTwofactor).toBe(false);
  expect(a?.loadBalancerPools?.length).toBe(1);
  expect(a?.aiGateways?.length).toBe(1);
  expect(a?.aiGateways?.[0]?.authentication).toBe(false);
}

describe("collector parity (fake API, no network)", () => {
  afterEach(() => vi.unstubAllGlobals());

  async function runTs(): Promise<Collection> {
    stubFetch();
    const ts = await collect("fake-token-for-tests");
    vi.unstubAllGlobals();
    return collectionSchema.parse(JSON.parse(JSON.stringify(ts)));
  }

  it("TS collector captures the evidence the checks consume", async () => {
    const ts = await runTs();
    expectEvidencePresent(ts);
    const text = JSON.stringify(ts);
    for (const secret of PLANTED_SECRETS) {
      expect(text, `leaked: ${secret}`).not.toContain(secret);
    }
  });

  it("TS and bash collectors emit equivalent, schema-valid, policy-clean collections", async () => {
    const ts = await runTs();
    const bash = collectionSchema.parse(runBash());

    expectEvidencePresent(bash);
    expect(normalize(bash)).toEqual(normalize(ts));
    expect(errorPaths(bash)).toEqual(errorPaths(ts));

    const text = JSON.stringify(bash);
    for (const secret of PLANTED_SECRETS) {
      expect(text, `leaked: ${secret}`).not.toContain(secret);
    }
  });

  it.runIf(PWSH !== undefined)(
    "TS and PowerShell collectors emit equivalent, schema-valid, policy-clean collections",
    async () => {
      const ts = await runTs();
      const ps = collectionSchema.parse(runPwsh(PWSH as string));

      expectEvidencePresent(ps);
      expect(normalize(ps)).toEqual(normalize(ts));
      expect(errorPaths(ps)).toEqual(errorPaths(ts));

      const text = JSON.stringify(ps);
      for (const secret of PLANTED_SECRETS) {
        expect(text, `leaked: ${secret}`).not.toContain(secret);
      }
    },
  );
});
