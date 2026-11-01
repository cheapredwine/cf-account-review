/**
 * Mode B single binary (src/bin/collect.ts, compiled with Bun).
 *
 * 1. In-process: main() against the fake API must produce the same collection
 *    as Mode A (same code; only `collector` differs) and leak nothing planted.
 * 2. Compiled: when Bun is available, build the host binary and check that it
 *    starts with no runtime installed beyond itself (--version, refusal paths).
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/bin/collect.js";
import { collect } from "../src/collect.js";
import { collectionSchema } from "../src/schema.js";

const ROOT = new URL("..", import.meta.url).pathname;
const api = JSON.parse(readFileSync(join(ROOT, "tests", "fixtures", "fake-api.json"), "utf8")) as Record<
  string,
  { status: number; body: unknown }
>;

function stubFetch(apiMap: Record<string, { status: number; body: unknown }> = api): void {
  vi.stubGlobal("fetch", async (input: URL | string) => {
    const path = new URL(String(input)).pathname.replace("/client/v4", "");
    const entry = apiMap[path] ?? { status: 404, body: { success: false, errors: [{ message: "not found" }] } };
    return new Response(JSON.stringify(entry.body), { status: entry.status, headers: { "content-type": "application/json" } });
  });
}

function strip(c: Record<string, unknown>): Record<string, unknown> {
  const { collectedAt: _a, collector: _b, ...rest } = c;
  return rest;
}

describe("single-binary collector entry", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("writes the same collection as Mode A, marked collector=binary, with no planted secrets", async () => {
    stubFetch();
    const expected = JSON.parse(JSON.stringify(await collect("t"))) as Record<string, unknown>;
    vi.stubEnv("CF_API_TOKEN", "fake-token-for-tests");
    const out = mkdtempSync(join(tmpdir(), "cfar-bin-"));
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    expect(await main([out])).toBe(0);
    const file = readdirSync(out).find((f) => /^cloudflare-config-\d{4}-\d{2}-\d{2}-\d{4}\.json$/.test(f));
    expect(file).toBeDefined();
    const text = readFileSync(join(out, file as string), "utf8");
    const written = collectionSchema.parse(JSON.parse(text));
    expect(written.collector).toBe("binary");
    expect(strip(JSON.parse(text) as Record<string, unknown>)).toEqual(strip(expected));
    for (const s of ["fake-token-for-tests", "198.51.100.7", "Basic c2VjcmV0", "bob@example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]) {
      expect(text).not.toContain(s);
    }
  });

  it("writes nothing and exits 3 when nothing is readable", async () => {
    stubFetch({});
    vi.stubEnv("CF_API_TOKEN", "bad");
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const out = mkdtempSync(join(tmpdir(), "cfar-bin-empty-"));
    expect(await main([out])).toBe(3);
    expect(readdirSync(out)).toEqual([]);
  });

  it("rejects unknown options", async () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    expect(await main(["--include-dns"])).toBe(2);
  });
});

const bun = join(ROOT, "node_modules", ".bin", "bun");
const hasBun = spawnSync(bun, ["--version"]).status === 0;

describe.runIf(hasBun)("compiled binary (host target)", () => {
  it("builds and runs standalone", () => {
    const outfile = join(mkdtempSync(join(tmpdir(), "cfar-bin-build-")), "cf-account-review-collect");
    const build = spawnSync(bun, ["build", join(ROOT, "src", "bin", "collect.ts"), "--compile", "--outfile", outfile], { encoding: "utf8" });
    expect(build.status, build.stderr).toBe(0);
    // Empty PATH: the binary must not need node, bun, python or curl.
    const env = { PATH: "", HOME: tmpdir() };
    const version = spawnSync(outfile, ["--version"], { env, encoding: "utf8" });
    expect(version.status).toBe(0);
    expect(version.stdout).toMatch(/^\d+\.\d+\.\d+ \(schema 1\.\d+\)/);
    const noToken = spawnSync(outfile, [], { env, encoding: "utf8", input: "" });
    expect(noToken.status).toBe(2);
    expect(noToken.stderr).toContain("CF_API_TOKEN is not set");
  }, 120_000);
});
