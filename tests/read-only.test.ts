/**
 * Read-only guarantee tests.
 *
 * These fail the build if any code path in src/ or collectors/ could issue a
 * mutating HTTP request or contact a host other than api.cloudflare.com.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = new URL("..", import.meta.url).pathname;

function walk(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
      out.push(...walk(full, exts));
    } else if (exts.some((e) => entry.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

const TS_FILES = walk(join(ROOT, "src"), [".ts"]);
const SH_FILES = [join(ROOT, "collectors", "sh", "collect-config.sh")];

const MUTATING_HTTP = /(method:\s*["'](?:POST|PUT|PATCH|DELETE)["']|fetch\(\s*[^,)]+,\s*\{?\s*method:\s*["'](POST|PUT|PATCH|DELETE))/i;

describe("read-only enforcement", () => {
  it("TypeScript sources never declare a mutating HTTP method", () => {
    for (const file of TS_FILES) {
      const text = readFileSync(file, "utf8");
      expect(MUTATING_HTTP.test(text), `${file} contains a mutating HTTP method`).toBe(false);
    }
  });

  it("bash collector only invokes curl with -X GET", () => {
    for (const file of SH_FILES) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        const code = line.replace(/#.*$/, ""); // strip comments
        if (code.includes("curl")) {
          expect(code.includes("-X GET"), `${file}:${i + 1} curl without -X GET: ${line.trim()}`).toBe(true);
        }
      });
    }
  });


  it("TS sources only contact api.cloudflare.com", () => {
    const URL_PATTERN = /https?:\/\/[a-zA-Z0-9.-]+/g;
    for (const file of TS_FILES) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(URL_PATTERN)) {
        const url = match[0];
        if (url.startsWith("https://developers.cloudflare.com")) continue; // citations
        expect(url, `${file} contacts unexpected host ${url}`).toMatch(
          /^https:\/\/api\.cloudflare\.com/,
        );
      }
    }
  });

  it("bash collector only contacts api.cloudflare.com", () => {
    for (const file of SH_FILES) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/https?:\/\/[a-zA-Z0-9.-]+/g)) {
        expect(match[0], `${file} contacts unexpected host`).toBe("https://api.cloudflare.com");
      }
    }
  });
});
