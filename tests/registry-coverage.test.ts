/**
 * Registry coverage: every API path used by the Mode A collector must exist in
 * the documented endpoint registry (src/endpoints.ts). This keeps
 * docs/endpoints.md — the "why each query exists" contract — from drifting
 * away from what the code actually requests.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ENDPOINTS, PHASES } from "../src/endpoints.js";

const ROOT = new URL("..", import.meta.url).pathname;

describe("endpoint registry coverage", () => {
  it("Mode A collector only requests registered paths", () => {
    const collectSrc = readFileSync(join(ROOT, "src", "collect.ts"), "utf8");
    const used = new Set<string>();
    for (const match of collectSrc.matchAll(/client\.(?:list|get)\(\s*[`"]([^`"]+)[`"]/g)) {
      used.add(match[1] ?? "");
    }
    expect(used.size, "collector should request several endpoints").toBeGreaterThan(10);

    const registered = new Set<string>(ENDPOINTS.map((e) => e.path));
    // phase entrypoints are part of the registry semantics via PHASES
    for (const phase of PHASES) {
      registered.add(`/zones/{zone_id}/rulesets/phases/${phase}/entrypoint`);
    }
    // token verification is a sanctioned status-only call
    registered.add("/user/tokens/verify");

    for (const path of used) {
      const normalized = path
        .replace("${accountId}", "{account_id}")
        .replace("${zoneId}", "{zone_id}")
        .replace("${tunnelId}", "{tunnel_id}")
        .replace("${phase}", "{phase}");
      const template = normalized
        .replace(/\$\{[^}]+\}/g, "{param}")
        .replace(/\{phase\}/, "{phase}");
      // match against registry entries with placeholders normalized
      const candidates = [...registered].map((p) =>
        p
          .replace("{account_id}", "\\{[^}]+\\}")
          .replace("{zone_id}", "\\{[^}]+\\}")
          .replace("{tunnel_id}", "\\{[^}]+\\}")
          .replace("{phase}", "\\{[^}]+\\}"),
      );
      const ok = candidates.some((c) => new RegExp(`^${c}$`).test(template));
      expect(ok, `collector path not in registry: ${path}`).toBe(true);
    }
  });
});
