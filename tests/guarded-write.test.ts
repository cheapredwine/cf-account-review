import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { guardedWrite } from "../src/analyzer/guarded-write.js";

function tmp(): string {
  const dir = join(
    tmpdir(),
    `cfar-guarded-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe("guardedWrite", () => {
  it("writes clean text with owner-only perms", () => {
    const dir = tmp();
    const p = join(dir, "out.md");
    guardedWrite(p, "# report\n\nall clean\n");
    expect(existsSync(p)).toBe(true);
    const mode = statSync(p).mode & 0o777;
    if (process.platform !== "win32") {
      expect(mode).toBe(0o600);
    }
    expect(readFileSync(p, "utf8")).toContain("all clean");
    rmSync(dir, { recursive: true, force: true });
  });

  it("redacts opaque 64+ char runs in the written file", () => {
    const dir = tmp();
    const p = join(dir, "out.md");
    const opaque = "a".repeat(96);
    guardedWrite(p, `value: ${opaque}\n`);
    const text = readFileSync(p, "utf8");
    expect(text).not.toContain(opaque);
    expect(text).toContain("[redacted]:opaque-96");
    rmSync(dir, { recursive: true, force: true });
  });

  it("throws and writes NOTHING on a fail-severity scan hit (fail-closed)", () => {
    const dir = tmp();
    const p = join(dir, "out.md");
    expect(() => guardedWrite(p, 'header: "Bearer abc.def-ghi"\n')).toThrow(
      /secret scan/,
    );
    expect(existsSync(p)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});
