/**
 * Test --include-dns-content and --include-ids re-inclusion flags.
 */
import { describe, expect, test } from "vitest";
import { hashId, redactDnsContent } from "../src/redact.js";

describe("re-inclusion flags", () => {
  test("hashId preserves value when include=true", () => {
    const id = "abc123def456";
    expect(hashId(id, false)).toMatch(/^h[0-9a-f]{16}$/);
    expect(hashId(id, true)).toBe(id);
  });

  test("redactDnsContent preserves value when include=true", () => {
    const content = "192.0.2.1";
    expect(redactDnsContent(content, false)).toBe("[redacted]");
    expect(redactDnsContent(content, true)).toBe(content);
  });

  test("redactDnsContent handles null/undefined correctly", () => {
    expect(redactDnsContent(null, false)).toBeUndefined();
    expect(redactDnsContent(undefined, false)).toBeUndefined();
    expect(redactDnsContent(null, true)).toBeUndefined();
    expect(redactDnsContent(undefined, true)).toBeUndefined();
  });
});
