import { describe, expect, it } from "vitest";
import {
  hashId,
  redactDnsContent,
  redactEmails,
  redactExpression,
  scanForSecrets,
} from "../src/redact.js";

describe("redaction", () => {
  it("hashes IDs deterministically and prefixes them", () => {
    const a = hashId("some-account-id");
    expect(a).toBe(hashId("some-account-id"));
    expect(a.startsWith("h")).toBe(true);
    expect(a).toHaveLength(17);
    expect(a).not.toContain("some-account-id");
  });

  it("redacts DNS record content unconditionally", () => {
    expect(redactDnsContent("203.0.113.5")).toBe("[redacted]");
    expect(redactDnsContent("origin.example.com")).toBe("[redacted]");
    expect(redactDnsContent(undefined)).toBeUndefined();
  });

  it("redacts IPs, emails, and internal hostnames in expressions", () => {
    const expr = 'ip.src eq 203.0.113.5 and http.host eq "app.internal" and any(bob@example.com)';
    const out = redactExpression(expr) ?? "";
    expect(out).not.toContain("203.0.113.5");
    expect(out).not.toContain("app.internal");
    expect(out).not.toContain("bob@example.com");
    expect(out).toContain("http.host");
  });

  it("keeps expressions otherwise readable", () => {
    expect(redactExpression("http.request.uri.path eq \"/login\"")).toBe(
      'http.request.uri.path eq "/login"',
    );
  });

  it("redacts emails in plain text", () => {
    expect(redactEmails("contact admin@corp.example now")).toBe("contact [redacted] now");
  });

  it("secret scan flags Bearer tokens as fail", () => {
    const hits = scanForSecrets('{"Authorization": "Bearer abc.def-ghi"}');
    expect(hits.some((h) => h.severity === "fail")).toBe(true);
  });

  it("secret scan flags kv-style assignments of secrets", () => {
    const hits = scanForSecrets("api_key: aaaabbbbccccddddeeeeffff00001111");
    expect(hits.some((h) => h.severity === "fail")).toBe(true);
  });

  it("clean config text does not produce fail hits", () => {
    const text = JSON.stringify({
      schemaVersion: "1.0",
      settings: { id: "ssl", value: "strict" },
      rules: [{ action: "block", expression: 'http.request.uri.path eq "/login"' }],
    });
    const failHits = scanForSecrets(text).filter((h) => h.severity === "fail");
    expect(failHits).toHaveLength(0);
  });
});
