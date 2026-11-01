/**
 * Report renderer — customer-facing Markdown with per-finding citations and a
 * "data we did NOT record" appendix.
 */
import type { Collection } from "../schema.js";
import type { Finding, Verdict } from "./engine.js";

const VERDICT_ICON: Record<Verdict, string> = {
  fail: "❌",
  warn: "⚠️",
  pass: "✅",
  manual: "🔍",
  na: "➖",
};

/**
 * Partially obscure 32-hex Cloudflare IDs (account/zone) in error paths:
 * keep the first 8 and last 4 characters, mask the middle with ****.
 * Zone IDs are low-sensitivity (not free-to-publish) but needlessly
 * identify infrastructure, so the middle is elided rather than shown in full.
 */
export function maskIdsInPath(path: string): string {
  return path.replace(/[0-9a-f]{32}/g, (m) => `${m.slice(0, 8)}****${m.slice(-4)}`);
}

/** Controls shown in the per-zone posture matrix, in display order. */
const MATRIX: { id: string; label: string }[] = [
  { id: "CF-ZONE-001", label: "Active" },
  { id: "CF-SSL-001", label: "SSL strict" },
  { id: "CF-SSL-002", label: "TLS ≥1.2" },
  { id: "CF-WAF-001", label: "Managed WAF" },
  { id: "CF-WAF-004", label: "OWASP" },
  { id: "CF-WAF-003", label: "No broad skips" },
  { id: "CF-WAF-006", label: "No allowlist bypass" },
  { id: "CF-RL-001", label: "Login RL" },
  { id: "CF-BOT-003", label: "Bots" },
  { id: "CF-DDOS-001", label: "DDoS" },
  { id: "CF-DNS-004", label: "Origin hidden" },
  { id: "CF-AOP-001", label: "Origin locked" },
];

function postureMatrix(findings: Finding[]): string[] {
  const zones = [...new Set(findings.filter((f) => f.scope !== "account" && f.scope !== "all").map((f) => f.scope))];
  const cols = MATRIX.filter((m) => findings.some((f) => f.check.id === m.id));
  if (zones.length === 0 || cols.length === 0) return [];
  const out: string[] = [];
  out.push("## Web security posture by zone");
  out.push("");
  out.push(`| Zone | ${cols.map((c) => c.label).join(" | ")} |`);
  out.push(`| --- | ${cols.map(() => ":---:").join(" | ")} |`);
  for (const z of zones) {
    const cells = cols.map((c) => {
      const f = findings.find((x) => x.check.id === c.id && x.scope === z);
      return f ? VERDICT_ICON[f.verdict] : " ";
    });
    out.push(`| ${z} | ${cells.join(" | ")} |`);
  }
  out.push("");
  out.push("Legend: ✅ pass · ⚠️ warn · ❌ fail · 🔍 manual review · ➖ not applicable. Details below.");
  out.push("");
  return out;
}

function topIssues(findings: Finding[]): string[] {
  const weight = { high: 3, medium: 2, low: 1 } as const;
  const fails = findings
    .filter((f) => f.verdict === "fail")
    .sort((a, b) => weight[b.check.severity] - weight[a.check.severity] || a.check.id.localeCompare(b.check.id));
  if (fails.length === 0) return [];
  const out = ["## Top issues", ""];
  for (const f of fails.slice(0, 10)) {
    out.push(`- **${f.check.severity.toUpperCase()}** ${f.check.id} (${f.scope}): ${f.check.name} — ${f.detail}`);
  }
  if (fails.length > 10) out.push(`- … ${fails.length - 10} more failures in Findings below`);
  out.push("");
  return out;
}

export function renderMarkdown(collection: Collection, findings: Finding[], opts: { profile?: string } = {}): string {
  const out: string[] = [];

  out.push("# Cloudflare Account Configuration Review");
  out.push("");
  if (opts.profile) out.push(`- **Profile:** ${opts.profile}`);
  out.push(`- **Collected:** ${collection.collectedAt}`);
  out.push(`- **Collector:** ${collection.collector} v${collection.collectorVersion}`);
  out.push(`- **Token status:** ${collection.tokenStatus}`);
  out.push(
    `- **Zones reviewed:** ${collection.zones.length} (plans: ${[...new Set(collection.zones.map((z) => z.plan ?? "unknown"))].join(", ") || "n/a"})`,
  );
  out.push(`- **Schema:** ${collection.schemaVersion}`);
  out.push("");
  out.push(
    "> This report was produced by a strictly read-only tool. It contains configuration",
    "> metadata only — no tokens, credentials, usernames, emails, DNS contents, or logs.",
    "> Fields that could carry sensitive values are recorded as `[redacted]`.",
  );
  out.push("");

  // Summary table
  const counts: Record<Verdict, number> = { fail: 0, warn: 0, pass: 0, manual: 0, na: 0 };
  for (const f of findings) counts[f.verdict] += 1;
  out.push("## Summary");
  out.push("");
  out.push("| Verdict | Count |");
  out.push("| --- | --- |");
  out.push(`| ❌ Fail | ${counts.fail} |`);
  out.push(`| ⚠️ Warn | ${counts.warn} |`);
  out.push(`| 🔍 Needs manual review | ${counts.manual} |`);
  out.push(`| ✅ Pass | ${counts.pass} |`);
  out.push(`| ➖ Not applicable | ${counts.na} |`);
  out.push("");

  out.push(...topIssues(findings));
  out.push(...postureMatrix(findings));

  // Findings sorted worst-first
  const order: Verdict[] = ["fail", "warn", "manual", "na", "pass"];
  const sorted = [...findings].sort(
    (a, b) => order.indexOf(a.verdict) - order.indexOf(b.verdict) || a.check.id.localeCompare(b.check.id),
  );

  out.push("## Findings");
  out.push("");
  let currentCheck = "";
  for (const f of sorted) {
    if (f.check.id !== currentCheck) {
      currentCheck = f.check.id;
      out.push(`### ${f.check.id} — ${f.check.name}`);
      out.push("");
      out.push(`**Domain:** ${f.check.domain} · **Severity:** ${f.check.severity} · **Evidence:** \`${f.check.evidence}\``);
      out.push("");
      out.push(`**Why this check exists:** ${f.check.remediation.trim()}`);
      out.push("");
      out.push(`**Source:** ${f.check.citation}`);
      out.push("");
      out.push("| Scope | Verdict | Detail |");
      out.push("| --- | --- | --- |");
    }
    out.push(`| ${f.scope} | ${VERDICT_ICON[f.verdict]} ${f.verdict} | ${f.detail.replaceAll("|", "\\|")} |`);
    const isLast = sorted[sorted.length - 1] === f;
    if (isLast || sorted[sorted.indexOf(f) + 1]?.check.id !== f.check.id) out.push("");
  }

  // Collection errors
  if (collection.collectionErrors.length > 0) {
    out.push("## Collection errors");
    out.push("");
    out.push(
      "These endpoints could not be read — usually a token-scope gap. Findings backed by",
      "this data are marked `manual`, never `pass`.",
    );
    out.push("");
    out.push("| Path | Status | Error |");
    out.push("| --- | --- | --- |");
    for (const e of collection.collectionErrors.slice(0, 50)) {
      out.push(`| \`${maskIdsInPath(e.path)}\` | ${e.status ?? "-"} | ${e.error.replaceAll("|", "\\|")} |`);
    }
    if (collection.collectionErrors.length > 50) {
      out.push(`| … ${collection.collectionErrors.length - 50} more | | |`);
    }
    out.push("");
  }

  // Data policy appendix
  out.push("## Data we did NOT record");
  out.push("");
  out.push("By design, this review never records:");
  out.push("");
  out.push("- API tokens, keys, or any credentials (the review token itself is never stored)");
  out.push("- Usernames, email addresses, or member identities (role names and 2FA booleans only)");
  out.push("- DNS record contents (origin IPs / CNAME targets) — recorded as `[redacted]`");
  out.push("- Account IDs, zone IDs, rule IDs (hashed) or header/cookie values from rule expressions");
  out.push("- Request logs, traffic analytics, or any request payload data");
  out.push("- Worker script contents or secret binding values (binding names/types only)");
  out.push("- IP Access Rule values (except country/ASN), page rule URL targets, DNS record comments");
  out.push("- Rule action parameters beyond a sanitized summary (no header values, no counting expressions)");
  out.push("");
  out.push("Any occurrence of `[redacted]` in the collection marks a field deliberately withheld.");
  out.push("");

  return out.join("\n");
}
