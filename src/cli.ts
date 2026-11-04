#!/usr/bin/env node
/**
 * cf-account-review CLI.
 *
 *   collect  — Mode A: live read-only collection with an API token
 *   analyze  — evaluate a collected JSON file against the findings rulebook
 *
 * The CLI never prints or stores the token. Output files are secret-scanned
 * before they are finalized; a fail-severity scan hit aborts the write.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { parse } from "yaml";
import { evaluate, filterChecksByDomains } from "./analyzer/engine.js";
import { renderMarkdown } from "./analyzer/report.js";
import { collect } from "./collect.js";
import { redactOpaqueStrings, scanForSecrets } from "./redact.js";
import { SCHEMA_VERSION, collectionSchema, type Collection } from "./schema.js";
import type { Check } from "./analyzer/engine.js";

function usage(): never {
  console.error(`Usage:
  cf-account-review collect  [--out output/collection.json]
  cf-account-review analyze  <collection.json> [--checks findings/checks.yaml] [--out output/report.md] [--fail-on <severity>] [--domains <list>]

Environment: CF_API_TOKEN for \`collect\`.

Flags:
  --fail-on <severity>    Exit 1 if findings at or above this severity exist (high|medium|low). Default: no exit code enforcement.
  --domains <list>        Comma-separated domain names to scope the report (see findings/checks.yaml). Default: all checks.
`);
  process.exit(2);
}

function parseArgs(argv: string[]): Map<string, string> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? "";
    if (a === "--out") {
      args.set("out", argv[++i] ?? "");
    } else if (a === "--checks") {
      args.set("checks", argv[++i] ?? "");
    } else if (a === "--fail-on") {
      args.set("fail-on", argv[++i] ?? "");
    } else if (a === "--domains") {
      args.set("domains", argv[++i] ?? "");
    } else if (a.startsWith("--")) {
      console.error(`unknown flag: ${a}`);
      usage();
    } else {
      args.set("positional", a);
    }
  }
  return args;
}

function writeJsonGuarded(path: string, data: unknown): void {
  // Opaque strings (64+ token-class chars) are redacted before serialization
  // and before the pre-write scan (docs/data-policy.md).
  const text = redactOpaqueStrings(JSON.stringify(data, null, 2));
  const hits = scanForSecrets(text).filter((h) => h.severity === "fail");
  if (hits.length > 0) {
    console.error(
      `ABORTING: pre-write secret scan found ${hits.length} fail-severity pattern(s). ` +
        `Nothing was written. Inspect the collector redaction and re-run.`,
    );
    process.exit(1);
  }
  writeFileSync(path, text, { mode: 0o600 });
  console.log(`written: ${path}`);
}

async function cmdCollect(outArg: string | undefined): Promise<void> {
  const token = process.env.CF_API_TOKEN;
  if (!token || token.trim() === "") {
    console.error("CF_API_TOKEN is not set. Export a read-only token first.");
    process.exit(2);
  }
  console.log("Verifying token and collecting configuration (GET requests only)…");
  const collection = await collect(token);
  const out = resolve(outArg ?? "output/collection.json");
  writeJsonGuarded(out, collection);
  console.log(
    `zones: ${collection.zones.length}; errors: ${collection.collectionErrors.length} ` +
      `(scope gaps are expected with narrowly-scoped tokens)`,
  );
}

function cmdAnalyze(positional: string | undefined, outArg: string | undefined, checksArg: string | undefined, failOnArg: string | undefined, domainsArg: string | undefined): void {
  if (!positional) usage();
  const collectionPath = resolve(positional);
  const raw = JSON.parse(readFileSync(collectionPath, "utf8")) as unknown;
  const parsed = collectionSchema.safeParse(raw);
  if (!parsed.success) {
    console.error(`collection file does not match schema ${SCHEMA_VERSION}:`);
    console.error(parsed.error.message);
    process.exit(1);
  }
  const collection: Collection = parsed.data;
  const checksPath = resolve(checksArg ?? "findings/checks.yaml");
  const doc = parse(readFileSync(checksPath, "utf8")) as { checks?: Check[] };
  const checks = doc.checks ?? [];
  if (checks.length === 0) {
    console.error(`no checks found in ${checksPath}`);
    process.exit(1);
  }
  let scopedChecks = checks;
  if (domainsArg !== undefined) {
    const domains = domainsArg.split(",").map((d) => d.trim()).filter((d) => d.length > 0);
    const known = new Set(checks.map((c) => c.domain));
    const unknown = domains.filter((d) => !known.has(d));
    if (unknown.length > 0) {
      console.error(`unknown domain(s): ${unknown.join(", ")} — known: ${[...known].sort().join(", ")}`);
      process.exit(2);
    }
    scopedChecks = filterChecksByDomains(checks, domains);
    console.log(`domain scope: ${scopedChecks.length}/${checks.length} checks (${domains.join(", ")})`);
  }
  const findings = evaluate(collection, scopedChecks);
  const report = renderMarkdown(collection, findings);
  const out = resolve(outArg ?? "output/report.md");
  writeFileSync(out, report, { mode: 0o600 });
  console.log(`report: ${out}`);
  const fail = findings.filter((f) => f.verdict === "fail").length;
  const warn = findings.filter((f) => f.verdict === "warn").length;
  console.log(`findings: ${fail} fail, ${warn} warn`);
  
  // Exit code enforcement
  if (failOnArg) {
    const severityOrder = { high: 3, medium: 2, low: 1 };
    const threshold = severityOrder[failOnArg as keyof typeof severityOrder];
    if (!threshold) {
      console.error(`invalid --fail-on value: ${failOnArg} (must be high, medium, or low)`);
      process.exit(2);
    }
    const blocking = findings.filter((f) => {
      if (f.verdict !== "fail") return false;
      const checkSeverity = severityOrder[f.check.severity];
      return checkSeverity >= threshold;
    });
    if (blocking.length > 0) {
      console.error(`${blocking.length} fail finding(s) at or above ${failOnArg} severity — exiting 1`);
      process.exit(1);
    }
  }
}

const [command, ...rest] = process.argv.slice(2);
if (command === "collect") {
  await cmdCollect(parseArgs(rest).get("out"));
} else if (command === "analyze") {
  const args = parseArgs(rest);
  cmdAnalyze(args.get("positional"), args.get("out"), args.get("checks"), args.get("fail-on"), args.get("domains"));
} else {
  usage();
}
