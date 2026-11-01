/**
 * Mode B single-binary collector (compiled with `bun build --compile`).
 *
 * Same collector, redaction and secret scan as Mode A (src/collect.ts,
 * src/summarize.ts, src/redact.ts) — one implementation for every mode. The
 * token is read from CF_API_TOKEN or a no-echo prompt, used only in memory,
 * and never written. Output: cloudflare-config-YYYY-MM-DD-HHMM.json (0600).
 *
 * READ ONLY: this entry adds no HTTP calls of its own; all requests go through
 * CfGetClient (GET-only, api.cloudflare.com only).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { collect, COLLECTOR_VERSION } from "../collect.js";
import { scanForSecrets } from "../redact.js";
import { SCHEMA_VERSION } from "../schema.js";

const HELP = `cf-account-review-collect ${COLLECTOR_VERSION} (schema ${SCHEMA_VERSION})

Read-only Cloudflare configuration collector. Writes a redacted JSON file you
can review and send for analysis. Your API token never leaves this machine.

Usage:
  cf-account-review-collect [output-dir]      default: current directory
  cf-account-review-collect --version | --help

Token: set CF_API_TOKEN, or paste it when prompted (input is hidden).
Required token permissions: see docs/endpoints.md in the repository.
`;

/** Read a line from the terminal without echoing it. */
export async function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    throw new Error("CF_API_TOKEN is not set and no terminal is available to prompt for it");
  }
  process.stdout.write(question);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  return await new Promise<string>((resolvePrompt, reject) => {
    let value = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolvePrompt(value);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("cancelled"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.on("data", onData);
  });
}

function stamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}`;
}

export async function main(argv: string[]): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (argv.includes("--version")) {
    process.stdout.write(`${COLLECTOR_VERSION} (schema ${SCHEMA_VERSION})\n`);
    return 0;
  }
  const unknown = argv.filter((a) => a.startsWith("-"));
  if (unknown.length > 0) {
    process.stderr.write(`unknown option: ${unknown.join(" ")}\n\n${HELP}`);
    return 2;
  }
  const outDir = resolve(argv[0] ?? ".");

  let token = process.env.CF_API_TOKEN?.trim() ?? "";
  if (!token) {
    try {
      token = (await promptHidden("Paste your Cloudflare API token (input hidden): ")).trim();
    } catch (err) {
      process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  if (!token) {
    process.stderr.write("No token supplied.\n");
    return 2;
  }

  process.stdout.write("Collecting configuration (GET requests to api.cloudflare.com only)…\n");
  const collection = await collect(token, "binary");
  token = "";

  if (collection.accounts.length === 0 && collection.zones.length === 0) {
    process.stderr.write(
      "Nothing could be read: the token is invalid or lacks Account/Zone read access, or api.cloudflare.com is unreachable.\n" +
        collection.collectionErrors.slice(0, 5).map((e) => `  ${e.path}: ${e.error}\n`).join("") +
        "No file was written.\n",
    );
    return 3;
  }

  const text = JSON.stringify(collection, null, 2);
  const hits = scanForSecrets(text).filter((h) => h.severity === "fail");
  if (hits.length > 0) {
    process.stderr.write(
      `ABORTING: pre-write secret scan found ${hits.length} credential-shaped pattern(s). Nothing was written.\n`,
    );
    return 1;
  }
  mkdirSync(outDir, { recursive: true });
  const outFile = join(outDir, `cloudflare-config-${stamp(new Date())}.json`);
  writeFileSync(outFile, text, { mode: 0o600 });
  process.stdout.write(
    `Written: ${outFile}\n` +
      `Zones: ${collection.zones.length}; unreadable endpoints: ${collection.collectionErrors.length}\n` +
      `Open the file and check it before sending: no tokens, DNS contents "[redacted]", IDs start with "h".\n`,
  );
  return 0;
}

// Run when executed directly (compiled binary or `node dist/bin/collect.js`), not when imported by tests.
const invokedDirectly =
  typeof process.argv[1] === "string" && /collect(\.js|\.ts)?$|cf-account-review-collect(\.exe)?$/.test(process.argv[1]);
if (invokedDirectly || (process.versions as Record<string, string | undefined>).bun !== undefined && import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}
