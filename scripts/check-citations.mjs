#!/usr/bin/env node
// Dev/CI tooling only — NOT part of the collector. Verifies that every
// citation URL in the rulebook and endpoint registry resolves (HTTP < 400),
// so "every finding cites the doc that justifies it" stays true as docs move.
// Contacts developers.cloudflare.com only.
import { readFileSync } from "node:fs";

const files = ["findings/checks.yaml", "src/endpoints.ts"];
const urls = new Set();
for (const f of files) {
  for (const m of readFileSync(f, "utf8").matchAll(/https:\/\/developers\.cloudflare\.com[^\s"'`)>]*/g)) urls.add(m[0]);
}
let bad = 0;
for (const url of [...urls].sort()) {
  let status = 0;
  try {
    const res = await fetch(url, { method: "GET", redirect: "follow" });
    status = res.status;
  } catch (e) {
    status = -1;
  }
  const ok = status > 0 && status < 400;
  if (!ok) bad++;
  console.log(`${ok ? "ok  " : "FAIL"} ${status} ${url}`);
}
console.log(`${urls.size} citation URL(s), ${bad} broken`);
process.exit(bad > 0 ? 1 : 0);
