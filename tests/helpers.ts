import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { collectionSchema, type Collection } from "../src/schema.js";
import type { Check } from "../src/analyzer/engine.js";

const ROOT = new URL("..", import.meta.url).pathname;

export function baseCollection(): Collection {
  return collectionSchema.parse({
    schemaVersion: "1.0",
    collectedAt: new Date().toISOString(),
    collector: "api",
    collectorVersion: "0.1.0",
    tokenStatus: "active",
    accounts: [],
    zones: [],
    collectionErrors: [],
  });
}

export function zoneWith(overrides: Record<string, unknown>): Collection["zones"][number] {
  return {
    name: "example.com",
    plan: "Enterprise",
    status: "active",
    paused: false,
    type: "full",
    createdOn: new Date().toISOString(),
    ...overrides,
  } as Collection["zones"][number];
}

export function loadChecks(): Check[] {
  const doc = parse(readFileSync(join(ROOT, "findings", "checks.yaml"), "utf8")) as {
    checks: Check[];
  };
  return doc.checks;
}
