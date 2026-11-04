/**
 * Guarded file writes: opaque strings are redacted and the result is scanned
 * for credential-shaped patterns BEFORE anything touches disk. A fail-severity
 * hit throws — nothing is written (fail-closed, docs/data-policy.md).
 */
import { writeFileSync } from "node:fs";
import { redactOpaqueStrings, scanForSecrets, type SecretScanHit } from "../redact.js";

export function guardedWrite(path: string, text: string): void {
  const redacted = redactOpaqueStrings(text);
  const hits: SecretScanHit[] = scanForSecrets(redacted).filter((h) => h.severity === "fail");
  if (hits.length > 0) {
    throw new Error(
      `pre-write secret scan found ${hits.length} fail-severity pattern(s) — nothing written`,
    );
  }
  writeFileSync(path, redacted, { mode: 0o600 });
}
