# Data policy

## The read-only guarantee (non-negotiable)

1. **No write path exists.** The TS client implements `GET` only. There is no
   `post`, `put`, `patch`, or `delete` anywhere in `src/`. The PowerShell and
   bash collectors call the API exclusively through GET-only wrappers
   (`Invoke-RestMethod -Method Get`, `curl -X GET`).
2. **Tests enforce it.** `tests/read-only.test.ts` fails the build if any
   source file declares a mutating HTTP method, if any `curl` is invoked without
   `-X GET`, or if any `Invoke-RestMethod` uses a non-GET method.
3. **One host only.** All API traffic goes to `https://api.cloudflare.com/client/v4`,
   pinned by constants and verified by a test. No telemetry, no uploads, no
   third-party calls of any kind.

## Token handling

- The token is read from `CF_API_TOKEN` (or a no-echo prompt in the shell
  collectors). It is never echoed, logged, or written to the output file.
- `GET /user/tokens/verify` is the only token-related call; it returns a status
  string (`active`), never token material.
- Pre-write secret scan: before any output file is finalized, the serialized
  JSON is scanned for `Bearer …`, long opaque strings, and credential-shaped
  assignments. Fail-severity hits abort the write — nothing is written.

## Redaction rules (applied at collection time, in every collector)

| Data | Treatment |
| --- | --- |
| DNS record contents (origin IPs / CNAME targets) | `[redacted]` by default |
| Account IDs, zone IDs, rule IDs | SHA-256 hash, first 16 hex chars (`h…`) |
| Rule expressions | IPs, email addresses, and internal hostname patterns redacted; zone's own hostname kept |
| Rule bodies (action parameters) | Collected for rule-shape checks (e.g. response-header transform audit). Header **names** and operations are kept; header **values** set by a rule are redacted to `[redacted]` at collection time in every collector. |
| Account member identities | Never exported — role names + 2FA booleans only |
| API/service token inventory | Status, expiry, last-used, permission-group names only (values never exist in list responses) |
| Worker bindings | Names and types only; values never exported |
| Access policy identities | Reduced to decision values (allow/bypass); no email/identity expressions |
| Access service tokens | Metadata only |
| Opaque strings: whitespace-free runs of 64+ token-class characters | `[redacted]:opaque-<len>` at serialization time, in every collector — before the pre-write scan. Legitimate posture data never contains such strings; this covers leaked credentials and long generated artifact names. |
| Request logs, analytics, payloads | Never requested at all |

Re-inclusion flags (explicit, per-field, and only where the operator is
authorized to see the data) are supported in Mode A:

- `--include-dns-content` — Do not redact DNS record content (origin IPs, CNAME targets)
- `--include-ids` — Do not hash account/zone/resource IDs

**These flags are for internal SE/CSM use only.** Output with re-inclusion flags
active contains sensitive infrastructure identifiers and MUST NOT be shared with
customers or stored in shared locations.

Mode B collectors (bash, PowerShell) redact unconditionally — no re-inclusion
flags exist for customer-run collectors.

## Analyzer contract

- The analyzer accepts only documents matching `schemaVersion: 1.0` (zod-validated).
- Verdict semantics: `pass | warn | fail | manual | na`.
  **Incomplete or unreadable evidence can never pass** — scope gaps produce
  `manual`, out-of-plan checks produce `na`.
- Every report carries a "Data we did NOT record" appendix.
