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
| DNS record comments | Never exported (free text: owners, tickets, emails) |
| Account IDs, zone IDs, rule IDs, tunnel IDs | SHA-256 hash, first 16 hex chars (`h…`) — including IDs embedded in `collectionErrors[].path` |
| Rule expressions | IPs, email addresses, and internal hostname patterns redacted; zone's own hostname kept |
| Account member identities | Never exported — role names + 2FA booleans only |
| API/service token inventory | Status, expiry, last-used, permission-group names only (values never exist in list responses) |
| Worker bindings | Names and types only; values never exported |
| Access policy identities | Reduced to decision values (allow/bypass); no email/identity expressions |
| Access service tokens | Metadata only |
| Rule `action_parameters` | Sanitized summary only (`src/summarize.ts`): executed managed ruleset as a canonical key, override shape (enabled/action/sensitivity, counts, disabled category tags, lowest score threshold), skip scope (counts, phase/product names), rate-limit numbers and characteristics, header **names** for transforms, cache eligibility. Never: header values, counting expressions, rule IDs inside overrides |
| IP Access Rules | `mode`, `target`, `scope`; `value` kept only for `country`/`asn` targets, otherwise `[redacted]`; notes dropped |
| Page rules | `status` + action ids; values only for enumerated security/cache settings; URL targets and forwarding URLs dropped |
| Bot management | Allow-listed configuration keys only |
| Load balancer pools / monitors | Origin addresses and notification emails `[redacted]`; monitor `header` (may carry auth) never exported |
| Account settings | Only `enforce_twofactor` (the raw settings object, which includes the abuse contact, is no longer exported) |
| Request logs, analytics, payloads | Never requested at all |

Re-inclusion flags (explicit, per-field, and only where the operator is
authorized to see the data) are supported in Mode A (`--include-*`); Mode B
collectors redact unconditionally.

## How the policy is enforced

`tests/collector-parity.test.ts` plants sensitive values (origin IPs, emails,
an LB monitor `Authorization` header, a header-transform value, raw IDs, page
rule targets, a Turnstile secret) in a fake Cloudflare API, runs the TS, bash
and PowerShell collectors against it, and fails if any planted value appears in
any output — or if the three outputs differ.

## Analyzer contract

- The analyzer accepts any `1.x` collection (zod-validated). `1.1` adds optional
  fields only; `1.0` files still analyze, but checks that need 1.1 evidence report
  `manual`.
- Readability contract (1.1): a list field is **omitted** when its endpoint was
  unreadable and `[]` when read and empty; phase entrypoints carry
  `present | absent | unreadable`.
- Verdict semantics: `pass | warn | fail | manual | na`.
  **Incomplete or unreadable evidence can never pass** — scope gaps produce
  `manual`, out-of-plan checks produce `na`.
- Every report carries a "Data we did NOT record" appendix.
