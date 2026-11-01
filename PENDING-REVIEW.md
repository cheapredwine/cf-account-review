# PENDING-REVIEW — blocked on user action

## Create the `cf-account-review-readonly` API token (2026-11-01)

**What's being decided:** the user will create a read-only Cloudflare API token
in the dashboard tomorrow morning so the dogfood run can complete under the
token scope gate (AGENTS.md rule 5, added 2026-11-01).

**State when paused:**
- Mode A + Mode B dogfood DONE against the personal test account with the
  wrangler OAuth token (partial scope): 3 collector bugs found and fixed in
  PR #1 (merged, `3ae39cf`), ID masking added, verdict parity confirmed.
  That run's report: 0 fail / 7 warn / 70 manual / 13 pass / 25 n/a — the
  70 manual verdicts are scope-gap artifacts, not real findings.
- Token scope gate added and pushed (`0995512`): never run collectors with a
  partial-scope token; stop and ask.
- Full-token run NOT yet done — that is the remaining dogfood step.

**What unblocks it:** user creates the token per the checklist in this
conversation (26 permissions from docs/endpoints.md — 14 account-level
scoped to "JSherron Test Account", 12 zone-level scoped to all zones of that
account; no expiry decision recorded, no IP restriction). Then either paste
the value or drop it in a file path outside git. On pickup:
1. Verify the token covers the scope list (permission-group reconciliation
   against docs/endpoints.md).
2. Run Mode A + Mode B, compare against the OAuth-token baseline report
   (output/dogfood-report.md kept untracked in output/).
3. Reconcile the CLIENT-GUIDE.md token table against the actual permission
   list — flagged 2026-11-01: CLIENT-GUIDE's 6-required+optional table does
   not match the endpoints.md registry; check whether the gap produces
   unexpected `manual` verdicts.
4. Tick off the dogfood item fully in TODO.md (line ~1) once the full-scope
   report is reviewed.

**Update 2026-11-01 (v0.2, branch `web-security-v0.2`):** the collection changed —
new endpoints (`/zones/{id}/managed_headers`, `/zones/{id}/leaked-credential-checks`),
new phases (`ddos_l7`, `http_response_headers_transform`), several endpoints removed.
Build the token from the regenerated docs/endpoints.md, not from the 26-permission
checklist above. Run the v0.2 collectors (Mode A, the single binary, and the bash script) and check
the permission names flagged in docs/EVOLUTION-20261101T2231Z.md §8.

**Delete this file when the token run lands.**
