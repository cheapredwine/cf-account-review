# TODO — cf-account-review

## Phase plan (2026-11-03, per customer scoping)

- **Phase 1 — web performance + security + AI controls** (default): all
  current checks except the two Workers ones; 31 checks as of the
  phase-filter merge (b7d62a8). `analyze --phase 1` filters reports.
- **Phase 2 — Developer Platform (Workers)**: CF-WRK-001/002 (`phase: 2`
  in the rulebook). Deferral matches the first customer's purchases.
- **Out of product scope: Cloudforce One** — zero checks, zero endpoints.
- **OPEN (user decision):** the first customer is an Area 1 (email
  security) subscriber; phase 1 as scoped has no email checks (batch 3:
  hop count, MX hygiene — CF-DNS-003 partially covers). Pull batch-3
  email checks forward into phase 1 for this account?

- [x] End-to-end dogfood: run `collect-config.sh` (bash) and the TS Mode A collector
      against the personal test account; run `analyze` on the real output and eyeball
      the report. **DONE 2026-11-01** against JSherron Test Account (5 Enterprise zones,
      wrangler OAuth token). Three bugs found and fixed in the same pass:
      1. `collect-config.sh` crashed on tunnels whose `configurations` payload has
         `config: null` (`.get("config", {})` returns None when the key exists with a
         null value) → now `(config.get("config") or {})`.
      2. `collect-config.sh` emitted `null` for `pageShield`/`authenticatedOriginPulls`
         on scope gaps → zod validation failed; now always emits the object, mirroring
         the TS collector's `asRecord()` behavior (unknown fields omitted, not null).
      3. `collect-config.sh` zone loop split on tab but the producer emitted a space, so
         `zone_id` was "id name" and every zone-level fetch failed (`HTTP 000`) →
         producer now tab-separated.
      Also: report's collection-errors table now partially masks 32-hex IDs
      (`3979b75a****f205`, user-approved style) via `maskIdsInPath` — Mode B's raw zone
      IDs in error paths are fixed by bug #3. Mode A/Mode B verdict parity confirmed
      identical (0 fail / 7 warn / 70 manual / 13 pass / 25 n/a). Remaining notes:
      OAuth-token runs report `verification-failed` (mode A verifies via
      `/user/tokens/verify`, which rejects OAuth tokens) — cosmetic; and dogfooding with
      the wrangler OAuth token leaves ~120 scope-gap errors (expected); real customer
      runs should use the scoped read-only token from docs/endpoints.md — and
      per AGENTS.md rule 5 (added 2026-11-01) future runs must STOP and ask the
      user for a scope-sufficient token rather than running with partial scope.
      The SRP account (read token pending) is the first real customer run.
- [x] Full-scope token dogfood — DONE 2026-11-03 with the `cf-account-review-readonly`
      token (26 read permissions minted via the API from a bootstrap token; scope-gate
      probe passed 24/26, residuals plan-tier). Four defects found and fixed in PR #4:
      account-settings 404 (bare /accounts/{id}), two 410-dead legacy endpoints removed
      (waf/overrides, rate_limits + vacuous-pass CF-RL-002), opaque-string redaction
      (96-char generated ruleset name tripped the pre-write scan; reproduced as a test),
      and docs/CLIENT-GUIDE drift corrected from the live permission-group registry.
      Full-token verdicts (per the report's own summary):
      17 fail / 20 warn / 22 pass / 26 manual / 25 n/a vs the OAuth
      baseline 0/7/13/70/25 — the narrow token's 70 manuals masked 17 real fails.
      Mode B (bash + pwsh) rerun clean with the fixes; pwsh writes repo-root by
      default (default $OutputDir) and 0644 perms (fixed to chmod 600 in the same
      session); collections moved to output/.
- [x] Certificate expiry check (CF-SSL-005) — DONE
- [x] Load balancer health checks (CF-LB-001, CF-LB-002) — DONE
- [x] Exit code enforcement (--fail-on flag) — DONE
- [ ] Mode A: implement `--include-*` explicit re-inclusion flags (DNS content, IDs)
      documented in docs/data-policy.md.
- [ ] HTML report renderer.
- [ ] Add CI-scheduled smoke: analyze a committed fixture collection so rulebook
      regressions fail visibly.
- [x] AI Gateway security checks (CF-AIG-001 through CF-AIG-005) — DONE
- [x] Check batch 2: Page Shield, Authenticated Origin Pulls (2 checks), DDoS, Cache, Tunnel-Access gap — DONE
- [ ] Check batch 3 (deferred after dogfood): Email Security misconfigurations (hop count, MX hygiene),
      Logpush enabled for security events, cloudflared version check, Security headers via Transform Rules,
      Waiting Room.
- [ ] Diff mode: `--compare-to previous-collection.json --diff-only` for quarterly check-ins
- [ ] Report write path: `cmdAnalyze` writes the report with a bare `writeFileSync`
      (no opaque redaction / secret scan). Analyzing a pre-redaction collection would
      pass raw values into the report. Add the same guarded write as the collect path.
      (Found in the 2026-11-03 evaluator pass; pre-existing, deferred.)
- [ ] Multi-zone batch: `--zones zone1,zone2,zone3` for Enterprise multi-zone customers
- [ ] Compliance framework mapping: add `compliance: []` to checks.yaml, map to SOC 2/PCI DSS
- [ ] Extract JSON Schema from zod for customers who want to validate Mode B files
      before sending them back.
- [ ] PowerShell collector: PSScriptAnalyzer pass + test with PowerShell 5.1.
- [ ] Upstream-friendly: consider contributing the zone-setting check shapes back to
      FlareGuard (or citing cross-links in its README).
