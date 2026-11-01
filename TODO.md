# TODO — cf-account-review

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
- [ ] Multi-zone batch: `--zones zone1,zone2,zone3` for Enterprise multi-zone customers
- [ ] Compliance framework mapping: add `compliance: []` to checks.yaml, map to SOC 2/PCI DSS
- [ ] Extract JSON Schema from zod for customers who want to validate Mode B files
      before sending them back.
- [ ] PowerShell collector: PSScriptAnalyzer pass + test with PowerShell 5.1.
- [ ] Upstream-friendly: consider contributing the zone-setting check shapes back to
      FlareGuard (or citing cross-links in its README).
