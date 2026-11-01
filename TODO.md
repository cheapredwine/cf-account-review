# TODO — cf-account-review

- [ ] End-to-end dogfood: run `collect-config.sh` (bash) and the TS Mode A collector
      against the personal test account; run `analyze` on the real output and eyeball
      the report. The SRP account (read token pending) is the first real customer run.
- [ ] Mode A: implement `--include-*` explicit re-inclusion flags (DNS content, IDs)
      documented in docs/data-policy.md.
- [ ] HTML report renderer.
- [ ] Add CI-scheduled smoke: analyze a committed fixture collection so rulebook
      regressions fail visibly.
- [ ] Check batch 2 (from plan): Page Shield, Logpush, Authenticated Origin Pulls,
      certificate expiry, session duration, challenge passage sizing.
- [ ] Extract JSON Schema from zod for customers who want to validate Mode B files
      before sending them back.
- [ ] PowerShell collector: PSScriptAnalyzer pass + test with PowerShell 5.1.
- [ ] Upstream-friendly: consider contributing the zone-setting check shapes back to
      FlareGuard (or citing cross-links in its README).
