# TODO — cf-account-review

## Scope for the first customer run

Chosen by broad category (user, 2026-11-04); scoped at report time via
`analyze --domains <comma,list>` — no build-phase machinery.

- **In (10 categories):** ssl-tls, waf, rate-limiting, bots (incl. Turnstile),
  ddos, dns, cache (web performance), origin-security, ai-gateway,
  account-hygiene (2FA + token expiry). 25 of 33 checks. On the latest
  full collection: 16 fail / 19 warn / 17 pass / 26 manual / 20 n/a.
- **Out (user did not select):** client-side-security (Page Shield),
  traffic (load balancing), workers (Developer Platform),
  zero-trust (Cloudflare One — Access apps, IdPs, tunnel-Access gap).
  The checks remain built; add the domain to `--domains` to include one.


## Done

- [x] Both collection modes (Mode A TypeScript, Mode B bash + PowerShell)
      dogfooded end-to-end against the test account; verdict parity confirmed
      between collectors; collector defects found and fixed in the process.
- [x] Full-scope token run: 17 fail / 20 warn / 22 pass / 26 manual / 25 n/a
      (narrow-token baseline was 0 fail / 70 manual — real findings were
      masked as manual). Verified the scope gate: probes before every run;
      never run with a partial-scope token (AGENTS.md rule 5).
- [x] Checks: SSL/TLS (5), WAF (3), rate limiting, bots (2), Turnstile,
      Access+IdP+2FA+token-expiry, DNS (3), Workers (2), LB (2),
      AI Gateway (5), Page Shield, Authenticated Origin Pulls (2), DDoS,
      cache, tunnel-Access gap, response-header transform audit (CF-HDR-001).
- [x] Exit code enforcement (`--fail-on`), category scope (`--domains`),
      zone scope (`--zones`), diff mode (`--compare-to [--diff-only]`),
      guarded writes on every output (collection AND report),
      pre-write secret scan + opaque-string redaction in all three collectors.
- [x] Standalone binary (Node SEA): mac arm64 builds and smokes locally;
      Linux built + published as a CI artifact. Customer hand-off = one file.
- [x] Committed-fixture rulebook smoke (golden verdicts fail visibly on
      rulebook/evaluator regressions) + collection JSON schema extraction
      (`pnpm schema`, CI-checked against drift).

## Open

- [ ] Windows binary artifact (SEA on a windows runner) + PSScriptAnalyzer/PS 5.1 pass.
- [ ] Redact header **values** set by response/request transform rules (header names
      are collected for CF-HDR-001; a short secret header value set by a rule would
      pass the opaque-string redaction — see docs/data-policy.md rule-bodies row).
- [ ] Mode A: implement `--include-*` explicit re-inclusion flags (DNS content, IDs)
      documented in docs/data-policy.md.
- [ ] HTML report renderer (Markdown is the customer deliverable today).
- [ ] Batch-3 candidates recorded with rationale — deliberately not built:
      email hop-count (message-header data is not collectible via these APIs;
      MX/SPF/DMARC posture already covered by CF-DNS-003), cloudflared version
      (field availability unverified against live tunnel data), Waiting Room
      (weak verdict signal), Logpush (destination-ownership judgment too
      context-dependent for a deterministic rule).
- [ ] Compliance framework mapping: add `compliance: []` to checks.yaml, map to SOC 2/PCI DSS.
- [ ] Upstream-friendly: consider contributing the zone-setting check shapes back to
      FlareGuard (or citing cross-links in its README).
