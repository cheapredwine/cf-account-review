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
      Access+IdP+2FA+token-expiry, DNS (3), Workers (2, phase 2), LB (2),
      AI Gateway (5), Page Shield, Authenticated Origin Pulls (2), DDoS,
      cache, tunnel-Access gap.
- [x] Exit code enforcement (`--fail-on`), phase filter (`--phase`),
      pre-write secret scan + opaque-string redaction in all three collectors.

## Open

- [ ] Mode A: implement `--include-*` explicit re-inclusion flags (DNS content, IDs)
      documented in docs/data-policy.md.
- [ ] HTML report renderer.
- [ ] Add CI-scheduled smoke: analyze a committed fixture collection so rulebook
      regressions fail visibly.
- [ ] Check batch 3: Email Security misconfigurations (hop count, MX hygiene),
      Logpush enabled for security events, cloudflared version check, Security headers
      via Transform Rules, Waiting Room. (Email subset may be pulled forward — see the
      phase plan's open decision.)
- [ ] Diff mode: `--compare-to previous-collection.json --diff-only` for quarterly check-ins
- [ ] Report write path: `cmdAnalyze` writes the report with a bare `writeFileSync`
      (no opaque redaction / secret scan). Analyzing a pre-redaction collection would
      pass raw values into the report. Add the same guarded write as the collect path.
- [ ] Multi-zone batch: `--zones zone1,zone2,zone3` for Enterprise multi-zone customers
- [ ] Compliance framework mapping: add `compliance: []` to checks.yaml, map to SOC 2/PCI DSS
- [ ] Extract JSON Schema from zod for customers who want to validate Mode B files
      before sending them back.
- [ ] Binary distribution completion: `build:binary` script (esbuild bundle →
      official nodejs.org binary + SEA embed → ad-hoc codesign), Linux build in CI
      with artifact upload; distro Node builds have SEA disabled so the embed must
      use an official build.
- [ ] PowerShell collector: PSScriptAnalyzer pass + test with PowerShell 5.1.
- [ ] Upstream-friendly: consider contributing the zone-setting check shapes back to
      FlareGuard (or citing cross-links in its README).
