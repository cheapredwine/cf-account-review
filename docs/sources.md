# Sources

Every finding in a generated report carries the citation that justifies its
check. This file lists the full source set and what was borrowed from each.

## External (primary, cited in findings)

- WAF managed rulesets — <https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/>,
  WAF get-started <https://developers.cloudflare.com/waf/get-started/>,
  exceptions and execution order <https://developers.cloudflare.com/waf/managed-rules/>,
  <https://developers.cloudflare.com/waf/managed-rules/waf-exceptions/>
- Custom rules — <https://developers.cloudflare.com/waf/custom-rules/>
- Rate limiting rules, best practices, parameters —
  <https://developers.cloudflare.com/waf/rate-limiting-rules/>,
  <https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/>,
  <https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/>
  (the legacy rate-limiting product and its docs were retired with check
  CF-RL-002 on 2026-11-03 — endpoint returns 410 Gone)
- Bot management and bot score — <https://developers.cloudflare.com/bots/>,
  <https://developers.cloudflare.com/bots/concepts/bot-score/>
- SSL/TLS — encryption modes <https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/>,
  minimum TLS <https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/>,
  HSTS <https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/>,
  Always Use HTTPS <https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/>,
  compliance baseline <https://developers.cloudflare.com/ssl/reference/compliance-and-vulnerabilities/>,
  API hardening use case <https://developers.cloudflare.com/use-cases/solutions/discover-secure-api-endpoints/>
- DNS — DNSSEC <https://developers.cloudflare.com/dns/dnssec/>,
  record types (CAA, MX/SPF) <https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/>
- Workers — routes <https://developers.cloudflare.com/workers/configuration/routes/>
- Turnstile — <https://developers.cloudflare.com/turnstile/>
- Zero Trust Access — applications <https://developers.cloudflare.com/cloudflare-one/applications/>,
  policies <https://developers.cloudflare.com/cloudflare-one/policies/access/>,
  IdPs <https://developers.cloudflare.com/cloudflare-one/identity-providers/>
- Account security / MFA — <https://developers.cloudflare.com/fundamentals/account/account-security/>

## Prior art (borrowed, attributed)

- **FlareGuard** — <https://github.com/harshadk99/flareguard> (MIT). The
  zone-setting check shapes (`expect` / `expect_one_of` / nested expectations)
  and the concept of a declarative, editable-baseline rulebook are modeled on
  its `baseline.yaml`. See `NOTICE`.
- **cloudflare-sec-inspector** (grclanker, spec-only) — the verdict semantics
  (pass/warn/fail/manual/na; unreadable evidence can never pass; truncation and
  scope-gap tracking) follow its design notes.
- **Cloudflare `security-audit-skill`** — machine-readable findings with
  independent verification; influenced the fail-closed report posture.

## Internal (guidance; no internal coupling in this repo)

Cloudflare-internal guidance informed the check design. These are referenced
as named prior art only — no internal endpoints, identifiers, or non-public
material appear in this repository:

- Internal wiki: Bot Management best-practices guidance (tiered verified/definite/
  likely-bot rules; the `not cf.bot_management.verified_bot` exclusion on
  definite-bot blocks; score 1–30 challenge band; JS detections are zone-level
  and require accompanying custom rules to take action).
- Internal Professional Services WAF/rate-limiting/bot-management guidance:
  deploy managed rulesets by default; start new rules in log mode, promote to
  block after validation; keep separate onboarding vs enforcement rulesets;
  a monitoring/log rule last for unmatched-traffic visibility; challenge
  passage sized to exceed ~95% of user sessions.
- Internal "config export → policy evaluation → report" health-check tooling
  (Conftest/Rego based). This project borrows the architecture but keeps
  evaluation in TypeScript so customers need no Rego runtime.
