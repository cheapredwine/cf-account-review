# cf-account-review

> ⚠️ **NOT OFFICIAL CLOUDFLARE.** Not affiliated with or endorsed by Cloudflare, Inc.
> NO WARRANTIES, EXPRESS OR IMPLIED. Effectively untested personal code — read everything
> before you run it. You assume all risk. See [DISCLAIMER.md](./DISCLAIMER.md).

A **strictly read-only** Cloudflare account configuration review tool. It collects
configuration through the public Cloudflare API and evaluates it against a YAML
best-practice rulebook (WAF, rate limiting, bot management, SSL/TLS, DNS, Workers,
Turnstile, Access, AI Gateway, Page Shield, Authenticated Origin Pulls, DDoS, Cache,
Zero Trust Tunnels, account hygiene), producing a customer-ready Markdown report where
every finding cites the Cloudflare documentation that justifies it.

## The guarantees

- **READ ONLY — enforced by tests, not convention.** The API layer implements `GET` only;
  the shell collectors call the API only through GET-only wrappers. `tests/read-only.test.ts`
  fails the build if any mutating HTTP method or non-`api.cloudflare.com` host appears.
- **Never records sensitive data.** DNS contents, origin IPs, IDs (hashed), identities
  (emails/names — reduced to role names and booleans), Worker binding values, and token
  material are redacted or never exported. See [docs/data-policy.md](./docs/data-policy.md).
- **Never exfiltrates.** Exactly one outbound host (`api.cloudflare.com/client/v4`), no
  telemetry, and a pre-write secret scan that aborts the output write if anything
  credential-shaped is detected.
- **Fail-closed findings.** A check backed by unreadable evidence reports `manual`, never
  `pass`. Scope-gap'd tokens still produce a useful partial report.

## Two ways to run

### Mode A — live API token

```bash
pnpm install && pnpm build
export CF_API_TOKEN=...   # read-only token; see docs/endpoints.md for the scope list
node dist/cli.js collect --out output/collection.json
node dist/cli.js analyze output/collection.json --out output/report.md

# Exit code enforcement (CI integration)
node dist/cli.js analyze output/collection.json --fail-on high  # Exit 1 if any high-severity fails

# Standalone binary (no Node needed on the customer machine)
pnpm binary      # -> dist/cf-account-review-<os>-<arch>

# Collection JSON schema for customers validating Mode B files
pnpm schema      # -> collection.schema.json

# Diff two collections (quarterly re-reviews)
node dist/cli.js analyze output/collection.json --compare-to output/previous.json --diff-only

# Scope the report to categories (domain names from findings/checks.yaml)
node dist/cli.js analyze output/collection.json --domains "ssl-tls,waf,dns"
```

### Mode B — offline shell collectors (token never leaves the customer)

PowerShell:

```powershell
.\collectors\ps\Collect-CFConfig.ps1            # writes cloudflare-config-*.json
```

Bash (macOS/Linux; curl + python3, no jq needed):

```bash
CF_API_TOKEN=xxx ./collectors/sh/collect-config.sh output/
```

Either file feeds the same analyzer: `node dist/cli.js analyze <file>`.

Token scopes (My Profile > API Tokens, all zones):
**Account Settings: Read**; **Zone: Read, Zone Settings: Read, DNS: Read,
Firewall Services: Read, Zone WAF: Read** (plus optional Workers/Access/Turnstile
read scopes — see `docs/endpoints.md` for the full table). Narrowly-scoped tokens
work: unreadable endpoints are skipped and listed in `collectionErrors`.

## What it checks

The rulebook lives in [`findings/checks.yaml`](./findings/checks.yaml) — 41 checks across
16 domains. Add a check there (and an evaluator if it needs logic beyond a setting
expectation). v1 covers:

- **SSL/TLS:** Full(strict) mode, min TLS ≥ 1.2, HSTS, Always Use HTTPS, certificate expiry
- **WAF:** managed ruleset deployed (not disabled via overrides), custom rules with
  enforcement, broad-skip-rule audit
- **Rate limiting:** login-endpoint protection, legacy rate-limit migration signal
- **Bots:** verified-bot exclusion on definite-bot blocks, zero-enforcement bot rules,
  Turnstile widget inventory
- **DNS:** DNSSEC, CAA records, mail posture
- **Workers:** zombie (unrouted) scripts, dangling routes
- **Load Balancing:** pool failover (multiple origins), monitor intervals
- **AI Gateway:** rate limiting, authentication, logging, DLP policies, guardrails
- **Client-Side Security:** Page Shield enabled
- **Origin Security:** Authenticated Origin Pulls enabled, zone-level cert preferred
- **DDoS:** HTTP DDoS managed rulesets not disabled
- **Cache:** HTML not cached aggressively by default
- **Zero Trust:** Tunnel public routes protected by Access
- **Access & account:** policy-less Access apps, bypass decisions, OTP-only IdPs,
  2FA enforcement, token expiry posture

Verdicts: `pass | warn | fail | manual | na` — **incomplete evidence can never pass.**

## Docs

- **[docs/CLIENT-GUIDE.md](./docs/CLIENT-GUIDE.md)** — comprehensive client-facing guide (send this to clients)
- **[docs/REDACTION-AND-EVALUATION.md](./docs/REDACTION-AND-EVALUATION.md)** — how backend analysis works on redacted data
- [docs/endpoints.md](./docs/endpoints.md) — every GET with its rationale and citation
- [docs/data-policy.md](./docs/data-policy.md) — read-only, redaction, no-exfiltration
- [docs/sources.md](./docs/sources.md) — the best-practice sources behind each check

## Distribution to customers

Two artifacts, one codebase — **never a second implementation of the safety
rules** (the read-only guarantee, redaction, and the output schema each exist
exactly once, in TypeScript, and tests enforce them):

- **Standalone binary** (built with Node's single-executable support, not Go):
  the default hand-off — one file, no Node/python/curl required on the
  customer machine. Platform warnings on first run (Gatekeeper/SmartScreen)
  are expected for unsigned binaries; notarization is a separate project.
  Why not Go: trivial cross-compilation, but it would mean a second parallel
  implementation of the schema/redaction/read-only logic that can silently
  drift from the audited TypeScript — the worst failure mode for a
  security-review tool.
- **Mode B shell collectors**: the auditable alternative — security teams
  that don't run opaque vendor binaries can read the scripts first. Already
  dependency-light (bash+curl+python3 / PowerShell).

Both paths emit the same JSON schema; the analyzer accepts either.

## Development

```bash
pnpm install
pnpm verify      # lint + tests (the done-check)
pnpm build       # tsc -> dist/
```

Node ≥ 24. See [AGENTS.md](./AGENTS.md) for project conventions.

## Attribution

Check shapes and verdict semantics borrow from prior art — see [NOTICE](./NOTICE)
and [docs/sources.md](./docs/sources.md).

## License

MIT — see [LICENSE](./LICENSE). Not official Cloudflare — see [DISCLAIMER.md](./DISCLAIMER.md).
