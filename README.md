# cf-account-review

> ⚠️ **NOT OFFICIAL CLOUDFLARE.** Not affiliated with or endorsed by Cloudflare, Inc.
> NO WARRANTIES, EXPRESS OR IMPLIED. Effectively untested personal code — read everything
> before you run it. You assume all risk. See [DISCLAIMER.md](./DISCLAIMER.md).

A **strictly read-only** Cloudflare account configuration review tool, focused first on
the **web security stack** (TLS, WAF managed + custom rules, rate limiting, bots, HTTP
DDoS, origin exposure, client-side security, security headers). It collects
configuration through the public Cloudflare API, evaluates it against a YAML
best-practice rulebook, and produces a customer-ready Markdown report with a per-zone
posture matrix, where every finding cites the Cloudflare documentation behind it.
Zero Trust and platform checks (Access, Tunnel, Workers, AI Gateway, account hygiene)
are available via `--profile`.

## The guarantees

- **READ ONLY — enforced by tests, not convention.** The API layer implements `GET` only, and the Mode B binary is that same code compiled. `tests/read-only.test.ts`
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
node dist/cli.js analyze output/collection.json --out output/report.md          # web-security profile
node dist/cli.js analyze output/collection.json --profile all --out output/all.md

# Exit code enforcement (CI integration)
node dist/cli.js analyze output/collection.json --fail-on high  # Exit 1 if any high-severity fails
```

### Mode B — offline collection (token never leaves the customer)

**Single binary (recommended, nothing to install):** release assets
`cf-account-review-collect-<version>-<os>-<arch>` for macOS, Linux and Windows, built
from the same TypeScript collector as Mode A with the Bun runtime embedded.

```bash
./cf-account-review-collect-0.2.0-darwin-arm64 output/   # prompts for the token (hidden)
scripts/build-binaries.sh                               # build all targets into dist-bin/
scripts/verify-build.sh dist-bin/SHA256SUMS             # rebuild the embedded bundle, compare hashes
```

The source is open so clients can inspect the collector or build it themselves. The JS
bundle embedded in each binary is reproducible (published with the release and
checked by `scripts/verify-build.sh`); the executables are not bit-identical across
builds, so clients who want zero trust in our artifacts build their own.

The binary's output feeds the same analyzer: `node dist/cli.js analyze <file>`.
Binaries are unsigned by design: verify `SHA256SUMS`, or build your own.

Token scopes: create a **read-only** token covering every permission in
[`docs/endpoints.md`](./docs/endpoints.md) (generated from the endpoint registry).
Narrowly-scoped tokens still work — unreadable endpoints are listed in
`collectionErrors` and the checks they feed report `manual`, never `pass` — but see
AGENTS.md rule 5 before running a review with one.

## What it checks

The rulebook lives in [`findings/checks.yaml`](./findings/checks.yaml). Profiles select
checks by domain; `web-security` is the default.

**web-security** (33 checks)

- **Zone:** active and proxied (a paused zone has no protections at all)
- **SSL/TLS:** Full (strict), min TLS ≥ 1.2, HSTS, Always Use HTTPS, custom cert expiry,
  0-RTT replay exposure, TLS 1.3
- **WAF:** Cloudflare Managed Ruleset deployed *and not overridden to off/log*, OWASP in
  blocking mode with sane threshold, custom rules that enforce, site-wide skip rules and
  WAF exceptions, leaked credentials detection, allowlist IP Access Rules (country/ASN
  allowlists fail), page rules that disable security, security level
- **Rate limiting:** login-path protection (enforcing, with parameters), any enforcing
  rule, legacy product migration
- **Bots:** plan-appropriate baseline (Bot Fight Mode / SBFM / Enterprise bot-score rules),
  verified-bot exclusion, bot rules that actually enforce, Turnstile widget binding
- **DDoS:** HTTP DDoS managed ruleset not disabled, logged, or set to essentially off
- **DNS & origin:** DNSSEC, CAA, mail posture, DNS-only records that expose the origin
  beside proxied ones, Authenticated Origin Pulls (zone-level cert preferred)
- **Client side & headers:** Page Shield, security response headers at the edge
- **Cache:** site-wide Cache Everything / cache-eligible rules (cache deception risk)

**zero-trust:** Access policies/bypass, IdPs, tunnel public hostnames behind Access.
**platform:** 2FA enforcement, token expiry, Workers routing hygiene, LB pools/monitors,
AI Gateway controls.

Verdicts: `pass | warn | fail | manual | na` — **incomplete evidence can never pass.**

## Docs

- **[docs/CLIENT-GUIDE.md](./docs/CLIENT-GUIDE.md)** — comprehensive client-facing guide (send this to clients)
- [docs/endpoints.md](./docs/endpoints.md) — every GET with its rationale and citation
- [docs/data-policy.md](./docs/data-policy.md) — read-only, redaction, no-exfiltration
- [docs/sources.md](./docs/sources.md) — the best-practice sources behind each check
- [docs/EVOLUTION-*.md](./docs/) — design review of the first take and the roadmap

## Development

```bash
pnpm install
pnpm verify      # lint + tests (the done-check), incl. the collector data-policy test
pnpm build       # tsc -> dist/
```

Node ≥ 24. See [AGENTS.md](./AGENTS.md) for project conventions.

## Attribution

Check shapes and verdict semantics borrow from prior art — see [NOTICE](./NOTICE)
and [docs/sources.md](./docs/sources.md).

## License

MIT — see [LICENSE](./LICENSE). Not official Cloudflare — see [DISCLAIMER.md](./DISCLAIMER.md).
