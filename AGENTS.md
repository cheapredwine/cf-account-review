# AGENTS.md — cf-account-review

## What this is

A strictly read-only Cloudflare account configuration review tool: collectors
(one TypeScript collector, run directly in Mode A and compiled as the Mode B single binary) emits a zod-validated JSON "collection"; an analyzer
evaluates a YAML findings rulebook against it and renders a Markdown report.

## Hard rules — do not violate these when editing

1. **READ ONLY.** Never add a mutating HTTP method (`post/put/patch/delete`,
   `-X POST`…). `tests/read-only.test.ts`
   enforces this and must stay in place. If a feature seems to need a write,
   stop — the tool is read-only by design.
2. **One outbound host.** All API calls go to `https://api.cloudflare.com/client/v4`
   (pinned in `src/cf/client.ts`).
   No telemetry, uploads, or third-party HTTP.
3. **Data policy.** Any new collected field must follow `docs/data-policy.md`:
   IDs hashed, DNS contents redacted, identities never exported, token material
   never present. Update the zod schema, `src/summarize.ts`, and the policy
   doc together. The pre-write secret scan must stay fail-closed.
4. **Fail-closed verdicts.** Unreadable evidence → `manual`, never `pass`.
   Out-of-plan checks → `na`. Never turn a data gap into a pass.
5. **Token scope gate — stop and ask before running collectors.** Never run
   `collect` (either mode) with a token whose permission list does not cover
   the review scopes in `docs/endpoints.md` (Account Settings Read + Workers/
   Access/Turnstile/AI Gateway/API-token reads at account level; Zone, Zone
   Settings, DNS, Firewall Services, Zone WAF, Rate Limiting, Page Shield,
   SSL and Certificates, Load Balancing reads at zone level). A wrangler
   OAuth token or a developer-oriented token is NOT acceptable for a review
   run: it silently narrows the report to ~15% readable endpoints. Before any
   run, confirm the token covers the scope list; if it doesn't, STOP and
   present the required scope list to the user for approval — do not run with
   partial scope and do not treat the resulting error count as acceptable.
6. **Every new check needs:** an entry in `findings/checks.yaml` (or a new YAML),
   an evaluator (only if not declarative), a `citation` to Cloudflare docs, a
   plan-tier, a `scope` if account-level, a domain that belongs to a profile, and
   a fixture-based test in `tests/engine.test.ts` or `tests/web-security.test.ts`.
7. **One collector.** The Mode B single binary (`src/bin/collect.ts`, built with
   `scripts/build-binaries.sh`) IS the Mode A collector compiled with Bun. The
   PowerShell and bash collectors were retired in v0.2 — do not reintroduce a
   second implementation; auditability comes from the open source, the reproducible
   bundle (`scripts/verify-build.sh`), and self-builds. Add any new sensitive field to
   `tests/fixtures/fake-api.json` with a planted value and to `PLANTED_SECRETS` in
   `tests/collector-policy.test.ts`. Binaries are unsigned by decision.

## Conventions

- Package manager: pnpm. Node ≥ 24 (`.nvmrc`). TypeScript strict.
- Lint: `pnpm lint` (oxlint). Format: `pnpm format` (oxfmt check).
- Done-check: `pnpm verify` (lint + tests) must exit 0 before any commit.
- New checks go on a branch; main merges via PR; CI runs `verify` on push/PR.
- Docs (`docs/endpoints.md`, `docs/data-policy.md`) must be updated in the same
  change that alters collection or checks. `docs/endpoints.md` is generated:
  `pnpm build && node scripts/gen-endpoints-doc.mjs`.
- Citations are link-checked in CI (`scripts/check-citations.mjs`).

## Layout

- `src/schema.ts` — collection contract (zod); version-bump on breaking change
- `src/redact.ts` — shared redaction
- `src/endpoints.ts` — the endpoint registry (Mode A iterates this only)
- `src/summarize.ts` — policy-safe summarizers for raw API objects (mirrored in Mode B)
- `src/collect.ts` — Mode A collector
- `src/analyzer/` — rulebook engine + Markdown report
- `src/cli.ts` — `collect` / `analyze` commands
- `src/bin/collect.ts` — Mode B single-binary entry (hidden token prompt; client installs no runtime)
- `findings/checks.yaml` — the rulebook
- `tests/` — read-only enforcement, redaction, engine + web-security fixtures,
  collector data policy (`tests/fixtures/fake-api.json`), binary tests
- `docs/EVOLUTION-*.md` — design review and roadmap (versioned, newest wins)

## Known gaps (see TODO.md and the latest docs/EVOLUTION-*.md)

- v0.2 collection has only been exercised against the fake API; the full-scope
  token dogfood run (PENDING-REVIEW.md) is still outstanding.
- `--include-*` re-inclusion flags in Mode A not yet implemented.
- HTML report renderer not implemented (Markdown only in v1).
- Access policy identity expressions are reduced to decisions; a deeper
  policy-level review (MFA on apps, WAF-for-Access) is future work.
