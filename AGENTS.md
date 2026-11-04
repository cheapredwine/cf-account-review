# AGENTS.md — cf-account-review

## What this is

A strictly read-only Cloudflare account configuration review tool: collectors
(TS client, PowerShell, bash) emit a zod-validated JSON "collection"; an analyzer
evaluates a YAML findings rulebook against it and renders a Markdown report.

## Hard rules — do not violate these when editing

1. **READ ONLY.** Never add a mutating HTTP method (`post/put/patch/delete`,
   `-X POST`, `Invoke-RestMethod -Method Post`…). `tests/read-only.test.ts`
   enforces this and must stay in place. If a feature seems to need a write,
   stop — the tool is read-only by design.
2. **One outbound host.** All API calls go to `https://api.cloudflare.com/client/v4`
   (pinned in `src/cf/client.ts` and `collectors/sh/collect-config.sh`).
   No telemetry, uploads, or third-party HTTP.
3. **Data policy.** Any new collected field must follow `docs/data-policy.md`:
   IDs hashed, DNS contents redacted, identities never exported, token material
   never present. Update the zod schema, both shell collectors, and the policy
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
   plan-tier, and a fixture-based test in `tests/engine.test.ts`.

## Conventions

- Package manager: pnpm. Node ≥ 24 (`.nvmrc`). TypeScript strict.
- Lint: `pnpm lint` (oxlint). Format: `pnpm format` (oxfmt check).
- Done-check: `pnpm verify` (lint + tests) must exit 0 before any commit.
- New checks go on a branch; main merges via PR; CI runs `verify` on push/PR.
- Docs (`docs/endpoints.md`, `docs/data-policy.md`) must be updated in the same
  change that alters collection or checks.

## Layout

- `src/schema.ts` — collection contract (zod); version-bump on breaking change
- `src/redact.ts` — shared redaction (mirror in both shell collectors)
- `src/endpoints.ts` — the endpoint registry (Mode A iterates this only)
- `src/collect.ts` — Mode A collector
- `src/analyzer/` — rulebook engine + Markdown report
- `src/cli.ts` — `collect` / `analyze` commands
- `findings/checks.yaml` — the rulebook
- `collectors/ps/`, `collectors/sh/` — Mode B collectors
- `tests/` — read-only enforcement, redaction, engine fixtures

## Known v1 gaps (see TODO.md)

- Analyzer round-trip against real collected output not yet run end-to-end.
- `--include-*` re-inclusion flags in Mode A not yet implemented.
- HTML report renderer not implemented (Markdown only in v1).
- Access policy identity expressions are reduced to decisions; a deeper
  policy-level review (MFA on apps, WAF-for-Access) is future work.
- Report write path has no guarded write (redaction/secret scan) — see TODO.md.

## Distribution decision (recorded)

Customer hand-off is a standalone binary (Node single-executable; official
nodejs.org build for the embed step — distro builds have SEA disabled) plus
the Mode B shell collectors as the auditable alternative. One codebase: the
read-only guarantee, redaction, and output schema each exist once, in
TypeScript. No second implementation in another language (e.g. Go) — drift
between two copies of the safety rules is the unacceptable failure mode.
Per-run scope is expressed as named domains via `analyze --domains` (chosen
per customer); there is no numeric phase system.
