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
5. **Every new check needs:** an entry in `findings/checks.yaml` (or a new YAML),
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
