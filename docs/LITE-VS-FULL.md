# Lite vs Full Rulebook Tiers

cf-account-review offers **two rulebook tiers** to balance public self-service with specialized SE-assisted assessments:

## Lite Rulebook (20 checks) — Public, Self-Service

**Target audience:** Customers running unassisted configuration reviews.

**What's included:** Binary checks with unambiguous pass/fail verdicts:
- Boolean flags (HSTS enabled, DNSSEC enabled, 2FA enforced)
- Numeric thresholds (TLS version ≥ 1.2, certificate expiry < 30 days)
- Inventory validations (Workers routes → scripts exist, Turnstile widgets have domains)

**Coverage:**
- SSL/TLS (5 checks) — encryption mode, TLS version, HSTS, Always Use HTTPS, cert expiry
- Zero Trust / Account Hygiene (3 checks) — 2FA enforcement, API token expiry, IdP config
- DNS (2 checks) — DNSSEC, CAA records
- Workers (2 checks) — zombie Workers, route validity
- Load Balancing (2 checks) — pool failover, monitor intervals
- AI Gateway (3 checks) — rate limiting, authentication, logging
- Origin Security (1 check) — Authenticated Origin Pulls enabled
- Bots (1 check) — Turnstile domain binding
- DDoS (1 check) — HTTP DDoS ruleset not disabled

**How to run:**
```bash
cf-account-review analyze collection.json --rulebook lite --out report.md
```

**Remediation:** Customers can act on lite findings without SE guidance — every fail has a clear fix path in the remediation text.

---

## Full Rulebook (35 checks) — SE-Assisted, Contextual

**Target audience:** Solutions Engineers conducting customer engagements, compliance reviews, or proof-of-concept assessments.

**What's included:** All 20 lite checks **PLUS** 15 contextual checks requiring:
- **Application/architecture knowledge** — which endpoints are "sensitive", which routes are "internal"
- **Threat modeling** — WAF skip rule risk analysis, bot allowlist decisions
- **Compliance expertise** — SOC 2 / PCI DSS control mapping (see `docs/compliance-mapping.md`)

**Additional checks (full only):**
- **WAF (3 checks)** — managed ruleset deployment, custom rules for sensitive endpoints, broad skip rule analysis
- **Rate Limiting (1 check)** — login endpoint protection (path detection requires app knowledge)
- **Response Headers (1 check)** — security header stripping analysis
- **Bots (2 checks)** — verified bot exclusion, bot management rule enforcement
- **Access (2 checks)** — Access app policy attachment, tunnel route protection
- **DNS (1 check)** — email posture (MX/SPF/DMARC) — informational only, interpretation varies
- **AI Gateway (2 checks)** — DLP policies, guardrails (sensitivity judgment required)
- **Client-Side Security (1 check)** — Page Shield enablement (plan-dependent, opt-in)
- **Origin Security (1 check)** — zone-level AOP preference (architecture decision)
- **Cache (1 check)** — HTML caching posture (app-specific)

**How to run:**
```bash
cf-account-review analyze collection.json --rulebook full --out report.md
```

**Remediation:** Full-tier findings include SE-contextualized recommendations and compliance framework mappings (SOC 2 TSC codes, PCI DSS requirements).

---

## Decision Criteria

### When to use **lite:**
- ✅ Customer self-service reviews ("scan my config for obvious issues")
- ✅ Pre-meeting prep without SE interpretation
- ✅ Continuous monitoring / scheduled checks (CI/CD integration)
- ✅ Public documentation and tooling examples

### When to use **full:**
- 🔒 SE-led customer engagements (POCs, architecture reviews, compliance audits)
- 🔒 Findings require app/threat model context to interpret
- 🔒 Customer needs SOC 2 / PCI DSS evidence mapping
- 🔒 Output will be delivered with SE commentary

---

## Implementation Notes

- **Single source of truth:** One `findings/checks.yaml` file contains both tiers; each check carries a `tier: lite` or `tier: full` field.
- **Tier field semantics:**
  - `lite` — Binary checks (boolean flags, numeric thresholds) with unambiguous pass/fail. No application context needed. Customer can self-remediate.
  - `full` — Contextual checks requiring app/architecture knowledge, threat modeling, or compliance expertise. SE interpretation recommended.
- **Filtering:** The analyzer's `--rulebook lite` flag filters to only lite checks; `--rulebook full` includes all 35 checks (20 lite + 15 full).
- **Read-only guarantee:** Both tiers remain strictly read-only (no mutating API calls).
- **Data policy:** Both tiers follow the same redaction/hashing policy (see `docs/data-policy.md`).

---

## Compliance Framework Coverage

**Full tier only:** 34 of 35 checks map to SOC 2 Trust Services Criteria and/or PCI DSS 4.0 requirements. See `docs/compliance-mapping.md` for the complete control matrix.

**Lite tier:** Compliance mappings are present in the YAML but not surfaced in lite reports — customers self-reviewing without SE guidance don't need TSC/DSS codes.

---

## Public Positioning

**Lite tier** enables the **first public Cloudflare config scanner** positioning:
- Customers can run unassisted reviews without SE intervention
- No proprietary SE methodology exposed (WAF skip analysis, Access coverage heuristics remain SE-only)
- Read-only guarantee + public Cloudflare docs citations build trust

**Full tier** preserves SE differentiation:
- Contextual checks require professional interpretation
- Compliance mappings add audit/certification value
- SE commentary turns findings into strategic recommendations

---

## Promotion Path

Checks may be promoted from `full` → `lite` when:
1. A formerly-contextual check becomes automatable (e.g., new API fields enable unambiguous evaluation)
2. Customer feedback shows consistent self-remediation success
3. The check gains public documentation that removes ambiguity

Promotions are recorded in this file's changelog and reflected in LITE-SPLIT.md.
