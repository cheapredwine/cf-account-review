# Lite vs Full Rulebook Split

## LITE rulebook (20 checks) — binary, obvious pass/fail

These checks have **unambiguous verdicts** — pass is always right, fail is always wrong, no context needed:

### SSL/TLS (5 checks)
- ✅ **CF-SSL-001** — SSL/TLS encryption mode is Full (strict) ← binary setting
- ✅ **CF-SSL-002** — Minimum TLS version is 1.2 or higher ← binary threshold
- ✅ **CF-SSL-003** — HSTS is enabled ← boolean flag
- ✅ **CF-SSL-004** — Always Use HTTPS is enabled ← boolean flag
- ✅ **CF-SSL-005** — Custom certificates not expiring soon ← date math

### Zero Trust / Account Hygiene (3 checks)
- ✅ **CF-ZT-003** — Two-factor authentication enforced on the account ← boolean flag
- ✅ **CF-IAM-001** — API tokens have expiry set ← date presence check
- ✅ **CF-ZT-002** — Identity providers beyond one-time PIN configured ← IdP count > 1

### DNS (2 checks)
- ✅ **CF-DNS-001** — DNSSEC enabled ← boolean flag
- ✅ **CF-DNS-002** — CAA records present ← record type presence

### Workers (2 checks)
- ✅ **CF-WRK-001** — No zombie Workers (deployed, never routed) ← inventory diff
- ✅ **CF-WRK-002** — Workers routes point to scripts that exist ← reference validity

### Load Balancing (2 checks)
- ✅ **CF-LB-001** — Load balancer pools have multiple origins for failover ← count ≥ 2
- ✅ **CF-LB-002** — Load balancer monitors use appropriate intervals ← numeric threshold

### AI Gateway (3 checks)
- ✅ **CF-AIG-001** — AI Gateways have rate limiting configured ← boolean flag
- ✅ **CF-AIG-002** — AI Gateways have authentication enabled ← boolean flag
- ✅ **CF-AIG-003** — AI Gateways have log collection enabled ← boolean flag

### Origin Security (2 checks)
- ✅ **CF-AOP-001** — Authenticated Origin Pulls enabled ← boolean flag
- ✅ **CF-DDOS-001** — HTTP DDoS managed ruleset not disabled ← ruleset presence

### Bots (1 check)
- ✅ **CF-TS-001** — Turnstile widgets have domains bound ← domain list non-empty

**Total: 20 checks** (all binary evaluations, no judgment calls)

---

## FULL rulebook (15 additional checks) — nuanced, contextual, SE-assisted

These checks require **application context, architecture knowledge, or compliance expertise**:

### WAF (3 checks) — requires app knowledge
- 🔒 **CF-WAF-001** — Managed WAF ruleset deployed ← *but what sensitivity level?*
- 🔒 **CF-WAF-002** — Custom WAF rules present for sensitive endpoints ← *which endpoints are "sensitive"?*
- 🔒 **CF-WAF-003** — Broad skip rules are not neutralizing the WAF ← *expression analysis, severity judgment*

### Rate Limiting (1 check) — requires app knowledge
- 🔒 **CF-RL-001** — Rate limiting rule protects login endpoints ← *which endpoints are "login"?*

### Response Headers (1 check) — requires app knowledge
- 🔒 **CF-HDR-001** — Edge response transforms do not strip security headers ← *transform rule analysis*

### Bots (2 checks) — requires threat model
- 🔒 **CF-BOT-001** — Definite-bot block excludes verified bots ← *which bots should be allowed?*
- 🔒 **CF-BOT-002** — Bot management rules actually enforce (not skip-only) ← *rule intent analysis*

### Zero Trust (1 check) — requires architecture understanding
- 🔒 **CF-ZT-001** — Access applications have policies attached ← *which apps SHOULD have Access?*
- 🔒 **CF-TUNNEL-001** — Public tunnel routes protected by Access ← *which routes are "internal"?*

### DNS (1 check) — informational only
- 🔒 **CF-DNS-003** — MX and SPF/DMARC email posture recorded ← *interpretation varies*

### AI Gateway (2 checks) — requires data classification
- 🔒 **CF-AIG-004** — AI Gateways have DLP policies configured ← *sensitivity judgment*
- 🔒 **CF-AIG-005** — AI Gateways have guardrails configured ← *risk tolerance*

### Client-side / Origin (3 checks) — requires architecture
- 🔒 **CF-PS-001** — Page Shield enabled ← *plan-dependent, opt-in*
- 🔒 **CF-AOP-002** — Zone-level Authenticated Origin Pulls preferred ← *architecture preference*
- 🔒 **CF-CACHE-001** — HTML not cached aggressively by default ← *app-specific*

**Total: 15 checks** (all require context, SE interpretation, or compliance mapping)

---

## Decision logic

**LITE check criteria:**
1. ✅ Boolean flag or numeric threshold (no gray area)
2. ✅ Pass is universally correct (no "it depends")
3. ✅ No application/architecture knowledge required
4. ✅ Customer can remediate without SE guidance

**FULL check criteria:**
1. 🔒 Requires understanding customer's app architecture
2. 🔒 Verdict depends on threat model or risk tolerance
3. 🔒 Remediation needs SE contextualization
4. 🔒 Compliance mapping value (SOC 2 / PCI DSS)
