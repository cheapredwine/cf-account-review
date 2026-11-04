# Cloudflare Account Security Review — Client Guide

**Last updated:** October 31, 2026  
**Tool version:** 0.1.0

> ⚠️ **NOT OFFICIAL CLOUDFLARE.** This tool is not affiliated with or endorsed by Cloudflare, Inc.
> NO WARRANTIES, EXPRESS OR IMPLIED. See [DISCLAIMER.md](../DISCLAIMER.md) for full terms.

## What this tool does

This is a **strictly read-only** security configuration review tool for Cloudflare accounts. It:

1. **Collects** your Cloudflare configuration through the public API
2. **Analyzes** it against 35 security best-practice checks across 16 domains
3. **Produces** a detailed Markdown report where every finding cites official Cloudflare documentation
4. **Generates Terraform code** (future) with hardened defaults to fix your findings — YOU review and apply it carefully

### Hard guarantees

- **READ ONLY** — The tool has no write code and is enforced by automated tests. It cannot modify your account.
- **Never records sensitive data** — DNS contents, origin IPs, account IDs (hashed only), email addresses, and API tokens are redacted or never collected. See [Data Privacy](#data-privacy) below.
- **Never exfiltrates** — All API calls go exclusively to `api.cloudflare.com`. No telemetry, no uploads, no third-party connections.
- **Fail-closed** — If the tool cannot read data needed for a check, it reports "manual review required," never "passed."

## What gets checked

The tool evaluates **41 security checks** across these areas:

### Security domains covered

- **SSL/TLS:** Full(strict) encryption mode, minimum TLS 1.2+, HSTS enabled, certificate expiry
- **WAF:** Managed rulesets deployed and active, custom firewall rules with enforcement
- **Rate Limiting:** Protection on authentication endpoints, legacy rate-limit migration
- **Bot Management:** Verified bot handling, Turnstile widget inventory, enforcement gaps
- **DDoS Protection:** HTTP DDoS managed rulesets not disabled
- **Origin Security:** Authenticated Origin Pulls enabled, zone-level certificates preferred
- **Client-Side Security:** Page Shield enabled for JavaScript monitoring
- **DNS:** DNSSEC enabled, CAA records present, email security posture
- **Cache:** HTML not cached aggressively by default
- **Workers:** Zombie scripts (deployed but unrouted), dangling routes
- **Load Balancing:** Multiple origins per pool for failover, health check intervals
- **Zero Trust Access:** Access policies on apps, bypass decision audit, MFA requirements
- **Zero Trust Tunnels:** Public tunnel routes protected by Access applications
- **AI Gateway:** Rate limits, authentication, logging, DLP policies, prompt guardrails
- **Account Security:** 2FA enforcement, token expiry posture, member role concentration

Each check produces one of these verdicts:

- **pass** — Configuration meets best practice
- **warn** — Non-critical gap or improvement opportunity
- **fail** — Security risk that should be addressed
- **manual** — Insufficient data; manual review required
- **na** — Not applicable (wrong plan tier, feature not in use)

**Every finding cites the Cloudflare documentation** that justifies the recommendation.

---

## Two ways to run the tool

You have two options for running this review. Choose based on your security requirements:

### Option 1: Offline collection (most secure)

**Best for:** Organizations that cannot share API tokens externally or prefer zero trust-by-default.

**How it works:**

1. You run a shell script (PowerShell or bash) **inside your environment**
2. The script collects configuration using your API token — **the token never leaves your machine**
3. The script writes a JSON file containing your configuration (with sensitive data redacted)
4. You send us **only the JSON file** — no tokens, no credentials
5. We run the analyzer against the JSON and return your report

**PowerShell (Windows):**

```powershell
# From the tool directory
.\collectors\ps\Collect-CFConfig.ps1

# You'll be prompted for your API token (input is hidden)
# Output: cloudflare-config-YYYYMMDD-HHMMSS.json
```

**Bash (macOS/Linux):**

```bash
# From the tool directory
CF_API_TOKEN=your_token_here ./collectors/sh/collect-config.sh output/

# Or use environment variable from your shell
export CF_API_TOKEN=...
./collectors/sh/collect-config.sh output/

# Output: output/cloudflare-config-YYYYMMDD-HHMMSS.json
```

**What you send us:** The generated JSON file only. We run `node dist/cli.js analyze <file>` and return your report plus (future) a Terraform configuration to fix the issues.

---

### Option 2: Direct API collection (requires token sharing)

**Best for:** Organizations comfortable sharing a read-only API token for direct analysis.

**How it works:**

1. You create a read-only Cloudflare API token (see [Creating the API Token](#creating-the-api-token) below)
2. You provide us the token securely (Signal, 1Password share, encrypted email, etc.)
3. We run the collector and analyzer in one pass
4. We return your report and delete the token

**Commands we run:**

```bash
# Collection
export CF_API_TOKEN=your_token_here
node dist/cli.js collect --out output/collection.json

# Analysis
node dist/cli.js analyze output/collection.json --out output/report.md
```

**Token security:**

- We store the token only in memory during collection (environment variable)
- The token is never written to disk, logged, or included in output files
- We delete the token immediately after generating your report
- A pre-write scan prevents any credential-shaped data from being written to output

---

## Creating the API Token

Whether you use Option 1 or 2, you need a **read-only API token**. The
permission names below are the **actual dashboard group names** (verified
against the live permission-group registry 2026-11-03); every gap produces
`manual` verdicts for the affected checks, never `pass`.

### Required permissions (all Read)

Go to **Cloudflare Dashboard** → **My Profile** → **API Tokens** → **Create
Token** → **Custom token**.

*Account-scoped — "Include · Specific account · *your account*":*

| Permission (dashboard name) | Covers |
|------------|-----------|
| Account Settings | Account posture, member 2FA |
| Account API Tokens | Account-owned token inventory |
| Load Balancing: Monitors and Pools | Pool failover posture |
| Account Rulesets | Account-level WAF (Enterprise) |
| Access: Apps and Policies | Access policy review |
| Access: Identity Providers | IdP and MFA posture |
| Access: Service Tokens | Service-token expiry hygiene |
| Turnstile Sites | Turnstile widget inventory |
| Cloudflare Tunnel | Tunnel-to-Access gap detection |
| Workers Scripts | Worker zombie scripts |
| Workers KV Storage | Data-at-rest inventory |
| D1 | Data-at-rest inventory |
| Workers R2 Storage | Data-at-rest inventory |
| AI Gateway | Gateway rate-limit/auth/log posture |

*User-scoped — "Include · *your user*":*

| Permission (dashboard name) | Covers |
|------------|-----------|
| API Tokens: Read (User section) | User-token rotation posture |

*Zone-scoped — "Include · All zones from an account · *your account*":*

| Permission (dashboard name) | Covers |
|------------|-----------|
| Zone | Zone inventory, plan tiers |
| Zone Settings | SSL mode, min TLS, HSTS, DNSSEC |
| Zone WAF | Zone rulesets, phase entrypoints, bot management |
| Firewall Services | IP access rules |
| Page Rules | Legacy page-rule migration signal |
| DNS | DNS hygiene (contents redacted) |
| SSL and Certificates | Certificate expiry, origin mTLS |
| Load Balancers | Zone LB posture |
| Workers Routes | Worker-to-zone routing |
| Domain API Gateway | API Shield discovery + config (Enterprise) |
| Bot Management | Bot handling rules (Pro+) |
| Domain Page Shield | Page Shield posture (Business+) |

Notes verified against the live registry (2026-11-03):

- **Phase note:** the Access and Tunnel rows above are **phase 3**
  (Cloudflare One / ZTNA) — for a phase-1 report their reads can be omitted;
  the affected checks simply report `manual` or are filtered out by
  `analyze --phase 1`.

- There is **no "Zone Rulesets" permission group** — zone rulesets and phase
  entrypoints are readable with **Zone WAF: Read**.
- There is **no zone-level "Zone Rate Limiting" group and the legacy
  `/zones/{id}/rate_limits` endpoint returns 410 Gone** (product EOL'd) — the
  tool no longer queries it; the `http_ratelimit` phase check covers current
  posture.
- `bot_management` requires **Bot Management: Read** (Zone WAF alone returns
  403); `api_gateway/configuration` additionally returns 403 "not entitled"
  on zones without API Shield enabled — those checks report `manual`.

**Token scope:** All zones in your account(s), read-only access only.
Suggest a 90-day TTL; delete the token after the review.

### Narrowly-scoped tokens work

If your token is missing some permissions, the tool will:

- Skip endpoints it cannot read
- List them in `collectionErrors` in the output
- Mark related checks as `manual` (not `pass` or `fail`)
- Still produce a useful partial report for everything it *can* read

---

## What the report looks like

The report is a detailed Markdown document with:

### Summary section

- **Overall score** — Pass/Warn/Fail counts
- **Critical findings** — High-severity issues requiring attention
- **Account overview** — Number of accounts, zones, plan tiers
- **Collection metadata** — What was successfully read, what was skipped

### Per-check findings

Each check includes:

```markdown
### CF-SSL-001: SSL/TLS encryption mode (fail)

**Severity:** High  
**Finding:** 3 zones use "Flexible" SSL mode, which does not encrypt traffic to your origin.

**Recommendation:**  
Switch to "Full (strict)" mode for end-to-end encryption. Flexible mode leaves your origin 
traffic unencrypted and vulnerable to interception.

**Affected zones:**  
- example.com (Flexible)
- staging.example.com (Flexible)  
- test.example.com (Off)

**Documentation:**  
https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/

**Plan requirement:** Available on all plans
```

### Appendix

- **What we checked** — Full list of 35 checks
- **What we did NOT collect** — Explicit list of data not recorded (request logs, Worker script contents, Access policy identities, etc.)
- **How to act on findings** — Prioritization guidance

---

## Data Privacy

### What is collected

The tool collects **configuration metadata only** — not traffic, logs, or content:

- Zone settings (SSL mode, security level, etc.)
- Firewall rule **metadata** (enabled/disabled, action types, rule counts)
- DNS record **structure** (record types, presence of DNSSEC/CAA) — **contents redacted by default**
- Worker script **names and routes** — **code never collected**
- Access app **names and policy decisions** (allow/bypass/block) — **identity expressions never collected**
- Load balancer **configuration** (pool counts, monitor intervals)
- Account **settings** (2FA enforcement, member role distribution)
- Certificate **expiry dates**

### What is NOT collected

The tool **never collects:**

- DNS record contents (origin IPs, CNAME targets) — redacted as `[redacted]`
- Worker script source code or environment variable values
- Access policy identity expressions (emails, IP ranges, groups)
- API token values or secrets
- Request logs, analytics data, or traffic samples
- Customer data, PII, or user identities
- KV/D1/R2 contents (only counts)

### How data is protected

1. **IDs are hashed** — Account IDs, zone IDs, rule IDs are SHA-256 hashed and truncated to 16 hex characters
2. **Identities are anonymized** — Account member emails/names become role names + 2FA booleans only
3. **Expressions are sanitized** — Firewall rules have IPs, emails, and internal hostnames redacted
4. **Secrets are scanned** — Pre-write scan blocks any credential-shaped data from being written
5. **One host only** — All API calls go to `api.cloudflare.com` only; no telemetry or third-party connections

### Re-inclusion (optional)

In **Option 1 (offline)**, all redaction is applied unconditionally.

In **Option 2 (direct API)**, you may opt to include DNS contents or other redacted fields using `--include-dns` flags (only when needed for deep-dive reviews). This is explicit and opt-in only.

---

## Interpreting your report

### Severity levels

- **High** (fail) — Address immediately (e.g., Flexible SSL, no WAF, 2FA not enforced)
- **Medium** (warn) — Improve when feasible (e.g., missing HSTS, aggressive HTML caching)
- **Low** (pass) — Configuration meets best practice

### Common findings and fixes

#### "Zones using Flexible SSL" (CF-SSL-001)

**What it means:** Traffic between Cloudflare and your origin is unencrypted.  
**Fix:** Switch to "Full (strict)" mode in SSL/TLS settings. Requires a valid certificate on your origin.  
**Plan:** All plans.

#### "WAF managed ruleset disabled via overrides" (CF-WAF-001)

**What it means:** Your WAF is deployed but disabled by an override rule.  
**Fix:** Remove or adjust the override that disables the managed ruleset.  
**Plan:** Pro+ for managed rules.

#### "No Access policy on application" (CF-ACCESS-001)

**What it means:** An Access app has no policies, allowing unrestricted access.  
**Fix:** Add at least one Allow policy with identity requirements.  
**Plan:** All plans (Access is add-on).

#### "Tunnel public hostnames not protected by Access" (CF-TUNNEL-001)

**What it means:** You're exposing internal services via public tunnel routes without Access protection.  
**Fix:** Create Access applications covering each public hostname.  
**Plan:** All plans (Tunnel and Access are add-ons).

#### "Page Shield not enabled" (CF-PS-001)

**What it means:** Client-side JavaScript monitoring is off; supply-chain attacks may go undetected.  
**Fix:** Enable Page Shield in Security → Page Shield.  
**Plan:** Business+ only.

#### "No Authenticated Origin Pulls" (CF-AOP-001)

**What it means:** Your origin cannot verify requests are from Cloudflare; attackers can bypass Cloudflare.  
**Fix:** Enable Authenticated Origin Pulls in SSL/TLS → Origin Server.  
**Plan:** All plans.

#### "2FA not enforced on account" (CF-ACCOUNT-001)

**What it means:** Account members can log in without MFA.  
**Fix:** Enable "Require 2FA" in Account Settings → Authentication.  
**Plan:** All plans.

---

## Frequently Asked Questions

### How long does collection take?

**Option 1 (offline):** 30 seconds to 3 minutes depending on account size (zones, rules, Workers).  
**Option 2 (direct):** Same; we run it once and deliver your report.

### What Cloudflare plans are supported?

All plans — Free, Pro, Business, Enterprise. Some checks only apply to certain plans:

- **Business+:** Page Shield, Advanced DDoS
- **Enterprise:** API Gateway, account-level rulesets, custom SSL
- **All plans:** SSL/TLS, DNS, basic WAF (Pro+), Access, Tunnel, Workers, 2FA

Plan-gated checks are marked `na` (not applicable) if your plan doesn't include them.

### Can I run this on multiple accounts?

Yes. The token must have access to all accounts you want to review. The report covers everything the token can read.

### Does this work with WARP or Magic WAN?

Not yet. Version 1 focuses on application security (WAF, Access, Workers, SSL/TLS). Network-layer products (WARP, Magic WAN, Spectrum) are planned for a future release.

### How often should I run this?

**Recommended cadence:**

- **Initial baseline:** Run once to establish your security posture
- **Quarterly:** Catch configuration drift and new best practices
- **After major changes:** Post-migration, new zone onboarding, team changes
- **Before audits:** SOC 2, ISO 27001, pen-test prep

### What if I disagree with a finding?

Every finding cites Cloudflare documentation. If your use case justifies an exception:

1. Document your rationale
2. Mark the finding as "accepted risk" in your own records
3. Re-run the tool quarterly to ensure the exception remains valid

### Can I customize the checks?

Not in the standard distribution. The checks are based on Cloudflare's published best practices.

If you need custom checks (compliance-specific, organizational policy), contact us about a custom rulebook — or fork the open-source version and edit `findings/checks.yaml` yourself.

### Is this open source?

**Yes.** MIT licensed. GitHub: `github.com/cheapredwine/cf-account-review`

You can:

- Inspect the source code
- Run it yourself without involving us
- Fork and customize it
- Contribute checks or improvements

### What Node.js version do I need?

**Node.js 24 or later** (Active or Maintenance LTS). The tool will not run on Node 20 or older.

Check your version:

```bash
node --version  # Should be v24.x.x or newer
```

Install Node 24: [nodejs.org](https://nodejs.org/)

### How do I install the tool?

**If you're running it yourself (not just the offline collector):**

```bash
# Clone or extract the tool
cd cf-account-review

# Install dependencies
pnpm install   # or npm install

# Build
pnpm build     # or npm run build

# Verify
pnpm verify    # or npm run verify (runs tests)
```

**If you're only using Option 1 (offline collector):**

- **PowerShell collector:** No installation needed; just run the `.ps1` script
- **Bash collector:** Requires `curl` and `python3` (pre-installed on macOS/Linux)

---

## Getting your report

### Option 1 workflow (offline collection)

1. **You:** Run the collection script, send us the JSON file
2. **Us:** Run the analyzer, generate the report
3. **Delivery:** Markdown report via secure channel (encrypted email, Signal, shared drive)
4. **Cleanup:** We delete your JSON file after delivery

**Turnaround:** Typically same business day; maximum 48 hours.

**What you get back:**
- Detailed security review report (Markdown) with findings, recommendations, and Cloudflare docs citations
- **(Future)** Terraform configuration addressing your high-severity findings — switch Flexible SSL to Full(strict), enable WAF managed rulesets, enforce 2FA, add DNSSEC, enable Authenticated Origin Pulls, etc.

**The Terraform workflow:**
1. We generate Terraform code with hardened settings based on your findings
2. YOU review every resource and setting before applying anything
3. YOU test the Terraform in a staging environment first (if possible)
4. YOU apply to production when you're confident the changes are correct
5. We help troubleshoot if anything breaks

The goal is to give you **actionable, reviewable fixes** — not just a list of problems. You stay in control of what gets applied and when.

### Option 2 workflow (direct API)

1. **You:** Create read-only API token, share it securely
2. **Us:** Run collection + analysis in one pass
3. **Delivery:** Markdown report + (future) Terraform via secure channel
4. **Cleanup:** We delete the token and collection file immediately

**Turnaround:** Typically same business day; maximum 48 hours.

**What you get back:** Same as Option 1 — detailed report plus (future) Terraform to fix the issues. See Option 1 workflow above for the Terraform review process.

---

## Support and questions

**Before the review:**

- Questions about token creation: reference this guide or Cloudflare's API token docs
- Questions about scope/coverage: see [What gets checked](#what-gets-checked)
- Custom requirements: contact us to discuss

**After receiving your report:**

- Interpretation questions: we'll walk through findings on a call
- Implementation guidance: we can help prioritize and plan fixes
- Follow-up reviews: re-run after remediation to verify improvements

**Contact:** [Your contact information here]

---

## Technical reference

### Collection schema version

This tool uses **collection schema v1.0**. The JSON output includes:

```json
{
  "schemaVersion": "1.0",
  "collectedAt": "2026-10-31T12:00:00Z",
  "accounts": [...],
  "zones": [...],
  "collectionErrors": [...]
}
```

### Exit codes (for CI integration)

If you're running the tool in CI/CD pipelines:

```bash
# Fail the build if any high-severity findings
node dist/cli.js analyze output/collection.json --fail-on high

# Exit codes:
# 0 = no failures at specified severity
# 1 = failures found
# 2 = invalid input or analysis error
```

### API endpoint inventory

The tool can make up to **25 different API calls** depending on your plan and enabled features. Full list: [docs/endpoints.md](endpoints.md)

Every endpoint is GET-only and read-scoped. See that document for the complete rationale and citation for each endpoint.

---

## License and disclaimer

**License:** MIT — see [LICENSE](../LICENSE)  
**Disclaimer:** Not official Cloudflare. No warranties. See [DISCLAIMER.md](../DISCLAIMER.md)

This tool is a personal project and is not affiliated with or endorsed by Cloudflare, Inc. Use at your own risk.

---

**Ready to get started?** Choose your option:

- **Option 1 (most secure):** Run the offline collector → [Jump to instructions](#option-1-offline-collection-most-secure)
- **Option 2 (faster):** Share read-only token → [Jump to instructions](#option-2-direct-api-collection-requires-token-sharing)

Questions? Contact us before you begin.
