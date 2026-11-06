# Customer Email — Cloudflare Account Security Review

---

**Subject:** Cloudflare security review — 20 minutes, read-only, you'll get immediate feedback

---

Hey [Customer Name],

Thanks for asking about the security review! Here's what I've built and how it works.

## What You're Getting

A security assessment of your Cloudflare account against 45 best-practice checks. Think health checkup for your config — it reads your settings (completely read-only), compares them to documented standards, and tells you what's solid and what needs attention.

**Two deliverables:**
1. **Immediate (while the script runs):** Real-time security observations on screen — quick pass/warn findings as it collects your config
2. **Detailed report (24-48 hours):** Full analysis with severity ratings, step-by-step fixes, and Cloudflare docs citations

## Three Safety Guarantees

1. **Actually read-only** — The code physically can't write. No write methods, automated tests enforce it, every API call is GET-only.
2. **Aggressive redaction** — Origin IPs, DNS content, account/zone IDs, emails all redacted/hashed before anything hits disk. The tool reads configuration structure (is 2FA on? what SSL mode?), not secrets.
3. **Token stays local** — You run the script on your machine. It uses your token to call the Cloudflare API, redacts data, writes JSON to your disk. The token never leaves your environment or appears in the output.

> ⚠️ **Important:** This isn't official Cloudflare software — it's a tool I built for config reviews. **Review the PowerShell script before running it** (~300 lines you can read through). I'll explain what it does, but verify it yourself.

---

## How This Works — 20 Minutes Total

### Step 1: Create Read-Only API Token (~5 min)

👉 **[Click here to create your token](https://dash.cloudflare.com/profile/api-tokens?permissions=account.access_accts_and_memberships%3Aread,account.access_apps%3Aread,account.access_identity_providers%3Aread,account.access_service_tokens%3Aread,account.account_analytics%3Aread,account.account_firewall_access_rules%3Aread,account.account_rulesets%3Aread,account.account_settings%3Aread,account.api_gateway%3Aread,account.billing%3Aread,account.cloudflare_tunnel%3Aread,account.d1%3Aread,account.load_balancers%3Aread,account.logs%3Aread,account.stream%3Aread,account.workers_kv_storage%3Aread,account.workers_r2%3Aread,account.workers_scripts%3Aread,zone.access_apps_and_policies%3Aread,zone.analytics%3Aread,zone.bot_management%3Aread,zone.cache_purge%3Aread,zone.dns%3Aread,zone.firewall_services%3Aread,zone.load_balancers%3Aread,zone.logs%3Aread,zone.page_shield%3Aread,zone.ssl_and_certificates%3Aread,zone.waf%3Aread,zone.workers_routes%3Aread,zone.zone%3Aread,zone.zone_settings%3Aread)**

This opens the Cloudflare dashboard with 31 read-only permissions pre-selected. Just:
1. Click the link
2. Name it "Security Review"
3. Create it
4. **Copy the token** (shown once)
5. Save it securely (password manager)

### Step 2: Download and Run the Collection Script (~10 min)

**📦 Download the review package:** https://github.com/cheapredwine/cf-account-review/releases/tag/v1.0.0

This includes:
- `Collect-CFConfig.ps1` — The PowerShell collector (Windows)
- `collect-config.sh` — The bash collector (Mac/Linux)
- `CUSTOMER-GUIDE.md` — Complete documentation (how it works, what gets collected, privacy, quick start)

**Review the script first:**
- Open `Collect-CFConfig.ps1` in a text editor
- ~300 lines of straightforward PowerShell
- Verify it's only GET requests to `api.cloudflare.com`
- Ask me about anything unclear

**Then run it:**
```powershell
cd C:\wherever\you\saved\it
.\Collect-CFConfig.ps1
```

**What happens:**
- Prompts for your API token (hidden input)
- Makes ~50 read-only API calls
- Shows **immediate security observations on screen** as it runs:
  - ✅ "2FA enforcement is ON"
  - ⚠️ "3 zones using Flexible SSL (not end-to-end encrypted)"
  - ⚠️ "HTTP/3 disabled on 4 zones"
  - ✅ "WAF deployed on 5 zones"
- Applies redaction
- Writes `cloudflare-config-YYYYMMDD-HHMMSS.json` to disk
- Takes ~5-10 minutes depending on zone count

You get **immediate value on screen** (quick health check) plus the **JSON file** for detailed analysis.

### Step 3: Send Me the JSON (~2 min)

Reply with the JSON file attached. That's it.

The file contains configuration structure (settings, rules, enabled/disabled states) but no secrets. Origin IPs redacted, IDs hashed, emails stripped. Your API token was used locally and isn't in the file.

---

## What You Get Back (24-48 hours)

Detailed Markdown report with:
- Pass/Warn/Fail for all 45 checks (not just the on-screen highlights)
- Severity ratings (high/medium/low)
- Exact remediation steps ("go here, change this to that")
- Cloudflare docs citations for every recommendation
- Compliance mappings (SOC 2, PCI DSS)

**The 45 checks cover:**
- SSL/TLS (5): Encryption mode, TLS version, HSTS, Always Use HTTPS, cert expiry
- Security Settings (4): Under Attack Mode, Browser Integrity Check, Challenge Passage, Hotlink Protection
- Performance (3): HTTP/2, HTTP/3, Brotli
- WAF (3): Managed rulesets, custom rules, skip audit
- Rate Limiting (1): Login protection
- Bots (2): Verified bot handling, enforcement gaps
- DDoS (1): HTTP DDoS active
- Origin Security (2): Authenticated pulls, certs
- Page Shield (1): JS monitoring
- DNS (3): DNSSEC, CAA, mail posture
- Cache (4): HTML defaults, Dev Mode, Browser TTL, Cache Level
- Workers (2): Zombie scripts, dangling routes
- Load Balancing (2): Multiple origins, health checks
- Zero Trust Access (3): Policy coverage, bypass audit, MFA
- Zero Trust Tunnels (1): Access protection
- AI Gateway (5): Rate limits, auth, logging, DLP, guardrails
- Account Security (2): 2FA enforcement, API token hygiene
- Response Headers (1): Security header preservation

---

## Why You're First

I want to make sure this works smoothly before offering it broadly. You'll get my full attention — I'll answer questions, explain findings, walk through fixes.

**Background:** This builds on FlareGuard (MIT, declarative checks) and cloudflare-sec-inspector (verdict semantics). Cloudflare has internal tooling (Conftest/Rego, employee-only) that does similar config analysis. This rebuilds that architecture in TypeScript for customer hand-off: aggressive redaction, auditable collectors, public API only, and docs explaining what/why.

**What I'd love:** Your honest feedback — was it clear? Was the report useful? What would make it better?

---

## Questions?

Ask anything — about the script, checks, redaction, token permissions, why checks matter — whatever. I'm here.

Looking forward to this!

Jason

---

## Download Link

**📦 https://github.com/cheapredwine/cf-account-review/releases/tag/v1.0.0**

Includes:
1. `Collect-CFConfig.ps1` — PowerShell collector (Windows)
2. `collect-config.sh` — Bash collector (Mac/Linux)
3. `CUSTOMER-GUIDE.md` — Complete documentation

---

**P.S.** — The read-only guarantee is real. The tool can't write even if it wanted to — no code path for it, tests enforce it. Review the script yourself and ask about anything unclear.
