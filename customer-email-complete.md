# Complete Customer Email — Cloudflare Account Security Review

---

**Subject:** Cloudflare Security Review — Everything You Need to Get Started

---

Hi [Customer Name],

I'm excited to offer you something new: a **comprehensive security review of your Cloudflare configuration** — and you'll be the very first customer to use this tool.

> ⚠️ **IMPORTANT: NOT OFFICIAL CLOUDFLARE SOFTWARE**  
> This tool is not affiliated with or endorsed by Cloudflare, Inc. It's personal code I've developed for configuration reviews. **Please review the PowerShell script before running it** — it's ~300 lines of auditable code that you should inspect to verify it does what I'm describing.

## What This Is

This is a **strictly read-only** security assessment tool that analyzes your Cloudflare account against 35 best-practice checks across 16 security domains. Think of it as a health checkup for your Cloudflare configuration — it looks at what you have configured, compares it to documented security best practices, and shows you exactly what's working well and what could be hardened.

The tool builds on proven open-source patterns (FlareGuard's declarative baseline approach and cloudflare-sec-inspector's verdict semantics) and extends them with comprehensive API coverage, aggressive data redaction, and detailed customer-facing documentation.

**Important:** This tool has been built with three non-negotiable guarantees:

### 1. Read-Only (Enforced, Not Just Promised)
- The tool physically cannot modify your account — there is no write code
- Automated tests block any commit that would add modification capability
- Every API call is GET-only and goes exclusively to `api.cloudflare.com`
- No telemetry, no uploads, no third-party connections

### 2. Sensitive Data Never Leaves Your Environment
Your configuration is collected with aggressive redaction applied *before* anything is written to disk:

- **Origin IPs and DNS content:** Replaced with `[redacted]`
- **Account/zone/resource IDs:** Deterministically hashed (can't be reversed)
- **Email addresses:** Stripped from all output
- **API tokens:** Never appear in the output at all
- **Customer traffic/logs:** Never requested

The tool collects *configuration structure* (boolean flags, rule actions, enabled/disabled states), not sensitive values. See the detailed breakdown in the attached `WHAT-WE-PROBE.md`.

### 3. You Keep Full Control

You'll run a PowerShell script **on your own machine** using your API token. The token never leaves your environment. The script writes a single JSON file with your redacted configuration. That's what you send me — no tokens, no credentials, just the configuration snapshot.

**Before you run anything:** Review the PowerShell script. It's designed to be readable — no obfuscation, no compiled binaries, just straightforward API calls you can audit line by line.

---

## What Happens Next — Three Steps

### Step 1: Create a Read-Only API Token (5 minutes)

**Click here to create your token (opens in Cloudflare dashboard):**

👉 **[Create API Token](https://dash.cloudflare.com/profile/api-tokens?permissions=account.access_accts_and_memberships%3Aread,account.access_apps%3Aread,account.access_identity_providers%3Aread,account.access_service_tokens%3Aread,account.account_analytics%3Aread,account.account_firewall_access_rules%3Aread,account.account_rulesets%3Aread,account.account_settings%3Aread,account.api_gateway%3Aread,account.billing%3Aread,account.cloudflare_tunnel%3Aread,account.d1%3Aread,account.load_balancers%3Aread,account.logs%3Aread,account.stream%3Aread,account.workers_kv_storage%3Aread,account.workers_r2%3Aread,account.workers_scripts%3Aread,zone.access_apps_and_policies%3Aread,zone.analytics%3Aread,zone.bot_management%3Aread,zone.cache_purge%3Aread,zone.dns%3Aread,zone.firewall_services%3Aread,zone.load_balancers%3Aread,zone.logs%3Aread,zone.page_shield%3Aread,zone.ssl_and_certificates%3Aread,zone.waf%3Aread,zone.workers_routes%3Aread,zone.zone%3Aread,zone.zone_settings%3Aread)**

This link pre-selects all the required read-only permissions. If the link doesn't work, use the manual instructions below.

#### Manual Token Creation (if the link doesn't work)

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Click **"Create Token"** → **"Create Custom Token"**
3. Give it a name like "Security Review (Read-Only)"
4. **Account Permissions (select these):**
   - Account Settings: **Read**
   - Access: Apps and Policies: **Read**
   - Access: Identity Providers: **Read**
   - Access: Service Tokens: **Read**
   - Cloudflare Tunnel: **Read**
   - Workers Scripts: **Read**
   - Workers KV Storage: **Read**
   - Workers R2 Storage: **Read**
   - D1: **Read**
   - Load Balancing: Monitors and Pools: **Read**
   - Account Rulesets: **Read**
   - Turnstile Sites: **Read**
   - AI Gateway: **Read**
   - API Tokens: **Read** (User section)
   - Account API Tokens: **Read**

5. **Zone Permissions (select these for "All zones"):**
   - Zone: **Read**
   - Zone Settings: **Read**
   - Zone WAF: **Read**
   - Bot Management: **Read**
   - Firewall Services: **Read**
   - DNS: **Read**
   - SSL and Certificates: **Read**
   - Load Balancers: **Read**
   - Workers Routes: **Read**
   - Page Shield: **Read**
   - Domain API Gateway: **Read**

6. Click **"Continue to summary"** → **"Create Token"**
7. **Copy the token** (you'll only see it once!)

**Keep this token secure** — save it in your password manager or a secure note. You'll paste it into the PowerShell script when prompted.

---

### Step 2: Run the Collection Script (10 minutes)

**Attached files:**
- `Collect-CFConfig.ps1` — The PowerShell collection script
- `WHAT-WE-PROBE.md` — Complete list of what gets collected and what doesn't
- `REDACTION-AND-EVALUATION.md` — How analysis works on redacted data
- `CLIENT-GUIDE.md` — Comprehensive technical guide

**Instructions:**

1. **Review the script first** — open `Collect-CFConfig.ps1` in a text editor
   - It's ~300 lines of readable PowerShell
   - No obfuscation, no compiled binaries
   - You should verify it only does GET requests to `api.cloudflare.com`

2. **Run the script:**
   ```powershell
   # Open PowerShell and navigate to where you saved the script
   cd C:\Path\To\Script
   
   # Run it
   .\Collect-CFConfig.ps1
   
   # You'll be prompted for your API token (input is hidden)
   # Output: cloudflare-config-YYYYMMDD-HHMMSS.json
   ```

3. **What happens:**
   - Script prompts for your API token (input is hidden for security)
   - Makes read-only GET requests to Cloudflare API
   - Applies redaction (origin IPs → `[redacted]`, IDs → hashed)
   - Writes JSON file to your disk immediately
   - Token never sent anywhere, never written to the file

**What you have at this point:** A complete snapshot of your Cloudflare configuration in JSON format. This file is self-contained and includes all the data needed for analysis — you could even run the analyzer yourself if wanted.

---

### Step 3: Send Me the JSON File (5 minutes)

Reply to this email with the generated JSON file attached.

**What you're sending:** Only the JSON configuration file — no tokens, no credentials, just the redacted configuration snapshot.

**Why this matters:** The collection and analysis are separate. Your API token was used locally on your machine and never left your environment. The file you're sending me contains no secrets.

---

## What You'll Get Back (24-48 Hours)

I'll run the analyzer against your JSON and send you back a **detailed Markdown report** showing:

- **Pass/Warn/Fail verdicts** for each of the 35 checks
- **Severity ratings** (high/medium/low) for every finding
- **Exact remediation steps** with step-by-step instructions
- **Citations to official Cloudflare documentation** justifying each recommendation
- **Compliance framework mappings** (SOC 2, PCI DSS) where applicable
- **Summary statistics** (X critical issues, Y warnings, Z passing checks)

**What requires my analysis:** The JSON file is just data — turning it into actionable findings requires running it through the rulebook engine. That's what takes 24-48 hours (though likely faster since you're the first customer and I'm focused on this).

**(Future)** I'll also generate Terraform code with hardened defaults to fix the findings — you review and apply it carefully.

---

## What You'll Learn

This review will show you:

### Security Posture
- **SSL/TLS:** Is your encryption mode secure? Is TLS 1.0/1.1 still allowed?
- **WAF:** Are managed rulesets deployed and active? Do custom rules actually enforce?
- **Bot Management:** Are verified bots (Googlebot, etc.) being blocked by accident?
- **DDoS:** Are HTTP DDoS protections disabled?
- **Origin Security:** Is Authenticated Origin Pulls configured correctly?

### Configuration Hygiene
- **Workers:** Are there zombie scripts deployed but not routed to any traffic?
- **Rate Limiting:** Are authentication endpoints protected against brute force?
- **DNS:** Is DNSSEC enabled? Are CAA records present?
- **Access:** Are Zero Trust Tunnel routes protected by Access policies?

### Account Security
- **2FA:** Is two-factor authentication enforced for all account members?
- **API Tokens:** Do tokens have expiry dates set?
- **Access Apps:** Are there policy-less Access applications (bypass-all)?

### Compliance Evidence
For each check, you'll see which SOC 2 Trust Services Criteria and PCI DSS requirements it maps to — useful for audit preparation.

---

## The 35 Checks (16 Domains)

**SSL/TLS** (5 checks)
- Encryption mode, TLS version, HSTS, Always Use HTTPS, certificate expiry

**WAF** (3 checks)
- Managed rulesets deployed, custom rule enforcement, broad-skip audit

**Rate Limiting** (2 checks)
- Login endpoint protection, legacy migration signal

**Bot Management** (3 checks)
- Verified bot handling, Turnstile widgets, enforcement gaps

**DDoS** (1 check)
- HTTP DDoS managed rulesets active

**Origin Security** (2 checks)
- Authenticated Origin Pulls, zone-level certificates

**Client-Side Security** (1 check)
- Page Shield enabled

**DNS** (4 checks)
- DNSSEC, CAA records, mail posture

**Cache** (1 check)
- HTML not aggressively cached

**Workers** (2 checks)
- Zombie scripts, dangling routes

**Load Balancing** (2 checks)
- Multiple origins, health check intervals

**Zero Trust Access** (4 checks)
- Policy coverage, bypass decisions, MFA enforcement

**Zero Trust Tunnels** (1 check)
- Public routes protected by Access

**AI Gateway** (2 checks)
- Rate limiting, authentication

**Page Shield** (1 check)
- JavaScript monitoring

**Account Security** (1 check)
- 2FA enforcement, token expiry

---

## Why You're First

You're the first customer to use this tool because I wanted to ensure the experience is smooth before broader rollout. I'll be available throughout the process to answer questions, explain findings, and help you understand the remediation steps.

**About the tool:** This builds on proven open-source patterns — the declarative rulebook design is modeled on [FlareGuard](https://github.com/harshadk99/flareguard)'s baseline.yaml approach, and the verdict semantics follow [cloudflare-sec-inspector](https://github.com/ethanolivertroy/grclanker)'s spec (both MIT-licensed). I've extended these patterns with comprehensive Cloudflare API coverage, aggressive redaction, and customer-facing documentation. It's not built from scratch — it's standing on the shoulders of good prior art.

In return, I'd love your feedback:
- Was the collection process clear?
- Was the report actionable?
- What findings surprised you?
- What would make the report more useful?

---

## Ready to Start?

**Estimated time commitment on your side:** 20 minutes total
- **5 minutes:** Create the read-only API token (use the clickable link above)
- **10 minutes:** Review and run the PowerShell script
- **5 minutes:** Reply with the JSON file attached

**What you get immediately:** The complete configuration snapshot in JSON format (written to your disk)

**What I analyze on my end:** I run your JSON through the 35-check rulebook engine and return the Markdown report with findings, severity ratings, remediation steps, and compliance mappings (24-48 hours)

---

Looking forward to helping you harden your Cloudflare configuration!

Best,  
Jason

---

## Attachments

1. **Collect-CFConfig.ps1** — PowerShell collection script (~300 lines, auditable)
2. **WHAT-WE-PROBE.md** — Complete list of what the tool collects and what it explicitly does NOT collect
3. **REDACTION-AND-EVALUATION.md** — How backend analysis works on redacted data (with concrete examples)
4. **CLIENT-GUIDE.md** — Comprehensive guide with full technical details

---

**P.S.** — The read-only guarantee isn't marketing copy. The tool is designed so that even if I wanted to modify your account, I physically couldn't — there's no code path for it, and automated tests enforce that on every commit. The PowerShell script is ~300 lines of auditable code with no obfuscation — I expect you to review it before running, and I'm happy to answer questions about what any section does.
