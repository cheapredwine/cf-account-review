# Customer Email — Cloudflare Account Security Review

---

**Subject:** Here's that Cloudflare config review you asked about

---

Hey [Customer Name],

Thanks for asking about this! Here's everything you need to run a security review of your Cloudflare account. You'll be my first customer on this, which is exciting — it means I'll be focused and available throughout.

> ⚠️ **Quick heads-up:** This isn't official Cloudflare software — it's a tool I built for doing config reviews. Please **review the PowerShell script before running it** (it's ~300 lines you can read through). I'll explain what it does, but you should verify it yourself.

## What You're Getting

A security assessment of your Cloudflare account against 35 best-practice checks across 16 different areas. Think of it like a health checkup — it reads your configuration (read-only, can't change anything), compares it to documented security standards, and tells you what's solid and what could be better.

I built this because we couldn't find any existing tools that did this for Cloudflare accounts. There's some good open-source prior art (FlareGuard for the check pattern, cloudflare-sec-inspector for the pass/warn/fail approach), but nothing with comprehensive coverage of the modern Cloudflare API. So I extended those patterns and added aggressive data redaction so you can safely hand me the output.

## Three Safety Guarantees

### 1. Actually Read-Only
Not "we promise not to write" — the code physically can't. There's no write methods, automated tests block any additions, and every API call is GET-only to `api.cloudflare.com`. No telemetry, no uploads, nothing else.

### 2. Your Secrets Stay Secret
Before anything hits disk, aggressive redaction runs:
- Origin IPs and DNS content → `[redacted]`
- Account/zone/resource IDs → hashed (one-way, can't reverse)
- Email addresses → stripped
- API tokens → never in the output
- Customer traffic/logs → never requested

The tool reads **configuration structure** (is 2FA enforced? is WAF deployed? what SSL mode?), not secrets.

### 3. Token Never Leaves Your Machine
You run the PowerShell script locally. It uses your token to call the Cloudflare API, applies redaction, writes a JSON file to your disk. That's it. The token never gets sent anywhere or written to the file.

More detail in the attached `WHAT-WE-PROBE.md` if you want to see exactly what gets collected.

---

## How This Works — Three Steps

### Step 1: Create a Read-Only API Token (~5 minutes)

I've pre-built the token creation link so you don't have to hunt through permission checkboxes:

👉 **[Click here to create your read-only token](https://dash.cloudflare.com/profile/api-tokens?permissions=account.access_accts_and_memberships%3Aread,account.access_apps%3Aread,account.access_identity_providers%3Aread,account.access_service_tokens%3Aread,account.account_analytics%3Aread,account.account_firewall_access_rules%3Aread,account.account_rulesets%3Aread,account.account_settings%3Aread,account.api_gateway%3Aread,account.billing%3Aread,account.cloudflare_tunnel%3Aread,account.d1%3Aread,account.load_balancers%3Aread,account.logs%3Aread,account.stream%3Aread,account.workers_kv_storage%3Aread,account.workers_r2%3Aread,account.workers_scripts%3Aread,zone.access_apps_and_policies%3Aread,zone.analytics%3Aread,zone.bot_management%3Aread,zone.cache_purge%3Aread,zone.dns%3Aread,zone.firewall_services%3Aread,zone.load_balancers%3Aread,zone.logs%3Aread,zone.page_shield%3Aread,zone.ssl_and_certificates%3Aread,zone.waf%3Aread,zone.workers_routes%3Aread,zone.zone%3Aread,zone.zone_settings%3Aread)**

This opens the Cloudflare dashboard with all the right permissions already selected (31 read-only permissions covering account settings, Access, Workers, WAF, DNS, SSL, etc.). 

Just:
1. Click the link
2. Give it a name like "Security Review"
3. Click through to create it
4. **Copy the token** (you only see it once)
5. Save it somewhere secure (password manager is best)

If the link breaks for some reason, let me know and I'll send you the manual permission list.

---

### Step 2: Run the Collection Script (~10 minutes)

**I've attached 4 files to this email:**
1. `Collect-CFConfig.ps1` — The PowerShell collection script
2. `WHAT-WE-PROBE.md` — What the tool collects (and what it doesn't)
3. `REDACTION-AND-EVALUATION.md` — How the analysis works on redacted data
4. `CLIENT-GUIDE.md` — Full technical docs if you want them

**Here's what to do:**

1. **Review the script first** — Open `Collect-CFConfig.ps1` in a text editor
   - It's ~300 lines of straightforward PowerShell
   - No obfuscation, no compiled code
   - You should verify it's only doing GET requests to `api.cloudflare.com`
   - I'm happy to answer questions about any part of it

2. **Run it:**
   ```powershell
   cd C:\wherever\you\saved\it
   .\Collect-CFConfig.ps1
   ```

3. **What happens:**
   - Prompts for your API token (input hidden)
   - Makes ~50 read-only API calls to collect your config
   - Applies redaction as it goes
   - Writes `cloudflare-config-YYYYMMDD-HHMMSS.json` to disk
   - Takes ~5-10 minutes depending on how many zones you have

**When it's done:** You have a complete snapshot of your Cloudflare configuration in JSON format, written to your disk. It's self-contained — all the data needed for analysis is in that one file.

---

### Step 3: Send Me the JSON File (~2 minutes)

Just reply to this email with the JSON file attached. That's it.

**Important:** The file contains your configuration structure (settings, rules, enabled/disabled states) but no secrets. Origin IPs are redacted, IDs are hashed, emails are stripped. Your API token was used locally and never made it into the file.

This is why the collection and analysis are separate — your token never leaves your environment.

---

## What You Get Back (24-48 hours, probably faster)

I'll run the analyzer against your JSON and send you a detailed Markdown report:

**What's in the report:**
- Pass/Warn/Fail verdict for each of 35 checks
- Severity rating (high/medium/low) for every issue
- Exact remediation steps ("go to X, change Y to Z")
- Links to Cloudflare docs justifying each recommendation
- Compliance mappings (SOC 2, PCI DSS) for audit prep
- Summary stats (how many critical issues, warnings, passing checks)

**What you'll learn:**

Security gaps like:
- SSL/TLS weaknesses (Flexible mode, TLS 1.0/1.1 still allowed)
- WAF not deployed or disabled
- Bot management accidentally blocking Googlebot
- No rate limiting on login endpoints
- Authentication endpoints unprotected
- DNSSEC or CAA records missing

Config hygiene issues like:
- Workers deployed but not routed (zombie scripts)
- Access apps with no policies (bypass-all)
- Zero Trust tunnels exposed without Access protection
- Stale API tokens without expiry dates
- 2FA not enforced on the account

The report cites official Cloudflare docs for everything, so you know exactly why each item matters and how to fix it.

**Later:** I'm working on auto-generating Terraform code to fix the findings — you'd review it carefully before applying. Not ready yet, but that's the direction.

---

## The 35 Checks

Quick summary of what gets evaluated:

- **SSL/TLS** (5): Encryption mode, TLS version, HSTS, Always Use HTTPS, cert expiry
- **WAF** (3): Managed rulesets, custom rules, broad-skip audit
- **Rate Limiting** (2): Login protection, legacy migration
- **Bots** (3): Verified bot handling, Turnstile, enforcement gaps
- **DDoS** (1): HTTP DDoS protections active
- **Origin Security** (2): Authenticated Origin Pulls, zone certs
- **Page Shield** (1): JavaScript monitoring
- **DNS** (4): DNSSEC, CAA, mail posture
- **Cache** (1): HTML caching defaults
- **Workers** (2): Zombie scripts, dangling routes
- **Load Balancing** (2): Multiple origins, health checks
- **Zero Trust Access** (4): Policy coverage, bypass audit, MFA
- **Zero Trust Tunnels** (1): Access protection
- **AI Gateway** (2): Rate limits, auth
- **Account Security** (1): 2FA enforcement, token expiry

Full details in the attached `CLIENT-GUIDE.md`.

---

## Why You're First

Honestly, because I wanted to make sure this actually works smoothly before offering it more broadly. You'll get my full attention — I'll be available to answer questions, explain findings, and walk through remediation.

A bit of background: This builds on patterns from FlareGuard (MIT-licensed, declarative rulebook design) and cloudflare-sec-inspector (verdict semantics). Cloudflare does have internal tooling that does config-export → policy-evaluation → report (Conftest/Rego based), but that's for internal SEs and CSMs — it's not customer-facing, and you'd need to be a Cloudflare employee to use it. This tool borrows that architecture but rebuilds it in TypeScript with customer hand-off in mind: aggressive redaction, shell collectors you can audit, public API only, and documentation explaining what gets probed and why.

What I'd love in return is your honest feedback:
- Was the process clear?
- Was the report useful?
- What surprised you?
- What would make this better?

---

## Time Commitment

**About 20 minutes total:**
- 5 min: Create the API token (clickable link makes it fast)
- 10 min: Review and run the script
- 5 min: Reply with the JSON file

**You get immediately:** The JSON file on your disk (complete config snapshot)

**I deliver in 24-48 hours:** The analysis report with findings and remediation steps (probably faster since you're first)

---

## Questions?

Seriously, ask anything. About the script, the checks, the redaction, the token permissions, why a particular check matters — whatever. I'm here.

Looking forward to this!

Jason

---

## Attached Files

1. **Collect-CFConfig.ps1** — PowerShell script (~300 lines, review before running)
2. **WHAT-WE-PROBE.md** — What gets collected and what doesn't
3. **REDACTION-AND-EVALUATION.md** — How analysis works on redacted data
4. **CLIENT-GUIDE.md** — Full technical guide

---

**P.S.** — The read-only thing is real. The tool can't write to your account even if it wanted to — there's no code path for it, and tests enforce that. The script is just API calls you can read yourself. I expect you to review it before you run it, and I'm happy to explain any part that looks confusing.
