# Cloudflare Account Security Review — Complete Guide

**Last updated:** November 5, 2026  
**Tool version:** 0.1.0

> ⚠️ **NOT OFFICIAL CLOUDFLARE.** This tool is not affiliated with or endorsed by Cloudflare, Inc.
> NO WARRANTIES, EXPRESS OR IMPLIED. See [DISCLAIMER.md](../DISCLAIMER.md) for full terms.

---

## Table of Contents

1. [What This Tool Does](#what-this-tool-does)
2. [What Gets Checked](#what-gets-checked)
3. [What We Collect](#what-we-collect)
4. [Data Privacy & Redaction](#data-privacy--redaction)
5. [How It Works](#how-it-works)
6. [Option 1: You Run the Collector](#option-1-you-run-the-collector)
7. [Option 2: We Run the Collector](#option-2-we-run-the-collector)
8. [PowerShell Collector Quick Start](#powershell-collector-quick-start)
9. [Bash Collector Quick Start](#bash-collector-quick-start)
10. [What You Get Back](#what-you-get-back)
11. [Support and Questions](#support-and-questions)

---

## What This Tool Does

This is a **strictly read-only** security configuration review tool for Cloudflare accounts. It:

1. **Collects** your Cloudflare configuration through the public API
2. **Analyzes** it against 45 security best-practice checks across 18 domains
3. **Produces** a detailed Markdown report where every finding cites official Cloudflare documentation

### Hard Guarantees

- **READ ONLY** — The tool has no write code and is enforced by automated tests. It cannot modify your account.
- **Never records sensitive data** — DNS contents, origin IPs, account IDs (hashed only), email addresses, and API tokens are redacted or never collected.
- **Never exfiltrates** — All API calls go exclusively to `api.cloudflare.com`. No telemetry, no uploads, no third-party connections.
- **Fail-closed** — If the tool cannot read data needed for a check, it reports "manual review required," never "passed."

---

## What Gets Checked

The tool evaluates **45 security checks** across these areas:

### Security Domains Covered

- **SSL/TLS (5 checks):** Full(strict) encryption mode, minimum TLS 1.2+, HSTS enabled, certificate expiry, Always Use HTTPS
- **Security Settings (4 checks):** Under Attack Mode, Browser Integrity Check, Challenge Passage duration, Hotlink Protection
- **Performance (3 checks):** HTTP/2, HTTP/3, Brotli compression
- **WAF (3 checks):** Managed rulesets deployed and active, custom firewall rules with enforcement
- **Rate Limiting (1 check):** Protection on authentication endpoints
- **Bot Management (2 checks):** Verified bot handling, enforcement gaps
- **DDoS Protection (1 check):** HTTP DDoS managed rulesets not disabled
- **Origin Security (2 checks):** Authenticated Origin Pulls enabled, zone-level certificates preferred
- **Client-Side Security (1 check):** Page Shield enabled for JavaScript monitoring
- **DNS (3 checks):** DNSSEC enabled, CAA records present, email security posture
- **Cache (4 checks):** HTML not cached aggressively, Development Mode not left on, Browser Cache TTL appropriate, Cache Level matches zone purpose
- **Workers (2 checks):** Zombie scripts (deployed but unrouted), dangling routes
- **Load Balancing (2 checks):** Multiple origins per pool for failover, health check intervals
- **Zero Trust Access (3 checks):** Access policies on apps, bypass decision audit, MFA requirements
- **Zero Trust Tunnels (1 check):** Public tunnel routes protected by Access applications
- **AI Gateway (5 checks):** Rate limits, authentication, logging, DLP policies, prompt guardrails
- **Account Security (2 checks):** 2FA enforcement, API token hygiene
- **Response Headers (1 check):** Security header preservation

### Check Verdicts

Each check produces one of these verdicts:

- **pass** — Meets best practice
- **fail** — Does not meet best practice (actionable finding)
- **warn** — Potentially risky configuration that may be intentional
- **manual** — Requires human judgment or the tool couldn't read the necessary data
- **na** — Not applicable (e.g., no Load Balancers configured, so no LB checks run)

### Plan Tier Support

Checks are marked with minimum plan requirements:

- **free** — Works on Free, Pro, Business, Enterprise
- **pro** — Requires Pro or higher
- **business** — Requires Business or higher
- **enterprise** — Requires Enterprise

The tool will not run checks that require a higher plan than your zones have.

---

## What We Collect

### Account-Level Data

- Account ID (hashed in output)
- Account name (hashed in output)
- Account settings (2FA enforcement, IP geo settings)
- API tokens metadata (last 4 chars only, scopes, expiration status)
- Account members count (not identities)

### Zone-Level Data

For each zone in your account:

- Zone ID (hashed in output)
- Zone name (redacted in output — replaced with `zone-<hash>.example`)
- Zone plan (`free`, `pro`, `business`, `enterprise`)
- Zone status (`active`, `pending`, etc.)

### Security & Performance Settings

- **SSL/TLS:** encryption mode, minimum TLS version, HSTS settings, Always Use HTTPS
- **Security:** Browser Integrity Check, Challenge Passage, Hotlink Protection, Under Attack Mode
- **Performance:** HTTP/2, HTTP/3, Brotli, cache settings, Development Mode
- **WAF:** deployed managed rulesets, custom firewall rules (counts/actions, no match patterns)
- **Rate Limiting:** rule counts, actions (no rate values or match patterns)
- **Bot Management:** presence/absence of config (no ML scores)
- **DDoS:** L7 ruleset status
- **Origin:** Authenticated Origin Pull status, certificate presence (no private keys)
- **Page Shield:** enabled status (no detected scripts)

### DNS Data (Redacted)

- **DNS records:** type and count only — all target IPs, CNAMEs, MX hostnames, and TXT content are **redacted**
- **DNSSEC:** enabled/disabled status
- **CAA records:** presence/absence only (no specific values)

### Zero Trust

- **Access applications:** count, policy structure (no identity expressions)
- **Tunnels:** route counts, public/private exposure (no hostnames, no connector IPs)

### AI Gateway

- Gateway IDs (hashed), rate limit presence, authentication requirement, logging status (no prompts/responses)

### Workers & Load Balancers

- **Workers:** script names (hashed), routes (redacted), deployment status
- **Load Balancers:** pool/origin counts, health check intervals (no origin IPs)

### What We NEVER Collect

- **Credentials:** No API tokens, passwords, certificates, private keys
- **Origin IPs:** All origin server IPs are redacted
- **DNS content:** All A/AAAA/CNAME target IPs and hostnames are redacted
- **Personal data:** No email addresses, user identities, customer IPs
- **Application logic:** No WAF rule patterns, Rate Limiting match expressions, Worker code

---

## Data Privacy & Redaction

### Redaction Strategy

The tool applies **aggressive redaction** before any data leaves your environment:

1. **DNS records:** All A/AAAA/CNAME targets, MX hostnames, TXT content → `<redacted>`
2. **Origin IPs:** All origin server IPs → `<redacted-origin-ip>`
3. **Account/Zone IDs:** SHA-256 hashed (one-way, non-reversible)
4. **Zone names:** Replaced with `zone-<hash>.example`
5. **Email addresses:** Never collected (member count only)
6. **API tokens:** Never sent (you create a read-only token, run the tool locally, delete the token)

### Why Evaluation Works on Redacted Data

The analyzer evaluates **configuration structure and settings**, not content:

- **"Is DNSSEC enabled?"** — Yes/no flag in the API response
- **"Is TLS 1.2+ enforced?"** — Minimum TLS version setting
- **"Are WAF rulesets deployed?"** — Ruleset deployment status and actions
- **"Are there CAA records?"** — Record type presence, not content

**What requires un-redacted data:**
- Validating specific DNS targets (we don't do this)
- Inspecting WAF rule patterns (we don't do this)
- Auditing origin server security posture (out of scope)

The tool performs **configuration posture assessment**, not deep content inspection.

---

## How It Works

### Two Collection Options

**Option 1: You run the collector (recommended)**
- You create a read-only API token (takes 5 minutes)
- You run a PowerShell or bash script locally (10 minutes)
- The script shows you real-time security observations while running
- You send us ONLY the generated JSON file (already redacted)
- You delete the API token immediately after

**Option 2: We run the collector (if you prefer)**
- You create a read-only API token
- You send us the token via secure channel (1Password, etc.)
- We run the collector and return the results
- We delete the token immediately after collection

### Timeline

- **Your time:** ~20 minutes total
  - 5 minutes: Create read-only API token via clickable link
  - 10 minutes: Run collector + watch real-time feedback
  - 5 minutes: Send JSON file
- **Our turnaround:** Same business day (maximum 48 hours)

---

## Option 1: You Run the Collector

### Step 1: Create Read-Only API Token

**Use this pre-configured link** to create a token with the exact permissions we need (31 read-only permissions, no write access):

👉 **[Create Read-Only Review Token](https://dash.cloudflare.com/?to=/:account/profile/api-tokens&create=eyJuYW1lIjoiQ0YgQWNjb3VudCBSZXZpZXciLCJwb2xpY2llcyI6W3siZWZmZWN0IjoiYWxsb3ciLCJyZXNvdXJjZXMiOnsiY29tLmNsb3VkZmxhcmUuYXBpLmFjY291bnQiOnsiaW4iOlt7ImlkIjoiYWxsIn1dfX0sInBlcm1pc3Npb25fZ3JvdXBzIjpbeyJpZCI6IjFhNTI4MzdiNzhjNTRkMmMxNTY1MjY3MWM5NjlkZDQzIiwibmFtZSI6IkFjY291bnQgU2V0dGluZ3MgUmVhZCJ9LHsiaWQiOiJlMTdhZmU1MjFkNjc0NTE3YThjNjA2NzU1YWJkMmZkZCIsIm5hbWUiOiJXb3JrZXJzIFIyIFJlYWQifSx7ImlkIjoiZTBkZGVmYzZlNGM5ZGY5YmQ2M2VmZDllZDIwYzBkNmIiLCJuYW1lIjoiWmVybyBUcnVzdCBSZWFkIn0seyJpZCI6IjNkODYwNDVmNGM5MjQyZTc5MTk1ZGI3ZDU4NWQzNTgzIiwibmFtZSI6IkFjY2VzcyBBcHBsaWNhdGlvbnMgYW5kIFBvbGljaWVzIFJlYWQifSx7ImlkIjoiYjI5YTM4YWIwMzI1NGIxODhmNGI0NzM4YzI1MjJhNWYiLCJuYW1lIjoiV29ya2VycyBTY3JpcHRzIFJlYWQifSx7ImlkIjoiMzAzMDY4N2YzYzcwNDEzODkwN2Q1YWJmNDBkZDFjMGQiLCJuYW1lIjoiVHVybnN0aWxlIFJlYWQifSx7ImlkIjoiZjdmMDVlYTM0YTIyNGRkMWFhYzgxYWU0YTgzZjg0M2EiLCJuYW1lIjoiQUkgR2F0ZXdheSBSZWFkIn0seyJpZCI6IjI0ZTAxMGQ3ZGI0MDQ5Y2Q4YTQ0N2FmMTBjZDc2YTIzIiwibmFtZSI6IkFQSSBUb2tlbnMgUmVhZCJ9XX0seyJlZmZlY3QiOiJhbGxvdyIsInJlc291cmNlcyI6eyJjb20uY2xvdWRmbGFyZS5hcGkuYWNjb3VudC56b25lIjp7ImluIjpbeyJpZCI6ImFsbCJ9XX19LCJwZXJtaXNzaW9uX2dyb3VwcyI6W3siaWQiOiJjOGZlZDIwMzlhZTA0MGM1OTE3YjU2YjFjZjMwMDZkNCIsIm5hbWUiOiJab25lIFJlYWQifSx7ImlkIjoiNDc1NWE1NjlmZTEzNTQyODIzMjY4Nzg1ZmZhMThmMzMiLCJuYW1lIjoiWm9uZSBTZXR0aW5ncyBSZWFkIn0seyJpZCI6IjgyZTY0YTgzZmY4MTQwNDFhYzYzMzYxMzYwZTdhOWRjIiwibmFtZSI6IkROUyBSZWFkIn0seyJpZCI6IjI0NTJhNGYwZDU5NDQxMDFiZjFkMzQ1YzljOGQxNjY5IiwibmFtZSI6IkZpcmV3YWxsIFNlcnZpY2VzIFJlYWQifSx7ImlkIjoiZTYzN2ZmZmFhOWVkNDY4ZDgzNTA2ZjQxY2MyYzMwOWQiLCJuYW1lIjoiWm9uZSBXQUYgUmVhZCJ9LHsiaWQiOiI4MjA4NTVhZjQwNGY0ZjY3ODQ4MjA4OTA4YTQxN2M1NSIsIm5hbWUiOiJSYXRlIExpbWl0aW5nIFJlYWQifSx7ImlkIjoiZTZkZWNkMDE3YjMyNDZmOGIzMDQxZWE0ODhkYzJkMTciLCJuYW1lIjoiUGFnZSBTaGllbGQgUmVhZCJ9LHsiaWQiOiI0NzU1YTU2OWZlMTM1NDI4MjMyNjg3ODVmZmExOGYzMyIsIm5hbWUiOiJTU0wgYW5kIENlcnRpZmljYXRlcyBSZWFkIn0seyJpZCI6ImM4ZmVkMjAzOWFlMDQwYzU5MTdiNTZiMWNmMzAwNmQ0IiwibmFtZSI6IkxvYWQgQmFsYW5jaW5nIFJlYWQifV19XX0)**

This link pre-fills all required permissions. Just click **Continue to summary** → **Create Token**.

**Token name suggestion:** `CF Account Review`

### Step 2: Download the Collector

Download from the [latest release](https://github.com/cheapredwine/cf-account-review/releases/latest):

- **Windows:** `Collect-CFConfig.ps1` (PowerShell)
- **Mac/Linux:** `collect-config.sh` (bash)

### Step 3: Review the Script

**BEFORE RUNNING:** Open the script in a text editor and read it. Verify:
- Only `GET` requests (no POST/PUT/PATCH/DELETE)
- All calls to `api.cloudflare.com` only
- Redaction logic present

### Step 4: Run the Collector

**PowerShell (Windows):**
```powershell
$env:CF_API_TOKEN = "your-token-here"
.\Collect-CFConfig.ps1
```

**Bash (Mac/Linux):**
```bash
export CF_API_TOKEN="your-token-here"
bash collect-config.sh
```

### What You'll See (Real-Time Feedback)

The collector shows immediate security observations while running:

```
============================================================================
IMMEDIATE SECURITY OBSERVATIONS
============================================================================

ACCOUNT SECURITY:
  → 2FA Status: ENFORCED (members must use two-factor authentication) ✓
  → API Tokens: 3 active tokens found
    WARNING: 1 token has not been used in 90+ days

SSL/TLS CONFIGURATION:
  zone-abc123.example:
    → SSL Mode: Full (strict) ✓
    → TLS 1.2+: Yes ✓
    → HSTS: No ⚠️
    
  zone-def456.example:
    → SSL Mode: Flexible ⚠️ (WARNING: Traffic between Cloudflare and origin is unencrypted)
    → TLS 1.2+: No ⚠️ (TLS 1.0 allowed)

DNS SECURITY:
  zone-abc123.example:
    → DNSSEC: ENABLED ✓

WAF & SECURITY:
  zone-abc123.example:
    → WAF Managed Rulesets: 2 active rulesets ✓
    → Custom Firewall Rules: 3 rules found
    
  zone-def456.example:
    → WAF Managed Rulesets: None deployed ⚠️

PERFORMANCE:
  zone-abc123.example:
    → HTTP/2: Enabled ✓
    → HTTP/3: Disabled ⚠️

[... more categories ...]

============================================================================
COLLECTION COMPLETE
============================================================================
Output file: cloudflare-config-20261105-143022.json
```

**16 categories with immediate feedback:**
1. Account 2FA status
2. API token hygiene
3. SSL/TLS mode per zone
4. TLS version enforcement
5. DNSSEC status
6. WAF deployment
7. Bot Management presence
8. DDoS protections
9. Development Mode warnings
10. Under Attack Mode status
11. HTTP/2 enablement
12. HTTP/3 enablement
13. Workers deployment
14. Access applications
15. Cloudflare Tunnels
16. Load Balancers

### Step 5: Verify the Output

Open the generated JSON file in a text editor and spot-check:
- Zone names: `zone-<hash>.example` (not real domains)
- IPs: `<redacted-origin-ip>` or `<redacted>`
- Account/Zone IDs: Long hex strings (hashed)

### Step 6: Send the JSON File

Send ONLY the JSON file via:
- Secure email
- File sharing service (Dropbox, Google Drive, etc.)
- 1Password secure note

**DO NOT send your API token.**

### Step 7: Delete the Token

Go back to your [Cloudflare API Tokens page](https://dash.cloudflare.com/profile/api-tokens) and delete the review token immediately.

---

## Option 2: We Run the Collector

If you prefer not to run the script yourself:

### Process

1. **You create the token** using the [pre-configured link](https://dash.cloudflare.com/?to=/:account/profile/api-tokens&create=eyJuYW1lIjoiQ0YgQWNjb3VudCBSZXZpZXciLCJwb2xpY2llcyI6W3siZWZmZWN0IjoiYWxsb3ciLCJyZXNvdXJjZXMiOnsiY29tLmNsb3VkZmxhcmUuYXBpLmFjY291bnQiOnsiaW4iOlt7ImlkIjoiYWxsIn1dfX0sInBlcm1pc3Npb25fZ3JvdXBzIjpbeyJpZCI6IjFhNTI4MzdiNzhjNTRkMmMxNTY1MjY3MWM5NjlkZDQzIiwibmFtZSI6IkFjY291bnQgU2V0dGluZ3MgUmVhZCJ9LHsiaWQiOiJlMTdhZmU1MjFkNjc0NTE3YThjNjA2NzU1YWJkMmZkZCIsIm5hbWUiOiJXb3JrZXJzIFIyIFJlYWQifSx7ImlkIjoiZTBkZGVmYzZlNGM5ZGY5YmQ2M2VmZDllZDIwYzBkNmIiLCJuYW1lIjoiWmVybyBUcnVzdCBSZWFkIn0seyJpZCI6IjNkODYwNDVmNGM5MjQyZTc5MTk1ZGI3ZDU4NWQzNTgzIiwibmFtZSI6IkFjY2VzcyBBcHBsaWNhdGlvbnMgYW5kIFBvbGljaWVzIFJlYWQifSx7ImlkIjoiYjI5YTM4YWIwMzI1NGIxODhmNGI0NzM4YzI1MjJhNWYiLCJuYW1lIjoiV29ya2VycyBTY3JpcHRzIFJlYWQifSx7ImlkIjoiMzAzMDY4N2YzYzcwNDEzODkwN2Q1YWJmNDBkZDFjMGQiLCJuYW1lIjoiVHVybnN0aWxlIFJlYWQifSx7ImlkIjoiZjdmMDVlYTM0YTIyNGRkMWFhYzgxYWU0YTgzZjg0M2EiLCJuYW1lIjoiQUkgR2F0ZXdheSBSZWFkIn0seyJpZCI6IjI0ZTAxMGQ3ZGI0MDQ5Y2Q4YTQ0N2FmMTBjZDc2YTIzIiwibmFtZSI6IkFQSSBUb2tlbnMgUmVhZCJ9XX0seyJlZmZlY3QiOiJhbGxvdyIsInJlc291cmNlcyI6eyJjb20uY2xvdWRmbGFyZS5hcGkuYWNjb3VudC56b25lIjp7ImluIjpbeyJpZCI6ImFsbCJ9XX19LCJwZXJtaXNzaW9uX2dyb3VwcyI6W3siaWQiOiJjOGZlZDIwMzlhZTA0MGM1OTE3YjU2YjFjZjMwMDZkNCIsIm5hbWUiOiJab25lIFJlYWQifSx7ImlkIjoiNDc1NWE1NjlmZTEzNTQyODIzMjY4Nzg1ZmZhMThmMzMiLCJuYW1lIjoiWm9uZSBTZXR0aW5ncyBSZWFkIn0seyJpZCI6IjgyZTY0YTgzZmY4MTQwNDFhYzYzMzYxMzYwZTdhOWRjIiwibmFtZSI6IkROUyBSZWFkIn0seyJpZCI6IjI0NTJhNGYwZDU5NDQxMDFiZjFkMzQ1YzljOGQxNjY5IiwibmFtZSI6IkZpcmV3YWxsIFNlcnZpY2VzIFJlYWQifSx7ImlkIjoiZTYzN2ZmZmFhOWVkNDY4ZDgzNTA2ZjQxY2MyYzMwOWQiLCJuYW1lIjoiWm9uZSBXQUYgUmVhZCJ9LHsiaWQiOiI4MjA4NTVhZjQwNGY0ZjY3ODQ4MjA4OTA4YTQxN2M1NSIsIm5hbWUiOiJSYXRlIExpbWl0aW5nIFJlYWQifSx7ImlkIjoiZTZkZWNkMDE3YjMyNDZmOGIzMDQxZWE0ODhkYzJkMTciLCJuYW1lIjoiUGFnZSBTaGllbGQgUmVhZCJ9LHsiaWQiOiI0NzU1YTU2OWZlMTM1NDI4MjMyNjg3ODVmZmExOGYzMyIsIm5hbWUiOiJTU0wgYW5kIENlcnRpZmljYXRlcyBSZWFkIn0seyJpZCI6ImM4ZmVkMjAzOWFlMDQwYzU5MTdiNTZiMWNmMzAwNmQ0IiwibmFtZSI6IkxvYWQgQmFsYW5jaW5nIFJlYWQifV19XX0)
2. **Send us the token** via secure channel (1Password share, encrypted email, secure Slack DM)
3. **We run the collector** and return your report
4. **We delete the token** immediately after collection

**Turnaround:** Same business day; maximum 48 hours.

**What you get back:** Same as Option 1 — detailed report with findings, recommendations, and remediation steps.

---

## PowerShell Collector Quick Start

### Requirements

- Windows PowerShell 5.1+ or PowerShell Core 7+
- Internet access to `api.cloudflare.com`
- Read-only Cloudflare API token

### Basic Usage

```powershell
# Set your token
$env:CF_API_TOKEN = "your-read-only-token-here"

# Run the collector
.\Collect-CFConfig.ps1

# Output: cloudflare-config-YYYYMMDD-HHMMSS.json
```

### Advanced Options

```powershell
# Specify output filename
.\Collect-CFConfig.ps1 -OutputFile "my-review.json"

# Skip real-time security observations (quiet mode)
.\Collect-CFConfig.ps1 -Quiet

# Collect only specific zones
.\Collect-CFConfig.ps1 -ZoneFilter "example.com,another.com"
```

### Troubleshooting

**"Execution policy error"**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Collect-CFConfig.ps1
```

**"API token not found"**
- Verify token is set: `$env:CF_API_TOKEN`
- Token must have the 31 read-only permissions listed above

**"Rate limit errors"**
- The script automatically retries with exponential backoff
- Large accounts (100+ zones) may take 15-20 minutes

---

## Bash Collector Quick Start

### Requirements

- Bash 4.0+
- `curl` and `jq` installed
- Internet access to `api.cloudflare.com`
- Read-only Cloudflare API token

### Basic Usage

```bash
# Set your token
export CF_API_TOKEN="your-read-only-token-here"

# Run the collector
bash collect-config.sh

# Output: cloudflare-config-YYYYMMDD-HHMMSS.json
```

### Advanced Options

```bash
# Specify output filename
bash collect-config.sh -o my-review.json

# Skip real-time security observations (quiet mode)
bash collect-config.sh --quiet

# Collect only specific zones
bash collect-config.sh --zones "example.com,another.com"
```

### Troubleshooting

**"jq: command not found"**
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# CentOS/RHEL
sudo yum install jq
```

**"curl: command not found"**
```bash
# Ubuntu/Debian
sudo apt-get install curl

# CentOS/RHEL
sudo yum install curl
```

---

## What You Get Back

### Detailed Security Report

A Markdown document with:

1. **Executive Summary**
   - Overall security posture
   - Critical findings count
   - High-priority recommendations

2. **Per-Zone Findings**
   - SSL/TLS configuration gaps
   - WAF deployment status
   - DNS security posture
   - Performance optimizations
   - Zero Trust coverage

3. **Account-Level Findings**
   - 2FA enforcement status
   - API token hygiene
   - Workers deployment patterns

4. **Remediation Steps**
   - Step-by-step instructions for each finding
   - Official Cloudflare documentation links
   - Priority guidance (critical → nice-to-have)

5. **Compliance Mapping** (if requested)
   - PCI DSS requirements coverage
   - SOC 2 control alignment
   - GDPR technical measures

### Example Finding

```markdown
### Finding: Flexible SSL Mode Detected

**Zone:** zone-abc123.example  
**Severity:** High  
**Plan Requirement:** Free+

**Current State:**
- SSL/TLS encryption mode: Flexible
- Traffic between Cloudflare and your origin is unencrypted (HTTP)

**Risk:**
- Credentials, session tokens, and sensitive data transmitted in clear text
- Vulnerable to man-in-the-middle attacks on origin infrastructure

**Remediation:**
1. Install an SSL certificate on your origin server (use Cloudflare Origin CA or Let's Encrypt)
2. Configure your origin to accept HTTPS connections on port 443
3. Change Cloudflare SSL mode to "Full (strict)" in dashboard → SSL/TLS → Overview
4. Verify with: `curl -I https://your-origin-server.example`

**Documentation:**
- [SSL Modes](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/)
- [Cloudflare Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)

**Estimated Time:** 30-60 minutes
```

---

## Support and Questions

### Before Running

- Review this guide completely
- Read the PowerShell/bash script before executing
- Verify the API token has only read permissions
- Test on a non-production account first (if possible)

### During Collection

- The script will show real-time progress and immediate observations
- Expect 10-15 minutes for accounts with 10-50 zones
- Large accounts (100+ zones) may take 20+ minutes

### After Collection

- Verify the JSON file contains no real domain names or IPs
- Send ONLY the JSON file (never your API token)
- Delete the API token from Cloudflare dashboard immediately

### Common Questions

**Q: Can this tool modify my account?**  
A: No. The tool is strictly read-only and enforced by automated tests. It cannot create, update, or delete any configuration.

**Q: Will you see my origin IPs?**  
A: No. All origin IPs are redacted before data leaves your environment.

**Q: What if I have 100+ zones?**  
A: The collector handles large accounts automatically. Expect ~20 minutes runtime and rate limit handling.

**Q: Can I run this on a subset of zones?**  
A: Yes. Use `-ZoneFilter "zone1.com,zone2.com"` (PowerShell) or `--zones "zone1.com,zone2.com"` (bash).

**Q: Do you store the collected data?**  
A: We retain the JSON file only for the duration of analysis (24-48 hours), then securely delete it.

**Q: Can I run this regularly?**  
A: Yes. Create a fresh read-only token each time, run the collector, and delete the token after. We recommend quarterly reviews.

**Q: What about Enterprise-only features?**  
A: The tool automatically detects your plan tier and only runs checks applicable to your zones.

---

## License & Disclaimer

This tool is provided under the MIT License. See [LICENSE](../LICENSE) for details.

**NOT OFFICIAL CLOUDFLARE.** This tool is not affiliated with or endorsed by Cloudflare, Inc.

**NO WARRANTIES, EXPRESS OR IMPLIED.** See [DISCLAIMER.md](../DISCLAIMER.md) for complete terms.

**Use at your own risk.** Always review the collector script before running it.

---

**Questions?** Contact us before sending any data.

**Ready to start?** [Create your read-only token](https://dash.cloudflare.com/?to=/:account/profile/api-tokens&create=eyJuYW1lIjoiQ0YgQWNjb3VudCBSZXZpZXciLCJwb2xpY2llcyI6W3siZWZmZWN0IjoiYWxsb3ciLCJyZXNvdXJjZXMiOnsiY29tLmNsb3VkZmxhcmUuYXBpLmFjY291bnQiOnsiaW4iOlt7ImlkIjoiYWxsIn1dfX0sInBlcm1pc3Npb25fZ3JvdXBzIjpbeyJpZCI6IjFhNTI4MzdiNzhjNTRkMmMxNTY1MjY3MWM5NjlkZDQzIiwibmFtZSI6IkFjY291bnQgU2V0dGluZ3MgUmVhZCJ9LHsiaWQiOiJlMTdhZmU1MjFkNjc0NTE3YThjNjA2NzU1YWJkMmZkZCIsIm5hbWUiOiJXb3JrZXJzIFIyIFJlYWQifSx7ImlkIjoiZTBkZGVmYzZlNGM5ZGY5YmQ2M2VmZDllZDIwYzBkNmIiLCJuYW1lIjoiWmVybyBUcnVzdCBSZWFkIn0seyJpZCI6IjNkODYwNDVmNGM5MjQyZTc5MTk1ZGI3ZDU4NWQzNTgzIiwibmFtZSI6IkFjY2VzcyBBcHBsaWNhdGlvbnMgYW5kIFBvbGljaWVzIFJlYWQifSx7ImlkIjoiYjI5YTM4YWIwMzI1NGIxODhmNGI0NzM4YzI1MjJhNWYiLCJuYW1lIjoiV29ya2VycyBTY3JpcHRzIFJlYWQifSx7ImlkIjoiMzAzMDY4N2YzYzcwNDEzODkwN2Q1YWJmNDBkZDFjMGQiLCJuYW1lIjoiVHVybnN0aWxlIFJlYWQifSx7ImlkIjoiZjdmMDVlYTM0YTIyNGRkMWFhYzgxYWU0YTgzZjg0M2EiLCJuYW1lIjoiQUkgR2F0ZXdheSBSZWFkIn0seyJpZCI6IjI0ZTAxMGQ3ZGI0MDQ5Y2Q4YTQ0N2FmMTBjZDc2YTIzIiwibmFtZSI6IkFQSSBUb2tlbnMgUmVhZCJ9XX0seyJlZmZlY3QiOiJhbGxvdyIsInJlc291cmNlcyI6eyJjb20uY2xvdWRmbGFyZS5hcGkuYWNjb3VudC56b25lIjp7ImluIjpbeyJpZCI6ImFsbCJ9XX19LCJwZXJtaXNzaW9uX2dyb3VwcyI6W3siaWQiOiJjOGZlZDIwMzlhZTA0MGM1OTE3YjU2YjFjZjMwMDZkNCIsIm5hbWUiOiJab25lIFJlYWQifSx7ImlkIjoiNDc1NWE1NjlmZTEzNTQyODIzMjY4Nzg1ZmZhMThmMzMiLCJuYW1lIjoiWm9uZSBTZXR0aW5ncyBSZWFkIn0seyJpZCI6IjgyZTY0YTgzZmY4MTQwNDFhYzYzMzYxMzYwZTdhOWRjIiwibmFtZSI6IkROUyBSZWFkIn0seyJpZCI6IjI0NTJhNGYwZDU5NDQxMDFiZjFkMzQ1YzljOGQxNjY5IiwibmFtZSI6IkZpcmV3YWxsIFNlcnZpY2VzIFJlYWQifSx7ImlkIjoiZTYzN2ZmZmFhOWVkNDY4ZDgzNTA2ZjQxY2MyYzMwOWQiLCJuYW1lIjoiWm9uZSBXQUYgUmVhZCJ9LHsiaWQiOiI4MjA4NTVhZjQwNGY0ZjY3ODQ4MjA4OTA4YTQxN2M1NSIsIm5hbWUiOiJSYXRlIExpbWl0aW5nIFJlYWQifSx7ImlkIjoiZTZkZWNkMDE3YjMyNDZmOGIzMDQxZWE0ODhkYzJkMTciLCJuYW1lIjoiUGFnZSBTaGllbGQgUmVhZCJ9LHsiaWQiOiI0NzU1YTU2OWZlMTM1NDI4MjMyNjg3ODVmZmExOGYzMyIsIm5hbWUiOiJTU0wgYW5kIENlcnRpZmljYXRlcyBSZWFkIn0seyJpZCI6ImM4ZmVkMjAzOWFlMDQwYzU5MTdiNTZiMWNmMzAwNmQ0IiwibmFtZSI6IkxvYWQgQmFsYW5jaW5nIFJlYWQifV19XX0) and [download the collector](https://github.com/cheapredwine/cf-account-review/releases/latest).
