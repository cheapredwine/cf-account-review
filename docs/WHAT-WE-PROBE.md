# What cf-account-review Probes

This document explains what the cf-account-review tool collects from your Cloudflare account and how it accesses that data. This applies to **both** the lite (public, 23 checks) and full (SE-assisted, 45 checks) rulebook tiers — see `docs/LITE-VS-FULL.md` for tier differences.

## Read-only guarantee

**The tool is strictly read-only.** It only performs HTTP GET requests to the Cloudflare API. It:

- ✅ **Does** read configuration metadata
- ❌ **Does not** create, modify, or delete anything
- ❌ **Does not** change settings
- ❌ **Does not** access customer traffic or logs
- ❌ **Does not** read credentials beyond token verification

Every collection run is a snapshot of your current configuration — nothing changes in your account.

## What we collect

The tool collects configuration metadata from these Cloudflare products and features:

### Account-level

- **Account settings:** Two-factor authentication enforcement, API token access policy
- **Account members:** User count and role distribution (no emails, no names)
- **Cloudflare Tunnel:** Tunnel inventory (connection count, status) — no tunnel credentials
- **AI Gateway:** Gateway inventory, rate limiting configuration, cache settings, logging status
- **Load Balancer pools:** Pool configuration, origin health check settings, enabled/disabled state
- **Workers & Pages:** Script/project inventory, route coverage, binding types — no code, no environment variables

### Zone-level (per domain)

- **Zone metadata:** Plan type, status, name servers
- **SSL/TLS:** Encryption mode, minimum TLS version, HSTS settings, Always Use HTTPS
- **WAF (Web Application Firewall):** Managed ruleset deployment, custom rules (expressions only, no secrets), rate limiting rules
- **Bot Management:** Bot Fight Mode status, Super Bot Fight Mode configuration, verified bot allowlists
- **Response headers:** Security header configuration (CSP, X-Frame-Options, etc.) — header names and operations only, values are redacted
- **DNS:** Record types and proxying status — **content (IPs, CNAMEs) is redacted**
- **Page Rules:** Rule count and order
- **Page Shield:** Script monitoring status, connection monitoring
- **DDoS settings:** HTTP DDoS, Layer 3/4 DDoS sensitivity settings
- **Authenticated Origin Pulls:** Certificate validation configuration
- **Cache:** Cache level, browser TTL, development mode status
- **Rulesets:** Transform rules, firewall rules (expressions only)

## What we explicitly DO NOT collect

### Never requested

These are **not collected at all** — the tool never requests them:

- ❌ Customer traffic or analytics data
- ❌ Request logs or error logs
- ❌ User credentials (passwords, API tokens beyond verification)
- ❌ Email addresses, phone numbers, or personal information
- ❌ Payment information or billing data
- ❌ Workers code or environment variables
- ❌ Custom TLS certificates (private keys)
- ❌ R2 bucket contents
- ❌ KV namespace contents
- ❌ D1 database contents

### Collected but redacted

These fields **are requested** but their values are **replaced with `[redacted]`** before storage:

- 🔒 DNS record content (origin IPs, CNAME targets)
- 🔒 Email addresses in rule descriptions or comments
- 🔒 Transform rule header values (header names kept, values redacted)
- 🔒 IP addresses that appear to be origin servers in WAF expressions

### Hashed for privacy

- 🔐 Account IDs (deterministically hashed: `h` + first 16 hex chars of SHA-256)
- 🔐 Zone IDs (deterministically hashed)
- 🔐 Resource IDs (pools, monitors, tunnels, scripts, rulesets — all hashed)

Hashing prevents accidental leakage of infrastructure identifiers while preserving the ability to match findings across multiple review runs.

## How we access your data

### Required API token permissions

The tool requires a Cloudflare API token with **read-only permissions** scoped to:

- Account Settings (Read)
- Account Rulesets (Read)
- Access: Apps and Policies (Read)
- DNS (Read)
- Load Balancers (Read)
- Zone (Read)
- Zone Settings (Read)
- Workers Scripts (Read)

**We recommend:**
1. Create a dedicated token for this tool
2. Use the minimum necessary permissions (read-only scopes above)
3. Set a token expiration date
4. Revoke the token after the review is complete

### Token handling

- The tool reads the token from the `CF_API_TOKEN` environment variable
- The token is **never printed** to the screen or log files
- The token is **never stored** in the output file
- Token verification uses the Cloudflare API's `/user/tokens/verify` endpoint (result: "active" or "verification-failed")

### Mode A vs. Mode B

The tool has two collection modes:

**Mode A (Node.js collector):**
- Runs on a Cloudflare Solutions Engineer's machine
- Uses the TS/Node.js collector (`cf-account-review collect`)
- Output stays with the SE for analysis

**Mode B (Bash/PowerShell collectors):**
- Runs in **your environment** with **your token**
- Shell scripts (`collect.sh` or `Collect.ps1`) you run yourself
- You receive the output file and can inspect it before sharing
- Unconditional redaction (no re-inclusion flags)

Both modes produce the same redacted, schema-validated JSON output.

## Output file format

The collected data is saved as a JSON file (`collection.json`) containing:

```json
{
  "schemaVersion": "1.0",
  "collectedAt": "2024-11-05T20:30:00Z",
  "collector": "ts",
  "collectorVersion": "1.0.0",
  "tokenStatus": "active",
  "accounts": [ ... ],
  "zones": [ ... ],
  "collectionErrors": [ ... ]
}
```

Every field in the output matches the published schema (`collection.schema.json`) and is subject to:
1. **Secret scanning** — output is scanned for credential patterns before writing; scan failures abort the write
2. **Schema validation** — output must match the declared schema version
3. **Redaction enforcement** — PII and sensitive values are removed

## Analysis

After collection, the tool analyzes the JSON file against a best-practice rulebook (`findings/checks.yaml`):

- Checks SSL/TLS settings, WAF coverage, bot management, DNS security, and more
- Produces a Markdown report with pass/warn/fail findings
- Every finding cites its source (Cloudflare documentation URL)
- Compliance mappings show which findings support SOC 2 / PCI DSS controls

**The analysis phase is completely offline** — no network access, no API calls.

## Security and transparency

- **Open source:** Full source code available at [github.com/cheapredwine/cf-account-review](https://github.com/cheapredwine/cf-account-review)
- **Test suite:** 68 automated tests enforce read-only behavior, redaction correctness, and schema compliance
- **Documentation:** Every endpoint queried is listed in `docs/endpoints.md`
- **Data policy:** Complete redaction and retention rules in `docs/data-policy.md`

## Questions?

If you have concerns about what the tool collects or how it accesses your account:

1. Review the source code (open source)
2. Inspect the token permissions (read-only scopes)
3. Run Mode B collectors yourself in your environment
4. Ask your Cloudflare Solutions Engineer for clarification

**Bottom line:** The tool is a read-only configuration snapshot. It cannot change settings, access customer traffic, or read credentials. Output is redacted and secret-scanned before storage.
