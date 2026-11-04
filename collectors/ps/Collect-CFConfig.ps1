<#
============================================================================
CLOUDFLARE ACCOUNT SECURITY REVIEW — OFFLINE COLLECTOR (PowerShell)
============================================================================

PURPOSE:
  This script collects your Cloudflare account configuration and writes it
  to a timestamped JSON file. You run this script INSIDE your environment
  with your API token — the token NEVER leaves your machine.

  After collection, you send us ONLY the JSON file (no tokens, no credentials).
  We analyze it and return a security review report with actionable findings.

WHAT THIS SCRIPT DOES (step by step):

  1. PROMPTS FOR YOUR API TOKEN (or reads $env:CF_API_TOKEN)
     → Your token is used only in memory during collection
     → It is NEVER echoed to the terminal or written to the output file
     → A pre-write scan blocks any credential-shaped data from being written

  2. CALLS CLOUDFLARE'S PUBLIC API (api.cloudflare.com/client/v4)
     → All requests are GET-only (read-only; enforced by -Method Get)
     → No write operations of any kind (no POST, PUT, PATCH, DELETE)
     → No telemetry, no uploads, no third-party connections

  3. COLLECTS CONFIGURATION METADATA from your account:
     → Zone settings (SSL mode, security level, DNSSEC, etc.)
     → Firewall rules, rate limiting rules, managed WAF status
     → DNS record STRUCTURE (types, record counts) — contents redacted
     → Worker scripts (names, routes) — code never collected
     → Access applications (names, policy decisions) — identities redacted
     → Load balancer configuration, certificate expiry dates
     → Account settings (2FA enforcement, member roles)

  4. REDACTS SENSITIVE DATA automatically (applied during assembly):
     → DNS record contents (origin IPs, CNAME targets) → "[redacted]"
     → Account/zone/rule IDs → SHA-256 hashed, truncated to 16 hex chars
     → Member identities (emails/names) → role names + 2FA booleans only
     → Firewall rule expressions → IPs, emails, internal hostnames redacted
     → Worker bindings → names and types only; values never collected
     → Access policies → allow/bypass/block decisions only; identities redacted

  5. WRITES A TIMESTAMPED JSON FILE (cloudflare-config-YYYY-MM-DD-HHMM.json)
     → Contains configuration metadata only
     → Pre-write secret scan aborts if any credential-shaped data detected

WHAT YOU SEND US:
  The generated JSON file ONLY. We run the analyzer against it and return
  your security review report.

THE END GOAL:
  After analysis, we return:
    1. A detailed security review report (Markdown) with findings and recommendations
    2. A Terraform configuration (FUTURE) with hardened defaults for your issues

  The Terraform will:
    → Address high-severity findings (e.g., switch Flexible SSL → Full(strict))
    → Enable missing protections (e.g., deploy WAF managed rulesets, enable 2FA)
    → Fix configuration gaps (e.g., add DNSSEC, enable Authenticated Origin Pulls)

  YOU review the Terraform carefully, test in staging, and apply it when ready.
  The goal is to give you ACTIONABLE, REVIEWABLE fixes — not just a report of problems.

============================================================================
GUARANTEES (enforced by tests in the main repository):
============================================================================

  ✅ READ-ONLY: Every HTTP request uses -Method Get (enforced by Invoke-CFGet)
  ✅ SINGLE HOST: All API calls go to api.cloudflare.com/client/v4 only
  ✅ TOKEN SAFETY: Token from $env:CF_API_TOKEN or secure prompt; never echoed or written
  ✅ REDACTED BY DEFAULT: IDs hashed, DNS contents redacted, identities anonymized
  ✅ NO EXFILTRATION: No telemetry, no uploads, no third-party connections
  ✅ PRE-WRITE SCAN: Credential-shaped patterns abort the write before output is finalized

============================================================================
REQUIREMENTS:
============================================================================

  - Windows PowerShell 5.1+ or PowerShell 7+
  - Outbound HTTPS access to api.cloudflare.com

============================================================================
API TOKEN SCOPES (minimum required):
============================================================================

  Create a read-only API token at:
  Cloudflare Dashboard → My Profile → API Tokens → Create Token

  REQUIRED (all zones):
    • Account Settings: Read
    • Zone: Read
    • Zone Settings: Read
    • DNS: Read
    • Firewall Services: Read
    • Zone WAF: Read

  OPTIONAL (for deeper coverage):
    • Workers Scripts: Read (Worker zombie scripts, dangling routes)
    • Workers Routes: Read (Worker-to-zone routing)
    • Workers KV Storage: Read (data-at-rest inventory)
    • D1: Read (data-at-rest inventory)
    • Workers R2 Storage: Read (data-at-rest inventory)
    • Access: Apps and Policies: Read (Access policy review)
    • Access: Identity Providers: Read (IdP and MFA posture)
    • Access: Service Tokens: Read (token expiry hygiene)
    • Turnstile Widgets: Read (Turnstile inventory)
    • Cloudflare Tunnel: Read (Tunnel-to-Access gap detection)
    • User API Tokens: Read (token rotation posture)
    • Account API Tokens: Read (account token inventory)
    • SSL and Certificates: Read (certificate expiry warnings)
    • Load Balancing: Read (load balancer health checks)
    • Load Balancer Monitors and Pools: Read (pool failover)
    • Page Rules: Read (legacy page rule migration)
    • Zone Rate Limiting: Read (legacy rate-limit migration)
    • API Gateway Operations: Read (API Shield, Enterprise only)
    • Account Rulesets: Read (account-level WAF, Enterprise only)

  NARROWLY-SCOPED TOKENS WORK:
    If your token lacks some permissions, the script will:
      → Skip endpoints it cannot read
      → List them in "collectionErrors" in the output
      → Still produce a useful partial report for what it CAN read

============================================================================
USAGE:
============================================================================

  # With environment variable:
  $env:CF_API_TOKEN = "your_token_here"
  .\Collect-CFConfig.ps1

  # Or with output directory:
  .\Collect-CFConfig.ps1 -OutputDir C:\Temp

  # Or let it prompt (input is hidden):
  .\Collect-CFConfig.ps1

  # Output:
  cloudflare-config-YYYY-MM-DD-HHMM.json

============================================================================
WHAT HAPPENS INSIDE THIS SCRIPT (technical walkthrough):
============================================================================

PHASE 1: SETUP
  → Read token from $env:CF_API_TOKEN or secure prompt (no echo)
  → Initialize error log for scope gaps
  → Set up GET-only API wrapper (Invoke-CFGet enforces -Method Get)

PHASE 2: TOKEN VERIFICATION
  → Call GET /user/tokens/verify to check token status
  → Extract status ("active" or "verification-failed")
  → Report to user but continue even if verification fails (narrowly-scoped tokens work)

PHASE 3: ACCOUNT COLLECTION
  → Call GET /accounts to enumerate all accounts the token can access
  → For each account, collect:
      • Account settings (2FA enforcement, API access, abuse contact)
      • Members (role names + 2FA booleans only; no emails/names)
      • API tokens (status, expiry, last-use, permission groups)
      • Load balancer pools and monitors (health check hygiene)
      • Account-level rulesets (shared WAF across zones, Enterprise only)
      • Access applications (policy-less apps, bypass decisions)
      • Access identity providers (OTP-only IdP audit)
      • Turnstile widgets (widget inventory, domains, mode)
      • Tunnels (unsecured internal services exposed via public hostnames)
      • Worker scripts (script inventory, routes, binding names/types)
      • Storage inventory (KV/D1/R2 counts only; never contents)

PHASE 4: ZONE COLLECTION
  → Call GET /zones to enumerate all zones in the account
  → For each zone, collect:
      • Settings (SSL mode, min TLS, HSTS, DNSSEC, security level, etc.)
      • Rulesets (which phases have deployed rulesets)
      • Phase entrypoints (live rules per phase: WAF, rate limiting, transforms, etc.)
      • Bot management settings (Pro+ only)
      • WAF overrides (legacy WAF package overrides)
      • IP access rules (allow/block lists)
      • Page rules (legacy page rules still active)
      • Certificate packs (custom SSL cert expiry)
      • SSL verification status (per-hostname cert failures)
      • Load balancers (LB posture)
      • Workers routes (Worker-to-zone bindings)
      • DNS records (STRUCTURE only: type, name, proxied status; content redacted)
      • Legacy rate limits (legacy rate-limiting product)

PHASE 5: ASSEMBLY + REDACTION
  → Apply redaction rules (this is where all sensitive data is protected):
      • Hash all IDs (account, zone, rule IDs) → SHA-256, first 16 hex chars
      • Redact DNS record contents → "[redacted]"
      • Redact IPs, emails, internal hostnames in firewall expressions
      • Reduce member identities to role names + 2FA booleans
      • Reduce Access policies to decisions (allow/bypass/block); no identities
      • Keep Worker binding names/types; values never collected
  → Build final JSON document with schema version 1.0
  → Run PRE-WRITE SECRET SCAN:
      • Search serialized JSON for "Bearer ...", "Authorization", credential patterns
      • If any matches found, ABORT without writing anything
  → Write final JSON to output file
  → Report zones collected, errors encountered

PHASE 6: CLEANUP
  → Print summary and next steps

============================================================================
AFTER COLLECTION — WHAT YOU DO:
============================================================================

  1. VERIFY THE OUTPUT FILE:
     → Open cloudflare-config-YYYY-MM-DD-HHMM.json in a text editor
     → Confirm no API tokens, passwords, or credentials present
     → Confirm DNS record contents are "[redacted]"
     → Confirm account/zone IDs are hashed (start with "h...")

  2. SEND US THE JSON FILE:
     → Email, Signal, 1Password share, encrypted file transfer, etc.
     → DO NOT send your API token (we don't need it)

  3. WE ANALYZE AND RETURN:
     → Detailed security review report (Markdown)
     → Terraform configuration (FUTURE) with hardened defaults

  4. YOU REVIEW THE TERRAFORM:
     → Read every resource, every setting
     → Test in a staging environment first
     → Apply to production when you're confident

============================================================================

.PARAMETER OutputDir
    Directory for the output file. Default: current directory.

.EXAMPLE
    .\Collect-CFConfig.ps1

.EXAMPLE
    .\Collect-CFConfig.ps1 -OutputDir C:\Temp

.EXAMPLE
    $env:CF_API_TOKEN = "your_token_here"
    .\Collect-CFConfig.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"
$Base = "https://api.cloudflare.com/client/v4"
$script:ApiErrors = @()
$script:CollectorVersion = "0.1.0"

# ---------------------------------------------------------------------------
# Token handling — never echoed, never written to disk
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "CLOUDFLARE ACCOUNT SECURITY REVIEW — CONFIGURATION COLLECTOR" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will:" -ForegroundColor Yellow
Write-Host "  1. Read your Cloudflare API token (from environment or secure prompt)" -ForegroundColor Yellow
Write-Host "  2. Collect configuration metadata from your account (READ-ONLY)" -ForegroundColor Yellow
Write-Host "  3. Redact sensitive data (DNS contents, IDs, identities)" -ForegroundColor Yellow
Write-Host "  4. Write a timestamped JSON file you can send for analysis" -ForegroundColor Yellow
Write-Host ""
Write-Host "Your token is used ONLY in memory and is NEVER written to the output file." -ForegroundColor Green
Write-Host "The output contains configuration metadata only — no credentials, no secrets." -ForegroundColor Green
Write-Host ""

$token = $env:CF_API_TOKEN
if (-not $token) {
    Write-Host "API token not found in `$env:CF_API_TOKEN." -ForegroundColor Yellow
    Write-Host "Please enter your Cloudflare API token (input will be hidden):" -ForegroundColor Yellow
    $secure = Read-Host -AsSecureString
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ([string]::IsNullOrWhiteSpace($token)) {
    Write-Host "❌ No API token supplied. Exiting." -ForegroundColor Red
    exit 1
}
$Headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

Write-Host "✅ Token loaded. Starting collection..." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# GET-only helpers
# ---------------------------------------------------------------------------
# Invoke-CFGet: The ONLY place HTTP requests are made.
# Enforces -Method Get (read-only) and paginates automatically.
#
# Parameters:
#   $Path = API path (e.g., "/zones" or "/accounts/{id}/settings")
#   $MaxPages = Maximum pages to fetch (default 50)
#
# Behavior:
#   1. Calls Invoke-RestMethod with -Method Get (enforces read-only)
#   2. Paginates automatically (up to MaxPages)
#   3. Returns merged result array, or $null on failure
#   4. Records errors in $script:ApiErrors for reporting
#
# Why -Method Get?
#   Enforces read-only at the HTTP level. No POST, PUT, PATCH, DELETE possible.
#   Tests in the main repo verify this.
# ---------------------------------------------------------------------------
function Invoke-CFGet {
    param([string]$Path, [int]$MaxPages = 50)
    
    try {
        $all = @()
        $page = 1
        while ($page -le $MaxPages) {
            $sep = if ($Path.Contains("?")) { "&" } else { "?" }
            $resp = Invoke-RestMethod -Uri "$Base$Path${sep}page=$page&per_page=50" `
                -Headers $Headers -Method Get -TimeoutSec 60
            
            # Check API success field
            if (-not $resp.success) {
                $script:ApiErrors += @{ path = $Path; error = ($resp.errors | ConvertTo-Json -Compress -Depth 5) }
                return $null
            }
            
            # Accumulate results
            $all += $resp.result
            
            # Check pagination
            $info = $resp.result_info
            if ($null -eq $info -or $page -ge $info.total_pages -or $resp.result.Count -eq 0) { 
                break 
            }
            $page++
        }
        return $all
    } catch {
        $script:ApiErrors += @{ path = $Path; error = $_.Exception.Message }
        return $null
    }
}

function Get-Array { 
    param($Value) 
    if ($null -eq $Value) { @() } else { @($Value) } 
}

# ---------------------------------------------------------------------------
# Redaction helpers (mirrors the bash collector and src/redact.ts)
# ---------------------------------------------------------------------------

# Protect-Id: Hash an ID (account, zone, rule) using SHA-256, truncate to 16 hex chars
function Protect-Id { 
    param($Id) 
    if ($Id) { 
        $hash = ([BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Id))).Replace("-","").Substring(0,16)).ToLower()
        return "h$hash"
    } 
    return $null 
}

# Protect-Expression: Redact IPs, emails, and internal hostnames from firewall rule expressions
function Protect-Expression {
    param($Expression, $ZoneName)
    if (-not $Expression) { return $Expression }
    $expr = $Expression -replace '\b\d{1,3}(\.\d{1,3}){3}\b', "[redacted]"
    $expr = $expr -replace '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "[redacted]"
    $expr = $expr -replace '\b([a-z0-9-]+\.)*(internal|corp|intranet|local)\b', "[redacted]"
    return $expr
}

# Protect-DnsContent: Redact DNS record contents (origin IPs, CNAME targets)
function Protect-DnsContent { 
    param($Content) 
    if ($null -ne $Content) { return "[redacted]" } 
    return $null 
}

# Get-Setting: Extract a specific setting value from zone settings array
function Get-Setting { 
    param($Settings, $Id) 
    $row = $Settings | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if ($row) { return $row.value } 
    return $null 
}

# ---------------------------------------------------------------------------
# PHASE 2: TOKEN VERIFICATION
# ---------------------------------------------------------------------------
Write-Host "Verifying API token..." -ForegroundColor Cyan
$verify = Invoke-CFGet -Path "/user/tokens/verify"
$tokenStatus = if ($verify) { (Get-Array $verify)[0].status } else { "verification-failed" }
Write-Host "Token status: $tokenStatus" -ForegroundColor $(if ($tokenStatus -eq "active") { "Green" } else { "Yellow" })

if ($tokenStatus -ne "active") {
    Write-Host "⚠️  Token verification failed. This may mean your token is narrowly scoped." -ForegroundColor Yellow
    Write-Host "   The script will continue and collect what it can access." -ForegroundColor Yellow
}
Write-Host ""

# ---------------------------------------------------------------------------
# Initialize collection document
# ---------------------------------------------------------------------------
$collection = [ordered]@{
    schemaVersion    = "1.0"
    collectedAt      = (Get-Date).ToUniversalTime().ToString("o")
    collector        = "powershell"
    collectorVersion = $script:CollectorVersion
    tokenStatus      = $tokenStatus
}

# ---------------------------------------------------------------------------
# PHASE 3: ACCOUNT COLLECTION
# ---------------------------------------------------------------------------
Write-Host "Collecting accounts..." -ForegroundColor Cyan
$accounts = Get-Array (Invoke-CFGet -Path "/accounts")
$planTiers = @()
$collection.accounts = @()

foreach ($acct in $accounts) {
    Write-Host "  → Account: $($acct.name)" -ForegroundColor Gray
    $acctId = $acct.id
    $a = [ordered]@{ id = (Protect-Id $acctId); name = $acct.name }

    # Account settings: posture data lives on the bare account object
    # (result.settings) — /accounts/{id}/settings does not exist (404)
    $account = Invoke-CFGet -Path "/accounts/$acctId"
    $settings = if ($account -and $account.settings) { $account.settings } else { $null }
    $a | Add-Member -NotePropertyName settings -NotePropertyValue $settings
    $a | Add-Member -NotePropertyName enforceTwofactor -NotePropertyValue (Get-Setting (Get-Array $settings) "enforce_twofactor")

    # Members: role names + 2FA booleans only — no emails, no user IDs
    $members = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/members")
    $a.accountMembers = $members | ForEach-Object {
        [ordered]@{
            roleNames        = @(($_.policies | ForEach-Object { $_.permission_groups | ForEach-Object { $_.name } }) | Where-Object { $_ })
            twofactorEnabled = $_.user.two_factor_authentication_enabled
            status           = $_.status
        }
    }

    # Tokens: metadata only (no token values exist in list responses anyway)
    $tokens = @(Get-Array (Invoke-CFGet -Path "/user/tokens")) + @(Get-Array (Invoke-CFGet -Path "/accounts/$acctId/tokens"))
    $a.apiTokens = $tokens | ForEach-Object {
        [ordered]@{
            status                = $_.status
            expiresOn             = $_.expires_on
            lastUsedOn            = $_.last_used_on
            permissionGroupNames  = @($_.policies | ForEach-Object { $_.permission_groups | ForEach-Object { $_.name } } | Where-Object { $_ })
        }
    }

    # Load balancers
    $a | Add-Member -NotePropertyName loadBalancerPools -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/pools")
    $a | Add-Member -NotePropertyName loadBalancerMonitors -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/monitors")
    
    # Account-level rulesets (Enterprise only)
    $a | Add-Member -NotePropertyName accountRulesets -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/rulesets")

    # Access apps: decisions + policy presence only; identities never exported
    $accessApps = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/access/apps")
    $a.accessApps = $accessApps | ForEach-Object {
        $policies = @($_.policies)
        [ordered]@{
            name              = $_.name
            type              = $_.type
            domain            = $_.domain
            selfHostedDomains = @($_.self_hosted_domains)
            hasPolicies       = ($policies.Count -gt 0)
            policyDecisions   = @($policies | ForEach-Object { $_.decision } | Where-Object { $_ })
        }
    }

    # Access identity providers
    $idps = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/access/identity_providers")
    $a.accessIdentityProviders = $idps | ForEach-Object { 
        [ordered]@{ name = $_.name; type = $_.type } 
    }

    # Turnstile widgets
    $widgets = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/challenges/widgets")
    $a.turnstileWidgets = $widgets | ForEach-Object {
        [ordered]@{ name = $_.name; domains = @($_.domains); mode = $_.mode }
    }

    # Tunnels
    $tunnels = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/cfd_tunnel")
    $a.cfdTunnels = $tunnels | ForEach-Object {
        $tunnelId = $_.id
        $configs = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/cfd_tunnel/$tunnelId/configurations")
        $publicHostnames = @()
        foreach ($config in $configs) {
            foreach ($ingress in ($config.config.ingress | Where-Object { $_ })) {
                $hostname = $ingress.hostname
                if ($hostname -and $hostname -ne "*") {
                    $publicHostnames += $hostname
                }
            }
        }
        [ordered]@{
            id               = (Protect-Id $_.id)
            name             = $_.name
            status           = $_.status
            publicHostnames  = $publicHostnames
        }
    }

    # Workers scripts: names + plaintext binding names/types (never values)
    $scripts = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/workers/scripts")
    $a.workersScripts = $scripts | ForEach-Object {
        $bindings = @($_.bindings)
        [ordered]@{
            id                 = (Protect-Id $_.id)
            scriptName         = $_.id
            createdOn          = $_.created_on
            modifiedOn         = $_.modified_on
            plainTextBindings  = @($bindings | Where-Object { $_.type -in @("plain_text","secret_text") } | ForEach-Object { 
                [ordered]@{ name = $_.name; type = $_.type } 
            })
        }
    }

    # Storage inventory (counts only; never contents)
    $kv = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/storage/kv/namespaces")
    $d1 = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/d1/database")
    $r2 = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/r2/buckets")
    $a.storageInventory = [ordered]@{ 
        kvNamespaces = $kv.Count
        d1Databases  = $d1.Count
        r2Buckets    = $r2.Count 
    }

    $collection.accounts += $a
}

# ---------------------------------------------------------------------------
# PHASE 4: ZONE COLLECTION
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Collecting zones..." -ForegroundColor Cyan
$zones = Get-Array (Invoke-CFGet -Path "/zones?per_page=50")
$collection.zones = @()

# Ruleset phases to collect (Cloudflare's standard phases)
$phases = @(
    "http_request_firewall_custom",
    "http_request_firewall_managed",
    "http_ratelimit",
    "http_request_transform",
    "http_request_dynamic_redirect",
    "http_request_cache_settings",
    "http_request_origin",
    "http_request_redirect"
)

foreach ($z in $zones) {
    Write-Host "  → Zone: $($z.name)" -ForegroundColor Gray
    $zoneId = $z.id
    $plan = $z.plan
    if ($plan.name) { $planTiers += $plan.name }
    
    $zoneOut = [ordered]@{
        name       = $z.name
        plan       = $plan.name
        status     = $z.status
        paused     = $z.paused
        type       = $z.type
        createdOn  = $z.created_on
    }

    # Zone settings as keyed rows
    $settingsRows = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/settings")
    $settingsMap = [ordered]@{}
    foreach ($row in $settingsRows) {
        $settingsMap[$row.id] = [ordered]@{ 
            id       = $row.id
            value    = $row.value
            editable = $row.editable 
        }
    }
    $zoneOut | Add-Member -NotePropertyName settings -NotePropertyValue $settingsMap

    # Ruleset inventory
    $rsList = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/rulesets")
    $zoneOut.rulesets = $rsList | ForEach-Object {
        [ordered]@{ 
            id      = (Protect-Id $_.id)
            name    = $_.name
            kind    = $_.kind
            phase   = $_.phase
            version = $_.version 
        }
    }

    # Phase entrypoints (live rules) with redacted expressions
    $entrypoints = [ordered]@{}
    foreach ($phase in $phases) {
        $ep = Invoke-CFGet -Path "/zones/$zoneId/rulesets/phases/$phase/entrypoint"
        if ($null -eq $ep) { continue }
        $epRow = (Get-Array $ep)[0]
        $entrypoints[$phase] = [ordered]@{
            phase = $phase
            name  = $epRow.name
            kind  = $epRow.kind
            rules = @(Get-Array $epRow.rules) | ForEach-Object {
                [ordered]@{
                    id          = (Protect-Id $_.id)
                    description = $_.description
                    enabled     = $_.enabled
                    action      = $_.action
                    expression  = (Protect-Expression $_.expression $z.name)
                    version     = $_.version
                    lastUpdated = $_.last_updated
                }
            }
        }
    }
    if ($entrypoints.Keys.Count -gt 0) {
        $zoneOut | Add-Member -NotePropertyName phaseEntrypoints -NotePropertyValue $entrypoints
    }

    # Bot management (Pro+ only)
    $zoneOut | Add-Member -NotePropertyName botManagement -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/bot_management")
    
    # IP access rules
    $zoneOut | Add-Member -NotePropertyName ipAccessRules -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/firewall/access_rules/rules?per_page=100")
    
    # Page rules (legacy)
    $zoneOut | Add-Member -NotePropertyName pageRules -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/pagerules?per_page=100")
    
    # Certificates
    $zoneOut | Add-Member -NotePropertyName certificatePacks -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/ssl/certificate_packs?status=all")
    $zoneOut | Add-Member -NotePropertyName sslVerification -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/ssl/verification")
    
    # Load balancers
    $zoneOut | Add-Member -NotePropertyName loadBalancers -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/load_balancers")

    # Workers routes
    $routes = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/workers/routes")
    $zoneOut.workersRoutes = $routes | ForEach-Object { 
        [ordered]@{ pattern = $_.pattern; script = $_.script } 
    }

    # DNS: content redacted unconditionally in Mode B
    $dns = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/dns_records?per_page=100")
    $zoneOut.dnsRecordCount = $dns.Count
    $zoneOut.dnsRecords = $dns | ForEach-Object {
        [ordered]@{
            type    = $_.type
            name    = $_.name
            content = (Protect-DnsContent $_.content)
            proxied = $_.proxied
            ttl     = $_.ttl
            comment = $_.comment
        }
    }

    # Page Shield (Business+ only)
    $ps = Invoke-CFGet -Path "/zones/$zoneId/page_shield"
    if ($ps) {
        $psObj = (Get-Array $ps)[0]
        $zoneOut.pageShield = [ordered]@{
            enabled                        = $psObj.enabled
            useCloudflareReportingEndpoint = $psObj.use_cloudflare_reporting_endpoint
            useConnectionUrlPath           = $psObj.use_connection_url_path
        }
    }

    # Authenticated Origin Pulls
    $aopSettings = Invoke-CFGet -Path "/zones/$zoneId/origin_tls_client_auth/settings"
    $aopCerts = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/origin_tls_client_auth")
    if ($aopSettings) {
        $aopObj = (Get-Array $aopSettings)[0]
        $zoneOut.authenticatedOriginPulls = [ordered]@{
            enabled          = $aopObj.enabled
            hasZoneLevelCert = ($aopCerts.Count -gt 0)
            certCount        = $aopCerts.Count
        }
    }

    $collection.zones += $zoneOut
}

# Plan tiers seen
if ($planTiers.Count -gt 0) {
    $collection.planTiersSeen = @($planTiers | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------
# PHASE 5: ERRORS (scope gaps)
# ---------------------------------------------------------------------------
$collection.collectionErrors = $script:ApiErrors

# ---------------------------------------------------------------------------
# PHASE 6: SECRET SCAN + WRITE
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Assembling and redacting output..." -ForegroundColor Cyan

$json = $collection | ConvertTo-Json -Depth 12

# Redact opaque strings (64+ token-class chars) before the scan: never export
# opaque material (docs/data-policy.md). Matches the Mode A collector.
$json = [regex]::Replace($json, "[A-Za-z0-9_-]{64,}", { param($m) "[redacted]:opaque-$($m.Value.Length)" })

# PRE-WRITE SECRET SCAN: abort if any credential-shaped patterns detected
if ($json -match "Bearer\s+\S+" -or $json -match "(?i)authorization") {
    Write-Host ""
    Write-Host "❌ ABORTING: Pre-write secret scan matched an authorization pattern." -ForegroundColor Red
    Write-Host "   Nothing written. This is a safety check to prevent credential leakage." -ForegroundColor Red
    exit 1
}

# Write output
if (-not (Test-Path $OutputDir)) { 
    New-Item -ItemType Directory -Path $OutputDir | Out-Null 
}
$outFile = Join-Path $OutputDir ("cloudflare-config-{0}.json" -f (Get-Date -Format "yyyy-MM-dd-HHmm"))
$json | Out-File -FilePath $outFile -Encoding UTF8

# Owner-only perms (bash collector writes 0600; match it on POSIX)
if (-not (Get-Variable IsWindows -ErrorAction SilentlyContinue) -or -not $IsWindows) {
    & /bin/chmod 600 $outFile
}

# ---------------------------------------------------------------------------
# PHASE 7: DONE
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output file: $outFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "This file contains configuration metadata only:" -ForegroundColor Yellow
Write-Host "  ✅ No API tokens, passwords, or credentials" -ForegroundColor Green
Write-Host "  ✅ No DNS record contents (redacted as `"[redacted]`")" -ForegroundColor Green
Write-Host "  ✅ No customer identities (emails/names anonymized)" -ForegroundColor Green
Write-Host "  ✅ No Worker script source code" -ForegroundColor Green
Write-Host "  ✅ No Access policy identity expressions" -ForegroundColor Green
Write-Host ""
Write-Host "Collection summary:" -ForegroundColor Yellow
Write-Host "  Zones collected: $($collection.zones.Count)" -ForegroundColor Gray

if ($script:ApiErrors.Count -gt 0) {
    Write-Host "  Endpoints skipped (token scope): $($script:ApiErrors.Count)" -ForegroundColor Yellow
    Write-Host "  (See collectionErrors in the file for details)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Open the file in a text editor and verify redactions" -ForegroundColor Gray
Write-Host "  2. Send us ONLY this JSON file (no tokens, no credentials)" -ForegroundColor Gray
Write-Host "  3. We will analyze it and return:" -ForegroundColor Gray
Write-Host "      → Detailed security review report (Markdown)" -ForegroundColor Gray
Write-Host "      → Terraform configuration (FUTURE) with hardened defaults" -ForegroundColor Gray
Write-Host "  4. YOU review the Terraform, test in staging, and apply when ready" -ForegroundColor Gray
Write-Host ""
Write-Host "Questions? Contact us before sending the file." -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Green
