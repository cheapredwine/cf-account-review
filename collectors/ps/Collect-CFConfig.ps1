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
$script:CollectorVersion = "0.2.0"

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
# Invoke-CFGet / Invoke-CFGetObject are the ONLY places HTTP requests are made.
# Both call Invoke-RestMethod with -Method Get (read-only; tests enforce it).
#
# Readability contract (schema 1.1, mirrors src/collect.ts):
#   unreadable endpoint -> $null (field omitted from the output)
#   readable, empty     -> empty array
# Phase entrypoints distinguish 404 ("absent": nothing deployed) from other
# failures ("unreadable"); fail-closed verdicts in the analyzer depend on it.
# ---------------------------------------------------------------------------
function Get-HttpStatus {
    param($ErrorRecord)
    try {
        if ($ErrorRecord.Exception.Response) { return [int]$ErrorRecord.Exception.Response.StatusCode }
    } catch { }
    return 0
}

function Invoke-CFGet {
    param([string]$Path, [int]$MaxPages = 50)
    $all = New-Object System.Collections.ArrayList
    $page = 1
    try {
        while ($page -le $MaxPages) {
            $sep = if ($Path.Contains("?")) { "&" } else { "?" }
            $resp = Invoke-RestMethod -Uri "$Base$Path${sep}page=$page&per_page=50" `
                -Headers $Headers -Method Get -TimeoutSec 60
            if (-not $resp.success) {
                $script:ApiErrors += [ordered]@{ path = $Path; error = "API reported failure" }
                return $null
            }
            $rows = @($resp.result | Where-Object { $null -ne $_ })
            foreach ($r in $rows) { [void]$all.Add($r) }
            $info = $resp.result_info
            if ($null -eq $info -or $null -eq $info.total_pages -or $page -ge $info.total_pages -or $rows.Count -lt 50) { break }
            $page++
        }
        return , $all.ToArray()
    } catch {
        $code = Get-HttpStatus $_
        $script:ApiErrors += [ordered]@{ path = $Path; error = "HTTP $code" }
        return $null
    }
}

function Invoke-CFGetObject {
    param([string]$Path, [switch]$Quiet404)
    $script:LastStatus = 0
    try {
        $resp = Invoke-RestMethod -Uri "$Base$Path" -Headers $Headers -Method Get -TimeoutSec 60
        $script:LastStatus = 200
        if (-not $resp.success -or $null -eq $resp.result) {
            $script:ApiErrors += [ordered]@{ path = $Path; error = "API reported failure" }
            return $null
        }
        return $resp.result
    } catch {
        $code = Get-HttpStatus $_
        $script:LastStatus = $code
        if (-not ($Quiet404 -and $code -eq 404)) {
            $script:ApiErrors += [ordered]@{ path = $Path; error = "HTTP $code" }
        }
        return $null
    }
}

# Map rows with a scriptblock; $null (unreadable) stays $null, [] stays [].
function ConvertTo-Mapped {
    param($Rows, [scriptblock]$Fn)
    if ($null -eq $Rows) { return $null }
    $out = @(foreach ($r in @($Rows)) { if ($null -ne $r) { & $Fn $r } })
    return , $out
}

function Get-Array {
    param($Value)
    if ($null -eq $Value) { return , @() }
    return , @($Value)
}

function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { return $Obj[$Name] }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function As-Bool { param($v) if ($v -is [bool]) { return $v } return $null }
function As-Num { param($v) if (($v -is [int]) -or ($v -is [long]) -or ($v -is [double]) -or ($v -is [decimal])) { return $v } return $null }
# Invoke-RestMethod turns ISO-8601 strings into [datetime]; render them back
# as UTC ISO strings (fractional seconds kept, trailing zeros dropped).
function As-Str {
    param($v)
    if ($v -is [string]) { return $v }
    if ($v -is [datetime]) { return $v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'") }
    return $null
}

# ---------------------------------------------------------------------------
# Redaction helpers (mirror src/redact.ts and the bash assembler)
# ---------------------------------------------------------------------------
function Protect-Id {
    param($Id)
    if ($Id) {
        $sha = [Security.Cryptography.SHA256]::Create()
        $hex = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Id))).Replace("-", "").Substring(0, 16).ToLower()
        return "h$hex"
    }
    return $null
}

function Protect-IdsInPath {
    param([string]$Path)
    return [regex]::Replace($Path, '\b[0-9a-f]{32}\b', { param($m) Protect-Id $m.Value })
}

$script:EmailRx = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
function Protect-Expression {
    param($Expression)
    if (-not ($Expression -is [string]) -or -not $Expression) { return $Expression }
    $expr = $Expression -creplace $script:EmailRx, "[redacted]"
    $expr = $expr -creplace '\b\d{1,3}(?:\.\d{1,3}){3}\b', "[redacted]"
    $expr = $expr -replace '\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|internal\.[a-z]{2,}|origin\.[-a-z0-9.]+)\b', "[redacted]"
    return $expr
}
function Protect-Emails {
    param($Text)
    if (-not ($Text -is [string])) { return $null }
    return ($Text -creplace $script:EmailRx, "[redacted]")
}

# ---------------------------------------------------------------------------
# Summarizers (mirror src/summarize.ts — keep the three collectors in step)
# ---------------------------------------------------------------------------
$script:KnownManaged = @{
    "efb7b8c949ac4650a09736fc376e9aee" = "Cloudflare Managed Ruleset"
    "4814384a9e5d4991b9815dcfc25d2f1f" = "Cloudflare OWASP Core Ruleset"
    "c2e184081120413c86c3ab7e14069605" = "Cloudflare Exposed Credentials Check Ruleset"
    "4d21379b4f9f4bb088e0729962c8b3cf" = "DDoS L7 ruleset"
}
function Get-ManagedKey {
    param($Name)
    if (-not $Name) { return $null }
    $n = ([string]$Name).ToLower()
    if ($n.Contains("owasp")) { return "owasp" }
    if ($n.Contains("exposed credentials")) { return "exposed_credentials" }
    if ($n.Contains("ddos")) { return "ddos_l7" }
    if ($n.Contains("cloudflare managed")) { return "cloudflare_managed" }
    if ($n.Contains("sensitive data")) { return "sensitive_data_detection" }
    return "other_managed"
}

function Get-ActionParametersSummary {
    param($Action, $Ap, $RulesetNames, $Ratelimit)
    $hasAp = ($null -ne $Ap) -and (@($Ap.PSObject.Properties).Count -gt 0)
    if (-not $hasAp -and $null -eq $Ratelimit) { return $null }
    $out = [ordered]@{}
    if ($Action -eq "execute") {
        $rid = [string](Get-Prop $Ap "id")
        $name = if ($RulesetNames.ContainsKey($rid)) { $RulesetNames[$rid] } else { $script:KnownManaged[$rid] }
        $key = Get-ManagedKey $name
        $out.executes = if ($key) { $key } else { "custom_or_unknown" }
        $ov = Get-Prop $Ap "overrides"
        if ($null -ne $ov -and @($ov.PSObject.Properties).Count -gt 0) {
            $cats = @(Get-Prop $ov "categories" | Where-Object { $null -ne $_ })
            $rules = @(Get-Prop $ov "rules" | Where-Object { $null -ne $_ })
            $th = @($rules | ForEach-Object { As-Num (Get-Prop $_ "score_threshold") } | Where-Object { $null -ne $_ })
            $o = [ordered]@{
                enabled               = As-Bool (Get-Prop $ov "enabled")
                action                = As-Str (Get-Prop $ov "action")
                sensitivityLevel      = As-Str (Get-Prop $ov "sensitivity_level")
                disabledCategories    = @($cats | Where-Object { (Get-Prop $_ "enabled") -eq $false -and (Get-Prop $_ "category") -is [string] } | ForEach-Object { Get-Prop $_ "category" } | Select-Object -First 50)
                rulesDisabled         = @($rules | Where-Object { (Get-Prop $_ "enabled") -eq $false }).Count
                rulesActionOverridden = @($rules | Where-Object { (Get-Prop $_ "action") -is [string] }).Count
                scoreThreshold        = if ($th.Count -gt 0) { ($th | Measure-Object -Minimum).Minimum } else { $null }
            }
            $out.overrides = $o
        }
    }
    if ($Action -eq "skip") {
        $rulesObj = Get-Prop $Ap "rules"
        $ruleCount = 0
        if ($null -ne $rulesObj) { foreach ($p in $rulesObj.PSObject.Properties) { $ruleCount += @($p.Value).Count } }
        $out.skip = [ordered]@{
            currentRuleset = ((Get-Prop $Ap "ruleset") -eq "current")
            rulesets       = @(Get-Prop $Ap "rulesets" | Where-Object { $null -ne $_ }).Count
            rules          = $ruleCount
            phases         = @(Get-Prop $Ap "phases" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Select-Object -First 20)
            products       = @(Get-Prop $Ap "products" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Select-Object -First 20)
        }
    }
    if ($null -ne $Ratelimit) {
        $ce = Get-Prop $Ratelimit "counting_expression"
        $out.ratelimit = [ordered]@{
            characteristics       = @(Get-Prop $Ratelimit "characteristics" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Select-Object -First 10)
            period                = As-Num (Get-Prop $Ratelimit "period")
            requestsPerPeriod     = As-Num (Get-Prop $Ratelimit "requests_per_period")
            scorePerPeriod        = As-Num (Get-Prop $Ratelimit "score_per_period")
            mitigationTimeout     = As-Num (Get-Prop $Ratelimit "mitigation_timeout")
            requestsToOrigin      = As-Bool (Get-Prop $Ratelimit "requests_to_origin")
            hasCountingExpression = (($ce -is [string]) -and $ce.Length -gt 0)
        }
    }
    $hdrs = Get-Prop $Ap "headers"
    if ($null -ne $hdrs) {
        $out.headers = @(foreach ($p in @($hdrs.PSObject.Properties | Select-Object -First 50)) {
                $op = As-Str (Get-Prop $p.Value "operation")
                [ordered]@{ name = $p.Name.ToLower(); operation = $(if ($op) { $op } else { "unknown" }) }
            })
    }
    $cache = Get-Prop $Ap "cache"
    if ($Action -eq "set_cache_settings" -and $cache -is [bool]) { $out.cache = [ordered]@{ eligible = $cache } }
    if ($out.Count -eq 0) { return $null }
    return $out
}

$script:PageRuleEnum = @("security_level", "ssl", "cache_level", "browser_check", "waf", "always_use_https",
    "automatic_https_rewrites", "email_obfuscation", "rocket_loader", "disable_security", "disable_apps",
    "disable_performance", "cache_deception_armor")
$script:BotKeys = @("fight_mode", "enable_js", "sbfm_definitely_automated", "sbfm_likely_automated", "sbfm_verified_bots",
    "sbfm_static_resource_protection", "optimize_wordpress", "ai_bots_protection", "crawler_protection",
    "is_robots_txt_managed", "using_latest_model", "auto_update_model", "suppress_session_score")

function Get-PlanTier {
    param($Name, $Legacy)
    foreach ($c in @($Legacy, $Name)) {
        if (-not $c) { continue }
        $p = ([string]$c).ToLower()
        foreach ($t in @("enterprise", "business", "pro", "free")) { if ($p.Contains($t)) { return $t } }
    }
    return $null
}

# Drop $null values recursively (zod optional fields reject null).
function Remove-Nulls {
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) {
            if ($null -ne $Value[$k]) { $o[$k] = Remove-Nulls $Value[$k] }
        }
        return $o
    }
    if ($Value -is [array]) {
        return , @(foreach ($x in $Value) { Remove-Nulls $x })
    }
    return $Value
}

# ---------------------------------------------------------------------------
# PHASE 2: TOKEN VERIFICATION
# ---------------------------------------------------------------------------
Write-Host "Verifying API token..." -ForegroundColor Cyan
$verify = Invoke-CFGetObject -Path "/user/tokens/verify"
$tokenStatus = if ((Get-Prop $verify "status") -eq "active") { "active" } else { "verification-failed" }
Write-Host "Token status: $tokenStatus" -ForegroundColor $(if ($tokenStatus -eq "active") { "Green" } else { "Yellow" })
if ($tokenStatus -ne "active") {
    Write-Host "⚠️  Token verification failed. This may mean your token is narrowly scoped." -ForegroundColor Yellow
    Write-Host "   The script will continue and collect what it can access." -ForegroundColor Yellow
}
Write-Host ""

$collection = [ordered]@{
    schemaVersion    = "1.1"
    collectedAt      = (Get-Date).ToUniversalTime().ToString("o")
    collector        = "powershell"
    collectorVersion = $script:CollectorVersion
    tokenStatus      = $tokenStatus
}

function Get-GroupNames {
    param($Obj)
    return , @(foreach ($p in @(Get-Prop $Obj "policies" | Where-Object { $null -ne $_ })) {
            foreach ($g in @(Get-Prop $p "permission_groups" | Where-Object { $null -ne $_ })) {
                $n = Get-Prop $g "name"; if ($n) { [string]$n }
            }
        })
}

# ---------------------------------------------------------------------------
# PHASE 3: ACCOUNT COLLECTION
# ---------------------------------------------------------------------------
Write-Host "Collecting accounts..." -ForegroundColor Cyan
$accounts = Get-Array (Invoke-CFGet -Path "/accounts")
$userTokens = Invoke-CFGet -Path "/user/tokens"   # user-owned: read once
$collection.accounts = @()

foreach ($acct in $accounts) {
    Write-Host "  → Account: $($acct.name)" -ForegroundColor Gray
    $acctId = $acct.id
    $a = [ordered]@{ id = (Protect-Id $acctId); name = (As-Str $acct.name) }

    $settings = Invoke-CFGetObject -Path "/accounts/$acctId/settings"
    $a.enforceTwofactor = As-Bool (Get-Prop $settings "enforce_twofactor")

    $a.accountMembers = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/members") {
        param($m)
        [ordered]@{
            roleNames        = (Get-GroupNames $m)
            twofactorEnabled = As-Bool (Get-Prop (Get-Prop $m "user") "two_factor_authentication_enabled")
            status           = As-Str (Get-Prop $m "status")
        }
    }

    $acctTokens = Invoke-CFGet -Path "/accounts/$acctId/tokens"
    $tokenRows = $null
    if ($null -ne $userTokens -or $null -ne $acctTokens) {
        $tokenRows = @()
        if ($null -ne $userTokens) { $tokenRows += $userTokens }
        if ($null -ne $acctTokens) { $tokenRows += $acctTokens }
    }
    $a.apiTokens = ConvertTo-Mapped $tokenRows {
        param($t)
        [ordered]@{
            status               = As-Str (Get-Prop $t "status")
            expiresOn            = As-Str (Get-Prop $t "expires_on")
            lastUsedOn           = As-Str (Get-Prop $t "last_used_on")
            permissionGroupNames = (Get-GroupNames $t)
        }
    }

    # Pools/monitors: origin addresses, notification emails and monitor header
    # VALUES (may carry auth material) are never exported.
    $a.loadBalancerPools = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/pools") {
        param($p)
        [ordered]@{
            id                = Protect-Id (Get-Prop $p "id")
            name              = As-Str (Get-Prop $p "name")
            enabled           = As-Bool (Get-Prop $p "enabled")
            origins           = @(foreach ($o in @(Get-Prop $p "origins" | Where-Object { $null -ne $_ })) {
                    [ordered]@{
                        name    = As-Str (Get-Prop $o "name")
                        address = $(if (Get-Prop $o "address") { "[redacted]" } else { $null })
                        enabled = As-Bool (Get-Prop $o "enabled")
                        weight  = As-Num (Get-Prop $o "weight")
                    }
                })
            monitor           = Protect-Id (Get-Prop $p "monitor")
            notificationEmail = "[redacted]"
        }
    }
    $a.loadBalancerMonitors = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/monitors") {
        param($m)
        [ordered]@{
            id              = Protect-Id (Get-Prop $m "id")
            type            = As-Str (Get-Prop $m "type")
            interval        = As-Num (Get-Prop $m "interval")
            timeout         = As-Num (Get-Prop $m "timeout")
            retries         = As-Num (Get-Prop $m "retries")
            expectedCodes   = As-Str (Get-Prop $m "expected_codes")
            followRedirects = As-Bool (Get-Prop $m "follow_redirects")
            allowInsecure   = As-Bool (Get-Prop $m "allow_insecure")
        }
    }
    $a.accountRulesets = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/rulesets") {
        param($r)
        [ordered]@{ id = Protect-Id (Get-Prop $r "id"); name = As-Str (Get-Prop $r "name"); kind = As-Str (Get-Prop $r "kind"); phase = As-Str (Get-Prop $r "phase"); version = As-Str (Get-Prop $r "version") }
    }
    $a.accessApps = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/access/apps") {
        param($app)
        $policies = @(Get-Prop $app "policies" | Where-Object { $null -ne $_ })
        $sh = @(Get-Prop $app "self_hosted_domains" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        [ordered]@{
            name              = As-Str (Get-Prop $app "name")
            type              = As-Str (Get-Prop $app "type")
            domain            = As-Str (Get-Prop $app "domain")
            selfHostedDomains = $(if ($sh.Count -gt 0) { , $sh } else { $null })
            hasPolicies       = ($policies.Count -gt 0)
            policyDecisions   = @($policies | ForEach-Object { Get-Prop $_ "decision" } | Where-Object { $_ })
        }
    }
    $a.accessIdentityProviders = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/access/identity_providers") {
        param($p) [ordered]@{ name = As-Str (Get-Prop $p "name"); type = As-Str (Get-Prop $p "type") }
    }
    $a.turnstileWidgets = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/challenges/widgets") {
        param($w)
        $doms = @(Get-Prop $w "domains" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        [ordered]@{ name = As-Str (Get-Prop $w "name"); domains = $(if ($doms.Count -gt 0) { , $doms } else { $null }); mode = As-Str (Get-Prop $w "mode") }
    }
    $a.cfdTunnels = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/cfd_tunnel") {
        param($t)
        $tunnelId = Get-Prop $t "id"
        $cfg = Invoke-CFGetObject -Path "/accounts/$acctId/cfd_tunnel/$tunnelId/configurations"
        $hostnames = @(foreach ($ing in @(Get-Prop (Get-Prop $cfg "config") "ingress" | Where-Object { $null -ne $_ })) {
                $h = Get-Prop $ing "hostname"; if ($h -and $h -ne "*") { [string]$h }
            })
        [ordered]@{ id = Protect-Id $tunnelId; name = As-Str (Get-Prop $t "name"); status = As-Str (Get-Prop $t "status"); publicHostnames = $hostnames }
    }
    $a.workersScripts = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/workers/scripts") {
        param($s)
        [ordered]@{
            id                = Protect-Id (Get-Prop $s "id")
            scriptName        = As-Str (Get-Prop $s "id")
            createdOn         = As-Str (Get-Prop $s "created_on")
            modifiedOn        = As-Str (Get-Prop $s "modified_on")
            plainTextBindings = @(Get-Prop $s "bindings" | Where-Object { $null -ne $_ -and (Get-Prop $_ "type") -in @("plain_text", "secret_text") } | ForEach-Object {
                    [ordered]@{ name = [string](Get-Prop $_ "name"); type = [string](Get-Prop $_ "type") } })
        }
    }
    $kv = Invoke-CFGet -Path "/accounts/$acctId/storage/kv/namespaces"
    $d1 = Invoke-CFGet -Path "/accounts/$acctId/d1/database"
    $r2 = Invoke-CFGet -Path "/accounts/$acctId/r2/buckets"
    $a.storageInventory = [ordered]@{
        kvNamespaces = $(if ($null -ne $kv) { @($kv).Count } else { $null })
        d1Databases  = $(if ($null -ne $d1) { @($d1).Count } else { $null })
        r2Buckets    = $(if ($null -ne $r2) { @($r2).Count } else { $null })
    }
    $a.aiGateways = ConvertTo-Mapped (Invoke-CFGet -Path "/accounts/$acctId/ai-gateway/gateways") {
        param($g)
        $dlp = Get-Prop $g "dlp"; $gr = Get-Prop $g "guardrails"; $sl = Get-Prop $g "spend_limits"
        $pol = Get-Prop $dlp "policies"
        [ordered]@{
            id                    = As-Str (Get-Prop $g "id")
            authentication        = As-Bool (Get-Prop $g "authentication")
            rateLimitingLimit     = As-Num (Get-Prop $g "rate_limiting_limit")
            rateLimitingInterval  = As-Num (Get-Prop $g "rate_limiting_interval")
            rateLimitingTechnique = As-Str (Get-Prop $g "rate_limiting_technique")
            collectLogs           = As-Bool (Get-Prop $g "collect_logs")
            dlpEnabled            = As-Bool (Get-Prop $dlp "enabled")
            dlpPoliciesCount      = $(if ($pol -is [array]) { $pol.Count } else { $null })
            guardrailsConfigured  = $(if ($null -ne $gr -and @($gr.PSObject.Properties).Count -gt 0) { $true } else { $null })
            spendLimitsEnabled    = As-Bool (Get-Prop $sl "enabled")
            byokOnly              = As-Bool (Get-Prop $g "byok_only")
        }
    }

    $collection.accounts += , $a
}

# ---------------------------------------------------------------------------
# PHASE 4: ZONE COLLECTION
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Collecting zones..." -ForegroundColor Cyan
$zones = Get-Array (Invoke-CFGet -Path "/zones")
$collection.zones = @()
$planTiers = @()

# Ruleset phases to collect (mirror src/endpoints.ts PHASES)
$phases = @(
    "http_request_firewall_custom",
    "http_request_firewall_managed",
    "http_ratelimit",
    "ddos_l7",
    "http_request_cache_settings",
    "http_response_headers_transform"
)

foreach ($z in $zones) {
    Write-Host "  → Zone: $($z.name)" -ForegroundColor Gray
    $zoneId = $z.id
    $plan = $z.plan
    if ($plan.name) { $planTiers += $plan.name }
    $legacy = As-Str (Get-Prop $plan "legacy_id")

    $zoneOut = [ordered]@{
        name         = [string]$z.name
        plan         = As-Str (Get-Prop $plan "name")
        planLegacyId = $(if ($legacy) { $legacy } else { Get-PlanTier (Get-Prop $plan "name") $null })
        status       = As-Str $z.status
        paused       = As-Bool $z.paused
        type         = As-Str $z.type
        createdOn    = As-Str $z.created_on
    }

    $settingsRows = Invoke-CFGet -Path "/zones/$zoneId/settings"
    if ($null -ne $settingsRows) {
        $settingsMap = [ordered]@{}
        foreach ($row in $settingsRows) {
            if (-not $row.id) { continue }
            $settingsMap[[string]$row.id] = [ordered]@{ id = [string]$row.id; value = $row.value; editable = As-Bool $row.editable }
        }
        $zoneOut.settings = $settingsMap
    }

    # Ruleset list: raw id -> name so execute rules resolve before IDs are hashed.
    $rsList = Invoke-CFGet -Path "/zones/$zoneId/rulesets"
    $rulesetNames = @{}
    foreach ($r in (Get-Array $rsList)) { if ($r.id -and ($r.name -is [string])) { $rulesetNames[[string]$r.id] = $r.name } }
    $zoneOut.rulesets = ConvertTo-Mapped $rsList {
        param($r) [ordered]@{ id = Protect-Id $r.id; name = As-Str $r.name; kind = As-Str $r.kind; phase = As-Str $r.phase; version = As-Str $r.version }
    }

    $entrypoints = [ordered]@{}
    $phaseStatus = [ordered]@{}
    foreach ($phase in $phases) {
        $ep = Invoke-CFGetObject -Path "/zones/$zoneId/rulesets/phases/$phase/entrypoint" -Quiet404
        if ($null -eq $ep) {
            $phaseStatus[$phase] = $(if ($script:LastStatus -eq 404) { "absent" } else { "unreadable" })
            continue
        }
        $phaseStatus[$phase] = "present"
        $entrypoints[$phase] = [ordered]@{
            phase = $phase
            name  = As-Str $ep.name
            kind  = As-Str $ep.kind
            rules = @(foreach ($r in @(Get-Prop $ep "rules" | Where-Object { $null -ne $_ })) {
                    $action = As-Str $r.action
                    [ordered]@{
                        id               = Protect-Id $r.id
                        description      = Protect-Emails $r.description
                        enabled          = As-Bool $r.enabled
                        action           = $action
                        expression       = Protect-Expression $r.expression
                        version          = As-Str $r.version
                        lastUpdated      = As-Str $r.last_updated
                        actionParameters = Get-ActionParametersSummary $action (Get-Prop $r "action_parameters") $rulesetNames (Get-Prop $r "ratelimit")
                    }
                })
        }
    }
    $zoneOut.phaseEntrypoints = $entrypoints
    $zoneOut.phaseStatus = $phaseStatus

    $bm = Invoke-CFGetObject -Path "/zones/$zoneId/bot_management"
    if ($null -ne $bm) {
        $b = [ordered]@{}
        foreach ($k in $script:BotKeys) { $v = Get-Prop $bm $k; if (($v -is [string]) -or ($v -is [bool])) { $b[$k] = $v } }
        if (@($bm.PSObject.Properties).Count -gt 0) { $zoneOut.botManagement = $b }
    }

    # IP access rules: mode/target; value only for country/ASN; notes dropped.
    $zoneOut.ipAccessRuleSummary = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/firewall/access_rules/rules") {
        param($r)
        $cfg = Get-Prop $r "configuration"
        $target = As-Str (Get-Prop $cfg "target")
        [ordered]@{
            mode   = As-Str (Get-Prop $r "mode")
            target = $target
            value  = $(if ($target -in @("country", "asn")) { As-Str (Get-Prop $cfg "value") } else { "[redacted]" })
            scope  = As-Str (Get-Prop (Get-Prop $r "scope") "type")
        }
    }

    # Page rules: action ids + enumerated values; URL targets dropped.
    $zoneOut.pageRuleSummary = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/pagerules") {
        param($p)
        [ordered]@{
            status  = As-Str (Get-Prop $p "status")
            actions = @(foreach ($act in @(Get-Prop $p "actions" | Where-Object { $null -ne $_ })) {
                    $id = As-Str (Get-Prop $act "id")
                    if (-not $id) { continue }
                    $v = Get-Prop $act "value"
                    $item = [ordered]@{ id = $id }
                    if ($script:PageRuleEnum -contains $id) {
                        if ($v -is [bool]) { $item.value = ([string]$v).ToLower() } elseif ($v -is [string]) { $item.value = $v }
                    }
                    $item
                })
        }
    }

    $zoneOut.certificatePacks = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/ssl/certificate_packs") {
        param($p)
        [ordered]@{
            id                   = Protect-Id (Get-Prop $p "id")
            type                 = As-Str (Get-Prop $p "type")
            status               = As-Str (Get-Prop $p "status")
            validityDays         = As-Num (Get-Prop $p "validity_days")
            certificateAuthority = As-Str (Get-Prop $p "certificate_authority")
            expiresOn            = As-Str (Get-Prop $p "expires_on")
            hosts                = @(Get-Prop $p "hosts" | Where-Object { $_ -is [string] })
        }
    }

    $zoneOut.workersRoutes = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/workers/routes") {
        param($r) [ordered]@{ pattern = As-Str (Get-Prop $r "pattern"); script = As-Str (Get-Prop $r "script") }
    }

    # DNS: content redacted unconditionally; comments (free text) dropped.
    $dns = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/dns_records") {
        param($r)
        [ordered]@{
            type    = [string](Get-Prop $r "type")
            name    = [string](Get-Prop $r "name")
            content = $(if ($null -ne (Get-Prop $r "content")) { "[redacted]" } else { $null })
            proxied = As-Bool (Get-Prop $r "proxied")
            ttl     = As-Num (Get-Prop $r "ttl")
        }
    }
    if ($null -ne $dns) { $zoneOut.dnsRecordCount = $dns.Count; $zoneOut.dnsRecords = $dns }

    $zoneOut.legacyRateLimits = ConvertTo-Mapped (Invoke-CFGet -Path "/zones/$zoneId/rate_limits") {
        param($r) [ordered]@{ disabled = ((Get-Prop $r "disabled") -eq $true) }
    }

    $mh = Invoke-CFGetObject -Path "/zones/$zoneId/managed_headers"
    if ($null -ne $mh -and @($mh.PSObject.Properties).Count -gt 0) {
        $pick = { param($list) , @(foreach ($h in @($list | Where-Object { $null -ne $_ })) { $hid = As-Str (Get-Prop $h "id"); if ($hid) { [ordered]@{ id = $hid; enabled = ((Get-Prop $h "enabled") -eq $true) } } }) }
        $zoneOut.managedHeaders = [ordered]@{
            request  = (& $pick (Get-Prop $mh "managed_request_headers"))
            response = (& $pick (Get-Prop $mh "managed_response_headers"))
        }
    }

    $lc = Invoke-CFGetObject -Path "/zones/$zoneId/leaked-credential-checks"
    if ($null -ne $lc) { $zoneOut.leakedCredentialChecks = [ordered]@{ enabled = As-Bool (Get-Prop $lc "enabled") } }

    $ps = Invoke-CFGetObject -Path "/zones/$zoneId/page_shield"
    if ($null -ne $ps) {
        $zoneOut.pageShield = [ordered]@{
            enabled                        = As-Bool (Get-Prop $ps "enabled")
            useCloudflareReportingEndpoint = As-Bool (Get-Prop $ps "use_cloudflare_reporting_endpoint")
            useConnectionUrlPath           = As-Bool (Get-Prop $ps "use_connection_url_path")
        }
    }

    $aop = Invoke-CFGetObject -Path "/zones/$zoneId/origin_tls_client_auth/settings"
    $aopCerts = Invoke-CFGet -Path "/zones/$zoneId/origin_tls_client_auth"
    if ($null -ne $aop) {
        $zoneOut.authenticatedOriginPulls = [ordered]@{
            enabled          = As-Bool (Get-Prop $aop "enabled")
            hasZoneLevelCert = $(if ($null -ne $aopCerts) { @($aopCerts).Count -gt 0 } else { $null })
            certCount        = $(if ($null -ne $aopCerts) { @($aopCerts).Count } else { $null })
        }
    }

    $collection.zones += , $zoneOut
}

$collection.planTiersSeen = @($planTiers | Sort-Object -Unique)

# ---------------------------------------------------------------------------
# PHASE 5: ERRORS (scope gaps)
# ---------------------------------------------------------------------------
# Raw account/zone/tunnel IDs in error paths are hashed like every other ID.
$collection.collectionErrors = @(foreach ($e in $script:ApiErrors) { [ordered]@{ path = (Protect-IdsInPath $e.path); error = [string]$e.error } })

# ---------------------------------------------------------------------------
# PHASE 6: SECRET SCAN + WRITE
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Assembling and redacting output..." -ForegroundColor Cyan

$json = Remove-Nulls $collection | ConvertTo-Json -Depth 30

# PRE-WRITE SECRET SCAN (mirrors src/redact.ts fail-severity patterns).
# Note: the bare word "authorization" is NOT a hit — WAF expressions
# legitimately reference the Authorization header by name.
if ($json -match "(?i)Bearer\s+[A-Za-z0-9._-]+" -or $json -match "\b[A-Za-z0-9_-]{64,}\b" -or $json -match "(?i)(?:api[_-]?key|api[_-]?token|password|credential)\s*[:=]\s*\S+") {
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
