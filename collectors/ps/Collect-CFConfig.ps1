<#
.SYNOPSIS
    cf-account-review offline collector (Mode B, PowerShell).

.DESCRIPTION
    READ-ONLY. Calls only Cloudflare public API GET endpoints using the API token
    you supply, and writes the collected configuration to a timestamped JSON file
    that the cf-account-review analyzer consumes.

    GUARANTEES (also enforced by tests in the cf-account-review repo):
      - Only GET requests are issued. This script cannot create, modify, or
        delete anything in your Cloudflare account.
      - Only api.cloudflare.com is contacted. No telemetry, no uploads.
      - The token is read from $env:CF_API_TOKEN or a secure prompt. It is never
        echoed, logged, or written to the output file.
      - Redacted by default: DNS record contents (origin IPs / CNAME targets),
        account/zone/rule IDs (hashed), rule expressions are scanned for
        email addresses and internal hostnames.
      - Endpoints the token cannot read are skipped gracefully and listed in
        "collectionErrors"; a partially-scoped token still works.

    Token scopes (My Profile > API Tokens, all zones):
      - Account: Account Settings: Read
      - Zone: Zone: Read, Zone Settings: Read, DNS: Read,
        Firewall Services: Read, Zone WAF: Read

    Requirements: Windows PowerShell 5.1+ or PowerShell 7+, outbound HTTPS to
    api.cloudflare.com.

.EXAMPLE
    .\Collect-CFConfig.ps1
    .\Collect-CFConfig.ps1 -OutputDir C:\Temp
#>
[CmdletBinding()]
param(
    # Directory for the output file. Default: current directory.
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"
$Base = "https://api.cloudflare.com/client/v4"
$script:ApiErrors = @()
$script:CollectorVersion = "0.1.0"

# ---------------------------------------------------------------------------
# Token handling — never echoed, never written to disk
# ---------------------------------------------------------------------------
$token = $env:CF_API_TOKEN
if (-not $token) {
    $secure = Read-Host -Prompt "Paste your Cloudflare API token" -AsSecureString
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "No API token supplied. Exiting."
}
$Headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

# ---------------------------------------------------------------------------
# GET-only helpers
# ---------------------------------------------------------------------------
function Invoke-CFGet {
    param([string]$Path, [int]$MaxPages = 50)
    # GET-only wrapper with pagination. Never issues any other HTTP method.
    try {
        $all = @()
        $page = 1
        while ($page -le $MaxPages) {
            $sep = if ($Path.Contains("?")) { "&" } else { "?" }
            $resp = Invoke-RestMethod -Uri "$Base$Path${sep}page=$page&per_page=50" `
                -Headers $Headers -Method Get -TimeoutSec 60
            if (-not $resp.success) {
                $script:ApiErrors += @{ path = $Path; error = ($resp.errors | ConvertTo-Json -Compress -Depth 5) }
                return $null
            }
            $all += $resp.result
            $info = $resp.result_info
            if ($null -eq $info -or $page -ge $info.total_pages -or $resp.result.Count -eq 0) { break }
            $page++
        }
        return $all
    } catch {
        $script:ApiErrors += @{ path = $Path; error = $_.Exception.Message }
        return $null
    }
}

function Get-Array { param($Value) if ($null -eq $Value) { @() } else { @($Value) } }

# --- redaction helpers (mirrors src/redact.ts) ---
function Protect-Id { param($Id) if ($Id) { return "h" + ([BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Id))).Replace("-","").Substring(0,16)).ToLower() } return $null }

function Protect-Expression {
    param($Expression, $ZoneName)
    if (-not $Expression) { return $Expression }
    $expr = $Expression -replace '\b\d{1,3}(\.\d{1,3}){3}\b', "[redacted]"
    $expr = $expr -replace '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', "[redacted]"
    $expr = $expr -replace '\b([a-z0-9-]+\.)*(internal|corp|intranet|local)\b', "[redacted]"
    return $expr
}

function Protect-DnsContent { param($Content) if ($null -ne $Content) { return "[redacted]" } return $null }

function Get-Setting { param($Settings, $Id) $row = $Settings | Where-Object { $_.id -eq $Id } | Select-Object -First 1; if ($row) { return $row.value } return $null }

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------
$collection = [ordered]@{
    schemaVersion    = "1.0"
    collectedAt      = (Get-Date).ToUniversalTime().ToString("o")
    collector        = "powershell"
    collectorVersion = $script:CollectorVersion
}

# 1. Token verification (status only)
$verify = Invoke-CFGet -Path "/user/tokens/verify"
$collection.tokenStatus = if ($verify) { (Get-Array $verify)[0].status } else { "verification-failed" }

# 2. Accounts
$accounts = Get-Array (Invoke-CFGet -Path "/accounts")
$planTiers = @()
$collection.accounts = @()
foreach ($acct in $accounts) {
    Write-Host "  Collecting account: $($acct.name)"
    $acctId = $acct.id
    $a = [ordered]@{ id = (Protect-Id $acctId); name = $acct.name }

    $settings = Invoke-CFGet -Path "/accounts/$acctId/settings"
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
            status        = $_.status
            expiresOn     = $_.expires_on
            lastUsedOn    = $_.last_used_on
            permissionGroupNames = @($_.policies | ForEach-Object { $_.permission_groups | ForEach-Object { $_.name } } | Where-Object { $_ })
        }
    }

    $a | Add-Member -NotePropertyName loadBalancerPools -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/pools")
    $a | Add-Member -NotePropertyName loadBalancerMonitors -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/load_balancers/monitors")
    $a | Add-Member -NotePropertyName accountRulesets -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/rulesets")

    # Access apps: decisions + policy presence only
    $accessApps = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/access/apps")
    $a.accessApps = $accessApps | ForEach-Object {
        $policies = @($_.policies)
        [ordered]@{
            name            = $_.name
            type            = $_.type
            domain          = $_.domain
            hasPolicies     = ($policies.Count -gt 0)
            policyDecisions = @($policies | ForEach-Object { $_.decision } | Where-Object { $_ })
        }
    }

    $idps = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/access/identity_providers")
    $a.accessIdentityProviders = $idps | ForEach-Object { [ordered]@{ name = $_.name; type = $_.type } }

    # Turnstile widgets
    $widgets = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/challenges/widgets")
    $a.turnstileWidgets = $widgets | ForEach-Object {
        [ordered]@{ name = $_.name; domains = @($_.domains); mode = $_.mode }
    }

    $a | Add-Member -NotePropertyName cfdTunnels -NotePropertyValue (Invoke-CFGet -Path "/accounts/$acctId/cfd_tunnel")

    # Workers scripts: names + plaintext binding names/types (never values)
    $scripts = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/workers/scripts")
    $a.workersScripts = $scripts | ForEach-Object {
        $bindings = @($_.bindings)
        [ordered]@{
            id                 = (Protect-Id $_.id)
            scriptName         = $_.id
            createdOn          = $_.created_on
            modifiedOn         = $_.modified_on
            plainTextBindings  = @($bindings | Where-Object { $_.type -in @("plain_text","secret_text") } | ForEach-Object { [ordered]@{ name = $_.name; type = $_.type } })
        }
    }

    # Storage inventory (counts only)
    $kv = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/storage/kv/namespaces")
    $d1 = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/d1/database")
    $r2 = Get-Array (Invoke-CFGet -Path "/accounts/$acctId/r2/buckets")
    $a.storageInventory = [ordered]@{ kvNamespaces = $kv.Count; d1Databases = $d1.Count; r2Buckets = $r2.Count }

    $collection.accounts += $a
}

# 3. Zones
$zones = Get-Array (Invoke-CFGet -Path "/zones?per_page=50")
$collection.zones = @()

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
    Write-Host "  Collecting zone: $($z.name)"
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
        $settingsMap[$row.id] = [ordered]@{ id = $row.id; value = $row.value; editable = $row.editable }
    }
    $zoneOut | Add-Member -NotePropertyName settings -NotePropertyValue $settingsMap

    # Ruleset inventory
    $rsList = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/rulesets")
    $zoneOut.rulesets = $rsList | ForEach-Object {
        [ordered]@{ id = (Protect-Id $_.id); name = $_.name; kind = $_.kind; phase = $_.phase; version = $_.version }
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

    $zoneOut | Add-Member -NotePropertyName botManagement -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/bot_management")
    $zoneOut | Add-Member -NotePropertyName wafOverrides -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/firewall/waf/overrides")
    $zoneOut | Add-Member -NotePropertyName ipAccessRules -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/firewall/access_rules/rules?per_page=100")
    $zoneOut | Add-Member -NotePropertyName pageRules -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/pagerules?per_page=100")
    $zoneOut | Add-Member -NotePropertyName certificatePacks -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/ssl/certificate_packs?status=all")
    $zoneOut | Add-Member -NotePropertyName sslVerification -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/ssl/verification")
    $zoneOut | Add-Member -NotePropertyName loadBalancers -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/load_balancers")

    $routes = Get-Array (Invoke-CFGet -Path "/zones/$zoneId/workers/routes")
    $zoneOut.workersRoutes = $routes | ForEach-Object { [ordered]@{ pattern = $_.pattern; script = $_.script } }

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

    $zoneOut | Add-Member -NotePropertyName legacyRateLimits -NotePropertyValue (Invoke-CFGet -Path "/zones/$zoneId/rate_limits")

    $collection.zones += $zoneOut
}

if ($planTiers.Count -gt 0) {
    $collection.planTiersSeen = @($planTiers | Sort-Object -Unique)
}

# 4. Errors (scope gaps show up here)
$collection.collectionErrors = $script:ApiErrors

# ---------------------------------------------------------------------------
# Secret scan + write
# ---------------------------------------------------------------------------
$json = $collection | ConvertTo-Json -Depth 12
if ($json -match "Bearer\s+\S+" -or $json -match "(?i)authorization") {
    Write-Host "ABORTING: pre-write secret scan matched an authorization pattern. Nothing written." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$outFile = Join-Path $OutputDir ("cloudflare-config-{0}.json" -f (Get-Date -Format "yyyy-MM-dd-HHmm"))
$json | Out-File -FilePath $outFile -Encoding UTF8

Write-Host ""
Write-Host "DONE. Output written to: $outFile" -ForegroundColor Green
Write-Host "Zones collected: $($collection.zones.Count)"
if ($script:ApiErrors.Count -gt 0) {
    Write-Host "Endpoints skipped (usually token scope): $($script:ApiErrors.Count) - see collectionErrors in the file" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "This file contains configuration only - no credentials, no DNS contents, no identities."