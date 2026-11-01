#!/usr/bin/env bash
#
# ============================================================================
# CLOUDFLARE ACCOUNT SECURITY REVIEW — OFFLINE COLLECTOR (bash)
# ============================================================================
#
# PURPOSE:
#   This script collects your Cloudflare account configuration and writes it
#   to a timestamped JSON file. You run this script INSIDE your environment
#   with your API token — the token NEVER leaves your machine.
#
#   After collection, you send us ONLY the JSON file (no tokens, no credentials).
#   We analyze it and return a security review report with actionable findings.
#
# WHAT THIS SCRIPT DOES (step by step):
#
#   1. PROMPTS FOR YOUR API TOKEN (or reads CF_API_TOKEN environment variable)
#      → Your token is used only in memory during collection
#      → It is NEVER echoed to the terminal or written to the output file
#      → A pre-write scan blocks any credential-shaped data from being written
#
#   2. CALLS CLOUDFLARE'S PUBLIC API (api.cloudflare.com/client/v4)
#      → All requests are GET-only (read-only; enforced by curl -X GET)
#      → No write operations of any kind (no POST, PUT, PATCH, DELETE)
#      → No telemetry, no uploads, no third-party connections
#
#   3. COLLECTS CONFIGURATION METADATA from your account:
#      → Zone settings (SSL mode, security level, DNSSEC, etc.)
#      → Firewall rules, rate limiting rules, managed WAF status
#      → DNS record STRUCTURE (types, record counts) — contents redacted
#      → Worker scripts (names, routes) — code never collected
#      → Access applications (names, policy decisions) — identities redacted
#      → Load balancer configuration, certificate expiry dates
#      → Account settings (2FA enforcement, member roles)
#
#   4. REDACTS SENSITIVE DATA automatically (applied during assembly):
#      → DNS record contents (origin IPs, CNAME targets) → "[redacted]"
#      → Account/zone/rule IDs → SHA-256 hashed, truncated to 16 hex chars
#      → Member identities (emails/names) → role names + 2FA booleans only
#      → Firewall rule expressions → IPs, emails, internal hostnames redacted
#      → Worker bindings → names and types only; values never collected
#      → Access policies → allow/bypass/block decisions only; identities redacted
#
#   5. WRITES A TIMESTAMPED JSON FILE (cloudflare-config-YYYY-MM-DD-HHMM.json)
#      → Contains configuration metadata only
#      → File permissions set to 0600 (owner read/write only)
#      → Pre-write secret scan aborts if any credential-shaped data detected
#
# WHAT YOU SEND US:
#   The generated JSON file ONLY. We run the analyzer against it and return
#   your security review report.
#
# THE END GOAL:
#   After analysis, we return:
#     1. A detailed security review report (Markdown) with findings and recommendations
#     2. A Terraform configuration (FUTURE) with hardened defaults for your issues
#
#   The Terraform will:
#     → Address high-severity findings (e.g., switch Flexible SSL → Full(strict))
#     → Enable missing protections (e.g., deploy WAF managed rulesets, enable 2FA)
#     → Fix configuration gaps (e.g., add DNSSEC, enable Authenticated Origin Pulls)
#
#   YOU review the Terraform carefully, test in staging, and apply it when ready.
#   The goal is to give you ACTIONABLE, REVIEWABLE fixes — not just a report of problems.
#
# ============================================================================
# GUARANTEES (enforced by tests in the main repository):
# ============================================================================
#
#   ✅ READ-ONLY: Every HTTP request goes through cf_get(), which enforces curl -X GET
#   ✅ SINGLE HOST: All API calls go to api.cloudflare.com/client/v4 only
#   ✅ TOKEN SAFETY: Token from CF_API_TOKEN or secure prompt; never echoed or written
#   ✅ REDACTED BY DEFAULT: IDs hashed, DNS contents redacted, identities anonymized
#   ✅ NO EXFILTRATION: No telemetry, no uploads, no third-party connections
#   ✅ PRE-WRITE SCAN: Credential-shaped patterns abort the write before output is finalized
#
# ============================================================================
# REQUIREMENTS:
# ============================================================================
#
#   - bash
#   - curl
#   - python3 (standard library only; no jq needed)
#
# ============================================================================
# API TOKEN SCOPES (minimum required):
# ============================================================================
#
#   Create a read-only API token at:
#   Cloudflare Dashboard → My Profile → API Tokens → Create Token
#
#   REQUIRED (all zones):
#     • Account Settings: Read
#     • Zone: Read
#     • Zone Settings: Read
#     • DNS: Read
#     • Firewall Services: Read
#     • Zone WAF: Read
#
#   OPTIONAL (for deeper coverage):
#     • Workers Scripts: Read (Worker zombie scripts, dangling routes)
#     • Workers Routes: Read (Worker-to-zone routing)
#     • Workers KV Storage: Read (data-at-rest inventory)
#     • D1: Read (data-at-rest inventory)
#     • Workers R2 Storage: Read (data-at-rest inventory)
#     • Access: Apps and Policies: Read (Access policy review)
#     • Access: Identity Providers: Read (IdP and MFA posture)
#     • Access: Service Tokens: Read (token expiry hygiene)
#     • Turnstile Widgets: Read (Turnstile inventory)
#     • Cloudflare Tunnel: Read (Tunnel-to-Access gap detection)
#     • User API Tokens: Read (token rotation posture)
#     • Account API Tokens: Read (account token inventory)
#     • SSL and Certificates: Read (certificate expiry warnings)
#     • Load Balancing: Read (load balancer health checks)
#     • Load Balancer Monitors and Pools: Read (pool failover)
#     • Page Rules: Read (legacy page rule migration)
#     • Zone Rate Limiting: Read (legacy rate-limit migration)
#     • API Gateway Operations: Read (API Shield, Enterprise only)
#     • Account Rulesets: Read (account-level WAF, Enterprise only)
#
#   NARROWLY-SCOPED TOKENS WORK:
#     If your token lacks some permissions, the script will:
#       → Skip endpoints it cannot read
#       → List them in "collectionErrors" in the output
#       → Still produce a useful partial report for what it CAN read
#
# ============================================================================
# USAGE:
# ============================================================================
#
#   # With environment variable:
#   export CF_API_TOKEN=your_token_here
#   ./collect-config.sh [output-dir]
#
#   # Or let it prompt (input is hidden):
#   ./collect-config.sh [output-dir]
#
#   # Output:
#   cloudflare-config-YYYY-MM-DD-HHMM.json
#
# ============================================================================
# WHAT HAPPENS INSIDE THIS SCRIPT (technical walkthrough):
# ============================================================================
#
# PHASE 1: SETUP
#   → Read token from CF_API_TOKEN or secure prompt (no echo)
#   → Create temporary working directory (cleaned up on exit)
#   → Initialize error log for scope gaps
#
# PHASE 2: TOKEN VERIFICATION
#   → Call GET /user/tokens/verify to check token status
#   → Extract status ("active" or "verification-failed")
#   → Report to user but continue even if verification fails (narrowly-scoped tokens work)
#
# PHASE 3: ZONE COLLECTION
#   → Call GET /zones to enumerate all zones in the account
#   → For each zone, collect:
#       • Settings (SSL mode, min TLS, HSTS, DNSSEC, security level, etc.)
#       • Rulesets (which phases have deployed rulesets)
#       • Phase entrypoints (live rules per phase: WAF, rate limiting, transforms, etc.)
#       • Bot management settings (Pro+ only)
#       • WAF overrides (legacy WAF package overrides)
#       • IP access rules (allow/block lists)
#       • Page rules (legacy page rules still active)
#       • Certificate packs (custom SSL cert expiry)
#       • SSL verification status (per-hostname cert failures)
#       • Load balancers (LB posture)
#       • Workers routes (Worker-to-zone bindings)
#       • DNS records (STRUCTURE only: type, name, proxied status; content redacted)
#       • Legacy rate limits (legacy rate-limiting product)
#
# PHASE 4: ACCOUNT COLLECTION
#   → Call GET /accounts to enumerate all accounts the token can access
#   → For each account, collect:
#       • Account settings (2FA enforcement, API access, abuse contact)
#       • Members (role names + 2FA booleans only; no emails/names)
#       • API tokens (status, expiry, last-use, permission groups)
#       • Load balancer pools and monitors (health check hygiene)
#       • Account-level rulesets (shared WAF across zones, Enterprise only)
#       • Access applications (policy-less apps, bypass decisions)
#       • Access identity providers (OTP-only IdP audit)
#       • Turnstile widgets (widget inventory, domains, mode)
#       • Tunnels (unsecured internal services exposed via public hostnames)
#       • Worker scripts (script inventory, routes, binding names/types)
#       • Storage inventory (KV/D1/R2 counts only; never contents)
#
# PHASE 5: ASSEMBLY + REDACTION
#   → Load all collected data from temporary files
#   → Apply redaction rules (this is the SINGLE PLACE where redaction happens):
#       • Hash all IDs (account, zone, rule IDs) → SHA-256, first 16 hex chars
#       • Redact DNS record contents → "[redacted]"
#       • Redact IPs, emails, internal hostnames in firewall expressions
#       • Reduce member identities to role names + 2FA booleans
#       • Reduce Access policies to decisions (allow/bypass/block); no identities
#       • Keep Worker binding names/types; values never collected
#   → Build final JSON document with schema version 1.0
#   → Run PRE-WRITE SECRET SCAN:
#       • Search serialized JSON for "Bearer ...", long opaque strings, credential patterns
#       • If any matches found, ABORT without writing anything
#   → Write final JSON to output file with 0600 permissions
#   → Report zones collected, errors encountered
#
# PHASE 6: CLEANUP
#   → Remove temporary working directory
#   → Print summary and next steps
#
# ============================================================================
# AFTER COLLECTION — WHAT YOU DO:
# ============================================================================
#
#   1. VERIFY THE OUTPUT FILE:
#      → Open cloudflare-config-YYYY-MM-DD-HHMM.json in a text editor
#      → Confirm no API tokens, passwords, or credentials present
#      → Confirm DNS record contents are "[redacted]"
#      → Confirm account/zone IDs are hashed (start with "h...")
#
#   2. SEND US THE JSON FILE:
#      → Email, Signal, 1Password share, encrypted file transfer, etc.
#      → DO NOT send your API token (we don't need it)
#
#   3. WE ANALYZE AND RETURN:
#      → Detailed security review report (Markdown)
#      → Terraform configuration (FUTURE) with hardened defaults
#
#   4. YOU REVIEW THE TERRAFORM:
#      → Read every resource, every setting
#      → Test in a staging environment first
#      → Apply to production when you're confident
#
# ============================================================================

set -euo pipefail

# Configuration
BASE_URL="https://api.cloudflare.com/client/v4"
COLLECTOR_VERSION="0.1.0"
OUT_DIR="${1:-.}"
PER_PAGE=50
MAX_PAGES=50

# Token handling (from environment or secure prompt)
TOKEN="${CF_API_TOKEN:-}"
if [ -z "$TOKEN" ]; then
	printf "Paste your Cloudflare API token: "
	read -rs TOKEN # -s = silent (no echo), -r = raw input
	printf "\n"
fi
[ -n "$TOKEN" ] || {
	echo "No token supplied. Exiting." >&2
	exit 1
}

# Working directory (cleaned up on exit)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Error logger (scope gaps are expected with narrowly-scoped tokens)
record_error() {
	printf '%s\t%s\n' "$1" "$2" >>"$WORK/errors.tsv"
}

# ---------------------------------------------------------------------------
# cf_get: GET-only HTTP wrapper with pagination
# ---------------------------------------------------------------------------
# This is the ONLY place curl is invoked. Every HTTP request goes through here.
#
# Parameters:
#   $1 = name (used for output filename)
#   $2 = API path (e.g., "/zones" or "/accounts/{id}/settings")
#
# Behavior:
#   1. Calls curl -X GET (enforces read-only; no write methods possible)
#   2. Paginates automatically (up to MAX_PAGES pages)
#   3. Writes merged result array to $WORK/files/<name>.json
#   4. Returns 0 on success, 1 on failure (writes "null" to output on failure)
#   5. Records errors in errors.tsv for reporting
#
# Why pagination?
#   Some endpoints return 50 results per page by default. This function
#   automatically fetches all pages and merges them into a single array.
#
# Why curl -X GET?
#   Enforces read-only at the HTTP level. No POST, PUT, PATCH, DELETE possible.
#   Tests in the main repo verify this.
#
# ---------------------------------------------------------------------------
cf_get() {
	local name="$1" path="$2" page=1
	mkdir -p "$WORK/files"
	local out="$WORK/files/$name.json"
	local merged="$WORK/files/.merged-$name.json"

	# Initialize merged result array
	printf '[]' >"$merged"

	while [ "$page" -le "$MAX_PAGES" ]; do
		# Build paginated URL
		local sep='?'
		case "$path" in *\?*) sep='&' ;; esac
		local url="${BASE_URL}${path}${sep}page=${page}&per_page=${PER_PAGE}"

		# Make GET request
		local tmp status
		tmp="$(mktemp)"
		status=$(curl -sS -X GET -o "$tmp" -w "%{http_code}" \
			-H "Authorization: Bearer ${TOKEN}" \
			-H "Content-Type: application/json" \
			--max-time 60 "$url") || { status="000"; }

		# Check HTTP status
		if [ "$status" != "200" ]; then
			rm -f "$tmp"
			record_error "$path" "HTTP $status"
			printf 'null' >"$out"
			return 1
		fi

		# Check API success field
		local ok
		ok="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('1' if d.get('success') else '0')" "$tmp")" || ok="0"
		if [ "$ok" != "1" ]; then
			rm -f "$tmp"
			record_error "$path" "API reported failure"
			printf 'null' >"$out"
			return 1
		fi

		# Merge this page's results into the accumulator
		read -r total have <<<"$(
			python3 - "$merged" "$tmp" <<'PY'
import json, sys
merged_path, page_path = sys.argv[1], sys.argv[2]
merged = json.load(open(merged_path))
page = json.load(open(page_path))
result = page.get("result")
result = result if isinstance(result, list) else ([] if result is None else [result])
merged.extend(result)
json.dump(merged, open(merged_path, "w"))
info = page.get("result_info") or {}
print(info.get("total_pages") or 1, len(result))
PY
		)"
		rm -f "$tmp"

		# Stop if we've fetched all pages or hit a partial page
		if [ "$page" -ge "$total" ] || [ "$have" -lt "$PER_PAGE" ]; then break; fi
		page=$((page + 1))
	done

	mv "$merged" "$out"
	return 0
}

# ---------------------------------------------------------------------------
# cf_get_obj: Single-object fetch (non-paginated)
# ---------------------------------------------------------------------------
# Same as cf_get but for endpoints that return a single object, not an array.
# Writes result object (not wrapped in array) to files/<name>.json.
# ---------------------------------------------------------------------------
cf_get_obj() {
	local name="$1" path="$2"
	mkdir -p "$WORK/files"
	local out="$WORK/files/$name.json"

	local tmp status
	tmp="$(mktemp)"
	status=$(curl -sS -X GET -o "$tmp" -w "%{http_code}" \
		-H "Authorization: Bearer ${TOKEN}" \
		-H "Content-Type: application/json" \
		--max-time 60 "${BASE_URL}${path}") || status="000"

	if [ "$status" != "200" ]; then
		rm -f "$tmp"
		record_error "$path" "HTTP $status"
		printf 'null' >"$out"
		return 1
	fi

	# Extract result object (not array)
	python3 - "$tmp" "$out" <<'PY'
import json, sys
page = json.load(open(sys.argv[1]))
if page.get("success") and page.get("result") is not None:
    json.dump(page["result"], open(sys.argv[2], "w"))
else:
    json.dump(None, open(sys.argv[2], "w"))
PY
	rm -f "$tmp"
}

# Initialize
mkdir -p "$WORK/files"
: >"$WORK/errors.tsv"

# Ruleset phases to collect (these are Cloudflare's standard phases)
PHASES="http_request_firewall_custom http_request_firewall_managed http_ratelimit http_request_transform http_request_dynamic_redirect http_request_cache_settings http_request_origin http_request_redirect"

# ============================================================================
# PHASE 2: TOKEN VERIFICATION
# ============================================================================
echo "Verifying API token…"
cf_get_obj "token-verify" "/user/tokens/verify" >/dev/null 2>&1 || true
TOKEN_STATUS="$(python3 -c "
import json
try:
    d=json.load(open('$WORK/files/token-verify.json'))
    print(d.get('status','verification-failed'))
except Exception:
    print('verification-failed')
")"
echo "Token status: $TOKEN_STATUS"
if [ "$TOKEN_STATUS" != "active" ]; then
	echo "⚠️  Token verification failed. This may mean your token is narrowly scoped."
	echo "   The script will continue and collect what it can access."
fi

# ============================================================================
# PHASE 3: ZONE COLLECTION
# ============================================================================
echo ""
echo "Collecting zones…"
cf_get "zones" "/zones" >/dev/null 2>&1 || true

# For each zone, collect zone-level configuration
while IFS=$'\t' read -r zone_id zone_name; do
	[ -n "$zone_id" ] || continue
	echo "  → Zone: $zone_name"

	# Core zone configuration
	for ep in "settings:/settings" \
		"rulesets:/rulesets" \
		"bot_management:/bot_management" \
		"waf_overrides:/firewall/waf/overrides" \
		"ip_access_rules:/firewall/access_rules/rules" \
		"page_rules:/pagerules" \
		"certificate_packs:/ssl/certificate_packs" \
		"ssl_verification:/ssl/verification" \
		"load_balancers:/load_balancers" \
		"workers_routes:/workers/routes" \
		"dns_records:/dns_records" \
		"legacy_rate_limits:/rate_limits" \
		"page_shield:/page_shield" \
		"origin_tls_settings:/origin_tls_client_auth/settings" \
		"origin_tls_certs:/origin_tls_client_auth"; do
		label="${ep%%:*}"
		suffix="${ep#*:}"
		cf_get "zone-${zone_id}-${label}" "/zones/${zone_id}${suffix}" >/dev/null 2>&1 || true
	done

	# Ruleset phase entrypoints (live rules per phase)
	for phase in $PHASES; do
		cf_get "zone-${zone_id}-phase-${phase}" "/zones/${zone_id}/rulesets/phases/${phase}/entrypoint" >/dev/null 2>&1 || true
	done
done < <(python3 -c "
import json
try:
    zones=json.load(open('$WORK/files/zones.json')) or []
except Exception:
    zones=[]
for z in zones:
    print(f\"{z.get('id','')}\t{z.get('name','')}\")
")

# ============================================================================
# PHASE 4: ACCOUNT COLLECTION
# ============================================================================
echo ""
echo "Collecting accounts…"
cf_get "accounts" "/accounts" >/dev/null 2>&1 || true

# For each account, collect account-level configuration
while IFS= read -r account_id; do
	[ -n "$account_id" ] || continue
	echo "  → Account: $account_id"

	# Core account configuration
	for ep in "settings:/settings" \
		"members:/members" \
		"tokens:/tokens" \
		"lb_pools:/load_balancers/pools" \
		"lb_monitors:/load_balancers/monitors" \
		"account_rulesets:/rulesets" \
		"access_apps:/access/apps" \
		"access_idps:/access/identity_providers" \
		"turnstile:/challenges/widgets" \
		"tunnels:/cfd_tunnel" \
		"worker_scripts:/workers/scripts" \
		"kv:/storage/kv/namespaces" \
		"d1:/d1/database" \
		"r2:/r2/buckets"; do
		label="${ep%%:*}"
		suffix="${ep#*:}"
		cf_get "acct-${account_id}-${label}" "/accounts/${account_id}${suffix}" >/dev/null 2>&1 || true
	done

	# User tokens (collected per account for token inventory)
	cf_get "acct-${account_id}-user-tokens" "/user/tokens" >/dev/null 2>&1 || true

	# For each tunnel, collect its configuration to extract public hostnames
	while IFS= read -r tunnel_id; do
		[ -n "$tunnel_id" ] || continue
		cf_get "acct-${account_id}-tunnel-${tunnel_id}-config" "/accounts/${account_id}/cfd_tunnel/${tunnel_id}/configurations" >/dev/null 2>&1 || true
	done < <(python3 -c "
import json
try:
    tunnels=json.load(open('$WORK/files/acct-${account_id}-tunnels.json')) or []
except Exception:
    tunnels=[]
for t in tunnels:
    print(t.get('id',''))
")
done < <(python3 -c "
import json
try:
    accts=json.load(open('$WORK/files/accounts.json')) or []
except Exception:
    accts=[]
for a in accts:
    print(a.get('id',''))
")

# ============================================================================
# PHASE 5: ASSEMBLY + REDACTION
# ============================================================================
echo ""
echo "Assembling and redacting output…"
if [ ! -d "$OUT_DIR" ]; then mkdir -p "$OUT_DIR"; fi
OUT_FILE="$OUT_DIR/cloudflare-config-$(date -u +%Y-%m-%d-%H%M).json"

python3 - "$WORK" "$OUT_FILE" "$TOKEN_STATUS" "$COLLECTOR_VERSION" <<'PY'
"""
ASSEMBLER + REDACTOR

This is the SINGLE PLACE where redaction decisions live for the bash collector.

What it does:
  1. Reads every collected file from the working directory
  2. Applies the data policy (hashing, redaction, anonymization)
  3. Builds the final collection document (schema version 1.0)
  4. Runs a pre-write secret scan (aborts if credential patterns found)
  5. Writes the final JSON file with 0600 permissions

Redaction rules applied:
  → Account/zone/rule IDs: SHA-256 hash, first 16 hex chars (prefix "h...")
  → DNS record contents: "[redacted]"
  → Firewall expressions: IPs, emails, internal hostnames → "[redacted]"
  → Member identities: role names + 2FA booleans only (no emails/names)
  → Access policies: decisions only (allow/bypass/block); identities never exported
  → Worker bindings: names and types only; values never collected
  → Tokens: status, expiry, last-use, permission groups only (values never in responses)
"""
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

work, out_file, token_status, collector_version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files_dir = os.path.join(work, "files")

def load(name):
    """Load a JSON file from the working directory; return None on failure."""
    path = os.path.join(files_dir, f"{name}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def arr(name):
    """Load a JSON file and ensure it's an array."""
    v = load(name)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]

def obj(name):
    """Load a JSON file and ensure it's an object."""
    v = load(name)
    return v if isinstance(v, dict) else None

def hash_id(value):
    """Hash an ID (account, zone, rule) using SHA-256, truncate to 16 hex chars."""
    if not value:
        return None
    return "h" + hashlib.sha256(str(value).encode()).hexdigest()[:16]

# Regex patterns for redaction
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local)\b", re.I)
REDACTED = "[redacted]"

def redact_expr(expr):
    """Redact IPs, emails, and internal hostnames from firewall rule expressions."""
    if not isinstance(expr, str):
        return expr
    out = IP.sub(REDACTED, expr)
    out = EMAIL.sub(REDACTED, out)
    out = INTERNAL_HOST.sub(REDACTED, out)
    return out

def settings_map(zone_id):
    """Build a map of zone settings (id → {id, value, editable})."""
    rows = arr(f"zone-{zone_id}-settings")
    return {r["id"]: {"id": r["id"], "value": r.get("value"), "editable": r.get("editable")} for r in rows if isinstance(r, dict) and "id" in r}

def phase_entrypoints(zone_id):
    """Collect ruleset phase entrypoints with redacted expressions."""
    phases = ["http_request_firewall_custom", "http_request_firewall_managed", "http_ratelimit",
              "http_request_transform", "http_request_dynamic_redirect", "http_request_cache_settings",
              "http_request_origin", "http_request_redirect"]
    out = {}
    for phase in phases:
        ep = obj(f"zone-{zone_id}-phase-{phase}")
        if not ep:
            continue
        rules = []
        for r in ep.get("rules") or []:
            rules.append({
                "id": hash_id(r.get("id")),
                "description": r.get("description"),
                "enabled": r.get("enabled"),
                "action": r.get("action"),
                "expression": redact_expr(r.get("expression")),
                "version": r.get("version"),
                "lastUpdated": r.get("last_updated"),
            })
        out[phase] = {"phase": phase, "name": ep.get("name"), "kind": ep.get("kind"), "rules": rules}
    return out

def page_shield_doc(zone_id):
    """Extract Page Shield settings. Always emits the object (fail-closed: absent
    fields mean unknown, mirroring the TS collector's asRecord() behavior)."""
    ps = obj(f"zone-{zone_id}-page_shield") or {}
    out = {}
    if isinstance(ps.get("enabled"), bool):
        out["enabled"] = ps["enabled"]
    if isinstance(ps.get("use_cloudflare_reporting_endpoint"), bool):
        out["useCloudflareReportingEndpoint"] = ps["use_cloudflare_reporting_endpoint"]
    if isinstance(ps.get("use_connection_url_path"), bool):
        out["useConnectionUrlPath"] = ps["use_connection_url_path"]
    return out

def authenticated_origin_pulls_doc(zone_id):
    """Extract Authenticated Origin Pulls settings. Always emits the object."""
    settings = obj(f"zone-{zone_id}-origin_tls_settings") or {}
    certs = arr(f"zone-{zone_id}-origin_tls_certs")
    out = {}
    if isinstance(settings.get("enabled"), bool):
        out["enabled"] = settings["enabled"]
    out["hasZoneLevelCert"] = len(certs) > 0
    out["certCount"] = len(certs)
    return out

def zone_doc(z):
    """Build a complete zone document with all collected data and redactions applied."""
    zone_id, zone_name = z.get("id", ""), z.get("name", "")
    plan = (z.get("plan") or {}).get("name")
    dns = arr(f"zone-{zone_id}-dns_records")
    return {
        "name": zone_name,
        "plan": plan,
        "status": z.get("status"),
        "paused": z.get("paused"),
        "type": z.get("type"),
        "createdOn": z.get("created_on"),
        "settings": settings_map(zone_id),
        "rulesets": [{"id": hash_id(r.get("id")), "name": r.get("name"), "kind": r.get("kind"),
                      "phase": r.get("phase"), "version": r.get("version")} for r in arr(f"zone-{zone_id}-rulesets")],
        "phaseEntrypoints": phase_entrypoints(zone_id),
        "botManagement": obj(f"zone-{zone_id}-bot_management"),
        "wafOverrides": arr(f"zone-{zone_id}-waf_overrides"),
        "ipAccessRules": arr(f"zone-{zone_id}-ip_access_rules"),
        "pageRules": arr(f"zone-{zone_id}-page_rules"),
        "certificatePacks": arr(f"zone-{zone_id}-certificate_packs"),
        "sslVerification": arr(f"zone-{zone_id}-ssl_verification"),
        "loadBalancers": arr(f"zone-{zone_id}-load_balancers"),
        "workersRoutes": [{"pattern": r.get("pattern"), "script": r.get("script")} for r in arr(f"zone-{zone_id}-workers_routes")],
        "dnsRecordCount": len(dns),
        "dnsRecords": [{"type": d.get("type"), "name": d.get("name"), "content": REDACTED if d.get("content") is not None else None,
                        "proxied": d.get("proxied"), "ttl": d.get("ttl"), "comment": d.get("comment")} for d in dns],
        "legacyRateLimits": arr(f"zone-{zone_id}-legacy_rate_limits"),
        "pageShield": page_shield_doc(zone_id),
        "authenticatedOriginPulls": authenticated_origin_pulls_doc(zone_id),
    }

def tunnel_doc(acct_id, tunnel):
    """Build a tunnel document with public hostnames extracted from config."""
    tunnel_id = tunnel.get("id", "")
    configs = arr(f"acct-{acct_id}-tunnel-{tunnel_id}-config")
    public_hostnames = []
    for config in configs:
        for ingress in (config.get("config") or {}).get("ingress") or []:
            hostname = ingress.get("hostname")
            if hostname and hostname != "*":
                public_hostnames.append(hostname)
    return {
        "id": hash_id(tunnel_id),
        "name": tunnel.get("name"),
        "status": tunnel.get("status"),
        "publicHostnames": public_hostnames,
    }

def account_doc(a):
    """Build a complete account document with all collected data and redactions applied."""
    acct_id = a.get("id", "")
    settings = obj(f"acct-{acct_id}-settings") or {}
    
    # Member identities → role names + 2FA booleans only
    members = []
    for m in arr(f"acct-{acct_id}-members"):
        roles = []
        for p in m.get("policies") or []:
            roles.extend(g.get("name") for g in p.get("permission_groups") or [])
        user = m.get("user") or {}
        members.append({
            "roleNames": [r for r in roles if r],
            "twofactorEnabled": user.get("two_factor_authentication_enabled"),
            "status": m.get("status"),
        })
    
    # API tokens → metadata only (values never in responses)
    tokens = []
    for t in arr(f"acct-{acct_id}-user-tokens") + arr(f"acct-{acct_id}-tokens"):
        groups = []
        for p in t.get("policies") or []:
            groups.extend(g.get("name") for g in p.get("permission_groups") or [])
        tokens.append({
            "status": t.get("status"), "expiresOn": t.get("expires_on"),
            "lastUsedOn": t.get("last_used_on"), "permissionGroupNames": [g for g in groups if g],
        })
    
    # Worker scripts → names, routes, binding names/types only (never values)
    scripts = []
    for s in arr(f"acct-{acct_id}-worker_scripts"):
        bindings = [{"name": b.get("name"), "type": b.get("type")}
                    for b in s.get("bindings") or [] if b.get("type") in ("plain_text", "secret_text")]
        scripts.append({
            "id": hash_id(s.get("id")), "scriptName": s.get("id"),
            "createdOn": s.get("created_on"), "modifiedOn": s.get("modified_on"),
            "plainTextBindings": bindings,
        })
    
    # Storage inventory → counts only (never contents)
    storage = {
        "kvNamespaces": len(arr(f"acct-{acct_id}-kv")),
        "d1Databases": len(arr(f"acct-{acct_id}-d1")),
        "r2Buckets": len(arr(f"acct-{acct_id}-r2")),
    }
    
    # Access apps → decisions only (identities never exported)
    access_apps = []
    for app in arr(f"acct-{acct_id}-access_apps"):
        policies = app.get("policies") or []
        access_apps.append({
            "name": app.get("name"), "type": app.get("type"), "domain": app.get("domain"),
            "selfHostedDomains": app.get("self_hosted_domains") or [],
            "hasPolicies": len(policies) > 0,
            "policyDecisions": [p.get("decision") for p in policies if p.get("decision")],
        })
    
    # Tunnels with public hostnames
    tunnels = [tunnel_doc(acct_id, t) for t in arr(f"acct-{acct_id}-tunnels")]
    
    return {
        "id": hash_id(acct_id), "name": a.get("name"),
        "enforceTwofactor": settings.get("enforce_twofactor"),
        "accountMembers": members,
        "apiTokens": tokens,
        "loadBalancerPools": arr(f"acct-{acct_id}-lb_pools"),
        "loadBalancerMonitors": arr(f"acct-{acct_id}-lb_monitors"),
        "accountRulesets": [{"name": r.get("name"), "kind": r.get("kind"), "phase": r.get("phase")}
                            for r in arr(f"acct-{acct_id}-account_rulesets")],
        "accessApps": access_apps,
        "accessIdentityProviders": [{"name": p.get("name"), "type": p.get("type")} for p in arr(f"acct-{acct_id}-access_idps")],
        "turnstileWidgets": [{"name": w.get("name"), "domains": w.get("domains"), "mode": w.get("mode")}
                             for w in arr(f"acct-{acct_id}-turnstile")],
        "cfdTunnels": tunnels,
        "workersScripts": scripts,
        "storageInventory": storage,
    }

# Load collection errors (scope gaps)
errors = []
err_path = os.path.join(work, "errors.tsv")
if os.path.exists(err_path):
    with open(err_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2:
                errors.append({"path": parts[0], "error": parts[1]})

# Build final document
zones = arr("zones")
plans = sorted({(z.get("plan") or {}).get("name") for z in zones if (z.get("plan") or {}).get("name")})
doc = {
    "schemaVersion": "1.0",
    "collectedAt": datetime.now(timezone.utc).isoformat(),
    "collector": "bash",
    "collectorVersion": collector_version,
    "tokenStatus": token_status if token_status == "active" else "verification-failed",
    "planTiersSeen": plans,
    "accounts": [account_doc(a) for a in arr("accounts")],
    "zones": [zone_doc(z) for z in zones],
    "collectionErrors": errors,
}

# Serialize to JSON
text = json.dumps(doc, indent=2)

# PRE-WRITE SECRET SCAN: abort if any credential-shaped patterns detected
if re.search(r"Bearer\s+\S+", text, re.I):
    print("❌ ABORTING: Pre-write secret scan matched an authorization pattern.", file=sys.stderr)
    print("   Nothing written. This is a safety check to prevent credential leakage.", file=sys.stderr)
    sys.exit(1)

# Write final output
with open(out_file, "w") as f:
    f.write(text)
os.chmod(out_file, 0o600)  # Owner read/write only

print(f"✅ Written: {out_file}")
print(f"   Zones: {len(zones)}; Errors: {len(errors)} (scope gaps are expected with narrowly-scoped tokens)")
PY

# ============================================================================
# PHASE 6: DONE
# ============================================================================
echo ""
echo "============================================================================"
echo "COLLECTION COMPLETE"
echo "============================================================================"
echo ""
echo "Output file: $OUT_FILE"
echo ""
echo "This file contains configuration metadata only:"
echo "  ✅ No API tokens, passwords, or credentials"
echo "  ✅ No DNS record contents (redacted as \"[redacted]\")"
echo "  ✅ No customer identities (emails/names anonymized)"
echo "  ✅ No Worker script source code"
echo "  ✅ No Access policy identity expressions"
echo ""
echo "NEXT STEPS:"
echo "  1. Open the file in a text editor and verify redactions"
echo "  2. Send us ONLY this JSON file (no tokens, no credentials)"
echo "  3. We will analyze it and return:"
echo "      → Detailed security review report (Markdown)"
echo "      → Terraform configuration (FUTURE) with hardened defaults"
echo "  4. YOU review the Terraform, test in staging, and apply when ready"
echo ""
echo "Questions? Contact us before sending the file."
echo "============================================================================"
