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
#     → A detailed security review report (Markdown) with findings and recommendations
#     → Step-by-step remediation instructions for each finding
#     → Direct links to official Cloudflare documentation for every check
#
#   The report will:
#     → Identify high-severity findings (e.g., Flexible SSL → Full(strict))
#     → Flag missing protections (e.g., WAF managed rulesets, 2FA)
#     → Highlight configuration gaps (e.g., DNSSEC, Authenticated Origin Pulls)
#
#   YOU decide which recommendations to implement and when.
#   The goal is to give you ACTIONABLE, DOCUMENTED guidance — not just a list of problems.
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
#     • Turnstile Sites: Read (Turnstile inventory)
#     • Cloudflare Tunnel: Read (Tunnel-to-Access gap detection)
#     • API Tokens: Read (User section) (token rotation posture)
#     • Account API Tokens: Read (account token inventory)
#     • SSL and Certificates: Read (certificate expiry warnings)
#     • Load Balancing: Monitors and Pools: Read (pool failover)
#     • Page Rules: Read (legacy page rule migration)
#     • Domain API Gateway: Read (API Shield, Enterprise only)
#     • Account Rulesets: Read (account-level WAF, Enterprise only)
#   NOTE: there is no "Zone Rulesets" or "Zone Rate Limiting" permission
#   group — zone rulesets are covered by Zone WAF: Read, and the legacy
#   rate_limits endpoint returns 410 Gone (removed from collection).
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
#       • IP access rules (allow/block lists)
#       • Page rules (legacy page rules still active)
#       • Certificate packs (custom SSL cert expiry)
#       • SSL verification status (per-hostname cert failures)
#       • Load balancers (LB posture)
#       • Workers routes (Worker-to-zone bindings)
#       • DNS records (STRUCTURE only: type, name, proxied status; content redacted)
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
#      → Step-by-step remediation instructions
#      → Official Cloudflare documentation links for each finding
#
#   4. YOU IMPLEMENT FIXES:
#      → Review each recommendation
#      → Prioritize based on your risk tolerance
#      → Apply changes when you're ready
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
PHASES="ddos_l7 http_request_firewall_custom http_request_firewall_managed http_ratelimit http_request_transform http_request_dynamic_redirect http_request_cache_settings http_request_origin http_request_redirect http_response_headers_transform"

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
		"ip_access_rules:/firewall/access_rules/rules" \
		"page_rules:/pagerules" \
		"certificate_packs:/ssl/certificate_packs" \
		"ssl_verification:/ssl/verification" \
		"load_balancers:/load_balancers" \
		"workers_routes:/workers/routes" \
		"dns_records:/dns_records" \
		"page_shield:/page_shield" \
		"origin_tls_settings:/origin_tls_client_auth/settings" \
		"origin_tls_certs:/origin_tls_client_auth" \
		"api_gateway_discovery:/api_gateway/discovery"; do
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

	# Core account configuration ("account:" = bare /accounts/{id}; the
	# account posture data lives under result.settings — /settings 404s)
	for ep in "account:" \
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
		"r2:/r2/buckets" \
		"ai_gateways:/ai-gateway/gateways"; do
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
    """Load a single-object result. cf_get stores every result through the
    pagination accumulator, so a single object arrives as a one-element list —
    unwrap it. (v0.1 rejected lists here and silently dropped every phase
    entrypoint, bot_management, page_shield and AOP settings.)"""
    v = load(name)
    if isinstance(v, list):
        v = v[0] if len(v) == 1 else None
    return v if isinstance(v, dict) else None

def compact(d, keep=()):
    """Drop None values the way the TS collector drops `undefined`; keys in
    `keep` are intentionally nullable and stay as null."""
    return {k: v for k, v in d.items() if v is not None or k in keep}

def opt_str(v):
    return v if isinstance(v, str) else None

def opt_bool(v):
    return v if isinstance(v, bool) else None

def opt_num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

def hash_id(value):
    """Hash an ID (account, zone, rule) using SHA-256, truncate to 16 hex chars."""
    if not value:
        return None
    return "h" + hashlib.sha256(str(value).encode()).hexdigest()[:16]

# Regex patterns for redaction
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|internal\.[a-z]{2,}|origin\.[-a-z0-9.]+)\b", re.I)
REDACTED = "[redacted]"

def redact_expr(expr):
    """Redact IPs, emails, and internal hostnames from firewall rule expressions."""
    if not isinstance(expr, str):
        return expr
    out = EMAIL.sub(REDACTED, expr)
    out = IP.sub(REDACTED, out)
    out = INTERNAL_HOST.sub(REDACTED, out)
    return out

def redact_emails(text):
    """Redact email addresses from arbitrary text (e.g. DNS comments)."""
    return EMAIL.sub(REDACTED, text) if isinstance(text, str) else text

def settings_map(zone_id):
    """Build a map of zone settings (id → {id, value, editable})."""
    rows = arr(f"zone-{zone_id}-settings")
    return {r["id"]: compact({"id": r["id"], "value": r.get("value"), "editable": opt_bool(r.get("editable"))}, keep=("value",))
            for r in rows if isinstance(r, dict) and "id" in r}

def phase_entrypoints(zone_id):
    """Collect ruleset phase entrypoints with redacted expressions."""
    phases = ["ddos_l7", "http_request_firewall_custom", "http_request_firewall_managed", "http_ratelimit",
              "http_request_transform", "http_request_dynamic_redirect", "http_request_cache_settings",
              "http_request_origin", "http_request_redirect", "http_response_headers_transform"]
    out = {}
    for phase in phases:
        ep = obj(f"zone-{zone_id}-phase-{phase}")
        if not ep:
            continue
        rules = []
        for r in ep.get("rules") or []:
            # Header NAMES and operations are kept (drive CF-HDR-001); header
            # VALUES set by a rule are redacted — a short secret value would
            # otherwise pass the opaque-string scan untouched.
            ap = r.get("action_parameters")
            if isinstance(ap, dict) and isinstance(ap.get("headers"), dict):
                ap = dict(ap)
                ap["headers"] = {
                    h: ({**op, "value": REDACTED} if "value" in op else op)
                    for h, op in ap["headers"].items() if isinstance(op, dict)
                }
            rules.append(compact({
                "id": hash_id(r.get("id")),
                "description": EMAIL.sub(REDACTED, r["description"]) if isinstance(r.get("description"), str) else None,
                "enabled": opt_bool(r.get("enabled")),
                "action": opt_str(r.get("action")),
                "expression": redact_expr(r.get("expression")) if isinstance(r.get("expression"), str) else None,
                "action_parameters": ap,
                "version": opt_str(r.get("version")),
                "lastUpdated": opt_str(r.get("last_updated")),
            }))
        out[phase] = compact({"phase": phase, "name": opt_str(ep.get("name")), "kind": opt_str(ep.get("kind")), "rules": rules})
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

def api_gateway_discovery_doc(zone_id):
    """API Discovery reduced to a count — endpoint paths are never collected."""
    rows = arr(f"zone-{zone_id}-api_gateway_discovery")
    if not rows:
        return None
    return {"discoveredSchemaCount": sum(len(r.get("schemas") or []) for r in rows if isinstance(r, dict))}

def zone_doc(z):
    """Build a complete zone document with all collected data and redactions applied."""
    zone_id, zone_name = z.get("id", ""), z.get("name", "")
    plan = opt_str((z.get("plan") or {}).get("name"))
    dns = arr(f"zone-{zone_id}-dns_records")
    return compact({
        "name": zone_name,
        "plan": plan,
        "status": opt_str(z.get("status")),
        "paused": opt_bool(z.get("paused")),
        "type": opt_str(z.get("type")),
        "createdOn": opt_str(z.get("created_on")),
        "settings": settings_map(zone_id),
        "rulesets": [compact({"id": hash_id(r.get("id")), "name": opt_str(r.get("name")), "kind": opt_str(r.get("kind")),
                              "phase": opt_str(r.get("phase")), "version": opt_str(r.get("version"))})
                     for r in arr(f"zone-{zone_id}-rulesets")],
        "phaseEntrypoints": phase_entrypoints(zone_id),
        "botManagement": obj(f"zone-{zone_id}-bot_management") or {},
        # mode/target/scope only — matched values and notes never collected
        "ipAccessRules": [compact({"mode": opt_str(r.get("mode")),
                                   "target": opt_str((r.get("configuration") or {}).get("target")),
                                   "scope": opt_str((r.get("scope") or {}).get("type"))})
                          for r in arr(f"zone-{zone_id}-ip_access_rules")],
        # status + action ids only — URL targets never collected
        "pageRules": [compact({"status": opt_str(r.get("status")),
                               "actions": [a.get("id") for a in (r.get("actions") or []) if isinstance(a.get("id"), str)]})
                      for r in arr(f"zone-{zone_id}-page_rules")],
        "certificatePacks": [compact({
            "id": hash_id(c.get("id")) if isinstance(c.get("id"), str) else None,
            "type": opt_str(c.get("type")), "status": opt_str(c.get("status")),
            "validityDays": opt_num(c.get("validity_days")),
            "certificateAuthority": opt_str(c.get("certificate_authority")),
            "expiresOn": opt_str(c.get("expires_on")),
            "hosts": [h for h in (c.get("hosts") or []) if isinstance(h, str)],
        }, keep=("expiresOn",)) for c in arr(f"zone-{zone_id}-certificate_packs")],
        "sslVerification": [compact({"certificateStatus": opt_str(v.get("certificate_status")),
                                     "validationMethod": opt_str(v.get("validation_method")),
                                     "verificationType": opt_str(v.get("verification_type"))})
                            for v in arr(f"zone-{zone_id}-ssl_verification")],
        "loadBalancers": [compact({"name": opt_str(lb.get("name")), "enabled": opt_bool(lb.get("enabled")),
                                   "proxied": opt_bool(lb.get("proxied")), "steeringPolicy": opt_str(lb.get("steering_policy")),
                                   "poolCount": len(lb.get("default_pools") or [])})
                          for lb in arr(f"zone-{zone_id}-load_balancers")],
        "workersRoutes": [compact({"pattern": opt_str(r.get("pattern")), "script": opt_str(r.get("script"))})
                          for r in arr(f"zone-{zone_id}-workers_routes")],
        "dnsRecordCount": len(dns),
        "dnsRecords": [compact({"type": str(d.get("type") or ""), "name": str(d.get("name") or ""),
                                "content": REDACTED if isinstance(d.get("content"), str) else None,
                                "proxied": opt_bool(d.get("proxied")), "ttl": opt_num(d.get("ttl")),
                                "comment": redact_emails(opt_str(d.get("comment"))) if d.get("comment") else None}, keep=("proxied", "comment")) for d in dns],
        "apiGatewayDiscovery": api_gateway_discovery_doc(zone_id),
        "pageShield": page_shield_doc(zone_id),
        "authenticatedOriginPulls": authenticated_origin_pulls_doc(zone_id),
    })

def tunnel_doc(acct_id, tunnel):
    """Build a tunnel document with public hostnames extracted from config."""
    tunnel_id = tunnel.get("id", "")
    configs = arr(f"acct-{acct_id}-tunnel-{tunnel_id}-config")
    public_hostnames = []
    for config in configs:
        for ingress in (config.get("config") or {}).get("ingress") or []:
            hostname = ingress.get("hostname")
            if hostname and hostname != "*":
                public_hostnames.append(str(hostname))
    return compact({
        "id": hash_id(tunnel_id) if tunnel_id else None,
        "name": opt_str(tunnel.get("name")),
        "status": opt_str(tunnel.get("status")),
        "publicHostnames": public_hostnames,
    })

def group_names(policies):
    names = []
    for p in policies or []:
        names.extend(str((g or {}).get("name") or "") for g in (p or {}).get("permission_groups") or [])
    return names

def account_doc(a):
    """Build a complete account document with all collected data and redactions applied."""
    acct_id = a.get("id", "")
    # Posture data lives under result.settings of the bare /accounts/{id} fetch
    # (the /accounts/{id}/settings subpath does not exist — 404).
    raw_settings = (obj(f"acct-{acct_id}-account") or {}).get("settings") or {}
    # Allowlisted posture keys only: abuse_contact_email is an identity.
    settings = {
        "enforce_twofactor": opt_bool(raw_settings.get("enforce_twofactor")),
        "api_access_enabled": opt_bool(raw_settings.get("api_access_enabled")),
        "access_approval_expiry": opt_str(raw_settings.get("access_approval_expiry")),
        "oauth_app_access_enabled": opt_bool(raw_settings.get("oauth_app_access_enabled")),
    }

    # Member identities → role names + 2FA booleans only
    members = []
    for m in arr(f"acct-{acct_id}-members"):
        user = m.get("user") or {}
        members.append(compact({
            "roleNames": group_names(m.get("policies")),
            "twofactorEnabled": opt_bool(user.get("two_factor_authentication_enabled")),
            "status": opt_str(m.get("status")),
        }, keep=("twofactorEnabled",)))

    # API tokens → metadata only (values never in responses)
    tokens = []
    for t in arr(f"acct-{acct_id}-user-tokens") + arr(f"acct-{acct_id}-tokens"):
        tokens.append(compact({
            "status": opt_str(t.get("status")), "expiresOn": opt_str(t.get("expires_on")),
            "lastUsedOn": opt_str(t.get("last_used_on")), "permissionGroupNames": group_names(t.get("policies")),
        }, keep=("expiresOn", "lastUsedOn")))

    # Load balancer pools/monitors → origin addresses, notification emails and
    # monitor headers never exported
    pools = []
    for pool in arr(f"acct-{acct_id}-lb_pools"):
        pools.append(compact({
            "id": hash_id(pool.get("id")) if isinstance(pool.get("id"), str) else None,
            "name": opt_str(pool.get("name")), "enabled": opt_bool(pool.get("enabled")),
            "origins": [compact({"name": opt_str(o.get("name")),
                                 "address": REDACTED if isinstance(o.get("address"), str) else None,
                                 "enabled": opt_bool(o.get("enabled")), "weight": opt_num(o.get("weight"))})
                        for o in pool.get("origins") or []],
            "monitor": hash_id(pool.get("monitor")) if isinstance(pool.get("monitor"), str) else None,
            "notificationEmail": REDACTED,
        }, keep=("monitor",)))
    monitors = []
    for m in arr(f"acct-{acct_id}-lb_monitors"):
        monitors.append(compact({
            "id": hash_id(m.get("id")) if isinstance(m.get("id"), str) else None,
            "type": opt_str(m.get("type")), "interval": opt_num(m.get("interval")),
            "timeout": opt_num(m.get("timeout")), "retries": opt_num(m.get("retries")),
            "expectedCodes": opt_str(m.get("expected_codes")),
            "followRedirects": opt_bool(m.get("follow_redirects")),
            "allowInsecure": opt_bool(m.get("allow_insecure")),
        }))

    # Worker scripts → names, binding names/types only (never values)
    scripts = []
    for sc in arr(f"acct-{acct_id}-worker_scripts"):
        bindings = [{"name": str(b.get("name") or ""), "type": str(b.get("type") or "")}
                    for b in sc.get("bindings") or [] if b.get("type") in ("plain_text", "secret_text")]
        scripts.append(compact({
            "id": hash_id(str(sc.get("id"))) if sc.get("id") else None,
            "scriptName": opt_str(sc.get("id")),
            "createdOn": opt_str(sc.get("created_on")), "modifiedOn": opt_str(sc.get("modified_on")),
            "plainTextBindings": bindings,
            "routesBound": False,
        }))

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
        self_hosted = [str(d) for d in app.get("self_hosted_domains") or []]
        access_apps.append(compact({
            "name": opt_str(app.get("name")), "type": opt_str(app.get("type")), "domain": opt_str(app.get("domain")),
            "selfHostedDomains": self_hosted or None,
            "hasPolicies": len(policies) > 0,
            "policyDecisions": [str(p.get("decision")) for p in policies if p.get("decision")],
        }))

    widgets = []
    for w in arr(f"acct-{acct_id}-turnstile"):
        domains = [str(d) for d in w.get("domains") or []]
        widgets.append(compact({"name": opt_str(w.get("name")), "domains": domains or None, "mode": opt_str(w.get("mode"))}))

    # AI Gateway posture (authentication, rate limiting, DLP, guardrails, spend limits)
    gateways = []
    for g in arr(f"acct-{acct_id}-ai_gateways"):
        dlp = g.get("dlp") if isinstance(g.get("dlp"), dict) else {}
        guardrails = g.get("guardrails") if isinstance(g.get("guardrails"), dict) else {}
        spend = g.get("spend_limits") if isinstance(g.get("spend_limits"), dict) else {}
        gateways.append(compact({
            "id": opt_str(g.get("id")),
            "authentication": opt_bool(g.get("authentication")),
            "rateLimitingLimit": opt_num(g.get("rate_limiting_limit")),
            "rateLimitingInterval": opt_num(g.get("rate_limiting_interval")),
            "rateLimitingTechnique": opt_str(g.get("rate_limiting_technique")),
            "collectLogs": opt_bool(g.get("collect_logs")),
            "dlpEnabled": opt_bool(dlp.get("enabled")),
            "dlpPoliciesCount": len(dlp["policies"]) if isinstance(dlp.get("policies"), list) else None,
            "guardrailsConfigured": True if guardrails else None,
            "retryMaxAttempts": opt_num(g.get("retry_max_attempts")),
            "spendLimitsEnabled": opt_bool(spend.get("enabled")),
            "byokOnly": opt_bool(g.get("byok_only")),
        }, keep=("rateLimitingLimit", "rateLimitingInterval", "rateLimitingTechnique", "retryMaxAttempts")))

    tunnels = [tunnel_doc(acct_id, t) for t in arr(f"acct-{acct_id}-tunnels")]

    return compact({
        "id": hash_id(acct_id), "name": opt_str(a.get("name")),
        "enforceTwofactor": settings["enforce_twofactor"],
        "settings": settings,
        "accountMembers": members,
        "apiTokens": tokens,
        "loadBalancerPools": pools,
        "loadBalancerMonitors": monitors,
        "accountRulesets": [compact({"name": opt_str(r.get("name")), "kind": opt_str(r.get("kind")),
                                     "phase": opt_str(r.get("phase")), "version": opt_str(r.get("version"))})
                            for r in arr(f"acct-{acct_id}-account_rulesets")],
        "accessApps": access_apps,
        "accessIdentityProviders": [compact({"name": opt_str(p.get("name")), "type": opt_str(p.get("type"))})
                                    for p in arr(f"acct-{acct_id}-access_idps")],
        "turnstileWidgets": widgets,
        "cfdTunnels": tunnels,
        "workersScripts": scripts,
        "storageInventory": storage,
        "aiGateways": gateways,
    }, keep=("enforceTwofactor",))

# Load collection errors (scope gaps)
errors = []
err_path = os.path.join(work, "errors.tsv")
if os.path.exists(err_path):
    with open(err_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2:
                # Redact account/zone IDs from error paths (32-char hex)
                path = re.sub(r'\b[a-f0-9]{32}\b', lambda m: hash_id(m.group(0)), parts[0])
                errors.append({"path": path, "error": parts[1]})

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

# Redact opaque strings (64+ token-class chars) before the scan: never export
# opaque material (docs/data-policy.md). Matches the Mode A collector.
text = re.sub(r"[A-Za-z0-9_-]{64,}", lambda m: "[redacted]:opaque-%d" % len(m.group(0)), text)

# PRE-WRITE SECRET SCAN: abort if any credential-shaped patterns detected
if re.search(r"Bearer\s+\S+", text, re.I):
    print("❌ ABORTING: Pre-write secret scan matched an authorization pattern.", file=sys.stderr)
    print("   Nothing written. This is a safety check to prevent credential leakage.", file=sys.stderr)
    sys.exit(1)
if re.search(r"(?:api[_-]?key|api[_-]?token|password|credential)\s*[:=]\s*\S+", text, re.I):
    print("❌ ABORTING: Pre-write secret scan matched a credential-assignment pattern.", file=sys.stderr)
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
echo "      → Step-by-step remediation instructions"
echo "  4. YOU review recommendations and implement fixes when ready"
echo ""
echo "Questions? Contact us before sending the file."
echo "============================================================================"
