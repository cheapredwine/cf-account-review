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
COLLECTOR_VERSION="0.2.0"
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
			printf '%s' "$status" >"$WORK/files/$name.status"
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
	local name="$1" path="$2" quiet="${3:-}"
	mkdir -p "$WORK/files"
	local out="$WORK/files/$name.json"

	local tmp status
	tmp="$(mktemp)"
	status=$(curl -sS -X GET -o "$tmp" -w "%{http_code}" \
		-H "Authorization: Bearer ${TOKEN}" \
		-H "Content-Type: application/json" \
		--max-time 60 "${BASE_URL}${path}") || status="000"

	printf '%s' "$status" >"$WORK/files/$name.status"
	if [ "$status" != "200" ]; then
		rm -f "$tmp"
		# A 404 on a phase entrypoint means "nothing deployed", not a scope gap.
		if [ "$quiet" != "quiet404" ] || [ "$status" != "404" ]; then
			record_error "$path" "HTTP $status"
		fi
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
PHASES="http_request_firewall_custom http_request_firewall_managed http_ratelimit ddos_l7 http_request_cache_settings http_response_headers_transform"

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

	# List endpoints (paginated)
	for ep in "settings:/settings" \
		"rulesets:/rulesets" \
		"ip_access_rules:/firewall/access_rules/rules" \
		"page_rules:/pagerules" \
		"certificate_packs:/ssl/certificate_packs" \
		"workers_routes:/workers/routes" \
		"dns_records:/dns_records" \
		"legacy_rate_limits:/rate_limits" \
		"origin_tls_certs:/origin_tls_client_auth"; do
		label="${ep%%:*}"
		suffix="${ep#*:}"
		cf_get "zone-${zone_id}-${label}" "/zones/${zone_id}${suffix}" >/dev/null 2>&1 || true
	done

	# Single-object endpoints (NOT paginated — cf_get would wrap them in a list)
	for ep in "bot_management:/bot_management" \
		"managed_headers:/managed_headers" \
		"leaked_credentials:/leaked-credential-checks" \
		"page_shield:/page_shield" \
		"origin_tls_settings:/origin_tls_client_auth/settings"; do
		label="${ep%%:*}"
		suffix="${ep#*:}"
		cf_get_obj "zone-${zone_id}-${label}" "/zones/${zone_id}${suffix}" >/dev/null 2>&1 || true
	done

	# Ruleset phase entrypoints (live rules per phase); 404 = nothing deployed
	for phase in $PHASES; do
		cf_get_obj "zone-${zone_id}-phase-${phase}" "/zones/${zone_id}/rulesets/phases/${phase}/entrypoint" quiet404 >/dev/null 2>&1 || true
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
# User-owned tokens are not per-account; read once.
cf_get "user-tokens" "/user/tokens" >/dev/null 2>&1 || true

# For each account, collect account-level configuration
while IFS= read -r account_id; do
	[ -n "$account_id" ] || continue
	echo "  → Account: $account_id"

	# Account settings is a single object (cf_get would wrap it in a list)
	cf_get_obj "acct-${account_id}-settings" "/accounts/${account_id}/settings" >/dev/null 2>&1 || true

	# List endpoints (paginated)
	for ep in "members:/members" \
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
ASSEMBLER + REDACTOR (bash collector)

The SINGLE PLACE where redaction decisions live for Mode B (bash). Mirrors
src/summarize.ts and src/collect.ts in the main repo — keep them in step.

Readability contract (schema 1.1): a list field is OMITTED when its endpoint
could not be read, and [] when read and empty. Phase entrypoints carry an
explicit present/absent/unreadable status. The analyzer depends on this so
scope gaps never turn into passes.
"""
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

work, out_file, token_status, collector_version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files_dir = os.path.join(work, "files")
REDACTED = "[redacted]"
MISSING = object()

def load(name):
    """Load a fetched JSON file; MISSING if absent/unparseable."""
    try:
        with open(os.path.join(files_dir, f"{name}.json")) as f:
            return json.load(f)
    except Exception:
        return MISSING

def status(name):
    try:
        with open(os.path.join(files_dir, f"{name}.status")) as f:
            return f.read().strip()
    except Exception:
        return ""

def arr_opt(name):
    """List or None (None = unreadable)."""
    v = load(name)
    if v is MISSING or v is None:
        return None
    return v if isinstance(v, list) else [v]

def arr(name):
    return arr_opt(name) or []

def obj(name):
    v = load(name)
    return v if isinstance(v, dict) else None

def mapped(name, fn):
    rows = arr_opt(name)
    return None if rows is None else [fn(r) for r in rows if isinstance(r, dict)]

def hash_id(value):
    if not value:
        return None
    return "h" + hashlib.sha256(str(value).encode()).hexdigest()[:16]

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|internal\.[a-z]{2,}|origin\.[-a-z0-9.]+)\b", re.I)

def redact_expr(expr):
    if not isinstance(expr, str):
        return expr
    out = EMAIL.sub(REDACTED, expr)
    out = IP.sub(REDACTED, out)
    return INTERNAL_HOST.sub(REDACTED, out)

def redact_emails(text):
    return EMAIL.sub(REDACTED, text) if isinstance(text, str) else None

def d(v):
    return v if isinstance(v, dict) else {}

def l(v):
    return v if isinstance(v, list) else []

def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

def boolean(v):
    return v if isinstance(v, bool) else None

def prune(o):
    """Drop None values (zod optional fields reject null)."""
    return {k: v for k, v in o.items() if v is not None}

# ---- mirrors src/summarize.ts ------------------------------------------------
KNOWN_MANAGED = {
    "efb7b8c949ac4650a09736fc376e9aee": "Cloudflare Managed Ruleset",
    "4814384a9e5d4991b9815dcfc25d2f1f": "Cloudflare OWASP Core Ruleset",
    "c2e184081120413c86c3ab7e14069605": "Cloudflare Exposed Credentials Check Ruleset",
    "4d21379b4f9f4bb088e0729962c8b3cf": "DDoS L7 ruleset",
}

def managed_key(name):
    if not name:
        return None
    n = name.lower()
    if "owasp" in n: return "owasp"
    if "exposed credentials" in n: return "exposed_credentials"
    if "ddos" in n: return "ddos_l7"
    if "cloudflare managed" in n: return "cloudflare_managed"
    if "sensitive data" in n: return "sensitive_data_detection"
    return "other_managed"

def summarize_ap(action, raw, ruleset_names, ratelimit_raw=None):
    """action_parameters plus the rule-level `ratelimit` (it sits beside, not
    inside, action_parameters in the Rulesets API)."""
    ap = d(raw)
    if not ap and ratelimit_raw is None:
        return None
    out = {}
    if action == "execute":
        rid = ap.get("id") or ""
        out["executes"] = managed_key(ruleset_names.get(rid) or KNOWN_MANAGED.get(rid)) or "custom_or_unknown"
        ov = d(ap.get("overrides"))
        if ov:
            cats = [d(c) for c in l(ov.get("categories"))]
            rules = [d(r) for r in l(ov.get("rules"))]
            th = [num(r.get("score_threshold")) for r in rules if num(r.get("score_threshold")) is not None]
            out["overrides"] = prune({
                "enabled": boolean(ov.get("enabled")),
                "action": ov.get("action") if isinstance(ov.get("action"), str) else None,
                "sensitivityLevel": ov.get("sensitivity_level") if isinstance(ov.get("sensitivity_level"), str) else None,
                "disabledCategories": [c.get("category") for c in cats if c.get("enabled") is False and isinstance(c.get("category"), str)][:50],
                "rulesDisabled": sum(1 for r in rules if r.get("enabled") is False),
                "rulesActionOverridden": sum(1 for r in rules if isinstance(r.get("action"), str)),
                "scoreThreshold": min(th) if th else None,
            })
    if action == "skip":
        out["skip"] = {
            "currentRuleset": ap.get("ruleset") == "current",
            "rulesets": len(l(ap.get("rulesets"))),
            "rules": sum(len(l(v)) for v in d(ap.get("rules")).values()),
            "phases": [str(x) for x in l(ap.get("phases"))][:20],
            "products": [str(x) for x in l(ap.get("products"))][:20],
        }
    if ratelimit_raw is not None:
        rl = d(ratelimit_raw)
        ce = rl.get("counting_expression")
        out["ratelimit"] = prune({
            "characteristics": [str(x) for x in l(rl.get("characteristics"))][:10],
            "period": num(rl.get("period")),
            "requestsPerPeriod": num(rl.get("requests_per_period")),
            "scorePerPeriod": num(rl.get("score_per_period")),
            "mitigationTimeout": num(rl.get("mitigation_timeout")),
            "requestsToOrigin": boolean(rl.get("requests_to_origin")),
            "hasCountingExpression": isinstance(ce, str) and len(ce) > 0,
        })
    if "headers" in ap:
        out["headers"] = [{"name": str(k).lower(), "operation": d(v).get("operation") if isinstance(d(v).get("operation"), str) else "unknown"}
                          for k, v in list(d(ap.get("headers")).items())[:50]]
    if action == "set_cache_settings" and isinstance(ap.get("cache"), bool):
        out["cache"] = {"eligible": ap["cache"]}
    return out or None

def summarize_ip_rule(r):
    cfg = d(r.get("configuration"))
    target = cfg.get("target") if isinstance(cfg.get("target"), str) else None
    keep = target in ("country", "asn")
    return prune({
        "mode": r.get("mode") if isinstance(r.get("mode"), str) else None,
        "target": target,
        "value": (cfg.get("value") if isinstance(cfg.get("value"), str) else None) if keep else REDACTED,
        "scope": d(r.get("scope")).get("type") if isinstance(d(r.get("scope")).get("type"), str) else None,
    })

PAGE_RULE_ENUM = {"security_level", "ssl", "cache_level", "browser_check", "waf", "always_use_https",
                  "automatic_https_rewrites", "email_obfuscation", "rocket_loader", "disable_security",
                  "disable_apps", "disable_performance", "cache_deception_armor"}

def summarize_page_rule(r):
    acts = []
    for a in l(r.get("actions")):
        a = d(a)
        aid = a.get("id") if isinstance(a.get("id"), str) else ""
        if not aid:
            continue
        v = a.get("value")
        item = {"id": aid}
        if aid in PAGE_RULE_ENUM and isinstance(v, (str, bool)):
            item["value"] = str(v).lower() if isinstance(v, bool) else v
        acts.append(item)
    return prune({"status": r.get("status") if isinstance(r.get("status"), str) else None, "actions": acts})

BOT_KEYS = ["fight_mode", "enable_js", "sbfm_definitely_automated", "sbfm_likely_automated", "sbfm_verified_bots",
            "sbfm_static_resource_protection", "optimize_wordpress", "ai_bots_protection", "crawler_protection",
            "is_robots_txt_managed", "using_latest_model", "auto_update_model", "suppress_session_score"]

def summarize_bots(raw):
    r = d(raw)
    if not r:
        return None
    return {k: r[k] for k in BOT_KEYS if isinstance(r.get(k), (str, bool))}

def summarize_managed_headers(raw):
    r = d(raw)
    if not r:
        return None
    pick = lambda v: [{"id": h.get("id"), "enabled": h.get("enabled") is True} for h in map(d, l(v)) if isinstance(h.get("id"), str) and h.get("id")]
    return {"request": pick(r.get("managed_request_headers")), "response": pick(r.get("managed_response_headers"))}

def normalize_plan(name, legacy=None):
    for c in (legacy, name):
        if not c:
            continue
        p = c.lower()
        for tier in ("enterprise", "business", "pro", "free"):
            if tier in p:
                return tier
    return None

# ---- zone ---------------------------------------------------------------------
PHASES = ["http_request_firewall_custom", "http_request_firewall_managed", "http_ratelimit",
          "ddos_l7", "http_request_cache_settings", "http_response_headers_transform"]

def zone_doc(z):
    zone_id, zone_name = z.get("id", ""), z.get("name", "")
    plan = d(z.get("plan"))
    rs_list = arr_opt(f"zone-{zone_id}-rulesets")
    ruleset_names = {r.get("id"): r.get("name") for r in (rs_list or []) if isinstance(r, dict) and isinstance(r.get("name"), str)}

    entrypoints, phase_status = {}, {}
    for phase in PHASES:
        name = f"zone-{zone_id}-phase-{phase}"
        ep = obj(name)
        if ep is None:
            phase_status[phase] = "absent" if status(name) == "404" else "unreadable"
            continue
        phase_status[phase] = "present"
        rules = []
        for r in l(ep.get("rules")):
            r = d(r)
            action = r.get("action") if isinstance(r.get("action"), str) else None
            rules.append(prune({
                "id": hash_id(r.get("id")),
                "description": redact_emails(r.get("description")),
                "enabled": boolean(r.get("enabled")),
                "action": action,
                "expression": redact_expr(r.get("expression")),
                "version": r.get("version") if isinstance(r.get("version"), str) else None,
                "lastUpdated": r.get("last_updated") if isinstance(r.get("last_updated"), str) else None,
                "actionParameters": summarize_ap(action, r.get("action_parameters"), ruleset_names, r.get("ratelimit")),
            }))
        entrypoints[phase] = prune({"phase": phase, "name": ep.get("name"), "kind": ep.get("kind"), "rules": rules})

    settings_rows = arr_opt(f"zone-{zone_id}-settings")
    settings = None if settings_rows is None else {
        r["id"]: prune({"id": r["id"], "value": r.get("value"), "editable": boolean(r.get("editable"))})
        for r in settings_rows if isinstance(r, dict) and "id" in r}

    # DNS: content redacted, comments dropped (free text).
    dns = mapped(f"zone-{zone_id}-dns_records", lambda r: prune({
        "type": str(r.get("type", "")), "name": str(r.get("name", "")),
        "content": REDACTED if r.get("content") is not None else None,
        "proxied": boolean(r.get("proxied")), "ttl": num(r.get("ttl"))}))

    ps = obj(f"zone-{zone_id}-page_shield")
    aop = obj(f"zone-{zone_id}-origin_tls_settings")
    aop_certs = arr_opt(f"zone-{zone_id}-origin_tls_certs")
    leaked = obj(f"zone-{zone_id}-leaked_credentials")

    return prune({
        "name": zone_name,
        "plan": plan.get("name"),
        "planLegacyId": plan.get("legacy_id") or normalize_plan(plan.get("name")),
        "status": z.get("status"),
        "paused": boolean(z.get("paused")),
        "type": z.get("type"),
        "createdOn": z.get("created_on"),
        "settings": settings,
        "rulesets": None if rs_list is None else [prune({"id": hash_id(r.get("id")), "name": r.get("name"), "kind": r.get("kind"),
                      "phase": r.get("phase"), "version": r.get("version")}) for r in rs_list if isinstance(r, dict)],
        "phaseEntrypoints": entrypoints,
        "phaseStatus": phase_status,
        "botManagement": summarize_bots(obj(f"zone-{zone_id}-bot_management")),
        "ipAccessRuleSummary": mapped(f"zone-{zone_id}-ip_access_rules", summarize_ip_rule),
        "pageRuleSummary": mapped(f"zone-{zone_id}-page_rules", summarize_page_rule),
        "certificatePacks": mapped(f"zone-{zone_id}-certificate_packs", lambda p: prune({
            "id": hash_id(p.get("id")), "type": p.get("type"), "status": p.get("status"),
            "validityDays": num(p.get("validity_days")), "certificateAuthority": p.get("certificate_authority"),
            "expiresOn": p.get("expires_on"), "hosts": [h for h in l(p.get("hosts")) if isinstance(h, str)]})),
        "workersRoutes": mapped(f"zone-{zone_id}-workers_routes", lambda r: prune({"pattern": r.get("pattern"), "script": r.get("script")})),
        "dnsRecordCount": None if dns is None else len(dns),
        "dnsRecords": dns,
        "legacyRateLimits": mapped(f"zone-{zone_id}-legacy_rate_limits", lambda r: {"disabled": r.get("disabled") is True}),
        "managedHeaders": summarize_managed_headers(obj(f"zone-{zone_id}-managed_headers")),
        "leakedCredentialChecks": None if leaked is None else prune({"enabled": boolean(leaked.get("enabled"))}),
        "pageShield": None if ps is None else prune({
            "enabled": boolean(ps.get("enabled")),
            "useCloudflareReportingEndpoint": boolean(ps.get("use_cloudflare_reporting_endpoint")),
            "useConnectionUrlPath": boolean(ps.get("use_connection_url_path"))}),
        "authenticatedOriginPulls": None if aop is None else prune({
            "enabled": boolean(aop.get("enabled")),
            "hasZoneLevelCert": None if aop_certs is None else len(aop_certs) > 0,
            "certCount": None if aop_certs is None else len(aop_certs)}),
    })

# ---- account ------------------------------------------------------------------
def tunnel_doc(acct_id, t):
    tid = t.get("id", "")
    hostnames = []
    for cfg in arr(f"acct-{acct_id}-tunnel-{tid}-config"):
        for ing in l(d(d(cfg).get("config")).get("ingress")):
            h = d(ing).get("hostname")
            if h and h != "*":
                hostnames.append(h)
    return prune({"id": hash_id(tid), "name": t.get("name"), "status": t.get("status"), "publicHostnames": hostnames})

def groups(t):
    out = []
    for p in l(t.get("policies")):
        out.extend(g.get("name") for g in map(d, l(d(p).get("permission_groups"))) if g.get("name"))
    return out

def account_doc(a):
    acct_id = a.get("id", "")
    settings = obj(f"acct-{acct_id}-settings") or {}
    user_tokens, acct_tokens = arr_opt("user-tokens"), arr_opt(f"acct-{acct_id}-tokens")
    token_rows = None if user_tokens is None and acct_tokens is None else (user_tokens or []) + (acct_tokens or [])
    tunnels = arr_opt(f"acct-{acct_id}-tunnels")
    kv, d1, r2 = arr_opt(f"acct-{acct_id}-kv"), arr_opt(f"acct-{acct_id}-d1"), arr_opt(f"acct-{acct_id}-r2")
    return prune({
        "id": hash_id(acct_id), "name": a.get("name"),
        "enforceTwofactor": boolean(settings.get("enforce_twofactor")),
        "accountMembers": mapped(f"acct-{acct_id}-members", lambda m: prune({
            "roleNames": groups(m), "twofactorEnabled": boolean(d(m.get("user")).get("two_factor_authentication_enabled")),
            "status": m.get("status")})),
        "apiTokens": None if token_rows is None else [prune({
            "status": t.get("status"), "expiresOn": t.get("expires_on"), "lastUsedOn": t.get("last_used_on"),
            "permissionGroupNames": groups(t)}) for t in token_rows if isinstance(t, dict)],
        # Pools/monitors: origin addresses, notification emails and monitor
        # header VALUES (may carry auth material) are never exported.
        "loadBalancerPools": mapped(f"acct-{acct_id}-lb_pools", lambda p: prune({
            "id": hash_id(p.get("id")), "name": p.get("name"), "enabled": boolean(p.get("enabled")),
            "origins": [prune({"name": o.get("name"), "address": REDACTED if o.get("address") else None,
                               "enabled": boolean(o.get("enabled")), "weight": num(o.get("weight"))}) for o in map(d, l(p.get("origins")))],
            "monitor": hash_id(p.get("monitor")), "notificationEmail": REDACTED})),
        "loadBalancerMonitors": mapped(f"acct-{acct_id}-lb_monitors", lambda m: prune({
            "id": hash_id(m.get("id")), "type": m.get("type"), "interval": num(m.get("interval")),
            "timeout": num(m.get("timeout")), "retries": num(m.get("retries")), "expectedCodes": m.get("expected_codes"),
            "followRedirects": boolean(m.get("follow_redirects")), "allowInsecure": boolean(m.get("allow_insecure"))})),
        "accountRulesets": mapped(f"acct-{acct_id}-account_rulesets", lambda r: prune({
            "id": hash_id(r.get("id")), "name": r.get("name"), "kind": r.get("kind"), "phase": r.get("phase"), "version": r.get("version")})),
        "accessApps": mapped(f"acct-{acct_id}-access_apps", lambda app: prune({
            "name": app.get("name"), "type": app.get("type"), "domain": app.get("domain"),
            "selfHostedDomains": [str(x) for x in l(app.get("self_hosted_domains"))] or None,
            "hasPolicies": len(l(app.get("policies"))) > 0,
            "policyDecisions": [p.get("decision") for p in map(d, l(app.get("policies"))) if p.get("decision")]})),
        "accessIdentityProviders": mapped(f"acct-{acct_id}-access_idps", lambda p: prune({"name": p.get("name"), "type": p.get("type")})),
        "turnstileWidgets": mapped(f"acct-{acct_id}-turnstile", lambda w: prune({
            "name": w.get("name"), "domains": [str(x) for x in l(w.get("domains"))] or None, "mode": w.get("mode")})),
        "cfdTunnels": None if tunnels is None else [tunnel_doc(acct_id, t) for t in tunnels if isinstance(t, dict)],
        "workersScripts": mapped(f"acct-{acct_id}-worker_scripts", lambda sc: prune({
            "id": hash_id(sc.get("id")), "scriptName": sc.get("id"),
            "createdOn": sc.get("created_on"), "modifiedOn": sc.get("modified_on"),
            "plainTextBindings": [{"name": str(b.get("name", "")), "type": str(b.get("type", ""))}
                                  for b in map(d, l(sc.get("bindings"))) if b.get("type") in ("plain_text", "secret_text")]})),
        "storageInventory": prune({"kvNamespaces": None if kv is None else len(kv),
                                   "d1Databases": None if d1 is None else len(d1),
                                   "r2Buckets": None if r2 is None else len(r2)}),
        "aiGateways": mapped(f"acct-{acct_id}-ai_gateways", lambda g: prune({
            "id": g.get("id"), "authentication": boolean(g.get("authentication")),
            "rateLimitingLimit": num(g.get("rate_limiting_limit")), "rateLimitingInterval": num(g.get("rate_limiting_interval")),
            "rateLimitingTechnique": g.get("rate_limiting_technique") if isinstance(g.get("rate_limiting_technique"), str) else None,
            "collectLogs": boolean(g.get("collect_logs")), "dlpEnabled": boolean(d(g.get("dlp")).get("enabled")),
            "dlpPoliciesCount": len(l(d(g.get("dlp")).get("policies"))) if isinstance(d(g.get("dlp")).get("policies"), list) else None,
            "guardrailsConfigured": True if d(g.get("guardrails")) else None,
            "spendLimitsEnabled": boolean(d(g.get("spend_limits")).get("enabled")),
            "byokOnly": boolean(g.get("byok_only"))})),
    })

# ---- assemble -------------------------------------------------------------------
errors = []
err_path = os.path.join(work, "errors.tsv")
if os.path.exists(err_path):
    with open(err_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2:
                # Raw account/zone/tunnel IDs in error paths are hashed like every other ID.
                path = re.sub(r"\b[0-9a-f]{32}\b", lambda m: hash_id(m.group(0)), parts[0])
                errors.append({"path": path, "error": parts[1]})

zones = arr("zones")
plans = sorted({d(z.get("plan")).get("name") for z in zones if d(z.get("plan")).get("name")})
doc = {
    "schemaVersion": "1.1",
    "collectedAt": datetime.now(timezone.utc).isoformat(),
    "collector": "bash",
    "collectorVersion": collector_version,
    "tokenStatus": token_status if token_status == "active" else "verification-failed",
    "planTiersSeen": plans,
    "accounts": [account_doc(a) for a in arr("accounts") if isinstance(a, dict)],
    "zones": [zone_doc(z) for z in zones if isinstance(z, dict)],
    "collectionErrors": errors,
}

text = json.dumps(doc, indent=2)

# PRE-WRITE SECRET SCAN (mirrors src/redact.ts fail-severity patterns)
SECRET_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._-]+", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{64,}\b"),
    re.compile(r"(?:api[_-]?key|api[_-]?token|password|credential)\s*[:=]\s*\S+", re.I),
]
for pat in SECRET_PATTERNS:
    if pat.search(text):
        print("❌ ABORTING: Pre-write secret scan matched a credential-shaped pattern.", file=sys.stderr)
        print("   Nothing written. This is a safety check to prevent credential leakage.", file=sys.stderr)
        sys.exit(1)

with open(out_file, "w") as f:
    f.write(text)
os.chmod(out_file, 0o600)

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
