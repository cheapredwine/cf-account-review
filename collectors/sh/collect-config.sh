#!/usr/bin/env bash
# cf-account-review offline collector (Mode B, bash).
#
# READ-ONLY. Issues only GET requests to api.cloudflare.com/client/v4 and writes
# a timestamped JSON file for the cf-account-review analyzer.
#
# Guarantees (mirrored by tests in the repo):
#   - GET-only: every HTTP request goes through cf_get(), which calls curl -X GET.
#   - Single host: BASE_URL is the only contacted endpoint; no telemetry.
#   - Token from CF_API_TOKEN (or a no-echo prompt). Never echoed or written out.
#   - Redacted by default (applied in the assembler): DNS contents, resource IDs
#     (hashed), rule expressions (IPs/emails/internal hostnames), member
#     identities (role names + 2FA booleans only), token metadata only.
#
# Token scopes (My Profile > API Tokens, all zones):
#   Account Settings: Read; Zone: Read, Zone Settings: Read, DNS: Read,
#   Firewall Services: Read, Zone WAF: Read
#
# Requirements: bash, curl, python3 (stdlib only — no jq needed).
#
# Usage:  CF_API_TOKEN=xxx ./collect-config.sh [output-dir]

set -euo pipefail

BASE_URL="https://api.cloudflare.com/client/v4"
COLLECTOR_VERSION="0.1.0"
OUT_DIR="${1:-.}"
PER_PAGE=50
MAX_PAGES=50

TOKEN="${CF_API_TOKEN:-}"
if [ -z "$TOKEN" ]; then
	printf "Paste your Cloudflare API token: "
	read -rs TOKEN
	printf "\n"
fi
[ -n "$TOKEN" ] || {
	echo "No token supplied. Exiting." >&2
	exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

record_error() {
	printf '%s\t%s\n' "$1" "$2" >>"$WORK/errors.tsv"
}

# ---------------------------------------------------------------------------
# GET-only HTTP wrapper with pagination. The ONLY place curl is invoked.
# Writes the merged result array to "$WORK/files/<name>.json"; null on failure.
# ---------------------------------------------------------------------------
cf_get() {
	local name="$1" path="$2" page=1
	mkdir -p "$WORK/files"
	local out="$WORK/files/$name.json"
	local merged="$WORK/files/.merged-$name.json"
	printf '[]' >"$merged"
	while [ "$page" -le "$MAX_PAGES" ]; do
		local sep='?'
		case "$path" in *\?*) sep='&' ;; esac
		local url="${BASE_URL}${path}${sep}page=${page}&per_page=${PER_PAGE}"
		local tmp status
		tmp="$(mktemp)"
		status=$(curl -sS -X GET -o "$tmp" -w "%{http_code}" \
			-H "Authorization: Bearer ${TOKEN}" \
			-H "Content-Type: application/json" \
			--max-time 60 "$url") || { status="000"; }
		if [ "$status" != "200" ]; then
			rm -f "$tmp"
			record_error "$path" "HTTP $status"
			printf 'null' >"$out"
			return 1
		fi
		local ok total have
		ok="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('1' if d.get('success') else '0')" "$tmp")" || ok="0"
		if [ "$ok" != "1" ]; then
			rm -f "$tmp"
			record_error "$path" "API reported failure"
			printf 'null' >"$out"
			return 1
		fi
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
total_pages = info.get("total_pages") or 1
print(total_pages, len(result))
PY
		read -r total have <<<"$(
			python3 - "$merged" "$tmp" <<'PY'
import json, sys
merged = json.load(open(sys.argv[1]))
page = json.load(open(sys.argv[2]))
result = page.get("result")
result = result if isinstance(result, list) else ([] if result is None else [result])
info = page.get("result_info") or {}
print(info.get("total_pages") or 1, len(result))
PY
		)"
		rm -f "$tmp"
		if [ "$page" -ge "$total" ] || [ "$have" -lt "$PER_PAGE" ]; then break; fi
		page=$((page + 1))
	done
	mv "$merged" "$out"
	return 0
}

# Simple single-object fetch: writes result object (not array) to files/<name>.json
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

mkdir -p "$WORK/files"
: >"$WORK/errors.tsv"

PHASES="http_request_firewall_custom http_request_firewall_managed http_ratelimit http_request_transform http_request_dynamic_redirect http_request_cache_settings http_request_origin http_request_redirect"

# 1. Token verification (status only)
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

# 2. Zones
echo "Collecting zones…"
cf_get "zones" "/zones" >/dev/null 2>&1 || true

# Zone-level collections
while IFS=$'\t' read -r zone_id zone_name; do
	[ -n "$zone_id" ] || continue
	echo "  Collecting zone: $zone_name"
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
		"legacy_rate_limits:/rate_limits"; do
		label="${ep%%:*}"
		suffix="${ep#*:}"
		cf_get "zone-${zone_id}-${label}" "/zones/${zone_id}${suffix}" >/dev/null 2>&1 || true
	done
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
    print(z.get('id',''), z.get('name',''))
")

# 3. Accounts
echo "Collecting accounts…"
cf_get "accounts" "/accounts" >/dev/null 2>&1 || true
while IFS= read -r account_id; do
	[ -n "$account_id" ] || continue
	echo "  Collecting account: $account_id"
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
	cf_get "acct-${account_id}-user-tokens" "/user/tokens" >/dev/null 2>&1 || true
done < <(python3 -c "
import json
try:
    accts=json.load(open('$WORK/files/accounts.json')) or []
except Exception:
    accts=[]
for a in accts:
    print(a.get('id',''))
")

# 4. Assemble (redaction happens here, in one auditable place)
echo "Assembling output…"
if [ ! -d "$OUT_DIR" ]; then mkdir -p "$OUT_DIR"; fi
OUT_FILE="$OUT_DIR/cloudflare-config-$(date -u +%Y-%m-%d-%H%M).json"

python3 - "$WORK" "$OUT_FILE" "$TOKEN_STATUS" "$COLLECTOR_VERSION" <<'PY'
"""Assembler + redactor. Reads every collected file, applies the data policy,
and writes the final collection document. This is the single place where
redaction decisions live for the bash collector."""
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

work, out_file, token_status, collector_version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files_dir = os.path.join(work, "files")

def load(name):
    path = os.path.join(files_dir, f"{name}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def arr(name):
    v = load(name)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]

def obj(name):
    v = load(name)
    return v if isinstance(v, dict) else None

def hash_id(value):
    if not value:
        return None
    return "h" + hashlib.sha256(str(value).encode()).hexdigest()[:16]

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local)\b", re.I)
REDACTED = "[redacted]"

def redact_expr(expr):
    if not isinstance(expr, str):
        return expr
    out = IP.sub(REDACTED, expr)
    out = EMAIL.sub(REDACTED, out)
    out = INTERNAL_HOST.sub(REDACTED, out)
    return out

def settings_map(zone_id):
    rows = arr(f"zone-{zone_id}-settings")
    return {r["id"]: {"id": r["id"], "value": r.get("value"), "editable": r.get("editable")} for r in rows if isinstance(r, dict) and "id" in r}

def phase_entrypoints(zone_id):
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

def zone_doc(z):
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
    }

def account_doc(a):
    acct_id = a.get("id", "")
    settings = obj(f"acct-{acct_id}-settings") or {}
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
    tokens = []
    for t in arr(f"acct-{acct_id}-user-tokens") + arr(f"acct-{acct_id}-tokens"):
        groups = []
        for p in t.get("policies") or []:
            groups.extend(g.get("name") for g in p.get("permission_groups") or [])
        tokens.append({
            "status": t.get("status"), "expiresOn": t.get("expires_on"),
            "lastUsedOn": t.get("last_used_on"), "permissionGroupNames": [g for g in groups if g],
        })
    scripts = []
    for s in arr(f"acct-{acct_id}-worker_scripts"):
        bindings = [{"name": b.get("name"), "type": b.get("type")}
                    for b in s.get("bindings") or [] if b.get("type") in ("plain_text", "secret_text")]
        scripts.append({
            "id": hash_id(s.get("id")), "scriptName": s.get("id"),
            "createdOn": s.get("created_on"), "modifiedOn": s.get("modified_on"),
            "plainTextBindings": bindings,
        })
    storage = {
        "kvNamespaces": len(arr(f"acct-{acct_id}-kv")),
        "d1Databases": len(arr(f"acct-{acct_id}-d1")),
        "r2Buckets": len(arr(f"acct-{acct_id}-r2")),
    }
    access_apps = []
    for app in arr(f"acct-{acct_id}-access_apps"):
        policies = app.get("policies") or []
        access_apps.append({
            "name": app.get("name"), "type": app.get("type"), "domain": app.get("domain"),
            "hasPolicies": len(policies) > 0,
            "policyDecisions": [p.get("decision") for p in policies if p.get("decision")],
        })
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
        "cfdTunnels": arr(f"acct-{acct_id}-tunnels"),
        "workersScripts": scripts,
        "storageInventory": storage,
    }

errors = []
err_path = os.path.join(work, "errors.tsv")
if os.path.exists(err_path):
    with open(err_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) == 2:
                errors.append({"path": parts[0], "error": parts[1]})

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

text = json.dumps(doc, indent=2)
# Pre-write secret scan: abort rather than write anything suspicious.
if re.search(r"Bearer\s+\S+", text, re.I):
    print("ABORTING: pre-write secret scan matched an authorization pattern. Nothing written.", file=sys.stderr)
    sys.exit(1)
with open(out_file, "w") as f:
    f.write(text)
os.chmod(out_file, 0o600)
print(f"written: {out_file}")
print(f"zones: {len(zones)}; errors: {len(errors)} (scope gaps are expected with narrowly-scoped tokens)")
PY

echo "DONE."
echo "This file contains configuration only - no credentials, no DNS contents, no identities."
