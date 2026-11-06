# Redaction & Evaluation: How Backend Analysis Works on Redacted Data

## Summary

**Yes, the analyzer can evaluate redacted collections.** Redaction preserves structure, booleans, counts, expressions, and decision values — everything needed for security/compliance checks — while removing only sensitive identifiers and values.

## What Gets Redacted vs. What Gets Kept

| Data Type | Redacted | Kept for Evaluation | Example |
|-----------|----------|---------------------|---------|
| **IDs** | ✅ Hash first 16 chars | Deterministic hash allows correlation | `zone_id: "h3a7f9c2b1e4d6a8"` |
| **DNS content** | ✅ Origin IPs, CNAMEs | Record type, proxied status, count | `content: "[redacted]", proxied: true` |
| **Rule expressions** | ✅ Internal IPs/hosts/emails | Public hostnames, operators, structure | `cf.bot_management.score lt 30` |
| **Boolean flags** | ❌ Never | Complete value | `enforceTwofactor: true`, `ssl: "flexible"` |
| **Counts** | ❌ Never | Complete value | `ruleCount: 47`, `memberCount: 12` |
| **Rule actions** | ❌ Never | Action type, enabled status | `action: "block"`, `enabled: true` |
| **Header names** | ❌ Never | Header name, operation | `set: "Strict-Transport-Security"` |
| **Header values** | ✅ Values set by transforms | Operation, presence | `value: "[redacted]"` |
| **Timestamps** | ❌ Never | Last-used dates, expiry | `expiresOn: "2027-01-15"` |
| **Email addresses** | ✅ All addresses | Role names, 2FA status | `role: "Administrator", twoFA: false` |

## Evaluation Examples

### 1. Boolean Flag Check (LITE tier)
**Check:** Two-factor authentication enforced (`CF-ZT-003`)

```yaml
evidence: accounts[].enforceTwofactor
params: { flag: enforceTwofactor, expect: true }
```

**Collected data (redacted):**
```json
{
  "accounts": [{
    "id": "h3a7f9c2b1e4d6a8",
    "enforceTwofactor": false
  }]
}
```

**Evaluation:** `fail` — the boolean value is present and false
**Impact of redaction:** None — account ID hash doesn't affect the check

---

### 2. Count-Based Check (LITE tier)
**Check:** Rate limiting on login endpoints (`CF-RL-001`)

```yaml
evidence: zones[].phaseEntrypoints["http_ratelimit"]
params: { phase: http_ratelimit, loginPaths: [...] }
```

**Collected data (redacted):**
```json
{
  "zones": [{
    "id": "hb2e6f8a4c9d1e3f",
    "name": "example.com",
    "phaseEntrypoints": {
      "http_ratelimit": {
        "phase": "http_ratelimit",
        "rules": []
      }
    }
  }]
}
```

**Evaluation:** `fail` — rule count is zero
**Impact of redaction:** None — zone ID hash doesn't affect the check

---

### 3. Expression Analysis Check (FULL tier)
**Check:** Bot rules exclude verified bots (`CF-BOT-001`)

```yaml
evidence: zones[].phaseEntrypoints["http_request_firewall_custom"]
```

**Collected data (redacted):**
```json
{
  "zones": [{
    "phaseEntrypoints": {
      "http_request_firewall_custom": {
        "rules": [{
          "action": "block",
          "enabled": true,
          "expression": "cf.bot_management.score lt 30"
        }]
      }
    }
  }]
}
```

**Evaluation:** `fail` — expression lacks `not cf.bot_management.verified_bot`
**Impact of redaction:** None — the Cloudflare namespace expression is preserved verbatim

---

### 4. Transform Rule Check (FULL tier)
**Check:** Security headers not removed (`CF-HDR-002`)

```yaml
evidence: zones[].phaseEntrypoints["http_response_headers_transform"]
```

**Collected data (redacted):**
```json
{
  "zones": [{
    "phaseEntrypoints": {
      "http_response_headers_transform": {
        "rules": [{
          "action": "rewrite",
          "enabled": true,
          "actionParameters": {
            "headers": {
              "remove": {
                "Strict-Transport-Security": {}
              },
              "set": {
                "X-Custom-Header": {
                  "value": "[redacted]"
                }
              }
            }
          }
        }]
      }
    }
  }]
}
```

**Evaluation:** `fail` — HSTS header in `remove` list
**Impact of redaction:** None — header *names* and operations are kept; only custom header *values* are redacted

---

### 5. SSL Mode Check (LITE tier)
**Check:** SSL mode not flexible (`CF-SSL-001`)

```yaml
evidence: zones[].settings.ssl
params: { setting: ssl, expectNot: "flexible" }
```

**Collected data (redacted):**
```json
{
  "zones": [{
    "settings": {
      "ssl": {
        "id": "ssl",
        "value": "flexible"
      }
    }
  }]
}
```

**Evaluation:** `fail` — mode is exactly "flexible"
**Impact of redaction:** None — setting value is never redacted

---

## What Cannot Be Evaluated (Produces `manual`)

1. **Missing scope** — Check requires zone-level evidence but only account data was collected
2. **Unreadable phase** — WAF check needs `http_request_firewall_managed` but token lacked Zone WAF Read
3. **Empty arrays** — Check expects DNS records but `zones[].dnsRecords` is `[]` (could be "no records" or "no permission")

The analyzer contract: **incomplete evidence can never pass**. Gaps yield `manual` ("requires human review"), never `pass`.

## Re-Inclusion Flags (Mode A Only, SE/CSM Use)

For internal review where the operator is authorized:

```bash
# Include actual IDs and origin IPs
cf-account-review collect --include-ids --include-dns-content
```

**These flags DO NOT change evaluation logic** — they only swap:
- `h3a7f9c2b1e4d6a8` → `f1234567890abcdef` (real zone ID)
- `[redacted]` → `203.0.113.42` (real origin IP)

All checks run identically on both versions. The flags exist for:
1. **Debugging** — "which zone actually failed this check?"
2. **Remediation** — linking findings to dashboard deep links

**Customer-run Mode B collectors (bash/PowerShell) redact unconditionally** — no re-inclusion flags.

## The Read-Only Guarantee

Redaction happens **at collection time**, before any data leaves the Cloudflare API:
1. Collector fetches data via GET-only API calls
2. Redaction applied in-memory before serialization
3. Pre-write secret scan aborts on any credential-shaped string
4. JSON written to disk

The analyzer **only reads** this file. It has no API access, no write methods, no network calls.

Tests enforce both:
- `tests/read-only.test.ts` — fails build if any mutating HTTP method exists
- `tests/redaction.test.ts` — verifies each redaction rule

## Conclusion

**Backend evaluation works perfectly on redacted data** because:
- Security checks evaluate **configuration structure**, not sensitive values
- Booleans, counts, expressions, actions, and enabled-state are preserved
- Only secrets and identifiers are redacted — never the decision surface
- The zod schema guarantees both collectors and analyzer agree on structure

A customer can hand you a fully-redacted collection and get a complete 35-check report without revealing their origin IPs, account IDs, or internal hostnames.
