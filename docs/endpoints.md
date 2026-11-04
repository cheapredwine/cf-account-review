# Endpoints and why each one is collected

Every GET this tool can make is registered in `src/endpoints.ts` (Mode A) and
hard-coded in the PowerShell and bash collectors (Mode B). Anything not listed
here cannot be requested — the collectors iterate the registry only.

This table is mirrored in the generated report's findings: each finding cites
the doc that justifies its check.

## Account level

| Endpoint | Why it's collected | Token permission (read) | Plan tier |
| --- | --- | --- | --- |
| `/accounts` | Enumerate accounts; everything else is scoped per account. | Account Settings: Read | any |
| `/accounts/{id}` | Account posture: enforce-2FA flag, API access, abuse contact (under `result.settings`; the `/settings` subpath 404s). | Account Settings: Read | any |
| `/accounts/{id}/members` | 2FA adoption and role concentration. Only role names + 2FA booleans are exported; no names or emails. | Account Settings: Read | any |
| `/user/tokens` | Token expiry/rotation posture (status, expiry, last-use only). | API Tokens: Read (User section) | any |
| `/accounts/{id}/tokens` | Account-owned token inventory (metadata only). | Account API Tokens: Read | any |
| `/accounts/{id}/load_balancers/pools` | Pool health-check hygiene and failover posture. | Load Balancing: Monitors and Pools: Read | any |
| `/accounts/{id}/load_balancers/monitors` | Monitor configuration sanity (intervals, expected codes). | Load Balancing: Monitors and Pools: Read | any |
| `/accounts/{id}/rulesets` | Account-level custom/managed rulesets — shared WAF across zones. | Account Rulesets: Read | Enterprise |
| `/accounts/{id}/access/apps` | Access application inventory: policy-less apps, bypass decisions. | Access: Apps and Policies: Read | any |
| `/accounts/{id}/access/identity_providers` | IdP posture: OTP-only setups are a finding. | Access: Identity Providers: Read | any |
| `/accounts/{id}/access/service_tokens` | Service token expiry posture (metadata only). | Access: Service Tokens: Read | any |
| `/accounts/{id}/challenges/widgets` | Turnstile inventory: widgets present, domains bound, mode. | Turnstile Sites: Read | any |
| `/accounts/{id}/cfd_tunnel` | Tunnel inventory: unsecured internal services exposed via public hostnames. | Cloudflare Tunnel: Read | any |
| `/accounts/{id}/cfd_tunnel/{tunnel_id}/configurations` | Tunnel ingress config: public hostnames and their Access coverage. | Cloudflare Tunnel: Read | any |
| `/accounts/{id}/workers/scripts` | Worker script inventory: routes bound, plaintext binding names/types (values never exported). | Workers Scripts: Read | any |
| `/accounts/{id}/storage/kv/namespaces` | Data-at-rest inventory (count only). | Workers KV Storage: Read | any |
| `/accounts/{id}/d1/database` | Data-at-rest inventory (count only). | D1: Read | any |
| `/accounts/{id}/r2/buckets` | Data-at-rest inventory (count only). | Workers R2 Storage: Read | any |
| `/accounts/{id}/ai-gateway/gateways` | AI Gateway inventory: rate limiting, authentication, DLP, guardrails, log-collection posture. | AI Gateway: Read | any |

## Zone level

| Endpoint | Why it's collected | Token permission (read) | Plan tier |
| --- | --- | --- | --- |
| `/zones` | Zone inventory: plan, status, paused — drives plan-tier applicability. | Zone: Read | any |
| `/zones/{id}/settings` | Core posture: SSL mode, min TLS, HSTS, always-use-HTTPS, security level, challenge passage, bot fight mode, DNSSEC. | Zone Settings: Read | any |
| `/zones/{id}/rulesets` | Which phases have deployed rulesets at all. | Zone WAF: Read (no "Zone Rulesets" group exists) | any |
| `/zones/{id}/rulesets/phases/{phase}/entrypoint` | Live rules per phase (custom WAF, managed WAF, rate limiting, transforms, redirects, cache, origin). | Zone WAF: Read | any |
| `/zones/{id}/bot_management` | Bot posture: fight mode, AI crawler controls, JS detections. | Bot Management: Read (Zone WAF alone 403s) | Pro+ |
| `/zones/{id}/firewall/access_rules/rules` | IP access rules: allow/block posture, stale entries. | Firewall Services: Read | any |
| `/zones/{id}/pagerules` | Legacy page rules still active — migration + regression signal. | Page Rules: Read | any |
| `/zones/{id}/dns_records` | DNS hygiene: subdomain-takeover risk, missing CAA, MX posture, orphaned records. Content values are redacted by default. | DNS: Read | any |
| `/zones/{id}/ssl/verification` | Certificate verification failures per hostname. | SSL and Certificates: Read | any |
| `/zones/{id}/ssl/certificate_packs` | Custom cert packs: expiry and coverage. | SSL and Certificates: Read | any |
| `/zones/{id}/load_balancers` | Zone LB posture. | Load Balancers: Read | any |
| `/zones/{id}/workers/routes` | What runs where: Workers routes vs zone traffic. | Workers Routes: Read | any |
| `/zones/{id}/api_gateway/discovery` | API discovery inventory: endpoints known to Cloudflare. | Domain API Gateway: Read | Enterprise |
| `/zones/{id}/api_gateway/configuration` | API Shield session/JWT posture. 403 "not entitled" on zones without API Shield — fails closed to `manual`. | Domain API Gateway: Read | Enterprise |
| `/zones/{id}/page_shield` | Page Shield posture: JavaScript monitoring enabled. | Domain Page Shield: Read | Business+ |
| `/zones/{id}/origin_tls_client_auth/settings` | Authenticated Origin Pulls (zone-level) enablement. | SSL and Certificates: Read | any |
| `/zones/{id}/origin_tls_client_auth` | AOP client certificates present per zone. | SSL and Certificates: Read | any |

## Phases whose entrypoint rules are collected

`http_request_firewall_custom`, `http_request_firewall_managed`, `http_ratelimit`,
`http_request_transform`, `http_request_dynamic_redirect`,
`http_request_cache_settings`, `http_request_origin`, `http_request_redirect`,
`http_response_headers_transform`

## What is deliberately NOT collected

- Any endpoint requiring write scope — the tool has no write code at all.
- `/zones/{id}/logs/*`, Logpush targets, request sampling — request data never leaves the account.
- Endpoint detail bodies that carry secret values (Worker script contents, KV values,
  Access policy identity expressions — identities are reduced to counts/decisions).
- Anything the token cannot read is skipped and recorded in `collectionErrors`;
  findings backed by unreadable data are marked `manual`, never `pass`.

## Removed endpoints

- `/zones/{id}/firewall/waf/overrides` — returns **410 Gone** (legacy WAF
  overrides API removed; no check consumed it).
- `/zones/{id}/rate_limits` — returns **410 Gone** (legacy rate-limiting
  product EOL'd; no permission group exists for it either). The
  `http_ratelimit` phase entrypoint check covers current rate-limiting posture.
- Whitespace-free opaque strings of 64+ characters (token-class material,
  including long generated artifact names) are redacted to
  `[redacted]:opaque-<len>` at collection time — see `docs/data-policy.md`.
