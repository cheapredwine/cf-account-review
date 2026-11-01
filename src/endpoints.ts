/**
 * Endpoint registry — every GET the tool can make, with the reason it exists
 * and the documentation that justifies it. Mirrored in docs/endpoints.md.
 *
 * Anything not listed here cannot be called by the collector: the Mode A
 * collector iterates THIS list only. That is the second layer of the
 * read-only + minimal-collection guarantee (first layer: GET-only client).
 */
export interface Endpoint {
  /** API path; {account_id} / {zone_id} placeholders. */
  path: string;
  /** Human explanation of why this data is collected for the review. */
  rationale: string;
  /** Required token permission (read), as named in Cloudflare docs. */
  tokenPermission: string;
  /** Scope level for the collector. */
  scope: "account" | "zone";
  /** Plan tiers where this endpoint is meaningful; others report N/A. */
  planTier?: "any" | "pro-plus" | "business-plus" | "enterprise";
  /** Findings domain it feeds. */
  domain: string;
  /** Docs citation surfaced in the report. */
  citation: string;
}

export const ENDPOINTS: Endpoint[] = [
  // ---- account level ----
  {
    path: "/accounts",
    rationale: "Enumerate accounts; everything else is scoped per account.",
    tokenPermission: "Account Settings: Read",
    scope: "account",
    planTier: "any",
    domain: "inventory",
    citation: "https://developers.cloudflare.com/api/resources/accounts/methods/list/",
  },
  {
    path: "/accounts/{account_id}/settings",
    rationale: "Account posture: enforce 2FA, abuse contact, API access settings.",
    tokenPermission: "Account Settings: Read",
    scope: "account",
    planTier: "any",
    domain: "account-hygiene",
    citation: "https://developers.cloudflare.com/fundamentals/account/account-security/",
  },
  {
    path: "/accounts/{account_id}/members",
    rationale:
      "2FA adoption and role concentration. Only role names + 2FA booleans are exported; no names or emails.",
    tokenPermission: "Account Settings: Read",
    scope: "account",
    planTier: "any",
    domain: "account-hygiene",
    citation: "https://developers.cloudflare.com/fundamentals/manage-members/manage/",
  },
  {
    path: "/user/tokens",
    rationale: "Token expiry/rotation posture (status, expiry, last-use only).",
    tokenPermission: "User API Tokens: Read",
    scope: "account",
    planTier: "any",
    domain: "account-hygiene",
    citation: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
  },
  {
    path: "/accounts/{account_id}/tokens",
    rationale: "Account-owned token inventory (metadata only).",
    tokenPermission: "Account API Tokens: Read",
    scope: "account",
    planTier: "any",
    domain: "account-hygiene",
    citation: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
  },
  {
    path: "/accounts/{account_id}/load_balancers/pools",
    rationale: "Pool health-check hygiene and failover posture.",
    tokenPermission: "Load Balancer Monitors and Pools: Read",
    scope: "account",
    planTier: "any",
    domain: "traffic",
    citation: "https://developers.cloudflare.com/load-balancing/pools/",
  },
  {
    path: "/accounts/{account_id}/load_balancers/monitors",
    rationale: "Monitor configuration sanity (intervals, expected codes).",
    tokenPermission: "Load Balancer Monitors and Pools: Read",
    scope: "account",
    planTier: "any",
    domain: "traffic",
    citation: "https://developers.cloudflare.com/load-balancing/monitors/",
  },
  {
    path: "/accounts/{account_id}/rulesets",
    rationale: "Account-level custom/managed rulesets (Enterprise) — shared WAF across zones.",
    tokenPermission: "Account Rulesets: Read",
    scope: "account",
    planTier: "enterprise",
    domain: "waf",
    citation: "https://developers.cloudflare.com/waf/account/managed-rulesets/",
  },
  {
    path: "/accounts/{account_id}/access/apps",
    rationale: "Access application inventory: policy-less apps and bypass decisions.",
    tokenPermission: "Access: Apps and Policies: Read",
    scope: "account",
    planTier: "any",
    domain: "zero-trust",
    citation: "https://developers.cloudflare.com/cloudflare-one/applications/",
  },
  {
    path: "/accounts/{account_id}/access/identity_providers",
    rationale: "IdP posture: OTP-only setups are a finding.",
    tokenPermission: "Access: Identity Providers: Read",
    scope: "account",
    planTier: "any",
    domain: "zero-trust",
    citation: "https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/",
  },
  {
    path: "/accounts/{account_id}/challenges/widgets",
    rationale: "Turnstile inventory: widgets present, domains bound, mode.",
    tokenPermission: "Turnstile Widgets: Read",
    scope: "account",
    planTier: "any",
    domain: "bots",
    citation: "https://developers.cloudflare.com/turnstile/",
  },
  {
    path: "/accounts/{account_id}/cfd_tunnel",
    rationale: "Tunnel inventory: unsecured internal services exposed via public hostnames.",
    tokenPermission: "Cloudflare Tunnel: Read",
    scope: "account",
    planTier: "any",
    domain: "unsecured-endpoints",
    citation: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/",
  },
  {
    path: "/accounts/{account_id}/workers/scripts",
    rationale: "Worker script inventory: routes bound, plaintext binding names/types.",
    tokenPermission: "Workers Scripts: Read",
    scope: "account",
    planTier: "any",
    domain: "workers",
    citation: "https://developers.cloudflare.com/workers/wrangler/commands/#deploy",
  },
  {
    path: "/accounts/{account_id}/storage/kv/namespaces",
    rationale: "Data-at-rest inventory (count only).",
    tokenPermission: "Workers KV Storage: Read",
    scope: "account",
    planTier: "any",
    domain: "workers",
    citation: "https://developers.cloudflare.com/kv/",
  },
  {
    path: "/accounts/{account_id}/d1/database",
    rationale: "Data-at-rest inventory (count only).",
    tokenPermission: "D1: Read",
    scope: "account",
    planTier: "any",
    domain: "workers",
    citation: "https://developers.cloudflare.com/d1/",
  },
  {
    path: "/accounts/{account_id}/r2/buckets",
    rationale: "Data-at-rest inventory (count only).",
    tokenPermission: "Workers R2 Storage: Read",
    scope: "account",
    planTier: "any",
    domain: "workers",
    citation: "https://developers.cloudflare.com/r2/",
  },

  // ---- zone level ----
  {
    path: "/zones",
    rationale: "Zone inventory: plan, status, paused — drives plan-tier applicability of all checks.",
    tokenPermission: "Zone: Read",
    scope: "zone",
    planTier: "any",
    domain: "inventory",
    citation: "https://developers.cloudflare.com/api/resources/zones/methods/list/",
  },
  {
    path: "/zones/{zone_id}/settings",
    rationale:
      "Core posture: SSL mode, min TLS, HSTS, always-use-HTTPS, security level, challenge passage, bot fight mode, DNSSEC.",
    tokenPermission: "Zone Settings: Read",
    scope: "zone",
    planTier: "any",
    domain: "ssl-tls",
    citation: "https://developers.cloudflare.com/use-cases/solutions/encrypt-all-keep-site-secure/",
  },
  {
    path: "/zones/{zone_id}/rulesets",
    rationale: "Ruleset inventory: which phases have deployed rulesets at all.",
    tokenPermission: "Zone Rulesets: Read",
    scope: "zone",
    planTier: "any",
    domain: "waf",
    citation: "https://developers.cloudflare.com/ruleset-engine/rulesets-api/",
  },
  {
    path: "/zones/{zone_id}/rulesets/phases/{phase}/entrypoint",
    rationale:
      "Live rules per phase (custom WAF, managed WAF + overrides, rate limiting parameters, HTTP DDoS overrides, response header transforms). A 404 is recorded as 'absent' (nothing deployed), a 403 as 'unreadable'.",
    tokenPermission: "Phase-specific: Zone WAF: Read (firewall/ratelimit), HTTP DDoS Managed Ruleset: Read (ddos_l7), Transform Rules: Read, Cache Rules: Read",
    scope: "zone",
    planTier: "any",
    domain: "waf",
    citation: "https://developers.cloudflare.com/ruleset-engine/about/rulesets/",
  },
  {
    path: "/zones/{zone_id}/bot_management",
    rationale:
      "Bot posture: Bot Fight Mode (Free), Super Bot Fight Mode actions (Pro/Business), JS detections, AI-crawler blocking. Allow-listed keys only.",
    tokenPermission: "Bot Management: Read (or Zone WAF: Read)",
    scope: "zone",
    planTier: "any",
    domain: "bots",
    citation: "https://developers.cloudflare.com/bots/",
  },
  {
    path: "/zones/{zone_id}/firewall/access_rules/rules",
    rationale:
      "IP access rules: allowlist entries bypass every security product. Exported as mode/target only; IP values redacted, country/ASN kept.",
    tokenPermission: "Firewall Services: Read",
    scope: "zone",
    planTier: "any",
    domain: "waf",
    citation: "https://developers.cloudflare.com/waf/tools/ip-access-rules/",
  },
  {
    path: "/zones/{zone_id}/pagerules",
    rationale:
      "Legacy page rules that disable security, lower security level, or weaken SSL. Exported as action ids + enumerated values; URL targets dropped.",
    tokenPermission: "Page Rules: Read",
    scope: "zone",
    planTier: "any",
    domain: "unsecured-endpoints",
    citation: "https://developers.cloudflare.com/rules/page-rules/",
  },
  {
    path: "/zones/{zone_id}/dns_records",
    rationale:
      "DNS hygiene: subdomain-takeover risk, missing CAA, MX posture, orphaned records. Content values are redacted by default.",
    tokenPermission: "DNS: Read",
    scope: "zone",
    planTier: "any",
    domain: "dns",
    citation: "https://developers.cloudflare.com/dns/manage-dns-records/",
  },
  {
    path: "/zones/{zone_id}/ssl/certificate_packs",
    rationale: "Custom cert packs: expiry and coverage.",
    tokenPermission: "SSL and Certificates: Read",
    scope: "zone",
    planTier: "any",
    domain: "ssl-tls",
    citation: "https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/",
  },
  {
    path: "/zones/{zone_id}/workers/routes",
    rationale: "What runs where: Workers routes vs zone traffic.",
    tokenPermission: "Workers Routes: Read",
    scope: "zone",
    planTier: "any",
    domain: "workers",
    citation: "https://developers.cloudflare.com/workers/configuration/routing/routes/",
  },
  {
    path: "/zones/{zone_id}/rate_limits",
    rationale: "Legacy rate-limiting product still active — migration signal (old endpoint, not ratelimit phase).",
    tokenPermission: "Zone Rate Limiting: Read",
    scope: "zone",
    planTier: "any",
    domain: "rate-limiting",
    citation: "https://developers.cloudflare.com/waf/reference/legacy/old-rate-limiting/",
  },
  {
    path: "/zones/{zone_id}/managed_headers",
    rationale: "Managed Transforms: whether 'Add security headers' and 'Remove X-Powered-By' are on.",
    tokenPermission: "Transform Rules: Read (or Zone Settings: Read)",
    scope: "zone",
    planTier: "any",
    domain: "http-headers",
    citation: "https://developers.cloudflare.com/rules/transform/managed-transforms/reference/",
  },
  {
    path: "/zones/{zone_id}/leaked-credential-checks",
    rationale: "Leaked credentials detection enabled (flags requests using known-breached credential pairs).",
    tokenPermission: "Zone WAF: Read",
    scope: "zone",
    planTier: "any",
    domain: "waf",
    citation: "https://developers.cloudflare.com/waf/detections/leaked-credentials/",
  },
  {
    path: "/accounts/{account_id}/ai-gateway/gateways",
    rationale: "AI Gateway inventory: rate limiting, authentication, DLP, guardrails, and log collection posture.",
    tokenPermission: "AI Gateway: Read",
    scope: "account",
    planTier: "any",
    domain: "ai-gateway",
    citation: "https://developers.cloudflare.com/ai-gateway/",
  },
  {
    path: "/zones/{zone_id}/page_shield",
    rationale: "Client-side security (Page Shield) enablement: script/connection/cookie monitoring, malicious script detection.",
    tokenPermission: "Page Shield: Read",
    scope: "zone",
    planTier: "business-plus",
    domain: "client-side-security",
    citation: "https://developers.cloudflare.com/client-side-security/",
  },
  {
    path: "/zones/{zone_id}/origin_tls_client_auth/settings",
    rationale: "Authenticated Origin Pulls (mTLS) enablement: verifies requests come from Cloudflare network.",
    tokenPermission: "SSL and Certificates: Read",
    scope: "zone",
    planTier: "any",
    domain: "origin-security",
    citation: "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/",
  },
  {
    path: "/zones/{zone_id}/origin_tls_client_auth",
    rationale: "Authenticated Origin Pulls zone-level certificates: custom cert preferred over shared global cert.",
    tokenPermission: "SSL and Certificates: Read",
    scope: "zone",
    planTier: "any",
    domain: "origin-security",
    citation: "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/",
  },
  {
    path: "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
    rationale: "Tunnel public hostname inventory: cross-reference with Access apps to detect unprotected public routes.",
    tokenPermission: "Cloudflare Tunnel: Read",
    scope: "account",
    planTier: "any",
    domain: "zero-trust",
    citation: "https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/",
  },
];

/** Security/traffic phases whose entrypoint rules are collected. */
export const PHASES = [
  "http_request_firewall_custom",
  "http_request_firewall_managed",
  "http_ratelimit",
  "ddos_l7",
  "http_request_cache_settings",
  "http_response_headers_transform",
] as const;
