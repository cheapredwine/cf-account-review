/**
 * Mode A collector — live collection via a read-only API token.
 *
 * Iterates the ENDPOINTS registry only (no ad-hoc paths), redacts sensitive
 * fields at collection time, hashes IDs, and emits a Collection document.
 */
import { CfGetClient } from "./cf/client.js";
import { PHASES } from "./endpoints.js";
import {
  hashId,
  redactDnsContent,
  redactEmails,
  redactExpression,
  redactRuleActionParameters,
} from "./redact.js";
import {
  REDACTED,
  SCHEMA_VERSION,
  type Collection,
  type Zone,
} from "./schema.js";

const COLLECTOR_VERSION = "0.1.0";

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
}

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null
    ? (v as Record<string, unknown>)
    : {};
}

function optString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function optBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

function optBoolOrNull(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function optStringOrNull(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

/**
 * API Discovery returns `{ schemas: [...], timestamp }` (or nothing when the
 * zone is not entitled). Only the count is kept — endpoint paths are
 * customer API surface and are never collected.
 */
function apiGatewayDiscoverySummary(
  v: unknown,
): { discoveredSchemaCount: number } | undefined {
  const rows = asArray(v);
  if (rows.length === 0) return undefined;
  const count = rows.reduce<number>(
    (n, row) => n + asArray(asRecord(row).schemas).length,
    0,
  );
  return { discoveredSchemaCount: count };
}

export interface CollectOptions {
  includeDnsContent?: boolean;
  includeIds?: boolean;
}

export async function collect(
  token: string,
  options: CollectOptions = {},
): Promise<Collection> {
  const client = new CfGetClient(token);
  const { includeDnsContent = false, includeIds = false } = options;

  // Verify token (status only — never the token value).
  const verify = asRecord(await client.get("/user/tokens/verify"));
  const tokenStatus =
    verify.status === "active" ? "active" : "verification-failed";

  // ---- accounts ----
  const rawAccounts = asArray(await client.list("/accounts"));
  const accounts = rawAccounts.map((a) => asRecord(a));
  const accountDocs: Collection["accounts"] = [];

  for (const acct of accounts) {
    const accountId = String(acct.id ?? "");
    const hashed = hashId(accountId, includeIds);

    // Account posture data lives on the bare account object (result.settings);
    // the /accounts/{id}/settings subpath does not exist (404).
    const acctFull = asRecord(await client.get(`/accounts/${accountId}`));
    const rawSettings = asRecord(acctFull.settings ?? {});
    const settings = {
      enforce_twofactor: optBoolOrNull(rawSettings.enforce_twofactor),
      api_access_enabled: optBoolOrNull(rawSettings.api_access_enabled),
      access_approval_expiry: optStringOrNull(
        rawSettings.access_approval_expiry,
      ),
      oauth_app_access_enabled: optBoolOrNull(
        rawSettings.oauth_app_access_enabled,
      ),
    };
    const members = asArray(
      await client.list(`/accounts/${accountId}/members`),
    );
    const userTokens = asArray(await client.list("/user/tokens"));
    const accountTokens = asArray(
      await client.list(`/accounts/${accountId}/tokens`),
    );
    const lbPools = asArray(
      await client.list(`/accounts/${accountId}/load_balancers/pools`),
    );
    const lbMonitors = asArray(
      await client.list(`/accounts/${accountId}/load_balancers/monitors`),
    );
    const accountRulesets = asArray(
      await client.list(`/accounts/${accountId}/rulesets`),
    );
    const accessApps = asArray(
      await client.list(`/accounts/${accountId}/access/apps`),
    );
    const idps = asArray(
      await client.list(`/accounts/${accountId}/access/identity_providers`),
    );
    const widgets = asArray(
      await client.list(`/accounts/${accountId}/challenges/widgets`),
    );
    const tunnels = asArray(
      await client.list(`/accounts/${accountId}/cfd_tunnel`),
    );
    const scripts = asArray(
      await client.list(`/accounts/${accountId}/workers/scripts`),
    );
    const kv = asArray(
      await client.list(`/accounts/${accountId}/storage/kv/namespaces`),
    );
    const d1 = asArray(await client.list(`/accounts/${accountId}/d1/database`));
    const r2 = asArray(await client.list(`/accounts/${accountId}/r2/buckets`));
    const aiGateways = asArray(
      await client.list(`/accounts/${accountId}/ai-gateway/gateways`),
    );

    // Public hostnames referenced in expressions: keep zone names readable.
    const zoneNames = asArray(await client.list("/zones")).map((z) =>
      String(asRecord(z).name ?? ""),
    );

    accountDocs.push({
      id: hashed,
      name: typeof acct.name === "string" ? acct.name : undefined,
      enforceTwofactor:
        typeof settings.enforce_twofactor === "boolean"
          ? settings.enforce_twofactor
          : null,
      settings,
      accountMembers: members.map((m) => {
        const mem = asRecord(m);
        const user = asRecord(mem.user);
        const policies = asArray(mem.policies);
        return {
          roleNames: policies.flatMap((p) =>
            asArray(asRecord(p).permission_groups).map((g) =>
              String(asRecord(g).name ?? ""),
            ),
          ),
          twofactorEnabled:
            typeof user.two_factor_authentication_enabled === "boolean"
              ? user.two_factor_authentication_enabled
              : null,
          status: typeof mem.status === "string" ? mem.status : undefined,
        };
      }),
      apiTokens: [...userTokens, ...accountTokens].map((t) => {
        const tok = asRecord(t);
        return {
          status: typeof tok.status === "string" ? tok.status : undefined,
          expiresOn: typeof tok.expires_on === "string" ? tok.expires_on : null,
          lastUsedOn:
            typeof tok.last_used_on === "string" ? tok.last_used_on : null,
          permissionGroupNames: asArray(tok.policies).flatMap((p) =>
            asArray(asRecord(p).permission_groups).map((g) =>
              String(asRecord(g).name ?? ""),
            ),
          ),
        };
      }),
      loadBalancerPools: lbPools.map((pool) => {
        const p = asRecord(pool);
        return {
          id: typeof p.id === "string" ? hashId(p.id, includeIds) : undefined,
          name: typeof p.name === "string" ? p.name : undefined,
          enabled: typeof p.enabled === "boolean" ? p.enabled : undefined,
          origins: asArray(p.origins).map((o) => {
            const origin = asRecord(o);
            return {
              name: typeof origin.name === "string" ? origin.name : undefined,
              address:
                typeof origin.address === "string" ? REDACTED : undefined,
              enabled:
                typeof origin.enabled === "boolean"
                  ? origin.enabled
                  : undefined,
              weight:
                typeof origin.weight === "number" ? origin.weight : undefined,
            };
          }),
          monitor: typeof p.monitor === "string" ? hashId(p.monitor, includeIds) : null,
          notificationEmail: REDACTED,
        };
      }),
      loadBalancerMonitors: lbMonitors.map((mon) => {
        const m = asRecord(mon);
        return {
          id: typeof m.id === "string" ? hashId(m.id, includeIds) : undefined,
          type: typeof m.type === "string" ? m.type : undefined,
          interval: typeof m.interval === "number" ? m.interval : undefined,
          timeout: typeof m.timeout === "number" ? m.timeout : undefined,
          retries: typeof m.retries === "number" ? m.retries : undefined,
          expectedCodes:
            typeof m.expected_codes === "string" ? m.expected_codes : undefined,
          followRedirects:
            typeof m.follow_redirects === "boolean"
              ? m.follow_redirects
              : undefined,
          allowInsecure:
            typeof m.allow_insecure === "boolean"
              ? m.allow_insecure
              : undefined,
        };
      }),
      accountRulesets: accountRulesets.map((r) => {
        const rs = asRecord(r);
        return {
          name: typeof rs.name === "string" ? rs.name : undefined,
          kind: typeof rs.kind === "string" ? rs.kind : undefined,
          phase: typeof rs.phase === "string" ? rs.phase : undefined,
          version: typeof rs.version === "string" ? rs.version : undefined,
        };
      }),
      accessApps: accessApps.map((app) => {
        const a = asRecord(app);
        const policies = asArray(a.policies);
        const decisions = policies
          .map((p) => String(asRecord(p).decision ?? ""))
          .filter((d) => d.length > 0);
        const selfHosted = asArray(a.self_hosted_domains).map((d) => String(d));
        return {
          name: typeof a.name === "string" ? a.name : undefined,
          type: typeof a.type === "string" ? a.type : undefined,
          domain: typeof a.domain === "string" ? a.domain : undefined,
          selfHostedDomains: selfHosted.length > 0 ? selfHosted : undefined,
          hasPolicies: policies.length > 0,
          policyDecisions: decisions,
        };
      }),
      accessIdentityProviders: idps.map((p) => {
        const idp = asRecord(p);
        return {
          name: typeof idp.name === "string" ? idp.name : undefined,
          type: typeof idp.type === "string" ? idp.type : undefined,
        };
      }),
      turnstileWidgets: widgets.map((w) => {
        const wid = asRecord(w);
        const domains = asArray(wid.domains).map((d) => String(d));
        return {
          name: typeof wid.name === "string" ? wid.name : undefined,
          domains: domains.length > 0 ? domains : undefined,
          mode: typeof wid.mode === "string" ? wid.mode : undefined,
        };
      }),
      cfdTunnels: await Promise.all(
        tunnels.map(async (t) => {
          const tun = asRecord(t);
          const tunnelId = String(tun.id ?? "");
          const config = asRecord(
            await client.get(
              `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`,
            ),
          );
          const ingress = asArray(asRecord(config.config).ingress);
          const publicHostnames = ingress
            .map((i) => String(asRecord(i).hostname ?? ""))
            .filter((h) => h.length > 0 && h !== "*");
          return {
            id: tun.id ? hashId(tunnelId, includeIds) : undefined,
            name: typeof tun.name === "string" ? tun.name : undefined,
            status: typeof tun.status === "string" ? tun.status : undefined,
            publicHostnames,
          };
        }),
      ),
      workersScripts: scripts.map((s) => {
        const sc = asRecord(s);
        const bindings = asArray(sc.bindings).map((b) => asRecord(b));
        return {
          id: sc.id ? hashId(String(sc.id), includeIds) : undefined,
          scriptName: typeof sc.id === "string" ? String(sc.id) : undefined,
          createdOn:
            typeof sc.created_on === "string" ? sc.created_on : undefined,
          modifiedOn:
            typeof sc.modified_on === "string" ? sc.modified_on : undefined,
          routesBound: false, // resolved per-zone below
          plainTextBindings: bindings
            .filter((b) => b.type === "plain_text" || b.type === "secret_text")
            .map((b) => ({
              name: String(b.name ?? ""),
              type: String(b.type ?? ""),
            })),
        };
      }),
      storageInventory: {
        kvNamespaces: kv.length,
        d1Databases: d1.length,
        r2Buckets: r2.length,
      },
      aiGateways: aiGateways.map((gw) => {
        const g = asRecord(gw);
        const dlp = asRecord(g.dlp);
        const guardrails = asRecord(g.guardrails);
        const spendLimits = asRecord(g.spend_limits);
        return {
          id: typeof g.id === "string" ? g.id : undefined,
          authentication:
            typeof g.authentication === "boolean"
              ? g.authentication
              : undefined,
          rateLimitingLimit:
            typeof g.rate_limiting_limit === "number"
              ? g.rate_limiting_limit
              : null,
          rateLimitingInterval:
            typeof g.rate_limiting_interval === "number"
              ? g.rate_limiting_interval
              : null,
          rateLimitingTechnique:
            typeof g.rate_limiting_technique === "string"
              ? g.rate_limiting_technique
              : null,
          collectLogs:
            typeof g.collect_logs === "boolean" ? g.collect_logs : undefined,
          dlpEnabled:
            typeof dlp.enabled === "boolean" ? dlp.enabled : undefined,
          dlpPoliciesCount: Array.isArray(dlp.policies)
            ? dlp.policies.length
            : undefined,
          guardrailsConfigured:
            guardrails && Object.keys(guardrails).length > 0 ? true : undefined,
          retryMaxAttempts:
            typeof g.retry_max_attempts === "number"
              ? g.retry_max_attempts
              : null,
          spendLimitsEnabled:
            typeof spendLimits.enabled === "boolean"
              ? spendLimits.enabled
              : undefined,
          byokOnly: typeof g.byok_only === "boolean" ? g.byok_only : undefined,
        };
      }),
    });
    void zoneNames;
  }

  // ---- zones ----
  const rawZones = asArray(await client.list("/zones"));
  const zones: Zone[] = [];
  const planTiers = new Set<string>();

  for (const zRaw of rawZones) {
    const z = asRecord(zRaw);
    const zoneId = String(z.id ?? "");
    const zoneName = String(z.name ?? "");
    const plan = asRecord(z.plan);
    const planName = typeof plan.name === "string" ? plan.name : undefined;
    if (planName) planTiers.add(planName);

    const settingsRows = asArray(
      await client.list(`/zones/${zoneId}/settings`),
    );
    const settings: Record<
      string,
      { id: string; value: unknown; editable?: boolean }
    > = {};
    for (const row of settingsRows) {
      const s = asRecord(row);
      const id = String(s.id ?? "");
      if (!id) continue;
      settings[id] = {
        id,
        value: s.value,
        editable: typeof s.editable === "boolean" ? s.editable : undefined,
      };
    }

    const rulesetList = asArray(await client.list(`/zones/${zoneId}/rulesets`));
    const phaseEntrypoints: Zone["phaseEntrypoints"] = {};
    for (const phase of PHASES) {
      const ep = asRecord(
        await client.get(
          `/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`,
        ),
      );
      if (Object.keys(ep).length === 0) continue;
      const rules = asArray(ep.rules).map((rRaw) => {
        const r = asRecord(rRaw);
        return {
          id: r.id ? hashId(String(r.id), includeIds) : undefined,
          description:
            typeof r.description === "string"
              ? redactEmails(r.description)
              : undefined,
          enabled: typeof r.enabled === "boolean" ? r.enabled : undefined,
          action: typeof r.action === "string" ? r.action : undefined,
          expression: redactExpression(
            typeof r.expression === "string" ? r.expression : undefined,
            [zoneName],
          ),
          action_parameters: redactRuleActionParameters(r.action_parameters),
          version: typeof r.version === "string" ? r.version : undefined,
          lastUpdated:
            typeof r.last_updated === "string" ? r.last_updated : undefined,
        };
      });
      phaseEntrypoints[phase] = {
        phase,
        name: typeof ep.name === "string" ? ep.name : undefined,
        kind: typeof ep.kind === "string" ? ep.kind : undefined,
        rules,
      };
    }

    const dnsRaw = asArray(
      await client.list(`/zones/${zoneId}/dns_records`, { per_page: "100" }),
    );
    const dnsRecords = dnsRaw.map((dRaw) => {
      const d = asRecord(dRaw);
      return {
        type: String(d.type ?? ""),
        name: String(d.name ?? ""),
        content: redactDnsContent(
          typeof d.content === "string" ? d.content : undefined,
          includeDnsContent,
        ),
        proxied: typeof d.proxied === "boolean" ? d.proxied : null,
        ttl: typeof d.ttl === "number" ? d.ttl : undefined,
        comment: typeof d.comment === "string" ? redactEmails(d.comment) : null,
      };
    });

    const routes = asArray(
      await client.list(`/zones/${zoneId}/workers/routes`),
    );

    zones.push({
      name: zoneName,
      plan: planName,
      status: typeof z.status === "string" ? z.status : undefined,
      paused: typeof z.paused === "boolean" ? z.paused : undefined,
      type: typeof z.type === "string" ? z.type : undefined,
      createdOn: typeof z.created_on === "string" ? z.created_on : undefined,
      settings,
      rulesets: rulesetList.map((r) => {
        const rs = asRecord(r);
        return {
          id: rs.id ? hashId(String(rs.id), includeIds) : undefined,
          name: typeof rs.name === "string" ? rs.name : undefined,
          kind: typeof rs.kind === "string" ? rs.kind : undefined,
          phase: typeof rs.phase === "string" ? rs.phase : undefined,
          version: typeof rs.version === "string" ? rs.version : undefined,
        };
      }),
      phaseEntrypoints,
      botManagement: asRecord(
        await client.get(`/zones/${zoneId}/bot_management`),
      ),
      ipAccessRules: asArray(
        await client.list(`/zones/${zoneId}/firewall/access_rules/rules`),
      ).map((rule) => {
        const r = asRecord(rule);
        const cfg = asRecord(r.configuration);
        const scope = asRecord(r.scope);
        return {
          mode: optString(r.mode),
          target: optString(cfg.target),
          scope: optString(scope.type),
        };
      }),
      pageRules: asArray(await client.list(`/zones/${zoneId}/pagerules`)).map(
        (rule) => {
          const r = asRecord(rule);
          return {
            status: optString(r.status),
            actions: asArray(r.actions)
              .map((a) => asRecord(a).id)
              .filter((id): id is string => typeof id === "string"),
          };
        },
      ),
      certificatePacks: asArray(
        await client.list(`/zones/${zoneId}/ssl/certificate_packs`),
      ).map((pack) => {
        const p = asRecord(pack);
        return {
          id: typeof p.id === "string" ? hashId(p.id, includeIds) : undefined,
          type: typeof p.type === "string" ? p.type : undefined,
          status: typeof p.status === "string" ? p.status : undefined,
          validityDays:
            typeof p.validity_days === "number" ? p.validity_days : undefined,
          certificateAuthority:
            typeof p.certificate_authority === "string"
              ? p.certificate_authority
              : undefined,
          expiresOn: typeof p.expires_on === "string" ? p.expires_on : null,
          hosts: asArray(p.hosts).filter(
            (h) => typeof h === "string",
          ) as string[],
        };
      }),
      sslVerification: asArray(
        await client.list(`/zones/${zoneId}/ssl/verification`),
      ).map((row) => {
        const v = asRecord(row);
        return {
          certificateStatus: optString(v.certificate_status),
          validationMethod: optString(v.validation_method),
          verificationType: optString(v.verification_type),
        };
      }),
      loadBalancers: asArray(
        await client.list(`/zones/${zoneId}/load_balancers`),
      ).map((row) => {
        const lb = asRecord(row);
        return {
          name: optString(lb.name),
          enabled: optBool(lb.enabled),
          proxied: optBool(lb.proxied),
          steeringPolicy: optString(lb.steering_policy),
          poolCount: asArray(lb.default_pools).length,
        };
      }),
      workersRoutes: routes.map((r) => {
        const route = asRecord(r);
        return {
          pattern:
            typeof route.pattern === "string" ? route.pattern : undefined,
          script: typeof route.script === "string" ? route.script : undefined,
        };
      }),
      dnsRecordCount: dnsRecords.length,
      dnsRecords,
      apiGatewayDiscovery: apiGatewayDiscoverySummary(
        await client.list(`/zones/${zoneId}/api_gateway/discovery`),
      ),
    });

    // Page Shield and AOP collection
    const ps = asRecord(await client.get(`/zones/${zoneId}/page_shield`));
    const aopSettings = asRecord(
      await client.get(`/zones/${zoneId}/origin_tls_client_auth/settings`),
    );
    const aopCerts = asArray(
      await client.list(`/zones/${zoneId}/origin_tls_client_auth`),
    );

    const currentZone = zones[zones.length - 1];
    if (currentZone) {
      currentZone.pageShield = {
        enabled: typeof ps.enabled === "boolean" ? ps.enabled : undefined,
        useCloudflareReportingEndpoint:
          typeof ps.use_cloudflare_reporting_endpoint === "boolean"
            ? ps.use_cloudflare_reporting_endpoint
            : undefined,
        useConnectionUrlPath:
          typeof ps.use_connection_url_path === "boolean"
            ? ps.use_connection_url_path
            : undefined,
      };
      currentZone.authenticatedOriginPulls = {
        enabled:
          typeof aopSettings.enabled === "boolean"
            ? aopSettings.enabled
            : undefined,
        hasZoneLevelCert: aopCerts.length > 0,
        certCount: aopCerts.length,
      };
    }
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    collectedAt: new Date().toISOString(),
    collector: "api",
    collectorVersion: COLLECTOR_VERSION,
    tokenStatus,
    planTiersSeen: [...planTiers],
    accounts: accountDocs,
    zones,
    collectionErrors: client.getApiErrors(),
  };
}
