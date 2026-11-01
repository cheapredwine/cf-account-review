/**
 * Mode A collector — live collection via a read-only API token.
 *
 * Iterates the ENDPOINTS registry only (no ad-hoc paths), redacts sensitive
 * fields at collection time, hashes IDs, and emits a Collection document.
 *
 * Readability contract (schema 1.1): a list field is OMITTED when its endpoint
 * could not be read, and an empty array when it was read and is empty. The
 * analyzer relies on this to keep scope gaps from turning into passes.
 */
import { CfGetClient } from "./cf/client.js";
import { PHASES } from "./endpoints.js";
import { hashId, hashIdsInPath, redactDnsContent, redactEmails, redactExpression } from "./redact.js";
import { REDACTED, SCHEMA_VERSION, type Collection, type Zone } from "./schema.js";
import {
  normalizePlan,
  summarizeActionParameters,
  summarizeBotManagement,
  summarizeIpAccessRule,
  summarizeManagedHeaders,
  summarizePageRule,
} from "./summarize.js";

export const COLLECTOR_VERSION = "0.2.0";

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
}

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}

/** null (unreadable) → undefined; otherwise map the array. */
function mapOpt<T>(v: unknown[] | null, fn: (x: unknown) => T): T[] | undefined {
  return v === null ? undefined : v.map(fn);
}

export async function collect(token: string, collector: "api" | "binary" = "api"): Promise<Collection> {
  const client = new CfGetClient(token);

  // Verify token (status only — never the token value).
  const verify = asRecord(await client.get("/user/tokens/verify"));
  const tokenStatus = verify.status === "active" ? "active" : "verification-failed";

  // User-owned tokens are not per-account; read once.
  const userTokens = await client.list("/user/tokens");

  // ---- accounts ----
  const accounts = asArray(await client.list("/accounts")).map((a) => asRecord(a));
  const accountDocs: Collection["accounts"] = [];

  for (const acct of accounts) {
    const accountId = String(acct.id ?? "");
    const hashed = hashId(accountId);

    const settings = asRecord(await client.get(`/accounts/${accountId}/settings`));
    const members = await client.list(`/accounts/${accountId}/members`);
    const accountTokens = await client.list(`/accounts/${accountId}/tokens`);
    const lbPools = await client.list(`/accounts/${accountId}/load_balancers/pools`);
    const lbMonitors = await client.list(`/accounts/${accountId}/load_balancers/monitors`);
    const accountRulesets = await client.list(`/accounts/${accountId}/rulesets`);
    const accessApps = await client.list(`/accounts/${accountId}/access/apps`);
    const idps = await client.list(`/accounts/${accountId}/access/identity_providers`);
    const widgets = await client.list(`/accounts/${accountId}/challenges/widgets`);
    const tunnels = await client.list(`/accounts/${accountId}/cfd_tunnel`);
    const scripts = await client.list(`/accounts/${accountId}/workers/scripts`);
    const kv = await client.list(`/accounts/${accountId}/storage/kv/namespaces`);
    const d1 = await client.list(`/accounts/${accountId}/d1/database`);
    const r2 = await client.list(`/accounts/${accountId}/r2/buckets`);
    const aiGateways = await client.list(`/accounts/${accountId}/ai-gateway/gateways`);

    const tokenRows = userTokens === null && accountTokens === null ? null : [...(userTokens ?? []), ...(accountTokens ?? [])];

    const tunnelDocs =
      tunnels === null
        ? undefined
        : await Promise.all(
            tunnels.map(async (t) => {
              const tun = asRecord(t);
              const tunnelId = String(tun.id ?? "");
              const config = asRecord(await client.get(`/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`));
              const ingress = asArray(asRecord(config.config).ingress);
              const publicHostnames = ingress
                .map((i) => String(asRecord(i).hostname ?? ""))
                .filter((h) => h.length > 0 && h !== "*");
              return {
                id: tun.id ? hashId(tunnelId) : undefined,
                name: typeof tun.name === "string" ? tun.name : undefined,
                status: typeof tun.status === "string" ? tun.status : undefined,
                publicHostnames,
              };
            }),
          );

    accountDocs.push({
      id: hashed,
      name: typeof acct.name === "string" ? acct.name : undefined,
      enforceTwofactor: typeof settings.enforce_twofactor === "boolean" ? settings.enforce_twofactor : null,
      accountMembers: mapOpt(members, (m) => {
        const mem = asRecord(m);
        const user = asRecord(mem.user);
        return {
          roleNames: asArray(mem.policies).flatMap((p) =>
            asArray(asRecord(p).permission_groups).map((g) => String(asRecord(g).name ?? "")),
          ),
          twofactorEnabled:
            typeof user.two_factor_authentication_enabled === "boolean" ? user.two_factor_authentication_enabled : null,
          status: typeof mem.status === "string" ? mem.status : undefined,
        };
      }),
      apiTokens: mapOpt(tokenRows, (t) => {
        const tok = asRecord(t);
        return {
          status: typeof tok.status === "string" ? tok.status : undefined,
          expiresOn: typeof tok.expires_on === "string" ? tok.expires_on : null,
          lastUsedOn: typeof tok.last_used_on === "string" ? tok.last_used_on : null,
          permissionGroupNames: asArray(tok.policies).flatMap((p) =>
            asArray(asRecord(p).permission_groups).map((g) => String(asRecord(g).name ?? "")),
          ),
        };
      }),
      loadBalancerPools: mapOpt(lbPools, (pool) => {
        const p = asRecord(pool);
        return {
          id: typeof p.id === "string" ? hashId(p.id) : undefined,
          name: typeof p.name === "string" ? p.name : undefined,
          enabled: typeof p.enabled === "boolean" ? p.enabled : undefined,
          origins: asArray(p.origins).map((o) => {
            const origin = asRecord(o);
            return {
              name: typeof origin.name === "string" ? origin.name : undefined,
              address: typeof origin.address === "string" ? REDACTED : undefined,
              enabled: typeof origin.enabled === "boolean" ? origin.enabled : undefined,
              weight: typeof origin.weight === "number" ? origin.weight : undefined,
            };
          }),
          monitor: typeof p.monitor === "string" ? hashId(p.monitor) : null,
          notificationEmail: REDACTED,
        };
      }),
      loadBalancerMonitors: mapOpt(lbMonitors, (mon) => {
        // Monitor `header` values can carry auth material — never exported.
        const m = asRecord(mon);
        return {
          id: typeof m.id === "string" ? hashId(m.id) : undefined,
          type: typeof m.type === "string" ? m.type : undefined,
          interval: typeof m.interval === "number" ? m.interval : undefined,
          timeout: typeof m.timeout === "number" ? m.timeout : undefined,
          retries: typeof m.retries === "number" ? m.retries : undefined,
          expectedCodes: typeof m.expected_codes === "string" ? m.expected_codes : undefined,
          followRedirects: typeof m.follow_redirects === "boolean" ? m.follow_redirects : undefined,
          allowInsecure: typeof m.allow_insecure === "boolean" ? m.allow_insecure : undefined,
        };
      }),
      accountRulesets: mapOpt(accountRulesets, (r) => {
        const rs = asRecord(r);
        return {
          id: typeof rs.id === "string" ? hashId(rs.id) : undefined,
          name: typeof rs.name === "string" ? rs.name : undefined,
          kind: typeof rs.kind === "string" ? rs.kind : undefined,
          phase: typeof rs.phase === "string" ? rs.phase : undefined,
          version: typeof rs.version === "string" ? rs.version : undefined,
        };
      }),
      accessApps: mapOpt(accessApps, (app) => {
        const a = asRecord(app);
        const policies = asArray(a.policies);
        const selfHosted = asArray(a.self_hosted_domains).map((d) => String(d));
        return {
          name: typeof a.name === "string" ? a.name : undefined,
          type: typeof a.type === "string" ? a.type : undefined,
          domain: typeof a.domain === "string" ? a.domain : undefined,
          selfHostedDomains: selfHosted.length > 0 ? selfHosted : undefined,
          hasPolicies: policies.length > 0,
          policyDecisions: policies.map((p) => String(asRecord(p).decision ?? "")).filter((d) => d.length > 0),
        };
      }),
      accessIdentityProviders: mapOpt(idps, (p) => {
        const idp = asRecord(p);
        return {
          name: typeof idp.name === "string" ? idp.name : undefined,
          type: typeof idp.type === "string" ? idp.type : undefined,
        };
      }),
      turnstileWidgets: mapOpt(widgets, (w) => {
        const wid = asRecord(w);
        const domains = asArray(wid.domains).map((d) => String(d));
        return {
          name: typeof wid.name === "string" ? wid.name : undefined,
          domains: domains.length > 0 ? domains : undefined,
          mode: typeof wid.mode === "string" ? wid.mode : undefined,
        };
      }),
      cfdTunnels: tunnelDocs,
      workersScripts: mapOpt(scripts, (s) => {
        const sc = asRecord(s);
        const bindings = asArray(sc.bindings).map((b) => asRecord(b));
        return {
          id: sc.id ? hashId(String(sc.id)) : undefined,
          scriptName: typeof sc.id === "string" ? String(sc.id) : undefined,
          createdOn: typeof sc.created_on === "string" ? sc.created_on : undefined,
          modifiedOn: typeof sc.modified_on === "string" ? sc.modified_on : undefined,
          plainTextBindings: bindings
            .filter((b) => b.type === "plain_text" || b.type === "secret_text")
            .map((b) => ({ name: String(b.name ?? ""), type: String(b.type ?? "") })),
        };
      }),
      storageInventory: {
        kvNamespaces: kv?.length,
        d1Databases: d1?.length,
        r2Buckets: r2?.length,
      },
      aiGateways: mapOpt(aiGateways, (gw) => {
        const g = asRecord(gw);
        const dlp = asRecord(g.dlp);
        const guardrails = asRecord(g.guardrails);
        const spendLimits = asRecord(g.spend_limits);
        return {
          id: typeof g.id === "string" ? g.id : undefined,
          authentication: typeof g.authentication === "boolean" ? g.authentication : undefined,
          rateLimitingLimit: typeof g.rate_limiting_limit === "number" ? g.rate_limiting_limit : null,
          rateLimitingInterval: typeof g.rate_limiting_interval === "number" ? g.rate_limiting_interval : null,
          rateLimitingTechnique: typeof g.rate_limiting_technique === "string" ? g.rate_limiting_technique : null,
          collectLogs: typeof g.collect_logs === "boolean" ? g.collect_logs : undefined,
          dlpEnabled: typeof dlp.enabled === "boolean" ? dlp.enabled : undefined,
          dlpPoliciesCount: Array.isArray(dlp.policies) ? dlp.policies.length : undefined,
          guardrailsConfigured: Object.keys(guardrails).length > 0 ? true : undefined,
          retryMaxAttempts: typeof g.retry_max_attempts === "number" ? g.retry_max_attempts : null,
          spendLimitsEnabled: typeof spendLimits.enabled === "boolean" ? spendLimits.enabled : undefined,
          byokOnly: typeof g.byok_only === "boolean" ? g.byok_only : undefined,
        };
      }),
    });
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
    const planLegacyId = typeof plan.legacy_id === "string" ? plan.legacy_id : undefined;
    if (planName) planTiers.add(planName);

    const settingsRows = await client.list(`/zones/${zoneId}/settings`);
    let settings: Zone["settings"];
    if (settingsRows !== null) {
      settings = {};
      for (const row of settingsRows) {
        const s = asRecord(row);
        const id = String(s.id ?? "");
        if (!id) continue;
        settings[id] = { id, value: s.value, editable: typeof s.editable === "boolean" ? s.editable : undefined };
      }
    }

    // Ruleset list: also gives raw-id → name so execute rules resolve to
    // managed ruleset names before IDs are hashed.
    const rulesetList = await client.list(`/zones/${zoneId}/rulesets`);
    const rulesetNames: Record<string, string> = {};
    for (const r of rulesetList ?? []) {
      const rs = asRecord(r);
      if (typeof rs.id === "string" && typeof rs.name === "string") rulesetNames[rs.id] = rs.name;
    }

    const phaseEntrypoints: NonNullable<Zone["phaseEntrypoints"]> = {};
    const phaseStatus: NonNullable<Zone["phaseStatus"]> = {};
    for (const phase of PHASES) {
      const { status, result } = await client.getEntrypoint(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`);
      phaseStatus[phase] = status;
      if (status !== "present") continue;
      const ep = asRecord(result);
      phaseEntrypoints[phase] = {
        phase,
        name: typeof ep.name === "string" ? ep.name : undefined,
        kind: typeof ep.kind === "string" ? ep.kind : undefined,
        rules: asArray(ep.rules).map((rRaw) => {
          const r = asRecord(rRaw);
          const action = typeof r.action === "string" ? r.action : undefined;
          return {
            id: r.id ? hashId(String(r.id)) : undefined,
            description: typeof r.description === "string" ? redactEmails(r.description) : undefined,
            enabled: typeof r.enabled === "boolean" ? r.enabled : undefined,
            action,
            expression: redactExpression(typeof r.expression === "string" ? r.expression : undefined),
            version: typeof r.version === "string" ? r.version : undefined,
            lastUpdated: typeof r.last_updated === "string" ? r.last_updated : undefined,
            actionParameters: summarizeActionParameters(action, r.action_parameters, rulesetNames, r.ratelimit),
          };
        }),
      };
    }

    const dnsRaw = await client.list(`/zones/${zoneId}/dns_records`);
    // DNS comments are free text (tickets, owners, emails): never exported.
    const dnsRecords = mapOpt(dnsRaw, (dRaw) => {
      const d = asRecord(dRaw);
      return {
        type: String(d.type ?? ""),
        name: String(d.name ?? ""),
        content: redactDnsContent(typeof d.content === "string" ? d.content : undefined),
        proxied: typeof d.proxied === "boolean" ? d.proxied : null,
        ttl: typeof d.ttl === "number" ? d.ttl : undefined,
      };
    });

    const routes = await client.list(`/zones/${zoneId}/workers/routes`);
    const certPacks = await client.list(`/zones/${zoneId}/ssl/certificate_packs`);
    const ipRules = await client.list(`/zones/${zoneId}/firewall/access_rules/rules`);
    const pageRules = await client.list(`/zones/${zoneId}/pagerules`);
    const legacyRl = await client.list(`/zones/${zoneId}/rate_limits`);
    const botRaw = await client.get(`/zones/${zoneId}/bot_management`);
    const managedHeadersRaw = await client.get(`/zones/${zoneId}/managed_headers`);
    const leakedRaw = await client.get(`/zones/${zoneId}/leaked-credential-checks`);
    const ps = await client.get(`/zones/${zoneId}/page_shield`);
    const aopSettings = await client.get(`/zones/${zoneId}/origin_tls_client_auth/settings`);
    const aopCerts = await client.list(`/zones/${zoneId}/origin_tls_client_auth`);
    const psRec = asRecord(ps);
    const aopRec = asRecord(aopSettings);
    const leakedRec = asRecord(leakedRaw);

    zones.push({
      name: zoneName,
      plan: planName,
      planLegacyId: planLegacyId ?? normalizePlan(planName),
      status: typeof z.status === "string" ? z.status : undefined,
      paused: typeof z.paused === "boolean" ? z.paused : undefined,
      type: typeof z.type === "string" ? z.type : undefined,
      createdOn: typeof z.created_on === "string" ? z.created_on : undefined,
      settings,
      rulesets: mapOpt(rulesetList, (r) => {
        const rs = asRecord(r);
        return {
          id: rs.id ? hashId(String(rs.id)) : undefined,
          name: typeof rs.name === "string" ? rs.name : undefined,
          kind: typeof rs.kind === "string" ? rs.kind : undefined,
          phase: typeof rs.phase === "string" ? rs.phase : undefined,
          version: typeof rs.version === "string" ? rs.version : undefined,
        };
      }),
      phaseEntrypoints,
      phaseStatus,
      botManagement: summarizeBotManagement(botRaw),
      ipAccessRuleSummary: mapOpt(ipRules, summarizeIpAccessRule),
      pageRuleSummary: mapOpt(pageRules, summarizePageRule),
      certificatePacks: mapOpt(certPacks, (pack) => {
        const p = asRecord(pack);
        return {
          id: typeof p.id === "string" ? hashId(p.id) : undefined,
          type: typeof p.type === "string" ? p.type : undefined,
          status: typeof p.status === "string" ? p.status : undefined,
          validityDays: typeof p.validity_days === "number" ? p.validity_days : undefined,
          certificateAuthority: typeof p.certificate_authority === "string" ? p.certificate_authority : undefined,
          expiresOn: typeof p.expires_on === "string" ? p.expires_on : null,
          hosts: asArray(p.hosts).filter((h) => typeof h === "string") as string[],
        };
      }),
      workersRoutes: mapOpt(routes, (r) => {
        const route = asRecord(r);
        return {
          pattern: typeof route.pattern === "string" ? route.pattern : undefined,
          script: typeof route.script === "string" ? route.script : undefined,
        };
      }),
      dnsRecordCount: dnsRecords?.length,
      dnsRecords,
      legacyRateLimits: mapOpt(legacyRl, (r) => ({ disabled: asRecord(r).disabled === true })),
      managedHeaders: summarizeManagedHeaders(managedHeadersRaw),
      leakedCredentialChecks:
        leakedRaw === null ? undefined : { enabled: typeof leakedRec.enabled === "boolean" ? leakedRec.enabled : undefined },
      pageShield:
        ps === null
          ? undefined
          : {
              enabled: typeof psRec.enabled === "boolean" ? psRec.enabled : undefined,
              useCloudflareReportingEndpoint:
                typeof psRec.use_cloudflare_reporting_endpoint === "boolean" ? psRec.use_cloudflare_reporting_endpoint : undefined,
              useConnectionUrlPath: typeof psRec.use_connection_url_path === "boolean" ? psRec.use_connection_url_path : undefined,
            },
      authenticatedOriginPulls:
        aopSettings === null
          ? undefined
          : {
              enabled: typeof aopRec.enabled === "boolean" ? aopRec.enabled : undefined,
              hasZoneLevelCert: aopCerts === null ? undefined : aopCerts.length > 0,
              certCount: aopCerts?.length,
            },
    });
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    collectedAt: new Date().toISOString(),
    collector,
    collectorVersion: COLLECTOR_VERSION,
    tokenStatus,
    planTiersSeen: [...planTiers],
    accounts: accountDocs,
    zones,
    // Raw account/zone/tunnel IDs in error paths are hashed like every other ID.
    collectionErrors: client.getApiErrors().map((e) => ({ ...e, path: hashIdsInPath(e.path) })),
  };
}
