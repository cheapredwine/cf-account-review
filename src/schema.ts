/**
 * Collection schema — the contract between every collector (TS client, PowerShell
 * script, bash script) and the analyzer.
 *
 * Design rules:
 *  - Sensitive fields are either ABSENT from the schema or carry a "[redacted]"
 *    sentinel. The analyzer treats absent and "[redacted]" identically.
 *  - `schemaVersion` is required; collectors and analyzer must agree on major.
 *  - Everything here is configuration metadata: no tokens, no credentials, no
 *    request logs, no usernames, no emails.
 */
import { z } from "zod";

export const SCHEMA_VERSION = "1.0";
export const REDACTED = "[redacted]";

export const idSchema = z
  .string()
  .max(64)
  .regex(/^[a-zA-Z0-9_-]*$/, "id characters")
  .describe("Resource ID, hashed or redacted by the collector before emission");

const zoneSettingsSchema = z.record(
  z.string().min(1),
  z.object({
    id: z.string(),
    value: z.unknown(),
    editable: z.boolean().optional(),
  }),
);

const phaseEntrypointSchema = z.object({
  phase: z.string(),
  name: z.string().optional(),
  kind: z.string().optional(),
  rules: z
    .array(
      z.object({
        id: z.string().optional(),
        description: z.string().optional(),
        enabled: z.boolean().optional(),
        action: z.string().optional(),
        expression: z.string().optional(),
        // Expressions may reference hostnames; collectors redact origin hosts.
        version: z.string().optional(),
        lastUpdated: z.string().optional(),
      }),
    )
    .optional(),
});

const dnsRecordSchema = z.object({
  type: z.string(),
  name: z.string(),
  content: z.string().optional().describe("Redacted unless explicitly authorized"),
  proxied: z.boolean().nullable().optional(),
  ttl: z.number().optional(),
  comment: z.string().optional().nullable(),
});

const rulesetSummarySchema = z.object({
  id: idSchema.optional(),
  name: z.string().optional(),
  kind: z.string().optional(),
  phase: z.string().optional(),
  version: z.string().optional(),
});

const httpErrorSchema = z.object({
  path: z.string(),
  status: z.number().optional(),
  error: z.string(),
  note: z.string().optional(),
});

export const collectionSchema = z.object({
  schemaVersion: z.string(),
  collectedAt: z.string().datetime({ offset: true }),
  collector: z.enum(["api", "powershell", "bash"]),
  collectorVersion: z.string(),
  tokenStatus: z.enum(["active", "verification-failed", "not-verified"]),
  planTiersSeen: z.array(z.string()).optional(),
  accounts: z
    .array(
      z.object({
        id: idSchema.optional(),
        name: z.string().optional(),
        settings: z.unknown().optional(),
        enforceTwofactor: z.boolean().nullable().optional(),
        accountMembers: z
          .array(
            z.object({
              // Identity fields are counts / booleans only — no emails, no names.
              roleNames: z.array(z.string()).optional(),
              twofactorEnabled: z.boolean().nullable().optional(),
              status: z.string().optional(),
            }),
          )
          .optional(),
        apiTokens: z
          .array(
            z.object({
              status: z.string().optional(),
              expiresOn: z.string().nullable().optional(),
              lastUsedOn: z.string().nullable().optional(),
              permissionGroupNames: z.array(z.string()).optional(),
            }),
          )
          .optional(),
        loadBalancerPools: z.unknown().optional(),
        loadBalancerMonitors: z.unknown().optional(),
        accountRulesets: z.array(rulesetSummarySchema).optional(),
        accessApps: z
          .array(
            z.object({
              name: z.string().optional(),
              type: z.string().optional(),
              domain: z.string().optional(),
              selfHostedDomains: z.array(z.string()).optional().nullable(),
              policies: z.unknown().optional(),
              hasPolicies: z.boolean().optional(),
              policyDecisions: z.array(z.string()).optional(),
            }),
          )
          .optional(),
        accessIdentityProviders: z
          .array(z.object({ name: z.string().optional(), type: z.string().optional() }))
          .optional(),
        turnstileWidgets: z
          .array(
            z.object({
              name: z.string().optional(),
              domains: z.array(z.string()).optional().nullable(),
              mode: z.string().optional(),
            }),
          )
          .optional(),
        cfdTunnels: z.unknown().optional(),
        workersScripts: z
          .array(
            z.object({
              id: idSchema.optional(),
              // Script names are not credentials and appear in zone routes too,
              // so they are kept readable for route/script matching.
              scriptName: z.string().optional(),
              createdOn: z.string().optional(),
              modifiedOn: z.string().optional(),
              routesBound: z.boolean().optional(),
              // Secret-like binding values are never exported; names/types only.
              plainTextBindings: z
                .array(z.object({ name: z.string(), type: z.string() }))
                .optional(),
            }),
          )
          .optional(),
        storageInventory: z
          .object({
            kvNamespaces: z.number().optional(),
            d1Databases: z.number().optional(),
            r2Buckets: z.number().optional(),
          })
          .optional(),
      }),
    )
    .default([]),
  zones: z
    .array(
      z.object({
        name: z.string(),
        plan: z.string().optional(),
        status: z.string().optional(),
        paused: z.boolean().optional(),
        type: z.string().optional(),
        createdOn: z.string().optional(),
        settings: zoneSettingsSchema.optional(),
        rulesets: z.array(rulesetSummarySchema).optional(),
        phaseEntrypoints: z.record(z.string(), phaseEntrypointSchema).optional(),
        botManagement: z.unknown().optional(),
        wafOverrides: z.unknown().optional(),
        ipAccessRules: z.unknown().optional(),
        pageRules: z.unknown().optional(),
        certificatePacks: z.unknown().optional(),
        sslVerification: z.unknown().optional(),
        loadBalancers: z.unknown().optional(),
        workersRoutes: z
          .array(z.object({ pattern: z.string().optional(), script: z.string().optional() }))
          .optional(),
        dnsRecordCount: z.number().optional(),
        dnsRecords: z.array(dnsRecordSchema).optional(),
        legacyRateLimits: z.unknown().optional(),
        apiGatewayDiscovery: z.unknown().optional(),
      }),
    )
    .default([]),
  collectionErrors: z.array(httpErrorSchema).default([]),
});

export type PhaseEntrypoint = z.infer<typeof phaseEntrypointSchema>;
export type Collection = z.infer<typeof collectionSchema>;
export type Zone = z.infer<typeof collectionSchema>["zones"][number];
