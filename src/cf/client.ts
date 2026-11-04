/**
 * Cloudflare API client — GET-only by construction.
 *
 * READ-ONLY GUARANTEE: this module exports no method that can mutate anything.
 * There is no `post`, `put`, `patch`, or `delete` function in this file, and a
 * unit test (tests/read-only.test.ts) fails the build if any forbidden HTTP
 * method appears in the source tree. The outbound host is pinned to
 * api.cloudflare.com by the BASE_URL constant and verified by a second test.
 */
import { hashId } from "../redact.js";
import type { Collection } from "../schema.js";

export const BASE_URL = "https://api.cloudflare.com/client/v4";

const FORBIDDEN_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export function assertReadOnly(): void {
  // Documentation of the guarantee; enforced in tests/read-only.test.ts.
  void FORBIDDEN_METHODS;
}

const REQUEST_TIMEOUT_MS = 30_000;
const PER_PAGE = 50;
const MAX_PAGES = 100;
const USER_AGENT = "cf-account-review/0.1 (read-only collector)";

export interface ApiError {
  path: string;
  status?: number;
  error: string;
  note?: string;
}

export class CfGetClient {
  private readonly apiErrors: ApiError[] = [];
  private keepHosts: string[] = [];

  constructor(private readonly token: string) {}

  /** Only HTTP method ever used. Enforced GET-only. */
  private async getJson(
    path: string,
    params: Record<string, string> = {},
  ): Promise<unknown | null> {
    const url = new URL(BASE_URL + path);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
          "User-Agent": USER_AGENT,
        },
        signal: controller.signal,
      });
      if (!res.ok) {
        this.recordError(path, res.status, `HTTP ${res.status}`);
        return null;
      }
      const body = (await res.json()) as {
        success: boolean;
        result?: unknown;
        errors?: { message: string }[];
      };
      if (!body.success) {
        this.recordError(
          path,
          res.status,
          body.errors?.[0]?.message ?? "API reported failure",
        );
        return null;
      }
      return body.result ?? null;
    } catch (err) {
      this.recordError(
        path,
        undefined,
        err instanceof Error ? err.message : String(err),
      );
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  private recordError(
    path: string,
    status: number | undefined,
    error: string,
  ): void {
    this.apiErrors.push({
      path,
      status,
      error,
      note: status === 403 ? "likely token scope gap — skipped" : undefined,
    });
  }

  /** Paginated GET. Returns null when unreadable (scope gap or error). */
  async list(
    path: string,
    params: Record<string, string> = {},
  ): Promise<unknown[] | null> {
    const all: unknown[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const result = await this.getJson(path, {
        ...params,
        page: String(page),
        per_page: String(PER_PAGE),
      });
      if (result === null) return all.length > 0 ? all : null;
      const arr = Array.isArray(result) ? result : [result];
      all.push(...arr);
      if (arr.length < PER_PAGE) break;
    }
    return all;
  }

  /** Single-object GET. */
  async get(path: string): Promise<unknown | null> {
    return this.getJson(path);
  }

  getApiErrors(): ApiError[] {
    return [...this.apiErrors];
  }

  setKeepHosts(hosts: string[]): void {
    this.keepHosts = hosts;
  }

  getKeepHosts(): string[] {
    return [...this.keepHosts];
  }
}

export const hashAccountId = hashId;
export type { Collection };
