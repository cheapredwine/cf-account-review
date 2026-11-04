import { describe, expect, it } from "vitest";
import { maskIdsInPath, renderMarkdown } from "../src/analyzer/report.js";

describe("maskIdsInPath", () => {
  it("masks the middle of 32-hex IDs, keeping first 8 and last 4", () => {
    const zoneId = "3979b75ae8373fa279be6edfbd99f205";
    expect(maskIdsInPath(`/zones/${zoneId}/settings`)).toBe(
      `/zones/3979b75a****f205/settings`,
    );
  });

  it("leaves non-ID paths and short hex strings untouched", () => {
    expect(maskIdsInPath("/user/tokens")).toBe("/user/tokens");
    expect(maskIdsInPath("/zones/abc123/settings")).toBe(
      "/zones/abc123/settings",
    );
  });

  it("masks multiple IDs in one path", () => {
    const id = "a".repeat(32);
    expect(maskIdsInPath(`/accounts/${id}/zones/${id}`)).toBe(
      `/accounts/aaaaaaaa****aaaa/zones/aaaaaaaa****aaaa`,
    );
  });
});

describe("renderMarkdown collection-errors table", () => {
  it("masks 32-hex IDs appearing in error paths", () => {
    const zoneId = "3979b75ae8373fa279be6edfbd99f205";
    const collection = {
      schemaVersion: "1.0",
      collectedAt: "2026-11-01T00:00:00Z",
      collector: "api",
      collectorVersion: "0.1.0",
      tokenStatus: "active",
      zones: [],
      accounts: [],
      collectionErrors: [
        { path: `/zones/${zoneId}/settings`, status: 403, error: "HTTP 403" },
      ],
    } as never;
    const md = renderMarkdown(collection, []);
    expect(md).toContain("`/zones/3979b75a****f205/settings`");
    expect(md).not.toContain(zoneId);
  });
});
