/**
 * Unit tests for Couch DB / doc name classification helpers.
 */
import { describe, expect, it } from "vitest";
import { isDatabaseName, isDocumentId, isSystemDatabase } from "../../src/acl/names.js";

describe("isSystemDatabase", () => {
  it("flags Couch system DBs only", () => {
    expect(isSystemDatabase("_users")).toBe(true);
    expect(isSystemDatabase("_replicator")).toBe(true);
    expect(isSystemDatabase("_global_changes")).toBe(true);
    expect(isSystemDatabase("acldemo")).toBe(false);
  });
});

describe("isDatabaseName", () => {
  it("allows normal and known system DBs", () => {
    expect(isDatabaseName("acldemo")).toBe(true);
    expect(isDatabaseName("_users")).toBe(true);
    expect(isDatabaseName("_replicator")).toBe(true);
  });

  it("rejects server-level underscore endpoints", () => {
    expect(isDatabaseName("_membership")).toBe(false);
    expect(isDatabaseName("_node")).toBe(false);
  });
});

describe("isDocumentId", () => {
  it("allows normal and design/local ids", () => {
    expect(isDocumentId("msg-1")).toBe(true);
    expect(isDocumentId("_design/acl")).toBe(true);
    expect(isDocumentId("_local/checkpoint")).toBe(true);
  });

  it("rejects reserved underscore endpoints", () => {
    expect(isDocumentId("_purged_infos_limit")).toBe(false);
    expect(isDocumentId("_all_docs")).toBe(false);
  });
});
