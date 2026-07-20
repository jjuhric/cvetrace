import test from "node:test";
import assert from "node:assert/strict";
import { queryBatch, getVulnDetails } from "../src/trace/osv-client.js";

// These tests call the live OSV.dev API (https://osv.dev, no key required) against
// a package/version with a known, long-standing CVE, so they need network access.
test("queryBatch finds the known CVE for minimist@0.0.8", async () => {
  const [result] = await queryBatch([
    { name: "minimist", ecosystem: "npm", version: "0.0.8" },
  ]);

  assert.ok(result.vulnIds.includes("GHSA-vh95-rmgr-6w4m"));
});

test("getVulnDetails returns the advisory record for a known id", async () => {
  const detail = await getVulnDetails("GHSA-vh95-rmgr-6w4m");

  assert.equal(detail.id, "GHSA-vh95-rmgr-6w4m");
  assert.ok(detail.aliases.includes("CVE-2020-7598"));
});
