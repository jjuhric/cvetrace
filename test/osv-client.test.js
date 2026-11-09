import test from "node:test";
import assert from "node:assert/strict";
import { queryBatch, getVulnDetails, OSV_BATCH_LIMIT } from "../src/trace/osv-client.js";

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

// A fake OSV.dev that, like the real one, refuses more than 1000 queries in one
// request: 2,500 packages must go out as three requests (1000, 1000, 500) and come
// back as 2,500 results in the original order. Found 2026-11-09: a project with
// several lockfiles failed with "OSV.dev querybatch failed: 400 Bad Request".
test("queryBatch splits big projects into chunks OSV.dev accepts", async (t) => {
  const sizes = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    const { queries } = JSON.parse(init.body);
    if (queries.length > OSV_BATCH_LIMIT) {
      return { ok: false, status: 400, statusText: "Bad Request" };
    }
    sizes.push(queries.length);
    return { ok: true, json: async () => ({ results: queries.map((q) => ({ vulns: [{ id: `ID-${q.package.name}` }] })) }) };
  });
  const packages = Array.from({ length: 2500 }, (_, i) => ({ name: `pkg${i}`, ecosystem: "npm", version: "1.0.0" }));
  const results = await queryBatch(packages);
  assert.deepEqual(sizes, [1000, 1000, 500]);
  assert.equal(results.length, 2500);
  assert.deepEqual([results[0].vulnIds[0], results[1999].vulnIds[0], results[2499].vulnIds[0]], ["ID-pkg0", "ID-pkg1999", "ID-pkg2499"]);
  assert.equal(results[2499].package.name, "pkg2499");
});
