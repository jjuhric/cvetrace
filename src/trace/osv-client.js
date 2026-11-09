const OSV_API_BASE = "https://api.osv.dev/v1";

// Batch-queries OSV.dev (https://osv.dev, no API key required) for each
// { ecosystem, name, version } package and returns the matching vuln ids per package,
// in the same order as the input.
// OSV.dev's documented maximum number of queries in one /querybatch request. A
// bigger request is refused with "400 Bad Request", so a project with more
// dependencies than this (several lockfiles, a monorepo) is sent in chunks of at
// most this many and the answers are joined back in the original order.
export const OSV_BATCH_LIMIT = 1000;

export async function queryBatch(packages) {
  if (packages.length === 0) return [];

  const out = [];
  for (let start = 0; start < packages.length; start += OSV_BATCH_LIMIT) {
    const chunk = packages.slice(start, start + OSV_BATCH_LIMIT);
    const answers = await queryOneBatch(chunk);
    if (answers.length !== chunk.length) {
      throw new Error(`OSV.dev querybatch returned ${answers.length} results for ${chunk.length} queries`);
    }
    out.push(...answers);
  }
  return out;
}

// One /querybatch request (at most OSV_BATCH_LIMIT queries).
async function queryOneBatch(packages) {
  const res = await fetch(`${OSV_API_BASE}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      queries: packages.map((pkg) => ({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        version: pkg.version,
      })),
    }),
  });
  if (!res.ok) {
    throw new Error(`OSV.dev querybatch failed: ${res.status} ${res.statusText}`);
  }

  const { results } = await res.json();
  return results.map((result, i) => ({
    package: packages[i],
    vulnIds: (result.vulns ?? []).map((v) => v.id),
  }));
}

// Fetches the full advisory record (summary, severity, affected ranges) for a vuln id.
export async function getVulnDetails(id) {
  const res = await fetch(`${OSV_API_BASE}/vulns/${id}`);
  if (!res.ok) {
    throw new Error(`OSV.dev vuln lookup failed for ${id}: ${res.status} ${res.statusText}`);
  }
  return res.json();
}
