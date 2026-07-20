const OSV_API_BASE = "https://api.osv.dev/v1";

// Batch-queries OSV.dev (https://osv.dev, no API key required) for each
// { ecosystem, name, version } package and returns the matching vuln ids per package,
// in the same order as the input.
export async function queryBatch(packages) {
  if (packages.length === 0) return [];

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
