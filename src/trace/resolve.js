import { queryBatch, getVulnDetails } from "./osv-client.js";

// OSV.dev advisories sourced from GitHub Security Advisories carry this label
// (database_specific.severity) rather than always a parseable CVSS score, so it's
// used as the canonical severity for both display and --fail-on gating.
export const SEVERITY_RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// Batch-queries OSV.dev for every discovered package and merges the results into
// vulnerability records: { manifestPath, ecosystem, name, currentVersion, id, aliases,
// summary, severity, fixedVersion, url }.
export async function resolveVulnerabilities(discovered) {
  const batchResults = await queryBatch(discovered);

  const idsNeeded = new Set();
  for (const result of batchResults) {
    for (const id of result.vulnIds) idsNeeded.add(id);
  }

  const detailsById = new Map(
    await Promise.all(
      [...idsNeeded].map(async (id) => [id, await getVulnDetails(id)])
    )
  );

  const records = [];
  for (const result of batchResults) {
    for (const id of result.vulnIds) {
      records.push(buildRecord(result.package, detailsById.get(id)));
    }
  }

  return records.sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
  );
}

function buildRecord(pkg, detail) {
  return {
    manifestPath: pkg.manifestPath,
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    currentVersion: pkg.version,
    id: detail.id,
    aliases: detail.aliases ?? [],
    summary: detail.summary ?? "",
    severity: detail.database_specific?.severity ?? "UNKNOWN",
    fixedVersion: minimumFixedVersion(detail, pkg.ecosystem, pkg.name),
    url:
      detail.references?.find((ref) => ref.type === "ADVISORY")?.url ??
      `https://osv.dev/vulnerability/${detail.id}`,
  };
}

function minimumFixedVersion(detail, ecosystem, name) {
  const fixedVersions = [];
  for (const affected of detail.affected ?? []) {
    if (affected.package?.ecosystem !== ecosystem || affected.package?.name !== name) {
      continue;
    }
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixedVersions.push(event.fixed);
      }
    }
  }
  if (fixedVersions.length === 0) return null;
  return fixedVersions.sort(compareVersions)[0];
}

// Minimal numeric-segment comparator, sufficient for the dotted version numbers
// npm/PyPI/Maven advisories use in "fixed" events.
function compareVersions(a, b) {
  const partsA = a.split(/[.\-+]/).map(Number);
  const partsB = b.split(/[.\-+]/).map(Number);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const diff = (partsA[i] || 0) - (partsB[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
