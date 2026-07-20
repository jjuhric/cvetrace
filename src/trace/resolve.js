import { queryBatch, getVulnDetails } from "./osv-client.js";

// OSV.dev advisories sourced from GitHub Security Advisories carry this label
// (database_specific.severity) rather than always a parseable CVSS score, so it's
// used as the canonical severity for both display and --fail-on gating.
export const SEVERITY_RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// Batch-queries OSV.dev for every discovered package and merges the results into
// vulnerability records: { manifestPath, ecosystem, name, currentVersion, id, aliases,
// summary, severity, fixedVersion, url, dependencyScope, usageContext, updateImpact }.
//
// dependencyScope ("direct"/"transitive"/"unknown") and usageContext
// ("production"/"development"/"unknown") come from the discoverer (see src/discover/*)
// and are a noise-reduction heuristic, not a reachability proof — they flag the common
// case of a vulnerable dev/test-only tool that never ships, nothing more.
//
// updateImpact ("patch"/"minor"/"major"/"unknown") is a semver-distance heuristic
// between currentVersion and fixedVersion — a signal for how likely the fix is to be
// backwards-compatible, not a guarantee. Whether an update actually breaks the codebase
// can only be confirmed by building/testing it, which is left to whoever (human or AI
// agent) applies the fix with full codebase context.
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

  return dedupeByCve(records).sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
  );
}

// OSV.dev often indexes the same underlying CVE twice for one package/version — once
// from GitHub Security Advisories (a GHSA-* id) and once from an ecosystem-specific
// source (e.g. PYSEC-* for PyPI) that aliases the same CVE. Collapse those into a
// single record so the report doesn't show the same vulnerability twice. The key is
// scoped per manifestPath so that the *same* package/version pinned in two different
// manifests (e.g. a pom.xml and a build.gradle both on log4j-core 2.14.1) still gets
// reported once per manifest, instead of the second occurrence being dropped.
function dedupeByCve(records) {
  const seen = new Set();
  const out = [];
  for (const record of records) {
    const cve = record.aliases.find((alias) => alias.startsWith("CVE-"));
    const key = `${record.manifestPath}:${record.name}@${record.currentVersion}:${cve ?? record.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(record);
  }
  return out;
}

function buildRecord(pkg, detail) {
  const fixedVersion = minimumFixedVersion(detail, pkg.ecosystem, pkg.name, pkg.version);
  return {
    manifestPath: pkg.manifestPath,
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    currentVersion: pkg.version,
    id: detail.id,
    aliases: detail.aliases ?? [],
    summary: detail.summary ?? "",
    severity: detail.database_specific?.severity ?? "UNKNOWN",
    fixedVersion,
    url:
      detail.references?.find((ref) => ref.type === "ADVISORY")?.url ??
      `https://osv.dev/vulnerability/${detail.id}`,
    dependencyScope: pkg.dependencyScope ?? "unknown",
    usageContext: pkg.usageContext ?? "unknown",
    updateImpact: classifyVersionJump(pkg.version, fixedVersion),
  };
}

// Compares the first differing dotted-numeric segment between the current and fixed
// version. Not real semver (doesn't handle pre-release tags, and Maven/Gradle
// coordinates don't always follow semver conventions to begin with) — a best-effort
// signal for triage, always to be read as "likely," never "guaranteed."
export function classifyVersionJump(current, fixed) {
  if (!fixed) return "unknown";
  const c = parseVersionParts(current);
  const f = parseVersionParts(fixed);
  if (!c || !f) return "unknown";
  if (f[0] !== c[0]) return "major";
  if (f[1] !== c[1]) return "minor";
  return "patch";
}

// Lenient dotted-numeric parser: captures 1-3 numeric segments and stops at the first
// non-numeric character (so "2.0-beta9" parses as [2, 0, 0], enough for interval-boundary
// comparisons even though it discards the pre-release tag).
function parseVersionParts(version) {
  const match = String(version).match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1] ?? 0), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

// A single advisory can list multiple *disjoint* affected-version intervals for the
// same package — e.g. log4j-core has separate patched versions for its 2.0–2.3.x,
// 2.4–2.11.x, and 2.13–2.14.x release lines. Blending "fixed" versions across all of
// them (the previous, buggy approach) can suggest a version from a branch the current
// version was never even on — e.g. recommending log4j-core 2.3.1 (an old, still-
// vulnerable-to-other-CVEs branch) as the "fix" for 2.14.1, when the real fix on that
// line is 2.15.0. This only considers the interval that actually contains currentVersion.
export function minimumFixedVersion(detail, ecosystem, name, currentVersion) {
  const candidates = [];
  for (const affected of detail.affected ?? []) {
    if (affected.package?.ecosystem !== ecosystem || affected.package?.name !== name) {
      continue;
    }
    for (const range of affected.ranges ?? []) {
      const fixed = fixedVersionIfApplicable(range.events ?? [], currentVersion);
      if (fixed) candidates.push(fixed);
    }
  }
  if (candidates.length === 0) return null;
  return candidates.sort(compareVersions)[0];
}

// Walks one range's ordered events, pairing each "introduced" with the next "fixed"/
// "last_affected" to form an interval, and returns the "fixed" version of whichever
// interval currentVersion actually falls in (or null if none does, or if the interval
// it's in has no known fix yet — "last_affected" with no "fixed" event).
function fixedVersionIfApplicable(events, currentVersion) {
  let introduced = null;
  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced;
    } else if (event.fixed !== undefined) {
      if (introduced !== null && isVersionInInterval(currentVersion, introduced, event.fixed)) {
        return event.fixed;
      }
      introduced = null;
    } else if (event.last_affected !== undefined) {
      introduced = null;
    }
  }
  return null;
}

function isVersionInInterval(version, introducedInclusive, fixedExclusive) {
  const v = parseVersionParts(version);
  const lo = parseVersionParts(introducedInclusive);
  const hi = parseVersionParts(fixedExclusive);
  if (!v || !lo || !hi) return false;
  return compareVersionParts(v, lo) >= 0 && compareVersionParts(v, hi) < 0;
}

function compareVersionParts(a, b) {
  for (let i = 0; i < 3; i++) {
    const diff = (a[i] || 0) - (b[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// Minimal numeric-segment comparator, sufficient for the dotted version numbers
// npm/PyPI/Maven advisories use in "fixed" events.
function compareVersions(a, b) {
  return compareVersionParts(parseVersionParts(a) ?? [0, 0, 0], parseVersionParts(b) ?? [0, 0, 0]);
}
