import { queryBatch, getVulnDetails } from "./osv-client.js";

// OSV.dev advisories sourced from GitHub Security Advisories carry this label
// (database_specific.severity) rather than always a parseable CVSS score, so it's
// used as the canonical severity for both display and --fail-on gating.
export const SEVERITY_RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// Batch-queries OSV.dev for every discovered package and merges the results into
// vulnerability records: { manifestPath, ecosystem, name, currentVersion, id, aliases,
// summary, advisoryDetails, severity, fixedVersion, recommendedVersion, url,
// dependencyScope, usageContext, updateImpact, remediationTier }. src/index.js layers
// on further fields (dependencyPath, overrideSnippet, codeReference, priorityScore/
// priorityLabel) after this step -- see src/trace/priority.js for why those run last.
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
//
// recommendedVersion is the single highest fixedVersion across every CVE known for that
// exact package instance -- "upgrade to X, clears everything" instead of N separate
// per-CVE targets. advisoryDetails is OSV's full freeform text, which often has a
// mitigation/workaround section beyond "upgrade" (see resolve.js's buildRecord).
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

  const withRecommendations = addRecommendedVersions(dedupeByCve(records));
  return withRecommendations.sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
  );
}

// Aggregates each package instance's (manifestPath + name) individual CVE fixes into
// one recommendedVersion: the highest fixedVersion among them, since upgrading to it
// satisfies every lower one too. Lets a human/AI jump straight to "upgrade to X, clears
// all N known issues" instead of reconciling N separate per-CVE fix versions (log4j-core
// alone has 7 in the test fixture, each with its own nearest fix). A record whose own
// fixedVersion is null (no fix published yet for that specific CVE) is NOT resolved just
// by reaching recommendedVersion -- see advisoryDetails for mitigation guidance then.
export function addRecommendedVersions(records) {
  const maxFixedByPackage = new Map();
  for (const record of records) {
    if (!record.fixedVersion) continue;
    const key = `${record.manifestPath}:${record.name}`;
    const current = maxFixedByPackage.get(key);
    if (!current || compareVersions(record.fixedVersion, current) > 0) {
      maxFixedByPackage.set(key, record.fixedVersion);
    }
  }

  return records.map((record) => ({
    ...record,
    recommendedVersion: maxFixedByPackage.get(`${record.manifestPath}:${record.name}`) ?? null,
  }));
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
    // OSV.dev's longer freeform advisory text -- often includes a "Remediation Advice"
    // / mitigation section beyond just "upgrade to X" (e.g. Log4Shell's config-flag
    // workaround for anyone who can't upgrade immediately). null when OSV has none.
    advisoryDetails: detail.details ?? null,
    severity: detail.database_specific?.severity ?? "UNKNOWN",
    fixedVersion,
    url:
      detail.references?.find((ref) => ref.type === "ADVISORY")?.url ??
      `https://osv.dev/vulnerability/${detail.id}`,
    dependencyScope: pkg.dependencyScope ?? "unknown",
    usageContext: pkg.usageContext ?? "unknown",
    updateImpact: classifyVersionJump(pkg.version, fixedVersion),
    remediationTier: classifyRemediationTier(fixedVersion, classifyVersionJump(pkg.version, fixedVersion)),
  };
}

// Collapses fixedVersion + updateImpact into one decision an agent or human can branch
// on directly, instead of everyone re-deriving the same three-way call from those two
// fields independently (and potentially disagreeing on edge cases):
//   "safe-to-update"   patch/minor bump, likely backwards-compatible -- apply it.
//   "needs-approval"   major bump, likely to need code changes -- propose a plan, wait
//                      for a human to approve before touching anything.
//   "no-fix-available" no version resolves this specific CVE yet -- see advisoryDetails
//                      for a workaround/mitigation instead of a version bump.
//   "unknown-impact"   a fix exists but current/fixed versions weren't both parseable as
//                      dotted-numeric, so the size of the jump can't be classified --
//                      treated like needs-approval: safety can't be confirmed either way.
// Still a heuristic layered on other heuristics, not a safety guarantee -- see
// updateImpact's own caveat above.
export function classifyRemediationTier(fixedVersion, updateImpact) {
  if (!fixedVersion) return "no-fix-available";
  if (updateImpact === "patch" || updateImpact === "minor") return "safe-to-update";
  if (updateImpact === "major") return "needs-approval";
  return "unknown-impact";
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
