// Merges discovery results with OSV.dev query results into vulnerability records:
// { manifestPath, package, currentVersion, vulnIds, severity, fixedVersion, advisoryUrl }.
// TODO: implement, including "minimum version satisfying every fixed event" logic.
export function resolveVulnerabilities(discovered, osvResults) {
  throw new Error("not implemented");
}
