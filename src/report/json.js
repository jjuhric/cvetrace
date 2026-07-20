// Machine-readable JSON report for CI/AI consumption. `vulnerabilities` is already
// sorted by priorityScore descending (src/index.js). `ignored` carries the full
// findings that matched a .cvetraceignore/--ignore rule, for audit-trail purposes --
// they're excluded from `vulnerabilities` and from --fail-on, but never silently
// dropped without a trace.
export function buildJsonReport(vulnerabilities, ignored = []) {
  return {
    generatedAt: new Date().toISOString(),
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilities,
    ignoredCount: ignored.length,
    ignored,
  };
}
