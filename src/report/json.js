// Machine-readable JSON report for CI consumption.
export function buildJsonReport(vulnerabilities) {
  return {
    generatedAt: new Date().toISOString(),
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilities,
  };
}
