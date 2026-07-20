import { discover } from "./discover/index.js";
import { resolveVulnerabilities, SEVERITY_RANK } from "./trace/resolve.js";
import { printTerminalReport } from "./report/terminal.js";
import { buildJsonReport } from "./report/json.js";

// Orchestrates the discover -> trace -> report pipeline.
export async function scan(targetPath, options = {}) {
  const discovered = await discover(targetPath, { excludes: options.exclude });
  const vulnerabilities = await resolveVulnerabilities(discovered);

  if (options.json) {
    console.log(JSON.stringify(buildJsonReport(vulnerabilities), null, 2));
  } else {
    printTerminalReport(vulnerabilities);
  }

  if (options.failOn && meetsThreshold(vulnerabilities, options.failOn)) {
    process.exitCode = 1;
  }

  return vulnerabilities;
}

function meetsThreshold(vulnerabilities, failOn) {
  const threshold = SEVERITY_RANK[failOn.toUpperCase()];
  if (!threshold) {
    throw new Error(`Unknown --fail-on severity: ${failOn}`);
  }
  return vulnerabilities.some((v) => (SEVERITY_RANK[v.severity] ?? 0) >= threshold);
}
