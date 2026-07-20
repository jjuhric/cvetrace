import { discover } from "./discover/index.js";
import { resolveVulnerabilities, SEVERITY_RANK } from "./trace/resolve.js";
import { detectCodeReferences } from "./trace/usage.js";
import { generateOverrideSnippet } from "./trace/override.js";
import { computePriority } from "./trace/priority.js";
import { loadIgnoreFile, applyIgnoreRules } from "./trace/ignore.js";
import { printTerminalReport } from "./report/terminal.js";
import { buildJsonReport } from "./report/json.js";

// Orchestrates the full pipeline: discover -> trace (OSV.dev + recommendedVersion/
// advisoryDetails) -> usage detection (codeReference) -> override snippets -> priority
// scoring -> ignore-list filtering -> report. Usage detection and priority scoring are
// deliberately sequenced late: priority needs codeReference, and codeReference needs
// every discovered finding already resolved.
export async function scan(targetPath, options = {}) {
  const discovered = await discover(targetPath, { excludes: options.exclude });
  const resolved = await resolveVulnerabilities(discovered);
  const withUsage = await detectCodeReferences(targetPath, resolved, options.exclude);

  const enriched = withUsage
    .map((finding) => ({ ...finding, overrideSnippet: generateOverrideSnippet(finding) }))
    .map((finding) => ({ ...finding, ...computePriority(finding) }))
    .sort((a, b) => b.priorityScore - a.priorityScore);

  const ignoreFileRules = await loadIgnoreFile(targetPath);
  const { kept, ignored } = applyIgnoreRules(enriched, ignoreFileRules, options.ignore);

  if (options.json) {
    console.log(JSON.stringify(buildJsonReport(kept, ignored), null, 2));
  } else {
    printTerminalReport(kept, ignored);
  }

  if (options.failOn && meetsThreshold(kept, options.failOn)) {
    process.exitCode = 1;
  }

  return kept;
}

function meetsThreshold(vulnerabilities, failOn) {
  const threshold = SEVERITY_RANK[failOn.toUpperCase()];
  if (!threshold) {
    throw new Error(`Unknown --fail-on severity: ${failOn}`);
  }
  return vulnerabilities.some((v) => (SEVERITY_RANK[v.severity] ?? 0) >= threshold);
}
