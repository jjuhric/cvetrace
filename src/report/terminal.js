const RESET = "\x1b[0m";
const color = {
  red: (s) => `\x1b[31m${s}${RESET}`,
  yellow: (s) => `\x1b[33m${s}${RESET}`,
  gray: (s) => `\x1b[90m${s}${RESET}`,
  cyan: (s) => `\x1b[36m${s}${RESET}`,
  bold: (s) => `\x1b[1m${s}${RESET}`,
};

const SEVERITY_COLOR = {
  CRITICAL: color.red,
  HIGH: color.red,
  MODERATE: color.yellow,
  MEDIUM: color.yellow,
  LOW: color.gray,
  UNKNOWN: color.gray,
};

// Colorized, human-readable report grouped by manifest file, sorted by severity descending
// (vulnerabilities are expected to already be sorted by src/trace/resolve.js).
export function printTerminalReport(vulnerabilities) {
  if (vulnerabilities.length === 0) {
    console.log(color.gray("No known vulnerabilities found."));
    return;
  }

  for (const [manifestPath, vulns] of groupByManifest(vulnerabilities)) {
    console.log(color.bold(manifestPath));
    for (const v of vulns) {
      const paint = SEVERITY_COLOR[v.severity] ?? color.gray;
      const label = v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id;
      console.log(
        `  ${color.red(label)} ${v.name}@${v.currentVersion} ` +
          `[${paint(v.severity)}] -> fix: ${v.fixedVersion ?? "unknown"}`
      );
      console.log(`    ${color.gray(describeContext(v))}`);
      if (v.summary) console.log(`    ${color.gray(v.summary)}`);
      console.log(`    ${color.cyan(v.url)}`);
    }
    console.log("");
  }

  const noun = vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities";
  console.log(color.bold(`${vulnerabilities.length} ${noun} found.`));
}

const IMPACT_LABEL = {
  patch: "patch bump, likely safe",
  minor: "minor bump, likely safe",
  major: "major bump — review before applying",
  unknown: "fix version unknown",
};

// A one-line triage summary: dependency scope/usage (a noise-reduction heuristic, not
// proof the vulnerable code path is reachable) and the size of the version jump to fix
// it (a semver-distance heuristic, not proof the update is non-breaking). See
// src/trace/resolve.js for what these fields do and don't claim.
function describeContext(v) {
  const parts = [v.dependencyScope, v.usageContext].filter((p) => p && p !== "unknown");
  parts.push(IMPACT_LABEL[v.updateImpact] ?? IMPACT_LABEL.unknown);
  return parts.join(" · ");
}

function groupByManifest(vulnerabilities) {
  const map = new Map();
  for (const v of vulnerabilities) {
    if (!map.has(v.manifestPath)) map.set(v.manifestPath, []);
    map.get(v.manifestPath).push(v);
  }
  return map;
}
