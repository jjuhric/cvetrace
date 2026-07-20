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

const PRIORITY_COLOR = {
  P1: color.red,
  P2: color.red,
  P3: color.yellow,
  P4: color.gray,
};

// Colorized, human-readable report, flat and sorted by priorityScore descending
// (already sorted by src/index.js) -- priority mixes findings across manifests
// deliberately, so it's no longer grouped by manifest file; each line names its own
// manifest instead. This is meant to be worked top-down.
export function printTerminalReport(vulnerabilities, ignored = []) {
  if (vulnerabilities.length === 0) {
    console.log(color.gray("No known vulnerabilities found."));
    printIgnoredFooter(ignored);
    return;
  }

  for (const v of vulnerabilities) {
    const paint = SEVERITY_COLOR[v.severity] ?? color.gray;
    const priorityPaint = PRIORITY_COLOR[v.priorityLabel] ?? color.gray;
    const label = v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id;
    const fixArrow = v.fixedVersion ? ` -> ${v.fixedVersion}` : "";

    console.log(
      `${priorityPaint(`[${v.priorityLabel}]`)} ${color.red(label)} [${paint(v.severity)}] ` +
        `${v.name}@${v.currentVersion}${fixArrow}`
    );
    console.log(`  ${color.gray(v.manifestPath)}`);
    console.log(`  ${color.gray(describeContext(v))}`);
    if (v.recommendedVersion && v.recommendedVersion !== v.fixedVersion) {
      console.log(
        `  ${color.gray(`recommended target: ${v.recommendedVersion} (clears every known issue for this package)`)}`
      );
    }
    if (v.overrideSnippet) {
      console.log(
        `  ${color.gray(`override available (edit ${v.overrideSnippet.file}) without waiting on the parent -- see --json for the exact snippet`)}`
      );
    }
    if (v.summary) console.log(`  ${color.gray(v.summary)}`);
    console.log(`  ${color.cyan(v.url)}`);
    console.log("");
  }

  const noun = vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities";
  console.log(color.bold(`${vulnerabilities.length} ${noun} found.`));
  printIgnoredFooter(ignored);
}

function printIgnoredFooter(ignored) {
  if (ignored.length === 0) return;
  const noun = ignored.length === 1 ? "finding" : "findings";
  console.log(
    color.gray(`${ignored.length} ${noun} suppressed via .cvetraceignore/--ignore — see --json for details.`)
  );
}

const IMPACT_LABEL = {
  patch: "patch bump, likely safe",
  minor: "minor bump, likely safe",
  major: "major bump — review before applying",
  unknown: "fix version unknown",
};

const CODE_REF_LABEL = {
  found: "used in code",
  "not-found": "no code reference found",
  unknown: "code usage unknown",
};

// A one-line triage summary combining every heuristic field. None of these are proof of
// anything -- dependencyScope/usageContext/codeReference are noise-reduction signals,
// not a reachability guarantee; updateImpact is a semver-distance signal, not a safety
// guarantee. See the README's "Designed for AI/human-assisted remediation" section and
// src/trace/resolve.js / src/trace/usage.js for exactly what each does and doesn't claim.
function describeContext(v) {
  const parts = [];

  if (v.dependencyScope === "transitive" && v.dependencyPath?.length > 1) {
    parts.push(`transitive (via ${v.dependencyPath.slice(0, -1).join(" > ")})`);
  } else if (v.dependencyScope && v.dependencyScope !== "unknown") {
    parts.push(v.dependencyScope);
  }

  if (v.usageContext && v.usageContext !== "unknown") parts.push(v.usageContext);
  parts.push(CODE_REF_LABEL[v.codeReference] ?? CODE_REF_LABEL.unknown);
  parts.push(IMPACT_LABEL[v.updateImpact] ?? IMPACT_LABEL.unknown);

  return parts.join(" · ");
}
