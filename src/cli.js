import { Command } from "commander";
import { scan } from "./index.js";

const ROOT_HELP = `
DESCRIPTION
  cvetrace walks a project directory, identifies every dependency it can
  resolve (Node via package-lock.json; Java via Maven's pom.xml, or a real
  Gradle invocation for build.gradle/.kts; Python via Pipfile.lock,
  requirements.txt, or pyproject.toml), and batch-queries OSV.dev
  (https://osv.dev, no API key required) for known CVEs affecting each one.

  It never edits your files. The report is meant to be acted on -- by you,
  or by an AI coding agent (GitHub Copilot, Claude Code, etc.) with real
  codebase access to judge and apply fixes safely.

REQUIREMENTS
  Node.js 18+ and outbound internet access to api.osv.dev, always.
  A JDK, additionally, only when scanning a Gradle project.

QUICK START
  cvetrace scan .                     Scan the current directory
  cvetrace scan . --json              Machine-readable report
  cvetrace scan . --fail-on critical  Exit non-zero for CI gating
  cvetrace scan . --exclude 'test/**' Skip a directory tree

Run 'cvetrace scan --help' for the full option reference.

SEE ALSO
  README   https://github.com/jjuhric/cvetrace
  OSV.dev  https://osv.dev
`;

const SCAN_HELP = `
EXAMPLES
  cvetrace scan .
      Scan the current directory, colorized terminal report.

  cvetrace scan ../some-other-project --json
      Scan a different directory, JSON report instead.

  cvetrace scan . --fail-on high
      Exit 1 if anything HIGH or CRITICAL is found (also accepts
      low, moderate/medium, critical).

  cvetrace scan . --exclude 'test/**' --exclude 'legacy/**'
      Skip multiple directory trees -- repeat the flag as needed.

EXIT STATUS
  0  Scan completed. This is the default even when vulnerabilities are
     found -- cvetrace reports, it doesn't judge, unless asked to via
     --fail-on.
  1  A vulnerability at or above the --fail-on threshold was found, or
     an unrecognized --fail-on value was given.

REPORT FIELDS
  Beyond the CVE id, severity, and fixed version, each finding also
  carries three triage fields meant for whoever applies the fix -- see
  "Designed for AI/human-assisted remediation" in the README for what
  they do and don't claim:

    dependencyScope  direct | transitive | unknown
    usageContext     production | development | unknown
    updateImpact     patch | minor | major | unknown

SEE ALSO
  cvetrace --help
  README  https://github.com/jjuhric/cvetrace
`;

export function run(argv) {
  const program = new Command();

  program
    .name("cvetrace")
    .description(
      "Scan a Node, Java (Maven or Gradle), or Python project directory for known CVEs in its dependencies."
    )
    .version("0.1.0")
    .addHelpText("after", ROOT_HELP);

  program
    .command("scan")
    .description("Scan a target directory for CVEs")
    .argument("<path>", "path to the project directory to scan")
    .option("--json", "output a machine-readable JSON report")
    .option(
      "--fail-on <severity>",
      "exit non-zero if a vulnerability at or above this severity is found (low, moderate/medium, high, critical)"
    )
    .option(
      "--exclude <glob>",
      "glob pattern (relative to <path>) to skip, e.g. 'test/**' -- repeatable",
      (value, previous = []) => previous.concat([value])
    )
    .addHelpText("after", SCAN_HELP)
    .action(async (path, options) => {
      await scan(path, options);
    });

  // No subcommand given: show help instead of doing nothing silently.
  if (argv.slice(2).length === 0) {
    program.outputHelp();
    return;
  }

  program.parse(argv);
}
