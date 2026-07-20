import { Command } from "commander";
import { scan } from "./index.js";

const ROOT_HELP = `
DESCRIPTION
  cvetrace walks a project directory, identifies every dependency it can
  resolve (Node via package-lock.json; Java via Maven's pom.xml, or a real
  Gradle invocation for build.gradle/.kts; Python via Pipfile.lock,
  requirements.txt, or pyproject.toml), and batch-queries OSV.dev
  (https://osv.dev, no API key required) for known CVEs affecting each one.

  Every finding is enriched with triage signals -- is it actually reachable
  from production code, is it even imported anywhere, how big a version jump
  is the fix, is there a faster override -- and rolled into one priority
  score, so a pile of findings can be worked top-down instead of one by one.

  It never edits your files. Each finding's remediationTier field says what
  to do about it -- apply it directly, propose a plan and wait for
  approval, or fall back to a mitigation -- so the report is meant to be
  acted on: by you, or by an AI coding agent (GitHub Copilot, Claude Code,
  Gemini, etc.) with real codebase access to judge and apply fixes safely.
  See "Recommended agent workflow" in the README for the intended loop.

REQUIREMENTS
  Node.js 18+ and outbound internet access to api.osv.dev, always.
  A JDK, additionally, only when scanning a Gradle project.

QUICK START
  cvetrace scan .                     Scan the current directory
  cvetrace scan . --json              Machine-readable report
  cvetrace scan . --fail-on critical  Exit non-zero for CI gating
  cvetrace scan . --exclude 'test/**' Skip a directory tree
  cvetrace scan . --ignore CVE-2021-1 Dismiss a reviewed/accepted finding

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

  cvetrace scan . --ignore CVE-2021-1234 --ignore GHSA-xxxx-xxxx-xxxx
      Dismiss specific findings for this run -- repeatable, same as
      --exclude. For a permanent dismissal, use a .cvetraceignore file
      in the scanned directory instead (see IGNORING FINDINGS below).

EXIT STATUS
  0  Scan completed. This is the default even when vulnerabilities are
     found -- cvetrace reports, it doesn't judge, unless asked to via
     --fail-on. Ignored findings never count toward --fail-on.
  1  A vulnerability at or above the --fail-on threshold was found, or
     an unrecognized --fail-on value was given.

REPORT FIELDS
  Every finding carries triage fields beyond the CVE id, severity, and fix
  version -- see "Designed for AI/human-assisted remediation" in the README
  for exactly what each does and doesn't claim (none of these are proof of
  anything; they're heuristics for working through a pile of findings):

    remediationTier                safe-to-update | needs-approval |
                                    no-fix-available | unknown-impact -- the
                                    field to branch on for "what do I do
                                    about this". See "Recommended agent
                                    workflow" in the README for the intended
                                    loop around it.
    priorityScore / priorityLabel  cvetrace's own P1-P4 triage ranking,
                                    combining everything below. Deliberately
                                    worded differently from severity: a
                                    CRITICAL CVE in unused dev-only code can
                                    still land at P4.
    dependencyScope                direct | transitive | unknown
    usageContext                   production | development | unknown
    dependencyPath                 for transitive findings (Node/Gradle
                                    only): the chain from a direct
                                    dependency down to this package
    codeReference                  found | not-found | unknown -- is the
                                    package actually imported/required
                                    anywhere in your source, not just
                                    declared in a manifest
    updateImpact                   patch | minor | major | unknown
    recommendedVersion             the single version that clears every
                                    known CVE for this exact package, not
                                    just this one
    overrideSnippet                for transitive findings: the exact
                                    npm/Gradle/Maven snippet to force the
                                    patched version without waiting on the
                                    parent dependency (JSON output only)
    advisoryDetails                OSV.dev's full advisory text, which
                                    often has mitigation/workaround
                                    guidance beyond "upgrade" (JSON output
                                    only)

IGNORING FINDINGS
  Two ways to dismiss a reviewed-and-accepted finding so it stops showing
  up (mirrors Nexus IQ/Dependabot's "dismiss"):

    --ignore <id>          one-off, this run only
    .cvetraceignore file    permanent, in the directory being scanned:
                            one CVE/GHSA/etc. id per line, blank lines and
                            full-line "#" comments ignored, an optional
                            trailing "# reason" captured for the record.

  Ignored findings are dropped from the main report and don't count toward
  --fail-on, but are never silently discarded -- run with --json to see
  the full "ignored" array (id, reason, and which mechanism matched).

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
    .option(
      "--ignore <id>",
      "dismiss a specific CVE/GHSA/etc. id for this run -- repeatable (see IGNORING FINDINGS in --help for the permanent .cvetraceignore option)",
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
