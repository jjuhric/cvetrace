# cvetrace

A cross-platform, terminal-based CVE **discovery, trace, and solutions** tool.
Point it at any project directory — Node, Java (Maven or Gradle), or Python — and it
scans the dependency manifests for known vulnerabilities, using the free
[OSV.dev](https://osv.dev) vulnerability database (no API key required).

> Want to run this with nothing installed at all, not even Node? There's an in-progress
> Go port, [cvetrace-go](https://github.com/jjuhric/cvetrace-go), that compiles to a
> single static binary with no runtime dependency — currently an early, Node-ecosystem-
> only slice, with this project as the feature reference for what to port next.

## Requirements

| Scenario | What you need |
|---|---|
| Any scan | [Node.js](https://nodejs.org) 18+ on the machine running cvetrace, and outbound internet access to `api.osv.dev` (the vulnerability lookup) |
| Scanning a **Gradle** project specifically | Also a JDK on that same machine — cvetrace resolves Gradle dependencies by actually invoking the target project's own Gradle wrapper (see [Ecosystems supported](#ecosystems-supported)), which needs Java to run. Effectively: any machine that can already build the target project. First run also needs internet access to fetch the Gradle distribution (if not already cached) and whatever repositories the build declares (e.g. Maven Central) |

No other setup is required — nothing to install, configure, or authenticate beyond
having Node (and, for Gradle projects, Java) already on the machine. This is identical
on Windows, macOS, and Linux.

## Usage

```sh
npx github:jjuhric/cvetrace scan <path-to-project> [options]
```

`npx` downloads and runs cvetrace fresh each time — no install step, but a small
per-invocation delay. For repeated use, install it once instead:

```sh
npm install -g github:jjuhric/cvetrace
cvetrace scan <path-to-project> [options]
```

- `<path-to-project>` — directory to scan. cvetrace walks it, detects manifests
  (`package.json`/`package-lock.json`, `pom.xml`, `build.gradle`/`.kts`,
  `requirements.txt`/`pyproject.toml`/`Pipfile.lock`), and reports known CVEs against
  each resolved dependency version.
- `--json` — emit a machine-readable JSON report instead of the terminal report.
- `--fail-on <severity>` — exit non-zero if a vulnerability at or above the given
  severity (`low`, `moderate`/`medium`, `high`, `critical`) is found — useful for CI
  gating. Without it, cvetrace always exits `0`, since it's a discovery tool first: it
  reports what it finds ("No known vulnerabilities found." if nothing) without judging
  whether that should block anything, unless you tell it to. Ignored findings (see
  below) never count toward this.
- `--exclude <glob>` — skip any directory whose path relative to `<path-to-project>`
  matches the glob (`*` within one path segment, `**` across segments, `?` for a single
  character). Repeatable: pass `--exclude` more than once to skip several directories.
  For example, `cvetrace`'s own repo has `test/fixtures/*-fixture-project` directories
  that deliberately pin vulnerable packages for its test suite — scanning the repo
  itself with `--exclude 'test/**'` skips them.
- `--ignore <id>` — dismiss a specific CVE/GHSA/etc. id for this run. Repeatable. For a
  permanent dismissal, use a `.cvetraceignore` file instead (see
  [Ignoring findings](#ignoring-findings)).

Run `cvetrace --help` or `cvetrace scan --help` for the full reference.

## How it works

1. **Discover** — walk the target directory, skip build/dependency dirs
   (`node_modules`, `.git`, `venv`, `target`, `build`, ...), and extract every
   declared/resolved `{ecosystem, name, version}` dependency, including — for Node and
   Gradle, where cvetrace has a real resolved dependency graph — the full chain from a
   direct dependency down to a transitive one.
2. **Trace** — batch-query [OSV.dev](https://osv.dev) for each dependency, link any
   matching vulnerabilities (CVE/GHSA ids, severity, affected ranges, full advisory
   text) back to the manifest file that introduced them, and compute one
   `recommendedVersion` per package that clears every known CVE against it, not just
   one at a time.
3. **Solutions** — beyond "upgrade to X," check whether the vulnerable package is
   actually imported anywhere in your source, generate the exact override snippet to
   force a transitive dependency's version without waiting on its parent, and roll
   everything into one priority score so a pile of findings can be worked top-down.

## Designed for AI/human-assisted remediation

cvetrace never edits your files. Instead, every finding in the report carries fields
meant to help a human — or an AI coding agent (GitHub Copilot, Claude Code, etc.)
working through the report — triage and fix what's real and safe, without cvetrace
itself guessing wrong about your codebase. **Read all of these as triage aids, not
verdicts** — see the caveats under each one.

| Field | Values | What it actually tells you |
|---|---|---|
| `remediationTier` | `safe-to-update` / `needs-approval` / `no-fix-available` / `unknown-impact` | The single field to branch on for "what do I do about this": `safe-to-update` means apply `recommendedVersion`/`overrideSnippet` directly; `needs-approval` means propose a plan and wait for a human before touching anything (a major/breaking bump); `no-fix-available` means read `advisoryDetails` for a workaround instead of a version bump; `unknown-impact` means cvetrace couldn't confirm the jump size, so treat it like `needs-approval`. See [Recommended agent workflow](#recommended-agent-workflow). |
| `priorityScore` / `priorityLabel` | number / `P1`–`P4` | cvetrace's own triage ranking, combining every field below into one sortable number. The report is sorted by this. Deliberately worded differently from `severity` — a CRITICAL CVE in unused dev-only code can land at `P4`; that's not a contradiction, it's the point. This is cvetrace's own synthesis, not an authoritative risk score. |
| `dependencyScope` | `direct` / `transitive` / `unknown` | Whether the vulnerable package is declared directly in your manifest, or pulled in by something else you depend on. |
| `dependencyPath` | array or `null` | For transitive findings **in Node or Gradle** (the only ecosystems cvetrace resolves a real dependency graph for): the chain from a direct dependency down to this package, e.g. `["webpack", "loader-utils", "vulnerable-pkg"]`. `null` for direct dependencies, and always `null` for Maven/Python since those aren't resolved transitively at all. |
| `usageContext` | `production` / `development` / `unknown` | Whether the package is reachable from your production dependencies, or only from dev/test/build tooling (`devDependencies`, Maven `test` scope, Gradle `testImplementation`, etc.) that never ships. |
| `codeReference` | `found` / `not-found` / `unknown` | Whether the package is actually imported/required anywhere in your own source files, not just declared in a manifest. **This is a usage signal, not reachability analysis** — `found` doesn't mean the specific vulnerable function is called, and `not-found` doesn't prove the code is unused (dynamic requires, reflection, etc. are missed). Java/Kotlin detection assumes the library's import matches its Maven/Gradle groupId (usually true, not guaranteed); Python detection uses the PyPI package name directly, which misses packages whose import name differs from what's published (e.g. PyYAML is `import yaml`) — a known gap, not silently handled. |
| `updateImpact` | `patch` / `minor` / `major` / `unknown` | How big a semver jump the fix requires — a heuristic for how likely it is to be backwards-compatible, not a guarantee. Log4Shell's own fix (2.14.1 → 2.15.0) is itself a "minor" bump by this measure. |
| `recommendedVersion` | version or `null` | The single highest fix version across every CVE known for this exact package — "upgrade to X, clears everything" instead of reconciling N separate per-CVE targets. `null` if no fix is known for any of them yet. |
| `overrideSnippet` | object or `null` (JSON output only) | For transitive findings with a known target version: the exact `{file, instructions, snippet}` to force the patched version without waiting on the parent dependency to update — npm/yarn `overrides`, Gradle `resolutionStrategy.force`, or Maven `dependencyManagement`. Often the fastest real fix for a transitive CVE. |
| `advisoryDetails` | text or `null` (JSON output only) | OSV.dev's full advisory text, which frequently has a mitigation/workaround section beyond "upgrade" (e.g. Log4Shell's config-flag workaround for anyone who can't upgrade immediately). |

Whether an update actually breaks the codebase, or the vulnerable code path is actually
reachable, can only be confirmed by building/running/testing it — which is left to
whoever (human or AI agent) applies the fix with real codebase access, rather than
something cvetrace tries (or auto-applies) itself.

## Ignoring findings

Two ways to dismiss a reviewed-and-accepted finding so it stops showing up on every run
— mirrors how Nexus IQ/Dependabot let you dismiss something once:

- **`--ignore <id>`** — one-off, this run only. Repeatable.
- **`.cvetraceignore`** — permanent, checked in with the project. Put it in the
  directory being scanned: one CVE/GHSA/etc. id per line, blank lines and full-line `#`
  comments ignored, an optional trailing `# reason` captured for the record:

  ```
  # accepted risk, dev tooling only, reviewed by security team
  CVE-2021-1234
  GHSA-xxxx-xxxx-xxxx  # reviewed 2026-01-15, dev-only, accepted
  ```

Ignored findings are dropped from the main report and never count toward `--fail-on`,
but are never silently discarded — the JSON report's `ignored` array carries every
dismissed finding in full, plus which mechanism matched and why, for an audit trail.

## Recommended agent workflow

Both a human and an AI coding agent are meant to run cvetrace the same way — `cvetrace
scan <path> --json` — but an agent (GitHub Copilot, Claude Code/Cowork, Gemini
Antigravity, etc.) working inside a project's IDE can go further and act on the report
directly. The intended loop:

1. Run `cvetrace scan . --json` (add `--exclude`/`--ignore`/`--fail-on` as appropriate)
   and read the `vulnerabilities` array — already sorted by `priorityScore`, highest
   first. Work through it in that order.
2. For each finding, branch on `remediationTier`:
   - **`safe-to-update`** — apply it directly. Bump the package to `recommendedVersion`
     (or `fixedVersion`, to resolve only this one CVE) in the file named by
     `manifestPath`, or — if `dependencyScope` is `transitive` — apply `overrideSnippet`
     instead (it names the exact file and gives the exact snippet: npm/yarn
     `overrides`, Gradle `resolutionStrategy.force`, or Maven `dependencyManagement`).
     Then run the project's own install/build/test step to confirm nothing broke, and
     re-run `cvetrace scan` to confirm the finding is gone before moving to the next one.
   - **`needs-approval`** — don't change anything yet. Summarize the finding (package,
     current → target version, why it's a major/breaking bump) and propose a short
     implementation plan — what files change, what could break, how you'll verify it —
     then wait for the user to explicitly approve before touching any code.
   - **`no-fix-available`** — there's no version bump that resolves this yet. Read
     `advisoryDetails` for a mitigation/workaround (e.g. a config flag) and propose
     that instead, or just flag it for the user's awareness if no workaround exists.
   - **`unknown-impact`** — treat the same as `needs-approval`: cvetrace couldn't
     confirm the size of the version jump, so don't assume it's safe.
3. When reporting back, use `priorityScore`/`priorityLabel`, `usageContext`, and
   `codeReference` to explain *why* something ranks where it does — e.g. "this CRITICAL
   CVE is P4 because it's a dev-only dependency with no code reference found."
4. If the user says to skip a finding, record that decision instead of just not
   mentioning it next time: add its id to a `.cvetraceignore` file in the project
   (with a `# reason` noting who decided and why).

This is a description of the intended workflow, not something cvetrace enforces on its
own — copy it (or adapt it) into your own project's agent instructions file (`CLAUDE.md`,
`AGENTS.md`, `.github/copilot-instructions.md`, etc.) if you want an agent working in
that project to follow it automatically.

## Ecosystems supported

| Ecosystem | Manifests read | Notes |
|---|---|---|
| Node.js | `package.json`, `package-lock.json` | Lockfile (v2/v3) resolves the full transitive tree, including the dependency path to each transitive package; falls back to declared ranges in `package.json` if no lockfile exists. |
| Java (Maven) | `pom.xml` | Static parse; resolves simple `${property}` version references declared in the same `pom.xml`. Only directly declared dependencies are traced — no transitive resolution (that would require invoking `mvn`, not currently done), so `dependencyScope` is always `direct` and `dependencyPath` is always `null`. |
| Java (Gradle) | `build.gradle`, `build.gradle.kts` | **Fully resolved** by actually invoking the project's own Gradle wrapper (`gradlew`/`gradlew.bat`), or a system-installed `gradle` if no wrapper is present, via a throwaway init script — same accuracy as Maven/npm, including transitive dependencies and the full dependency path to each one. Multi-module builds are resolved once from their root. Requires Java to be installed. If Gradle can't be invoked at all (no wrapper, no system install, or the invocation fails), falls back to best-effort static regex parsing of literal `"group:artifact:version"` strings and prints a warning explaining why. |
| Python | `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Prefers the most resolved source available, in that order. `pyproject.toml` support (PEP 621 and Poetry) is best-effort, not a full TOML parser. No transitive resolution — `dependencyPath` is always `null`; `dependencyScope` is `direct` for requirements.txt/pyproject.toml or `unknown` for Pipfile.lock (whose lock format doesn't retain which entries were originally declared vs. pulled in transitively). |

## Development

```sh
npm install
npm test
node bin/cvetrace.js scan . --exclude 'test/**'
```

Test fixtures live under `test/fixtures/*-fixture-project`, each pinning a package
version with a real, well-known CVE, used by `test/e2e.test.js` to verify the whole
CLI end-to-end against live OSV.dev data. Scanning cvetrace's own repo without
`--exclude 'test/**'` will report those fixtures' intentional CVEs, too — expected, not
a sign cvetrace itself is vulnerable.

## License

MIT
