# cvetrace

A cross-platform, terminal-based CVE **discovery, trace, and solutions** tool.
Point it at any project directory — Node, Java (Maven or Gradle), or Python — and it
scans the dependency manifests for known vulnerabilities, using the free
[OSV.dev](https://osv.dev) vulnerability database (no API key required).

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
npx github:jjuhric/cvetrace scan <path-to-project> [--json] [--fail-on <severity>]
```

`npx` downloads and runs cvetrace fresh each time — no install step, but a small
per-invocation delay. For repeated use, install it once instead:

```sh
npm install -g github:jjuhric/cvetrace
cvetrace scan <path-to-project> [--json] [--fail-on <severity>]
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
  whether that should block anything, unless you tell it to.

## How it works

1. **Discover** — walk the target directory, skip build/dependency dirs
   (`node_modules`, `.git`, `venv`, `target`, `build`, ...), and extract every
   declared/resolved `{ecosystem, name, version}` dependency.
2. **Trace** — batch-query [OSV.dev](https://osv.dev) for each dependency and
   link any matching vulnerabilities (CVE/GHSA ids, severity, affected ranges)
   back to the manifest file that introduced them.
3. **Solutions** — for each vulnerability found, report the minimum version
   that resolves it and a link to the advisory.

## Designed for AI/human-assisted remediation

cvetrace never edits your files. Instead, every finding in the report carries three
fields meant to help a human — or an AI coding agent (GitHub Copilot, Claude Code, etc.)
working through the report — triage and fix what's real and safe, without cvetrace
itself guessing wrong about your codebase:

| Field | Values | What it actually tells you |
|---|---|---|
| `dependencyScope` | `direct` / `transitive` / `unknown` | Whether the vulnerable package is declared directly in your manifest, or pulled in by something else you depend on. |
| `usageContext` | `production` / `development` / `unknown` | Whether the package is reachable from your production dependencies, or only from dev/test/build tooling (`devDependencies`, Maven `test` scope, Gradle `testImplementation`, etc.) that never ships. |
| `updateImpact` | `patch` / `minor` / `major` / `unknown` | How big a semver jump the fix requires. |

**Read these as triage aids, not verdicts.** `usageContext: development` is a strong
signal that a "Critical" finding is noise you can deprioritize — it's a very common
source of false-urgency in scanners like Sonar/Nexus IQ, since a vulnerable test-only
tool can never be exploited in production. But cvetrace does **not** attempt reachability
analysis (proving the vulnerable function is actually called) — that's a much harder,
language-specific static-analysis problem outside its scope.

Likewise, `updateImpact: minor` or `patch` means the fix is *likely* backwards-compatible
by semver convention, not that it's guaranteed safe — Log4Shell's own fix (2.14.1 →
2.15.0) is itself a "minor" version bump by this measure. Whoever applies the fix should
still build and run the test suite before trusting it, which is exactly the judgment call
cvetrace leaves to a human or an AI agent with actual codebase access, rather than trying
to make (or auto-apply) that call itself.

## Ecosystems supported

| Ecosystem | Manifests read | Notes |
|---|---|---|
| Node.js | `package.json`, `package-lock.json` | Lockfile (v2/v3) resolves the full transitive tree; falls back to declared ranges in `package.json` if no lockfile exists. |
| Java (Maven) | `pom.xml` | Static parse; resolves simple `${property}` version references declared in the same `pom.xml`. Only directly declared dependencies are traced — no transitive resolution (that would require invoking `mvn`, not currently done). |
| Java (Gradle) | `build.gradle`, `build.gradle.kts` | **Fully resolved** by actually invoking the project's own Gradle wrapper (`gradlew`/`gradlew.bat`), or a system-installed `gradle` if no wrapper is present, via a throwaway init script — same accuracy as Maven/npm, including transitive dependencies. Multi-module builds are resolved once from their root. Requires Java to be installed. If Gradle can't be invoked at all (no wrapper, no system install, or the invocation fails), falls back to best-effort static regex parsing of literal `"group:artifact:version"` strings and prints a warning explaining why. |
| Python | `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Prefers the most resolved source available, in that order. `pyproject.toml` support (PEP 621 and Poetry) is best-effort, not a full TOML parser. Only directly declared dependencies are traced. |

## Development

```sh
npm install
npm test
node bin/cvetrace.js scan .
```

Test fixtures live under `test/fixtures/*-fixture-project`, each pinning a package
version with a real, well-known CVE, used by `test/e2e.test.js` to verify the whole
CLI end-to-end against live OSV.dev data.

## License

MIT
