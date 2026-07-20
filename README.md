# cvetrace

A cross-platform, terminal-based CVE **discovery, trace, and solutions** tool.
Point it at any project directory — Node, Java (Maven), or Python — and it scans
the dependency manifests for known vulnerabilities, using the free
[OSV.dev](https://osv.dev) vulnerability database (no API key required).

Works the same way on Windows, macOS, and Linux, as long as [Node.js](https://nodejs.org)
(18+) is installed.

## Usage

```sh
npx github:jjuhric/cvetrace scan <path-to-project> [--json] [--fail-on <severity>]
```

- `<path-to-project>` — directory to scan. cvetrace walks it, detects manifests
  (`package.json`/`package-lock.json`, `pom.xml`/`build.gradle`, `requirements.txt`/
  `pyproject.toml`/`Pipfile.lock`), and reports known CVEs against each resolved
  dependency version.
- `--json` — emit a machine-readable JSON report instead of the terminal report.
- `--fail-on <severity>` — exit non-zero if a vulnerability at or above the given
  severity (`low`, `moderate`, `high`, `critical`) is found — useful for CI gating.

## How it works

1. **Discover** — walk the target directory, skip build/dependency dirs
   (`node_modules`, `.git`, `venv`, `target`, `build`, ...), and extract every
   declared/resolved `{ecosystem, name, version}` dependency.
2. **Trace** — batch-query [OSV.dev](https://osv.dev) for each dependency and
   link any matching vulnerabilities (CVE/GHSA ids, severity, affected ranges)
   back to the manifest file that introduced them.
3. **Solutions** — for each vulnerability found, report the minimum version
   that resolves it and a link to the advisory.

## Ecosystems supported

| Ecosystem | Manifests read | Notes |
|---|---|---|
| Node.js | `package.json`, `package-lock.json` | Lockfile (v2/v3) resolves the full transitive tree; falls back to declared ranges in `package.json` if no lockfile exists. |
| Java (Maven) | `pom.xml` (best-effort for `build.gradle`/`.kts`) | Resolves simple `${property}` version references declared in the same `pom.xml`. Full Gradle dependency resolution would require invoking Gradle itself and isn't supported. |
| Python | `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Prefers the most resolved source available, in that order. `pyproject.toml` support (PEP 621 and Poetry) is best-effort, not a full TOML parser. |

Only directly declared/resolved dependencies are traced for Java and Python — unlike
Node's lockfile-based transitive resolution, there's no dependency-path tracing for
those two ecosystems yet.

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
