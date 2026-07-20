# cvetrace

A cross-platform, terminal-based CVE **discovery, trace, and solutions** tool.
Point it at any project directory — Node, Java (Maven), or Python — and it scans
the dependency manifests for known vulnerabilities, using the free
[OSV.dev](https://osv.dev) vulnerability database (no API key required).

Works the same way on Windows, macOS, and Linux, as long as [Node.js](https://nodejs.org)
(18+) is installed.

> **Status:** early scaffold. The CLI skeleton exists; the discover/trace/report
> pipeline is not implemented yet. See the roadmap below.

## Usage (planned)

```sh
npx github:jjuhric/cvetrace scan <path-to-project> [--json] [--fail-on <severity>]
```

- `<path-to-project>` — directory to scan. cvetrace walks it, detects manifests
  (`package.json`/`package-lock.json`, `pom.xml`, `requirements.txt`/`pyproject.toml`/
  `Pipfile.lock`), and reports known CVEs against each resolved dependency version.
- `--json` — emit a machine-readable JSON report instead of the terminal report.
- `--fail-on <severity>` — exit non-zero if a vulnerability at or above the given
  severity is found (useful for CI gating).

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

| Ecosystem | Manifests read |
|---|---|
| Node.js | `package.json`, `package-lock.json` |
| Java (Maven) | `pom.xml` (best-effort for Gradle) |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile.lock` |

## Development

```sh
npm install
npm test
node bin/cvetrace.js scan .
```

## License

MIT
