import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtemp, cp, writeFile, rm } from "node:fs/promises";
import os from "node:os";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(__dirname, "..");
const cliPath = path.join(repoRoot, "bin", "cvetrace.js");
const fixturesDir = path.join(__dirname, "fixtures");

async function scanJson(targetDir, extraArgs = []) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [cliPath, "scan", targetDir, "--json", ...extraArgs],
    { cwd: repoRoot }
  );
  return JSON.parse(stdout);
}

// Runs the built CLI against test/fixtures/node-fixture-project and asserts the known
// CVE pinned there (see that fixture's README) is reported. --fail-on makes the process
// exit non-zero, which execFile surfaces as a rejected promise, so it's asserted via catch.
test("cvetrace scan reports the known CVE in node-fixture-project", async () => {
  const report = await scanJson(path.join(fixturesDir, "node-fixture-project"));
  assert.ok(
    report.vulnerabilities.some((v) => v.aliases.includes("CVE-2020-7598")),
    "expected CVE-2020-7598 to be reported"
  );
});

test("cvetrace scan reports the known CVE in java-fixture-project", async () => {
  const report = await scanJson(path.join(fixturesDir, "java-fixture-project"));
  assert.ok(
    report.vulnerabilities.some((v) => v.aliases.includes("CVE-2021-44228")),
    "expected Log4Shell (CVE-2021-44228) to be reported"
  );
});

test("cvetrace scan reports the known CVE in python-fixture-project", async () => {
  const report = await scanJson(path.join(fixturesDir, "python-fixture-project"));
  const pyyamlVulns = report.vulnerabilities.filter((v) => v.name === "pyyaml");

  assert.ok(
    pyyamlVulns.some((v) => v.aliases.includes("CVE-2020-14343")),
    "expected CVE-2020-14343 to be reported"
  );
  // OSV.dev indexes this CVE under both a GHSA-* and a PYSEC-* id; resolve.js should
  // collapse those into one record instead of reporting the same CVE twice.
  const cveIds = pyyamlVulns.map((v) => v.aliases.find((a) => a.startsWith("CVE-")));
  assert.equal(new Set(cveIds).size, cveIds.length, "expected no duplicate CVEs");
});

// Gradle resolution invokes a real Gradle process (via the fixture's committed wrapper),
// which downloads its distribution and starts a daemon on first run -- can take a couple
// of minutes on a cold cache, hence the generous timeout. Requires Java on PATH.
test(
  "cvetrace scan reports the known CVE in gradle-fixture-project via real Gradle invocation",
  { timeout: 5 * 60 * 1000 },
  async () => {
    const report = await scanJson(path.join(fixturesDir, "gradle-fixture-project"));
    assert.ok(
      report.vulnerabilities.some((v) => v.aliases.includes("CVE-2021-44228")),
      "expected Log4Shell (CVE-2021-44228) to be reported via real Gradle resolution"
    );
  }
);

test(
  "cvetrace scan walks a directory of mixed ecosystems, reporting all four separately",
  { timeout: 5 * 60 * 1000 },
  async () => {
    const report = await scanJson(fixturesDir);
    const ecosystems = new Set(report.vulnerabilities.map((v) => v.ecosystem));
    assert.deepEqual([...ecosystems].sort(), ["Maven", "PyPI", "npm"]);

    // The pom.xml and build.gradle fixtures both pin log4j-core@2.14.1 -- regression
    // check for a bug where the CVE-dedupe in resolve.js collapsed them into a single
    // record instead of reporting each manifest's occurrence.
    const log4jManifests = new Set(
      report.vulnerabilities
        .filter((v) => v.name === "org.apache.logging.log4j:log4j-core")
        .map((v) => v.manifestPath)
    );
    assert.equal(log4jManifests.size, 2, "expected log4j-core reported for both manifests");
  }
);

test(
  "cvetrace scan --exclude skips a fixture's whole directory tree",
  { timeout: 5 * 60 * 1000 },
  async () => {
    const withoutExclude = await scanJson(fixturesDir);
    assert.ok(
      withoutExclude.vulnerabilities.some((v) => v.name === "pyyaml"),
      "expected pyyaml to be reported without --exclude"
    );

    const withExclude = await scanJson(fixturesDir, ["--exclude", "python-fixture-project/**"]);
    assert.ok(
      !withExclude.vulnerabilities.some((v) => v.name === "pyyaml"),
      "expected pyyaml to be skipped once its directory is excluded"
    );
    // The other three fixtures should be unaffected.
    assert.ok(withExclude.vulnerabilities.some((v) => v.ecosystem === "npm"));
    assert.ok(withExclude.vulnerabilities.some((v) => v.ecosystem === "Maven"));
  }
);

test("cvetrace scan exits non-zero when --fail-on threshold is met", async () => {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      [cliPath, "scan", path.join(fixturesDir, "node-fixture-project"), "--fail-on", "critical"],
      { cwd: repoRoot }
    ),
    /Command failed/
  );
});

test("cvetrace --help shows the root manpage sections, not the scan-only ones", async () => {
  const { stdout } = await execFileAsync(process.execPath, [cliPath, "--help"], { cwd: repoRoot });

  assert.match(stdout, /REQUIREMENTS/);
  assert.match(stdout, /QUICK START/);
  assert.doesNotMatch(stdout, /EXIT STATUS/);
  assert.doesNotMatch(stdout, /REPORT FIELDS/);
});

test("cvetrace scan --help shows the scan manpage sections, not the root-only ones", async () => {
  const { stdout } = await execFileAsync(process.execPath, [cliPath, "scan", "--help"], {
    cwd: repoRoot,
  });

  assert.match(stdout, /EXIT STATUS/);
  assert.match(stdout, /REPORT FIELDS/);
  assert.doesNotMatch(stdout, /QUICK START/);
  // --exclude's default accumulator shouldn't leak into the help text as noise.
  assert.doesNotMatch(stdout, /default: \[\]/);
});

test("cvetrace with no arguments prints help instead of doing nothing", async () => {
  const { stdout } = await execFileAsync(process.execPath, [cliPath], { cwd: repoRoot });
  assert.match(stdout, /Usage: cvetrace/);
});

test("cvetrace scan --ignore dismisses a specific finding and excludes it from --fail-on", async () => {
  const target = path.join(fixturesDir, "node-fixture-project");

  const report = await scanJson(target, ["--ignore", "CVE-2020-7598"]);
  assert.ok(!report.vulnerabilities.some((v) => v.aliases.includes("CVE-2020-7598")));
  assert.ok(report.vulnerabilities.some((v) => v.aliases.includes("CVE-2021-44906")));
  assert.equal(report.ignoredCount, 1);
  assert.equal(report.ignored[0].ignoredVia, "--ignore");

  // CVE-2020-7598 is MODERATE, not CRITICAL, so this would already pass either way --
  // the real check is that dismissing the one CRITICAL finding (CVE-2021-44906) makes
  // a critical --fail-on gate pass where it would otherwise fail.
  await assert.doesNotReject(
    execFileAsync(
      process.execPath,
      [cliPath, "scan", target, "--ignore", "CVE-2021-44906", "--fail-on", "critical"],
      { cwd: repoRoot }
    )
  );
});

test("cvetrace scan reads .cvetraceignore from the scanned directory, with a reason", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-e2e-ignorefile-"));
  try {
    await cp(path.join(fixturesDir, "node-fixture-project"), dir, { recursive: true });
    await writeFile(
      path.join(dir, ".cvetraceignore"),
      "CVE-2021-44906  # reviewed 2026-01-01, accepted risk\n"
    );

    const report = await scanJson(dir);
    assert.ok(!report.vulnerabilities.some((v) => v.aliases.includes("CVE-2021-44906")));
    assert.ok(report.vulnerabilities.some((v) => v.aliases.includes("CVE-2020-7598")));

    const ignoredEntry = report.ignored.find((v) => v.aliases.includes("CVE-2021-44906"));
    assert.equal(ignoredEntry.ignoredVia, ".cvetraceignore");
    assert.equal(ignoredEntry.ignoredReason, "reviewed 2026-01-01, accepted risk");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test(
  "cvetrace scan sorts the report by priorityScore descending, each finding carrying a P1-P4 label",
  { timeout: 5 * 60 * 1000 },
  async () => {
    const report = await scanJson(fixturesDir);
    assert.ok(report.vulnerabilities.length > 1);
    assert.ok(report.vulnerabilities.every((v) => /^P[1-4]$/.test(v.priorityLabel)));

    for (let i = 1; i < report.vulnerabilities.length; i++) {
      assert.ok(report.vulnerabilities[i - 1].priorityScore >= report.vulnerabilities[i].priorityScore);
    }
  }
);
