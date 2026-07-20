import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(__dirname, "..");
const cliPath = path.join(repoRoot, "bin", "cvetrace.js");
const fixturesDir = path.join(__dirname, "fixtures");

async function scanJson(targetDir) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [cliPath, "scan", targetDir, "--json"],
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

test("cvetrace scan walks a directory of mixed ecosystems and reports all three", async () => {
  const report = await scanJson(fixturesDir);
  const ecosystems = new Set(report.vulnerabilities.map((v) => v.ecosystem));

  assert.deepEqual([...ecosystems].sort(), ["Maven", "PyPI", "npm"]);
});

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
