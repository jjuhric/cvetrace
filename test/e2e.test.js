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
const fixtureDir = path.join(__dirname, "fixtures", "node-fixture-project");

// Runs the built CLI against test/fixtures/node-fixture-project and asserts the known
// CVE pinned there (see that fixture's README) is reported. --fail-on makes the process
// exit non-zero, which execFile surfaces as a rejected promise, so it's asserted via catch.
test("cvetrace scan reports the known CVE in node-fixture-project", async () => {
  const { stdout } = await execFileAsync(
    process.execPath,
    [cliPath, "scan", fixtureDir, "--json"],
    { cwd: repoRoot }
  );

  const report = JSON.parse(stdout);
  assert.ok(
    report.vulnerabilities.some((v) => v.aliases.includes("CVE-2020-7598")),
    "expected CVE-2020-7598 to be reported"
  );
});

test("cvetrace scan exits non-zero when --fail-on threshold is met", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [cliPath, "scan", fixtureDir, "--fail-on", "critical"], {
      cwd: repoRoot,
    }),
    /Command failed/
  );
});
