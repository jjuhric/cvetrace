import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import { loadIgnoreFile, applyIgnoreRules } from "../src/trace/ignore.js";

test("loadIgnoreFile parses ids, skips blanks/comments, captures a trailing reason", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-ignore-"));
  try {
    await writeFile(
      path.join(dir, ".cvetraceignore"),
      [
        "# accepted risk, dev tooling only",
        "",
        "CVE-2021-1234",
        "GHSA-xxxx-xxxx-xxxx  # reviewed 2026-01-15, dev-only, accepted",
      ].join("\n")
    );

    const rules = await loadIgnoreFile(dir);
    assert.deepEqual(rules, [
      { id: "CVE-2021-1234", reason: null, source: ".cvetraceignore" },
      {
        id: "GHSA-xxxx-xxxx-xxxx",
        reason: "reviewed 2026-01-15, dev-only, accepted",
        source: ".cvetraceignore",
      },
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadIgnoreFile returns [] when no .cvetraceignore exists", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-ignore-"));
  try {
    assert.deepEqual(await loadIgnoreFile(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("applyIgnoreRules matches by OSV id or any alias, from file rules or --ignore", () => {
  const findings = [
    { id: "GHSA-aaaa", aliases: ["CVE-2021-1111"] },
    { id: "GHSA-bbbb", aliases: ["CVE-2021-2222"] },
    { id: "GHSA-cccc", aliases: [] },
  ];

  const { kept, ignored } = applyIgnoreRules(
    findings,
    [{ id: "CVE-2021-1111", reason: "accepted risk", source: ".cvetraceignore" }],
    ["GHSA-cccc"]
  );

  assert.deepEqual(
    kept.map((f) => f.id),
    ["GHSA-bbbb"]
  );
  assert.equal(ignored.length, 2);
  const byId = Object.fromEntries(ignored.map((f) => [f.id, f]));
  assert.equal(byId["GHSA-aaaa"].ignoredReason, "accepted risk");
  assert.equal(byId["GHSA-aaaa"].ignoredVia, ".cvetraceignore");
  assert.equal(byId["GHSA-cccc"].ignoredReason, null);
  assert.equal(byId["GHSA-cccc"].ignoredVia, "--ignore");
});
