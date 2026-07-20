import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import { detectCodeReferences } from "../src/trace/usage.js";

test("detectCodeReferences finds Node require/import and flags unused packages", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-usage-"));
  try {
    await mkdir(path.join(dir, "src"), { recursive: true });
    await writeFile(
      path.join(dir, "src", "index.js"),
      ['const minimist = require("minimist");', 'import { thing } from "esm-pkg";'].join("\n")
    );

    const findings = [
      { ecosystem: "npm", name: "minimist" },
      { ecosystem: "npm", name: "esm-pkg" },
      { ecosystem: "npm", name: "unused-pkg" },
    ];
    const result = await detectCodeReferences(dir, findings, []);
    const byName = Object.fromEntries(result.map((r) => [r.name, r.codeReference]));

    assert.equal(byName.minimist, "found");
    assert.equal(byName["esm-pkg"], "found");
    assert.equal(byName["unused-pkg"], "not-found");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("detectCodeReferences derives a Java import heuristic from the Maven/Gradle groupId", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-usage-java-"));
  try {
    await mkdir(path.join(dir, "src"), { recursive: true });
    await writeFile(
      path.join(dir, "src", "App.java"),
      "import org.apache.logging.log4j.core.Logger;\npublic class App {}"
    );

    const findings = [
      { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
      { ecosystem: "Maven", name: "com.unused.lib:some-artifact" },
    ];
    const result = await detectCodeReferences(dir, findings, []);
    const byName = Object.fromEntries(result.map((r) => [r.name, r.codeReference]));

    assert.equal(byName["org.apache.logging.log4j:log4j-core"], "found");
    assert.equal(byName["com.unused.lib:some-artifact"], "not-found");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("detectCodeReferences checks Python import statements", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-usage-py-"));
  try {
    await writeFile(path.join(dir, "main.py"), "import requests\nfrom flask import Flask\n");

    const findings = [
      { ecosystem: "PyPI", name: "requests" },
      { ecosystem: "PyPI", name: "flask" },
      { ecosystem: "PyPI", name: "unused" },
    ];
    const result = await detectCodeReferences(dir, findings, []);
    const byName = Object.fromEntries(result.map((r) => [r.name, r.codeReference]));

    assert.equal(byName.requests, "found");
    assert.equal(byName.flask, "found");
    assert.equal(byName.unused, "not-found");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("detectCodeReferences returns unknown when no relevant source files exist at all", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-usage-empty-"));
  try {
    const findings = [{ ecosystem: "npm", name: "minimist" }];
    const result = await detectCodeReferences(dir, findings, []);
    assert.equal(result[0].codeReference, "unknown");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("detectCodeReferences respects exclude patterns when scanning source", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-usage-exclude-"));
  try {
    await mkdir(path.join(dir, "vendor"), { recursive: true });
    await writeFile(path.join(dir, "vendor", "bundled.js"), 'require("only-in-vendor");');

    const findings = [{ ecosystem: "npm", name: "only-in-vendor" }];
    const withoutExclude = await detectCodeReferences(dir, findings, []);
    assert.equal(withoutExclude[0].codeReference, "found");

    const withExclude = await detectCodeReferences(dir, findings, ["vendor/**"]);
    assert.equal(withExclude[0].codeReference, "unknown");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
