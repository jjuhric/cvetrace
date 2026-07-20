import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverNode } from "../src/discover/node.js";
import { discoverJava } from "../src/discover/java.js";
import { discoverPython } from "../src/discover/python.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures");

test("discoverNode resolves the pinned dependency from package-lock.json", async () => {
  const deps = await discoverNode(path.join(fixturesDir, "node-fixture-project"));

  const minimist = deps.find((d) => d.name === "minimist");
  assert.ok(minimist, "expected minimist to be discovered");
  assert.equal(minimist.ecosystem, "npm");
  assert.equal(minimist.version, "0.0.8");
  assert.equal(path.basename(minimist.manifestPath), "package-lock.json");
});

test("discoverJava resolves a pom.xml dependency pinned via a <properties> reference", async () => {
  const deps = await discoverJava(path.join(fixturesDir, "java-fixture-project"));

  const log4j = deps.find((d) => d.name === "org.apache.logging.log4j:log4j-core");
  assert.ok(log4j, "expected log4j-core to be discovered");
  assert.equal(log4j.ecosystem, "Maven");
  assert.equal(log4j.version, "2.14.1");
  assert.equal(path.basename(log4j.manifestPath), "pom.xml");
});

test("discoverPython resolves a pinned requirements.txt dependency and normalizes its name", async () => {
  const deps = await discoverPython(path.join(fixturesDir, "python-fixture-project"));

  const pyyaml = deps.find((d) => d.name === "pyyaml");
  assert.ok(pyyaml, "expected PyYAML to be discovered under its normalized name");
  assert.equal(pyyaml.ecosystem, "PyPI");
  assert.equal(pyyaml.version, "5.3");
  assert.equal(path.basename(pyyaml.manifestPath), "requirements.txt");
});
