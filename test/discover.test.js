import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { discoverNode } from "../src/discover/node.js";
import { discoverJava } from "../src/discover/java.js";
import { discoverPython } from "../src/discover/python.js";
import { parseDependencyLines } from "../src/discover/gradle.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures");

test("discoverNode resolves the pinned dependency from package-lock.json", async () => {
  const deps = await discoverNode(path.join(fixturesDir, "node-fixture-project"));

  const minimist = deps.find((d) => d.name === "minimist");
  assert.ok(minimist, "expected minimist to be discovered");
  assert.equal(minimist.ecosystem, "npm");
  assert.equal(minimist.version, "0.0.8");
  assert.equal(path.basename(minimist.manifestPath), "package-lock.json");
  assert.equal(minimist.dependencyScope, "direct");
  assert.equal(minimist.usageContext, "production");
});

// Synthetic lockfile (no real npm install needed) covering all four scope
// combinations: a is a direct prod dep that also pulls in c transitively; b is a direct
// dev dep that pulls in d transitively -- proving the BFS reachability walk in
// buildScopeMap correctly separates "pulled in via prod" from "pulled in via dev only".
test("discoverNode classifies direct/transitive and production/development via the lockfile graph", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-node-scope-"));
  try {
    await writeFile(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "scope-test",
        lockfileVersion: 3,
        packages: {
          "": { name: "scope-test", dependencies: { a: "1.0.0" }, devDependencies: { b: "1.0.0" } },
          "node_modules/a": { version: "1.0.0", dependencies: { c: "1.0.0" } },
          "node_modules/b": { version: "1.0.0", dependencies: { d: "1.0.0" } },
          "node_modules/c": { version: "1.0.0" },
          "node_modules/d": { version: "1.0.0" },
        },
      })
    );

    const deps = await discoverNode(dir);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));

    assert.deepEqual(
      [byName.a.dependencyScope, byName.a.usageContext],
      ["direct", "production"]
    );
    assert.deepEqual(
      [byName.b.dependencyScope, byName.b.usageContext],
      ["direct", "development"]
    );
    assert.deepEqual(
      [byName.c.dependencyScope, byName.c.usageContext],
      ["transitive", "production"]
    );
    assert.deepEqual(
      [byName.d.dependencyScope, byName.d.usageContext],
      ["transitive", "development"]
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("discoverJava resolves a pom.xml dependency pinned via a <properties> reference", async () => {
  const deps = await discoverJava(path.join(fixturesDir, "java-fixture-project"));

  const log4j = deps.find((d) => d.name === "org.apache.logging.log4j:log4j-core");
  assert.ok(log4j, "expected log4j-core to be discovered");
  assert.equal(log4j.ecosystem, "Maven");
  assert.equal(log4j.version, "2.14.1");
  assert.equal(path.basename(log4j.manifestPath), "pom.xml");
  assert.equal(log4j.dependencyScope, "direct");
  assert.equal(log4j.usageContext, "production");
});

test("discoverJava maps Maven <scope>test</scope> to usageContext development", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-maven-scope-"));
  try {
    await writeFile(
      path.join(dir, "pom.xml"),
      `<project>
        <dependencies>
          <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.1</version>
            <scope>test</scope>
          </dependency>
        </dependencies>
      </project>`
    );

    const [junit] = await discoverJava(dir);
    assert.equal(junit.usageContext, "development");
    assert.equal(junit.dependencyScope, "direct");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// parseDependencyLines is pure (no Gradle process needed) -- exercises direct+production,
// transitive+production, and test-only+development classification from synthetic
// init-script-style output.
test("gradle parseDependencyLines classifies scope from configuration names", () => {
  const stdout = [
    "CVETRACE_DIRECT|/proj|com.example:direct-lib",
    "CVETRACE_DIRECT|/proj|com.example:test-only-lib",
    "CVETRACE_DEP|/proj|implementation|com.example:direct-lib:1.0.0",
    "CVETRACE_DEP|/proj|implementation|com.example:transitive-lib:2.0.0",
    "CVETRACE_DEP|/proj|testImplementation|com.example:test-only-lib:3.0.0",
  ].join("\n");

  const deps = parseDependencyLines(stdout);
  const byName = Object.fromEntries(deps.map((d) => [d.name, d]));

  assert.deepEqual(
    [byName["com.example:direct-lib"].dependencyScope, byName["com.example:direct-lib"].usageContext],
    ["direct", "production"]
  );
  assert.deepEqual(
    [byName["com.example:transitive-lib"].dependencyScope, byName["com.example:transitive-lib"].usageContext],
    ["transitive", "production"]
  );
  assert.deepEqual(
    [byName["com.example:test-only-lib"].dependencyScope, byName["com.example:test-only-lib"].usageContext],
    ["direct", "development"]
  );
});

test("discoverPython resolves a pinned requirements.txt dependency and normalizes its name", async () => {
  const deps = await discoverPython(path.join(fixturesDir, "python-fixture-project"));

  const pyyaml = deps.find((d) => d.name === "pyyaml");
  assert.ok(pyyaml, "expected PyYAML to be discovered under its normalized name");
  assert.equal(pyyaml.ecosystem, "PyPI");
  assert.equal(pyyaml.version, "5.3");
  assert.equal(path.basename(pyyaml.manifestPath), "requirements.txt");
  assert.equal(pyyaml.dependencyScope, "direct");
  assert.equal(pyyaml.usageContext, "production");
});

test("discoverPython maps Pipfile.lock default/develop to production/development", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cvetrace-pipfile-scope-"));
  try {
    await writeFile(
      path.join(dir, "Pipfile.lock"),
      JSON.stringify({
        default: { flask: { version: "==2.0.0" } },
        develop: { pytest: { version: "==7.0.0" } },
      })
    );

    const deps = await discoverPython(dir);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));

    assert.equal(byName.flask.usageContext, "production");
    assert.equal(byName.pytest.usageContext, "development");
    assert.equal(byName.flask.dependencyScope, "unknown");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
