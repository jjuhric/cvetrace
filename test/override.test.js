import test from "node:test";
import assert from "node:assert/strict";
import { generateOverrideSnippet } from "../src/trace/override.js";

test("generateOverrideSnippet returns null for direct dependencies", () => {
  const finding = {
    dependencyScope: "direct",
    ecosystem: "npm",
    name: "pkg",
    recommendedVersion: "1.2.3",
    manifestPath: "package-lock.json",
  };
  assert.equal(generateOverrideSnippet(finding), null);
});

test("generateOverrideSnippet returns null when no target version is known", () => {
  const finding = {
    dependencyScope: "transitive",
    ecosystem: "npm",
    name: "pkg",
    recommendedVersion: null,
    fixedVersion: null,
    manifestPath: "package-lock.json",
  };
  assert.equal(generateOverrideSnippet(finding), null);
});

test("generateOverrideSnippet: npm overrides", () => {
  const finding = {
    dependencyScope: "transitive",
    ecosystem: "npm",
    name: "loader-utils",
    recommendedVersion: "1.4.1",
    manifestPath: "package-lock.json",
  };
  const result = generateOverrideSnippet(finding);
  assert.equal(result.file, "package.json");
  assert.deepEqual(JSON.parse(result.snippet), { overrides: { "loader-utils": "1.4.1" } });
});

test("generateOverrideSnippet: Gradle resolutionStrategy.force", () => {
  const finding = {
    dependencyScope: "transitive",
    ecosystem: "Maven",
    name: "org.apache.logging.log4j:log4j-api",
    recommendedVersion: "2.17.1",
    manifestPath: "test/fixtures/gradle-fixture-project/build.gradle",
  };
  const result = generateOverrideSnippet(finding);
  assert.equal(result.file, "build.gradle");
  assert.match(result.snippet, /resolutionStrategy\.force 'org\.apache\.logging\.log4j:log4j-api:2\.17\.1'/);
});

test("generateOverrideSnippet: Maven dependencyManagement", () => {
  const finding = {
    dependencyScope: "transitive",
    ecosystem: "Maven",
    name: "org.apache.logging.log4j:log4j-api",
    recommendedVersion: "2.17.1",
    manifestPath: "some-project/pom.xml",
  };
  const result = generateOverrideSnippet(finding);
  assert.equal(result.file, "pom.xml");
  assert.match(result.snippet, /<artifactId>log4j-api<\/artifactId>/);
  assert.match(result.snippet, /<version>2\.17\.1<\/version>/);
});

test("generateOverrideSnippet falls back to fixedVersion when recommendedVersion is absent", () => {
  const finding = {
    dependencyScope: "transitive",
    ecosystem: "npm",
    name: "pkg",
    recommendedVersion: null,
    fixedVersion: "1.0.1",
    manifestPath: "package-lock.json",
  };
  const result = generateOverrideSnippet(finding);
  assert.deepEqual(JSON.parse(result.snippet), { overrides: { pkg: "1.0.1" } });
});
