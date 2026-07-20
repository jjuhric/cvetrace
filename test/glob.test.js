import test from "node:test";
import assert from "node:assert/strict";
import { globToRegExp, createExcludeMatcher } from "../src/discover/glob.js";

test("globToRegExp: trailing /** matches both the prefix itself and anything under it", () => {
  const re = globToRegExp("test/**");
  assert.ok(re.test("test"));
  assert.ok(re.test("test/fixtures"));
  assert.ok(re.test("test/fixtures/java-fixture-project"));
  assert.ok(!re.test("testing"));
  assert.ok(!re.test("other/test"));
});

test("globToRegExp: * matches within a single path segment only", () => {
  const re = globToRegExp("*-fixture-project");
  assert.ok(re.test("java-fixture-project"));
  assert.ok(!re.test("test/java-fixture-project"));
});

test("globToRegExp: ? matches exactly one character", () => {
  const re = globToRegExp("a?c");
  assert.ok(re.test("abc"));
  assert.ok(!re.test("ac"));
  assert.ok(!re.test("abbc"));
});

test("createExcludeMatcher: matches against any of several patterns, normalizing backslashes", () => {
  const isExcluded = createExcludeMatcher(["test/**", "vendor/**"]);
  assert.ok(isExcluded("test\\fixtures\\node-fixture-project"));
  assert.ok(isExcluded("vendor/legacy"));
  assert.ok(!isExcluded("src/discover"));
});

test("createExcludeMatcher: no patterns excludes nothing", () => {
  const isExcluded = createExcludeMatcher([]);
  assert.ok(!isExcluded("anything"));
});
