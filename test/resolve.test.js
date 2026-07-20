import test from "node:test";
import assert from "node:assert/strict";
import { minimumFixedVersion, classifyVersionJump } from "../src/trace/resolve.js";

// Regression test for a real bug: an advisory can list several disjoint affected-version
// intervals for the same package (log4j-core has separate patch lines for 2.0-2.3.x,
// 2.4-2.11.x, and 2.13-2.14.x). minimumFixedVersion used to blend "fixed" versions across
// all of them and pick the global minimum -- for log4j-core 2.14.1 that produced "2.3.1",
// an old release from a branch 2.14.1 was never on, which doesn't even fix the CVE.
test("minimumFixedVersion only considers the interval containing the current version", () => {
  const log4jShellDetail = {
    affected: [
      {
        package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
        ranges: [{ events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }] }],
      },
      {
        package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
        ranges: [{ events: [{ introduced: "2.0-beta9" }, { fixed: "2.3.1" }] }],
      },
      {
        package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
        ranges: [{ events: [{ introduced: "2.4" }, { fixed: "2.12.2" }] }],
      },
    ],
  };

  const fixed = minimumFixedVersion(
    log4jShellDetail,
    "Maven",
    "org.apache.logging.log4j:log4j-core",
    "2.14.1"
  );

  assert.equal(fixed, "2.15.0");
});

test("minimumFixedVersion returns null when no interval contains the current version", () => {
  const detail = {
    affected: [
      {
        package: { ecosystem: "npm", name: "foo" },
        ranges: [{ events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
      },
    ],
  };

  assert.equal(minimumFixedVersion(detail, "npm", "foo", "2.0.0"), null);
});

test("minimumFixedVersion returns null for an interval with no known fix yet", () => {
  const detail = {
    affected: [
      {
        package: { ecosystem: "npm", name: "foo" },
        ranges: [{ events: [{ introduced: "0" }, { last_affected: "1.5.0" }] }],
      },
    ],
  };

  assert.equal(minimumFixedVersion(detail, "npm", "foo", "1.0.0"), null);
});

test("classifyVersionJump", () => {
  assert.equal(classifyVersionJump("2.14.1", "2.14.2"), "patch");
  assert.equal(classifyVersionJump("2.14.1", "2.15.0"), "minor");
  assert.equal(classifyVersionJump("1.9.0", "2.0.0"), "major");
  assert.equal(classifyVersionJump("1.0.0", null), "unknown");
  assert.equal(classifyVersionJump("not-a-version", "1.0.0"), "unknown");
});
