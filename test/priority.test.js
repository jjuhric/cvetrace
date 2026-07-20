import test from "node:test";
import assert from "node:assert/strict";
import { computePriority } from "../src/trace/priority.js";

test("computePriority: critical, production, used, easy fix -> P1", () => {
  const { priorityScore, priorityLabel } = computePriority({
    severity: "CRITICAL",
    usageContext: "production",
    codeReference: "found",
    updateImpact: "patch",
  });
  assert.equal(priorityLabel, "P1");
  assert.ok(priorityScore >= 3.0);
});

test("computePriority: critical severity but dev-only and unused -> low priority, not P1", () => {
  const { priorityScore, priorityLabel } = computePriority({
    severity: "CRITICAL",
    usageContext: "development",
    codeReference: "not-found",
    updateImpact: "minor",
  });
  // The whole point: a CRITICAL CVE can still be a low real-world priority.
  assert.equal(priorityLabel, "P4");
  assert.ok(priorityScore < 3.0);
});

test("computePriority: unknown severity always floors to the lowest priority", () => {
  const { priorityScore, priorityLabel } = computePriority({
    severity: "UNKNOWN",
    usageContext: "production",
    codeReference: "found",
    updateImpact: "patch",
  });
  assert.equal(priorityLabel, "P4");
  assert.equal(priorityScore, 0.3); // just the effort bonus, since severity weight is 0
});

test("computePriority: missing usageContext/codeReference/updateImpact default sensibly, don't throw", () => {
  const { priorityScore, priorityLabel } = computePriority({ severity: "HIGH" });
  assert.equal(typeof priorityScore, "number");
  assert.match(priorityLabel, /^P[1-4]$/);
});

test("computePriority: higher severity always outranks lower severity at equal context/usage", () => {
  const high = computePriority({
    severity: "HIGH",
    usageContext: "production",
    codeReference: "found",
    updateImpact: "unknown",
  });
  const low = computePriority({
    severity: "LOW",
    usageContext: "production",
    codeReference: "found",
    updateImpact: "unknown",
  });
  assert.ok(high.priorityScore > low.priorityScore);
});
