import { SEVERITY_RANK } from "./resolve.js";

const CONTEXT_MULTIPLIER = { production: 1.0, development: 0.3, unknown: 0.7 };
const USAGE_MULTIPLIER = { found: 1.0, "not-found": 0.4, unknown: 0.85 };
const EFFORT_BONUS = { patch: 0.3, minor: 0.15, major: 0, unknown: 0 };

// Combines severity, usageContext, and codeReference (plus a small updateImpact
// tiebreak favoring easy wins) into one sortable priorityScore and a P1-P4
// priorityLabel -- deliberately different wording from `severity` (the CVE's own
// CVSS-derived rating) so that e.g. "severity: CRITICAL, priority: P4" (a critical CVE
// in dev-only code with no detected usage) reads as a sensible triage call, not a
// contradiction. Must run after usageContext (src/discover/*) and codeReference
// (src/trace/usage.js) are both known.
//
// This is cvetrace's own synthesis for triage *ordering*, not an authoritative risk
// score -- read it the same way as the fields it's built from: a heuristic aid for
// working through a pile of findings top-down, not a verdict on any single one.
export function computePriority(finding) {
  const severityWeight = SEVERITY_RANK[finding.severity] ?? 0;
  const contextMultiplier = CONTEXT_MULTIPLIER[finding.usageContext] ?? CONTEXT_MULTIPLIER.unknown;
  const usageMultiplier = USAGE_MULTIPLIER[finding.codeReference] ?? USAGE_MULTIPLIER.unknown;
  const effortBonus = EFFORT_BONUS[finding.updateImpact] ?? 0;

  const priorityScore =
    Math.round((severityWeight * contextMultiplier * usageMultiplier + effortBonus) * 100) / 100;

  return { priorityScore, priorityLabel: labelFor(priorityScore) };
}

function labelFor(score) {
  if (score >= 3.0) return "P1";
  if (score >= 1.8) return "P2";
  if (score >= 0.8) return "P3";
  return "P4";
}
