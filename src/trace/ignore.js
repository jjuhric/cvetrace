import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses a .cvetraceignore file at the scan target's root: one CVE/GHSA/PYSEC id per
// line, blank lines and full-line "#" comments skipped, an optional trailing "# reason"
// captured for the audit trail. Mirrors how Nexus IQ/Dependabot let you dismiss a
// reviewed-and-accepted finding so it doesn't get re-flagged on every run.
export async function loadIgnoreFile(targetPath) {
  const filePath = path.join(targetPath, ".cvetraceignore");
  let text;
  try {
    text = await readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }

  const rules = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const hashIndex = line.indexOf("#");
    const id = (hashIndex === -1 ? line : line.slice(0, hashIndex)).trim();
    const reason = hashIndex === -1 ? null : line.slice(hashIndex + 1).trim() || null;
    if (id) rules.push({ id, reason, source: ".cvetraceignore" });
  }
  return rules;
}

// Merges .cvetraceignore rules with --ignore <id> CLI values (which carry no reason),
// then splits findings into { kept, ignored }. A finding matches if its OSV id or any
// of its CVE/GHSA/etc. aliases matches a rule.
export function applyIgnoreRules(findings, ignoreFileRules, cliIds) {
  const rules = [
    ...ignoreFileRules,
    ...(cliIds ?? []).map((id) => ({ id, reason: null, source: "--ignore" })),
  ];
  const rulesById = new Map(rules.map((rule) => [rule.id, rule]));

  const kept = [];
  const ignored = [];
  for (const finding of findings) {
    const ids = [finding.id, ...finding.aliases];
    const matchedRule = ids.map((id) => rulesById.get(id)).find(Boolean);
    if (matchedRule) {
      ignored.push({ ...finding, ignoredReason: matchedRule.reason, ignoredVia: matchedRule.source });
    } else {
      kept.push(finding);
    }
  }
  return { kept, ignored };
}
