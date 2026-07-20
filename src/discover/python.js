import { readFile } from "node:fs/promises";
import path from "node:path";

const DEV_GROUP_RE = /^(dev|test|docs?|lint|typing)/i;
const DEV_REQUIREMENTS_FILES = ["requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt"];

// Parses requirements.txt, pyproject.toml (PEP 621 / Poetry), and Pipfile.lock into
// { ecosystem: "PyPI", name, version } tuples. Preference order favors the most
// resolved/precise source: Pipfile.lock (fully resolved) > requirements.txt (usually
// pinned) > pyproject.toml (declared ranges, best-effort — see README limitations).
//
// Each tuple is tagged usageContext ("production"/"development"): Pipfile.lock's
// default/develop split is reliable; elsewhere it's inferred by filename/group-name
// convention (requirements-dev.txt, a pyproject dev/test extras group, etc.) — a
// heuristic, not a guarantee. dependencyScope is "direct" for requirements.txt/
// pyproject.toml (user-curated declaration files) and "unknown" for Pipfile.lock, since
// that lock format doesn't retain which entries were originally declared vs. pulled in
// transitively.
export async function discoverPython(dir) {
  const pipfileLock = await readJson(path.join(dir, "Pipfile.lock"));
  if (pipfileLock) {
    return dedupe(fromPipfileLock(pipfileLock, path.join(dir, "Pipfile.lock")));
  }

  const requirementsText = await readText(path.join(dir, "requirements.txt"));
  if (requirementsText !== null) {
    const deps = fromRequirementsTxt(requirementsText, path.join(dir, "requirements.txt"), "production");
    for (const devFile of DEV_REQUIREMENTS_FILES) {
      const devText = await readText(path.join(dir, devFile));
      if (devText !== null) {
        deps.push(...fromRequirementsTxt(devText, path.join(dir, devFile), "development"));
      }
    }
    return dedupe(deps);
  }

  const pyprojectText = await readText(path.join(dir, "pyproject.toml"));
  if (pyprojectText !== null) {
    return dedupe(fromPyprojectToml(pyprojectText, path.join(dir, "pyproject.toml")));
  }

  return [];
}

function fromPipfileLock(lock, manifestPath) {
  const deps = [];
  for (const [group, usageContext] of [
    [lock.default, "production"],
    [lock.develop, "development"],
  ]) {
    if (!group) continue;
    for (const [name, info] of Object.entries(group)) {
      const version = stripPin(info.version);
      if (!version) continue;
      deps.push(makeDep(name, version, manifestPath, { usageContext, dependencyScope: "unknown" }));
    }
  }
  return deps;
}

function fromRequirementsTxt(text, manifestPath, usageContext) {
  const deps = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;

    const match = line.match(
      /^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;,]+)/
    );
    if (!match) continue;

    deps.push(
      makeDep(match[1], match[4], manifestPath, {
        usageContext,
        dependencyScope: "direct",
        resolved: match[3] === "==" ? undefined : false,
      })
    );
  }
  return deps;
}

// Best-effort: handles PEP 621 `dependencies = [...]` / `optional-dependencies.<group>`
// and Poetry `[tool.poetry.dependencies]` / `[tool.poetry.group.<name>.dependencies]` /
// legacy `[tool.poetry.dev-dependencies]` blocks. Full TOML parsing (nested tables,
// inline tables, multi-line arrays with trailing commas across arbitrary formatting) is
// out of scope for v1.
function fromPyprojectToml(text, manifestPath) {
  const deps = [];

  const pep621 = text.match(/\bdependencies\s*=\s*\[([\s\S]*?)\]/);
  if (pep621) {
    deps.push(...parseTomlStringArray(pep621[1], manifestPath, "production"));
  }
  // Standard PEP 621 shape: a single [project.optional-dependencies] table whose
  // entries are `group = ["pkg>=1.0", ...]` arrays, e.g. `dev = [...]`, `test = [...]`.
  const optionalBlock = text.match(/\[project\.optional-dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (optionalBlock) {
    for (const match of optionalBlock[1].matchAll(/([\w-]+)\s*=\s*\[([\s\S]*?)\]/g)) {
      const [, groupName, arrayBody] = match;
      const usageContext = DEV_GROUP_RE.test(groupName) ? "development" : "production";
      deps.push(...parseTomlStringArray(arrayBody, manifestPath, usageContext));
    }
  }

  const poetryMain = text.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetryMain) {
    deps.push(...parsePoetryTable(poetryMain[1], manifestPath, "production"));
  }
  const poetryLegacyDev = text.match(/\[tool\.poetry\.dev-dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetryLegacyDev) {
    deps.push(...parsePoetryTable(poetryLegacyDev[1], manifestPath, "development"));
  }
  for (const match of text.matchAll(/\[tool\.poetry\.group\.([\w-]+)\.dependencies\]([\s\S]*?)(?:\n\[|$)/g)) {
    const [, groupName, body] = match;
    const usageContext = DEV_GROUP_RE.test(groupName) ? "development" : "production";
    deps.push(...parsePoetryTable(body, manifestPath, usageContext));
  }

  return deps;
}

function parseTomlStringArray(source, manifestPath, usageContext) {
  const deps = [];
  for (const raw of source.match(/"([^"]+)"|'([^']+)'/g) ?? []) {
    const spec = raw.slice(1, -1);
    const match = spec.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;,]*)/);
    if (match?.[1] && match[4]) {
      deps.push(makeDep(match[1], match[4], manifestPath, { usageContext, dependencyScope: "direct", resolved: false }));
    }
  }
  return deps;
}

function parsePoetryTable(source, manifestPath, usageContext) {
  const deps = [];
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z0-9._-]+)\s*=\s*"([^"]+)"/);
    if (match && match[1].toLowerCase() !== "python") {
      deps.push(makeDep(match[1], match[2], manifestPath, { usageContext, dependencyScope: "direct", resolved: false }));
    }
  }
  return deps;
}

function makeDep(name, versionSpec, manifestPath, { usageContext, dependencyScope, resolved }) {
  return {
    ecosystem: "PyPI",
    name: normalizePyPiName(name),
    version: stripRangePrefix(versionSpec),
    manifestPath,
    dependencyScope,
    usageContext,
    ...(resolved === false ? { resolved: false } : {}),
  };
}

// PEP 503 normalization, since OSV.dev/PyPI treat e.g. "PyYAML" and "pyyaml" as the
// same package.
function normalizePyPiName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

function stripPin(version) {
  return version ? version.replace(/^==/, "") : null;
}

function stripRangePrefix(range) {
  return String(range).replace(/^[\^~>=<\s]+/, "");
}

function dedupe(deps) {
  const seen = new Set();
  const out = [];
  for (const dep of deps) {
    const key = `${dep.name}@${dep.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(dep);
  }
  return out;
}

async function readJson(filePath) {
  const text = await readText(filePath);
  return text === null ? null : JSON.parse(text);
}

async function readText(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}
