import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses requirements.txt, pyproject.toml (PEP 621 / Poetry), and Pipfile.lock into
// { ecosystem: "PyPI", name, version } tuples. Preference order favors the most
// resolved/precise source: Pipfile.lock (fully resolved) > requirements.txt (usually
// pinned) > pyproject.toml (declared ranges, best-effort — see README limitations).
export async function discoverPython(dir) {
  const pipfileLock = await readJson(path.join(dir, "Pipfile.lock"));
  if (pipfileLock) {
    return dedupe(fromPipfileLock(pipfileLock, path.join(dir, "Pipfile.lock")));
  }

  const requirementsText = await readText(path.join(dir, "requirements.txt"));
  if (requirementsText !== null) {
    return dedupe(fromRequirementsTxt(requirementsText, path.join(dir, "requirements.txt")));
  }

  const pyprojectText = await readText(path.join(dir, "pyproject.toml"));
  if (pyprojectText !== null) {
    return dedupe(fromPyprojectToml(pyprojectText, path.join(dir, "pyproject.toml")));
  }

  return [];
}

function fromPipfileLock(lock, manifestPath) {
  const deps = [];
  for (const group of [lock.default, lock.develop]) {
    if (!group) continue;
    for (const [name, info] of Object.entries(group)) {
      const version = stripPin(info.version);
      if (!version) continue;
      deps.push(makeDep(name, version, manifestPath));
    }
  }
  return deps;
}

function fromRequirementsTxt(text, manifestPath) {
  const deps = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;

    const match = line.match(
      /^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;,]+)/
    );
    if (!match) continue;

    deps.push(makeDep(match[1], match[4], manifestPath, match[3] !== "=="));
  }
  return deps;
}

// Best-effort: handles PEP 621 `dependencies = ["name>=1.2.3", ...]` and Poetry
// `[tool.poetry.dependencies]` `name = "^1.2.3"` blocks. Full TOML parsing (nested
// tables, inline tables, multi-line arrays with trailing commas across arbitrary
// formatting) is out of scope for v1.
function fromPyprojectToml(text, manifestPath) {
  const deps = [];

  const pep621 = text.match(/\bdependencies\s*=\s*\[([\s\S]*?)\]/);
  if (pep621) {
    for (const raw of pep621[1].match(/"([^"]+)"|'([^']+)'/g) ?? []) {
      const spec = raw.slice(1, -1);
      const match = spec.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;,]*)/);
      if (match?.[1] && match[4]) {
        deps.push(makeDep(match[1], match[4], manifestPath, true));
      }
    }
  }

  const poetrySection = text.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetrySection) {
    for (const line of poetrySection[1].split(/\r?\n/)) {
      const match = line.match(/^([A-Za-z0-9._-]+)\s*=\s*"([^"]+)"/);
      if (match && match[1].toLowerCase() !== "python") {
        deps.push(makeDep(match[1], match[2], manifestPath, true));
      }
    }
  }

  return deps;
}

function makeDep(name, versionSpec, manifestPath, unresolved = false) {
  return {
    ecosystem: "PyPI",
    name: normalizePyPiName(name),
    version: stripRangePrefix(versionSpec),
    manifestPath,
    ...(unresolved ? { resolved: false } : {}),
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
