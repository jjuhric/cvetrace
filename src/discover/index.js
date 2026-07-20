import { readdir } from "node:fs/promises";
import path from "node:path";
import { discoverNode } from "./node.js";
import { discoverJava } from "./java.js";
import { discoverPython } from "./python.js";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "venv",
  ".venv",
  "target",
  "build",
  "dist",
  "__pycache__",
]);

const PYTHON_MANIFESTS = ["Pipfile.lock", "requirements.txt", "pyproject.toml"];
const JAVA_MANIFESTS = ["pom.xml", "build.gradle", "build.gradle.kts"];

// Walks the target directory (skipping node_modules, .git, venv, target, build, etc.),
// detects manifests per ecosystem, and dispatches to the matching parser.
export async function discover(targetPath) {
  const results = [];
  await walk(targetPath, results);
  return results;
}

async function walk(dir, results) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  const fileNames = new Set(
    entries.filter((entry) => entry.isFile()).map((entry) => entry.name)
  );

  if (fileNames.has("package.json")) {
    results.push(...(await discoverNode(dir)));
  }
  if (JAVA_MANIFESTS.some((name) => fileNames.has(name))) {
    results.push(...(await discoverJava(dir)));
  }
  if (PYTHON_MANIFESTS.some((name) => fileNames.has(name))) {
    results.push(...(await discoverPython(dir)));
  }

  for (const entry of entries) {
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      await walk(path.join(dir, entry.name), results);
    }
  }
}
