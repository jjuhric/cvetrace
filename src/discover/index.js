import { readdir } from "node:fs/promises";
import path from "node:path";
import { discoverNode } from "./node.js";
import { discoverJava } from "./java.js";
import { discoverGradle } from "./gradle.js";
import { discoverPython } from "./python.js";
import { createExcludeMatcher } from "./glob.js";

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

// Walks the target directory (skipping node_modules, .git, venv, target, build, etc.,
// plus any directory matching an --exclude glob), detects manifests per ecosystem, and
// dispatches to the matching parser. Gradle is handled in a second phase (see below)
// since, unlike the other ecosystems, a multi-module Gradle build must be resolved once
// from its root rather than per-file.
export async function discover(targetPath, options = {}) {
  const isExcluded = createExcludeMatcher(options.excludes);
  const results = [];
  const gradleDirs = [];
  await walk(targetPath, targetPath, results, gradleDirs, isExcluded);

  if (gradleDirs.length > 0) {
    results.push(...(await discoverGradle(gradleDirs, targetPath)));
  }

  return results;
}

async function walk(dir, scanRoot, results, gradleDirs, isExcluded) {
  const relPath = path.relative(scanRoot, dir);
  if (relPath && isExcluded(relPath)) return;

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
  if (fileNames.has("pom.xml")) {
    results.push(...(await discoverJava(dir)));
  }
  if (fileNames.has("build.gradle") || fileNames.has("build.gradle.kts")) {
    gradleDirs.push(dir);
  }
  if (PYTHON_MANIFESTS.some((name) => fileNames.has(name))) {
    results.push(...(await discoverPython(dir)));
  }

  for (const entry of entries) {
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      await walk(path.join(dir, entry.name), scanRoot, results, gradleDirs, isExcluded);
    }
  }
}
