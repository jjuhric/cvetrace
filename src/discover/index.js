import { readdir } from "node:fs/promises";
import path from "node:path";
import { discoverNode } from "./node.js";

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

// Walks the target directory (skipping node_modules, .git, venv, target, build, etc.),
// detects manifests per ecosystem, and dispatches to the matching parser.
// TODO(M3/M4): dispatch pom.xml -> discoverJava, requirements.txt/pyproject.toml/
// Pipfile.lock -> discoverPython once those parsers are implemented.
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

  for (const entry of entries) {
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      await walk(path.join(dir, entry.name), results);
    }
  }
}
