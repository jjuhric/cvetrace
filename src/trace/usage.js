import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { createExcludeMatcher } from "../discover/glob.js";

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

const MAX_FILE_SIZE = 2 * 1024 * 1024; // skip anything oddly large (generated/binary-ish)

const EXTENSIONS_BY_ECOSYSTEM = {
  npm: [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"],
  Maven: [".java", ".kt", ".kts", ".groovy", ".scala"],
  PyPI: [".py"],
};

// Walks the target directory once, collecting source file contents bucketed by
// ecosystem-relevant extension, then tags each finding with codeReference
// ("found"/"not-found"/"unknown"): whether that package is actually imported/required
// anywhere in the project's own source -- not just declared in a manifest.
//
// This is a usage signal, not reachability analysis: "found" means the package is
// referenced somewhere, not that the specific vulnerable function is called; "not-found"
// means no reference was detected with this heuristic, not a proof the code is unused
// (dynamic requires, reflection, string-built imports, etc. would be missed). Java/
// Kotlin detection is itself a heuristic -- it checks for `import <groupId>`, which
// assumes the library's Java package matches its Maven/Gradle groupId (usually true,
// not guaranteed). Python detection checks for the PyPI distribution name directly,
// which misses packages whose import name differs from their published name (e.g.
// PyYAML is `import yaml`) -- a known, documented gap, not silently "handled".
export async function detectCodeReferences(targetPath, findings, excludePatterns) {
  const ecosystems = new Set(findings.map((f) => f.ecosystem));
  const relevantExtensions = new Set();
  for (const eco of ecosystems) {
    for (const ext of EXTENSIONS_BY_ECOSYSTEM[eco] ?? []) relevantExtensions.add(ext);
  }

  const filesByEcosystem = new Map();
  if (relevantExtensions.size > 0) {
    const isExcluded = createExcludeMatcher(excludePatterns);
    const collected = [];
    await walkSource(targetPath, targetPath, relevantExtensions, isExcluded, collected);
    for (const eco of ecosystems) {
      const exts = new Set(EXTENSIONS_BY_ECOSYSTEM[eco] ?? []);
      filesByEcosystem.set(
        eco,
        collected.filter((file) => exts.has(file.ext)).map((file) => file.content)
      );
    }
  }

  return findings.map((finding) => ({
    ...finding,
    codeReference: checkReference(finding, filesByEcosystem.get(finding.ecosystem)),
  }));
}

function checkReference(finding, files) {
  if (!files || files.length === 0) return "unknown";
  const pattern = referencePattern(finding);
  if (!pattern) return "unknown";
  return files.some((content) => pattern.test(content)) ? "found" : "not-found";
}

function referencePattern(finding) {
  if (finding.ecosystem === "npm") {
    const name = escapeRegExp(finding.name);
    return new RegExp(
      `require\\(\\s*['"]${name}(?:/[^'"]*)?['"]|` +
        `from\\s+['"]${name}(?:/[^'"]*)?['"]|` +
        `import\\(\\s*['"]${name}(?:/[^'"]*)?['"]|` +
        `import\\s+['"]${name}(?:/[^'"]*)?['"]`
    );
  }
  if (finding.ecosystem === "Maven") {
    const groupId = finding.name.split(":")[0];
    if (!groupId) return null;
    return new RegExp(`import\\s+${escapeRegExp(groupId)}`);
  }
  if (finding.ecosystem === "PyPI") {
    const name = escapeRegExp(finding.name);
    return new RegExp(`^\\s*(?:import\\s+${name}\\b|from\\s+${name}(?:\\.[\\w.]+)?\\s+import)`, "m");
  }
  return null;
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function walkSource(dir, scanRoot, extensions, isExcluded, collected) {
  const relPath = path.relative(scanRoot, dir);
  if (relPath && isExcluded(relPath)) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        await walkSource(path.join(dir, entry.name), scanRoot, extensions, isExcluded, collected);
      }
      continue;
    }

    const ext = path.extname(entry.name);
    if (!extensions.has(ext)) continue;

    const filePath = path.join(dir, entry.name);
    try {
      const stats = await stat(filePath);
      if (stats.size > MAX_FILE_SIZE) continue;
      collected.push({ ext, content: await readFile(filePath, "utf8") });
    } catch {
      // unreadable (permissions, race with deletion, binary read failure) -- skip
    }
  }
}
