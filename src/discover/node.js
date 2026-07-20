import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses package.json + package-lock.json (npm lockfile v2/v3) into
// { ecosystem: "npm", name, version } tuples, including the resolved
// transitive tree. Falls back to package.json ranges (best-effort) if no lockfile exists.
export async function discoverNode(dir) {
  const lockPath = path.join(dir, "package-lock.json");
  const lock = await readJson(lockPath);

  if (lock?.packages) {
    return dedupe(fromLockfilePackages(lock.packages, lockPath));
  }

  return discoverNodeFromPackageJson(dir);
}

function fromLockfilePackages(packages, manifestPath) {
  const deps = [];
  for (const [pkgPath, info] of Object.entries(packages)) {
    if (pkgPath === "" || !info.version) continue;
    deps.push({
      ecosystem: "npm",
      name: info.name ?? packageNameFromPath(pkgPath),
      version: info.version,
      manifestPath,
    });
  }
  return deps;
}

function packageNameFromPath(pkgPath) {
  const idx = pkgPath.lastIndexOf("node_modules/");
  return idx === -1 ? pkgPath : pkgPath.slice(idx + "node_modules/".length);
}

async function discoverNodeFromPackageJson(dir) {
  const manifestPath = path.join(dir, "package.json");
  const pkg = await readJson(manifestPath);
  if (!pkg) return [];

  const ranges = { ...pkg.dependencies, ...pkg.devDependencies };
  return dedupe(
    Object.entries(ranges).map(([name, range]) => ({
      ecosystem: "npm",
      name,
      version: stripRangePrefix(range),
      manifestPath,
      resolved: false,
    }))
  );
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
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}
