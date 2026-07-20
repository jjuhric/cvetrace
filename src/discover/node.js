import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses package.json + package-lock.json (npm lockfile v2/v3) into
// { ecosystem: "npm", name, version } tuples, including the resolved
// transitive tree. Falls back to package.json ranges (best-effort) if no lockfile exists.
// Each tuple is also tagged with dependencyScope ("direct"/"transitive"), usageContext
// ("production"/"development"), and -- for transitive deps -- dependencyPath (the chain
// from a direct dependency down to this package) -- see buildScopeMap below.
export async function discoverNode(dir) {
  const lockPath = path.join(dir, "package-lock.json");
  const lock = await readJson(lockPath);

  if (lock?.packages) {
    return dedupe(fromLockfilePackages(lock.packages, lockPath));
  }

  return discoverNodeFromPackageJson(dir);
}

function fromLockfilePackages(packages, manifestPath) {
  const scope = buildScopeMap(packages);
  const deps = [];
  for (const [pkgPath, info] of Object.entries(packages)) {
    if (pkgPath === "" || !info.version) continue;
    const name = info.name ?? packageNameFromPath(pkgPath);
    deps.push({
      ecosystem: "npm",
      name,
      version: info.version,
      manifestPath,
      ...scope.classify(name),
    });
  }
  return deps;
}

// Determines, for every package name in the lockfile, whether it's declared directly
// in the root manifest (vs. pulled in transitively), whether it's reachable from
// production dependencies, dev dependencies, or both, and -- for transitive packages --
// the shortest chain from a direct dependency down to it (e.g. ["webpack",
// "loader-utils", "vulnerable-pkg"]), by walking the lockfile's own per-package
// "dependencies" declarations as a name-keyed graph via BFS, seeded from the root
// entry's dependencies/devDependencies. This is name-based (not per-resolved-instance),
// so it can be imprecise if a project resolves multiple versions of the same package
// name — rare in practice given npm's default deduplication.
function buildScopeMap(packages) {
  const root = packages[""] ?? {};
  const prodDirect = new Set(Object.keys(root.dependencies ?? {}));
  const devDirect = new Set(Object.keys(root.devDependencies ?? {}));

  const requiresByName = new Map();
  for (const [pkgPath, info] of Object.entries(packages)) {
    if (pkgPath === "") continue;
    const name = info.name ?? packageNameFromPath(pkgPath);
    const required = [
      ...Object.keys(info.dependencies ?? {}),
      ...Object.keys(info.peerDependencies ?? {}),
      ...Object.keys(info.optionalDependencies ?? {}),
    ];
    if (!requiresByName.has(name)) requiresByName.set(name, new Set());
    for (const dep of required) requiresByName.get(name).add(dep);
  }

  const prodPredecessors = bfsPredecessors(prodDirect, requiresByName);
  const devPredecessors = bfsPredecessors(devDirect, requiresByName);

  return {
    classify(name) {
      const dependencyScope = prodDirect.has(name) || devDirect.has(name) ? "direct" : "transitive";
      const usageContext = prodPredecessors.has(name)
        ? "production"
        : devPredecessors.has(name)
          ? "development"
          : "unknown";
      const predecessors = usageContext === "production" ? prodPredecessors : devPredecessors;
      const dependencyPath =
        dependencyScope === "transitive" ? reconstructPath(name, predecessors) : null;
      return { dependencyScope, usageContext, dependencyPath };
    },
  };
}

// Breadth-first, so the reconstructed path is the shortest chain from a direct
// dependency to any given package -- an index-based queue (not Array#shift) keeps this
// O(n) rather than O(n^2) on large lockfiles.
function bfsPredecessors(seed, requiresByName) {
  const predecessorOf = new Map();
  const queue = [];
  for (const name of seed) {
    predecessorOf.set(name, null);
    queue.push(name);
  }

  let head = 0;
  while (head < queue.length) {
    const name = queue[head++];
    for (const dep of requiresByName.get(name) ?? []) {
      if (!predecessorOf.has(dep)) {
        predecessorOf.set(dep, name);
        queue.push(dep);
      }
    }
  }
  return predecessorOf;
}

function reconstructPath(name, predecessorOf) {
  if (!predecessorOf.has(name)) return null;
  const chain = [];
  for (let current = name; current !== null; current = predecessorOf.get(current)) {
    chain.unshift(current);
  }
  return chain;
}

function packageNameFromPath(pkgPath) {
  const idx = pkgPath.lastIndexOf("node_modules/");
  return idx === -1 ? pkgPath : pkgPath.slice(idx + "node_modules/".length);
}

async function discoverNodeFromPackageJson(dir) {
  const manifestPath = path.join(dir, "package.json");
  const pkg = await readJson(manifestPath);
  if (!pkg) return [];

  const prod = Object.entries(pkg.dependencies ?? {}).map(([name, range]) => [name, range, "production"]);
  const dev = Object.entries(pkg.devDependencies ?? {}).map(([name, range]) => [name, range, "development"]);

  return dedupe(
    [...prod, ...dev].map(([name, range, usageContext]) => ({
      ecosystem: "npm",
      name,
      version: stripRangePrefix(range),
      manifestPath,
      resolved: false,
      dependencyScope: "direct",
      usageContext,
      dependencyPath: null,
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
