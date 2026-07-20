import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses package.json + package-lock.json (npm lockfile v2/v3) into
// { ecosystem: "npm", name, version } tuples, including the resolved
// transitive tree. Falls back to package.json ranges (best-effort) if no lockfile exists.
// Each tuple is also tagged with dependencyScope ("direct"/"transitive") and
// usageContext ("production"/"development") — see buildScopeMap below — so the report
// can flag the common false-positive case of a vulnerable dev/build-only tool that
// never ships, without claiming to know whether the vulnerable code is actually called.
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
// in the root manifest (vs. pulled in transitively) and whether it's reachable from
// production dependencies, dev dependencies, or both — by walking the lockfile's own
// per-package "dependencies" declarations as a name-keyed graph, seeded from the root
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

  const prodReachable = bfsReachable(prodDirect, requiresByName);
  const devReachable = bfsReachable(devDirect, requiresByName);

  return {
    classify(name) {
      const dependencyScope = prodDirect.has(name) || devDirect.has(name) ? "direct" : "transitive";
      const usageContext = prodReachable.has(name)
        ? "production"
        : devReachable.has(name)
          ? "development"
          : "unknown";
      return { dependencyScope, usageContext };
    },
  };
}

function bfsReachable(seed, requiresByName) {
  const seen = new Set(seed);
  const queue = [...seed];
  while (queue.length > 0) {
    const name = queue.pop();
    for (const dep of requiresByName.get(name) ?? []) {
      if (!seen.has(dep)) {
        seen.add(dep);
        queue.push(dep);
      }
    }
  }
  return seen;
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
