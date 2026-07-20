// Parses package.json + package-lock.json (npm lockfile v2/v3) into
// { ecosystem: "npm", name, version } tuples, including the resolved
// transitive tree. Falls back to package.json ranges (best-effort) if no lockfile exists.
// TODO: implement.
export async function discoverNode(manifestPath) {
  throw new Error("not implemented");
}
