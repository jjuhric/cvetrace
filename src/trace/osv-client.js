// Thin wrapper around the OSV.dev batch query API (https://osv.dev), no API key required.
// POST https://api.osv.dev/v1/querybatch with { queries: [{ package: { name, ecosystem }, version }] }
// TODO: implement batching + retry.
export async function queryBatch(packages) {
  throw new Error("not implemented");
}
