import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverNode } from "../src/discover/node.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.join(__dirname, "fixtures", "node-fixture-project");

test("discoverNode resolves the pinned dependency from package-lock.json", async () => {
  const deps = await discoverNode(fixtureDir);

  const minimist = deps.find((d) => d.name === "minimist");
  assert.ok(minimist, "expected minimist to be discovered");
  assert.equal(minimist.ecosystem, "npm");
  assert.equal(minimist.version, "0.0.8");
  assert.equal(path.basename(minimist.manifestPath), "package-lock.json");
});
