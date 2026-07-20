import { readFile } from "node:fs/promises";
import path from "node:path";

// Parses pom.xml (Maven) <dependency> versions, resolving simple ${property} references
// declared in the same pom's <properties> block, into { ecosystem: "Maven",
// name: "groupId:artifactId", version } tuples. build.gradle/.kts is supported
// best-effort via regex — full Gradle resolution requires invoking Gradle itself and
// is out of scope for v1.
export async function discoverJava(dir) {
  const pomText = await readText(path.join(dir, "pom.xml"));
  if (pomText !== null) {
    return dedupe(fromPomXml(pomText, path.join(dir, "pom.xml")));
  }

  for (const gradleFile of ["build.gradle", "build.gradle.kts"]) {
    const gradlePath = path.join(dir, gradleFile);
    const gradleText = await readText(gradlePath);
    if (gradleText !== null) {
      return dedupe(fromGradle(gradleText, gradlePath));
    }
  }

  return [];
}

function fromPomXml(text, manifestPath) {
  const properties = extractProperties(text);
  const deps = [];

  for (const block of text.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
    const groupId = extractTag(block, "groupId");
    const artifactId = extractTag(block, "artifactId");
    const rawVersion = extractTag(block, "version");
    if (!groupId || !artifactId || !rawVersion) continue;

    const version = resolveProperty(rawVersion, properties);
    if (version.includes("$")) continue; // unresolved property reference — v1 limitation

    deps.push({
      ecosystem: "Maven",
      name: `${groupId}:${artifactId}`,
      version,
      manifestPath,
    });
  }
  return deps;
}

function extractProperties(text) {
  const propsBlock = text.match(/<properties>([\s\S]*?)<\/properties>/);
  const props = {};
  if (!propsBlock) return props;

  const tagRe = /<([\w.-]+)>([^<]*)<\/\1>/g;
  let match;
  while ((match = tagRe.exec(propsBlock[1]))) {
    props[match[1]] = match[2].trim();
  }
  return props;
}

function resolveProperty(value, properties) {
  const match = value.trim().match(/^\$\{([\w.-]+)\}$/);
  if (!match) return value.trim();
  return properties[match[1]] ?? value.trim();
}

function extractTag(block, tag) {
  const match = block.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
  return match ? match[1].trim() : null;
}

const GRADLE_DEP_RE =
  /(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[(]?\s*["']([\w.-]+):([\w.-]+):([\w.\-+]+)["']/g;

function fromGradle(text, manifestPath) {
  const deps = [];
  for (const match of text.matchAll(GRADLE_DEP_RE)) {
    deps.push({
      ecosystem: "Maven",
      name: `${match[1]}:${match[2]}`,
      version: match[3],
      manifestPath,
      resolved: false,
    });
  }
  return deps;
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

async function readText(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}
