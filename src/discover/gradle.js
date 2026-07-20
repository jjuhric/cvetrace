import { spawn } from "node:child_process";
import { writeFile, rm, access, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

// A throwaway Gradle init script that, for every project in the build, walks each
// resolvable configuration and prints its fully resolved module coordinates, tagged
// with the configuration name (so callers can classify production vs. test-only by
// whether every resolving configuration is test-related), plus which coordinates are
// *directly* declared in a `dependencies {}` block (vs. pulled in transitively) via
// config.dependencies. Running this forces the same configuration-phase evaluation
// (and dependency resolution) that `gradle dependencies` relies on, but in a flat,
// easy-to-parse line format instead of Gradle's indented tree output. `help` is used as
// the task because it exists in every Gradle project and doesn't otherwise build/test.
const INIT_SCRIPT = `
allprojects { proj ->
  proj.afterEvaluate {
    proj.configurations.each { config ->
      config.dependencies.each { dep ->
        if (dep.group != null) {
          println("CVETRACE_DIRECT|" + proj.projectDir.absolutePath + "|" + dep.group + ":" + dep.name)
        }
      }
      if (config.canBeResolved) {
        try {
          config.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { dep ->
            println("CVETRACE_DEP|" + proj.projectDir.absolutePath + "|" + config.name + "|" + dep.moduleGroup + ":" + dep.moduleName + ":" + dep.moduleVersion)
          }
        } catch (ignored) {
        }
      }
    }
  }
}
`;

// Configuration names containing "test" (testImplementation, testRuntimeClasspath,
// androidTestImplementation, ...) are Gradle's standard convention for test-only
// dependencies. compileOnly is treated as production since it's still needed to compile
// and ship-adjacent, even though it isn't bundled — erring toward not hiding a real
// production-relevant CVE behind a wrong "development" tag.
const TEST_CONFIG_RE = /test/i;

const GRADLE_TIMEOUT_MS = 5 * 60 * 1000;

// Given every directory discovered to contain a build.gradle/build.gradle.kts, groups
// them by their actual Gradle build root (nearest ancestor, bounded by scanRoot, that
// looks like an invocable root: has a wrapper or a settings.gradle[.kts]) and invokes
// Gradle once per unique root -- multi-module builds must be evaluated from the root,
// and doing it once per root avoids redundant Gradle invocations for the same build.
export async function discoverGradle(gradleDirs, scanRoot) {
  const rootToMembers = new Map();
  for (const dir of gradleDirs) {
    const root = await findGradleRoot(dir, scanRoot);
    if (!rootToMembers.has(root)) rootToMembers.set(root, []);
    rootToMembers.get(root).push(dir);
  }

  const results = [];
  for (const [root, memberDirs] of rootToMembers) {
    try {
      results.push(...(await resolveGradleProject(root)));
    } catch (err) {
      console.error(
        `cvetrace: couldn't invoke Gradle for ${root} (${err.message}); ` +
          "falling back to best-effort static parsing of build.gradle."
      );
      for (const dir of memberDirs) {
        results.push(...(await staticFallback(dir)));
      }
    }
  }
  return dedupe(results);
}

async function findGradleRoot(startDir, scanRoot) {
  const boundary = path.resolve(scanRoot);
  let dir = path.resolve(startDir);
  for (;;) {
    if (
      (await exists(path.join(dir, "gradlew"))) ||
      (await exists(path.join(dir, "gradlew.bat"))) ||
      (await exists(path.join(dir, "settings.gradle"))) ||
      (await exists(path.join(dir, "settings.gradle.kts")))
    ) {
      return dir;
    }
    if (dir === boundary) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return startDir;
}

async function resolveGradleProject(rootDir) {
  const invocation = await findGradleCommand(rootDir);
  const initScriptPath = path.join(os.tmpdir(), `cvetrace-init-${crypto.randomUUID()}.gradle`);
  await writeFile(initScriptPath, INIT_SCRIPT, "utf8");

  try {
    const stdout = await runGradle(invocation, rootDir, initScriptPath);
    return parseDependencyLines(stdout);
  } finally {
    await rm(initScriptPath, { force: true });
  }
}

async function findGradleCommand(dir) {
  const isWindows = process.platform === "win32";
  const wrapperPath = path.join(dir, isWindows ? "gradlew.bat" : "gradlew");

  if (await exists(wrapperPath)) {
    return isWindows
      ? { command: "cmd.exe", prefixArgs: ["/c", wrapperPath] }
      : { command: "sh", prefixArgs: [wrapperPath] };
  }

  // No local wrapper -- fall back to a system-installed `gradle` on PATH, if any.
  return isWindows
    ? { command: "cmd.exe", prefixArgs: ["/c", "gradle.bat"] }
    : { command: "gradle", prefixArgs: [] };
}

function runGradle({ command, prefixArgs }, cwd, initScriptPath) {
  return new Promise((resolve, reject) => {
    const args = [...prefixArgs, "help", "--init-script", initScriptPath, "--quiet", "--console=plain"];
    const child = spawn(command, args, { cwd });

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("Gradle invocation timed out"));
    }, GRADLE_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`Gradle exited with code ${code}: ${stderr.trim().slice(0, 300)}`));
        return;
      }
      resolve(stdout);
    });
  });
}

// Exported for unit testing without spawning a real Gradle process.
export function parseDependencyLines(stdout) {
  const directDeclared = new Set();
  const resolved = new Map(); // "projectDir|group:artifact:version" -> { projectDir, name, version, configs: Set }

  for (const line of stdout.split(/\r?\n/)) {
    if (line.startsWith("CVETRACE_DIRECT|")) {
      const [, projectDir, name] = line.split("|");
      directDeclared.add(`${projectDir}|${name}`);
      continue;
    }
    if (line.startsWith("CVETRACE_DEP|")) {
      const [, projectDir, configName, coordinate] = line.split("|");
      const [group, artifact, version] = coordinate.split(":");
      if (!group || !artifact || !version) continue;

      const key = `${projectDir}|${group}:${artifact}:${version}`;
      if (!resolved.has(key)) {
        resolved.set(key, { projectDir, name: `${group}:${artifact}`, version, configs: new Set() });
      }
      resolved.get(key).configs.add(configName);
    }
  }

  const deps = [];
  for (const { projectDir, name, version, configs } of resolved.values()) {
    const isDirect = directDeclared.has(`${projectDir}|${name}`);
    const isProduction = [...configs].some((config) => !TEST_CONFIG_RE.test(config));
    deps.push({
      ecosystem: "Maven",
      name,
      version,
      // Gradle always reports projectDir as absolute; relativize so manifestPath reads
      // consistently with the other discoverers, which preserve whatever style (relative
      // or absolute) the scanned target path was given in.
      manifestPath: path.join(path.relative(process.cwd(), projectDir), "build.gradle"),
      dependencyScope: isDirect ? "direct" : "transitive",
      usageContext: isProduction ? "production" : "development",
    });
  }
  return deps;
}

// Used only when Gradle itself can't be invoked (no wrapper, no system install, or the
// invocation failed/timed out) -- a regex scan for literal `"group:artifact:version"`
// dependency declarations. Misses anything using variables, `ext {}` properties, or
// version catalogs, since that requires actually evaluating the build script.
const GRADLE_DEP_RE =
  /(implementation|api|compile|runtimeOnly|testImplementation)\s*[(]?\s*["']([\w.-]+):([\w.-]+):([\w.\-+]+)["']/g;

async function staticFallback(dir) {
  for (const file of ["build.gradle", "build.gradle.kts"]) {
    const filePath = path.join(dir, file);
    const text = await readText(filePath);
    if (text !== null) {
      const deps = [];
      for (const match of text.matchAll(GRADLE_DEP_RE)) {
        const [, directive, group, artifact, version] = match;
        deps.push({
          ecosystem: "Maven",
          name: `${group}:${artifact}`,
          version,
          manifestPath: filePath,
          resolved: false,
          dependencyScope: "direct",
          usageContext: TEST_CONFIG_RE.test(directive) ? "development" : "production",
        });
      }
      return deps;
    }
  }
  return [];
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

async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readText(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}
