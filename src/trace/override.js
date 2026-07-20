import path from "node:path";

// Generates the exact snippet to force a transitive dependency to a patched version
// without waiting for its direct parent to publish an update -- often the fastest real
// fix for a transitive CVE. Only produced when the finding is confidently transitive
// (dependencyScope === "transitive") and a target version is known; the mechanism
// differs by ecosystem/build tool, and isn't attempted at all for ecosystems where
// cvetrace doesn't currently resolve transitive dependencies (Maven's pom.xml, Python),
// since a "transitive" tag never occurs there in the first place.
export function generateOverrideSnippet(finding) {
  if (finding.dependencyScope !== "transitive") return null;

  const targetVersion = finding.recommendedVersion ?? finding.fixedVersion;
  if (!targetVersion) return null;

  if (finding.ecosystem === "npm") {
    return npmOverride(finding.name, targetVersion);
  }
  if (finding.ecosystem === "Maven" && finding.manifestPath.endsWith("pom.xml")) {
    return mavenOverride(finding.name, targetVersion);
  }
  if (finding.ecosystem === "Maven" && /build\.gradle(\.kts)?$/.test(finding.manifestPath)) {
    return gradleOverride(finding.name, targetVersion, finding.manifestPath);
  }
  return null;
}

function npmOverride(name, version) {
  return {
    file: "package.json",
    instructions: `Force ${name}@${version} regardless of what pulls it in, without waiting for the parent package to publish an update (npm 8.3+; yarn uses a "resolutions" field of the same shape instead).`,
    snippet: JSON.stringify({ overrides: { [name]: version } }, null, 2),
  };
}

function mavenOverride(coordinate, version) {
  const [groupId, artifactId] = coordinate.split(":");
  return {
    file: "pom.xml",
    instructions: `Force ${coordinate}:${version} via <dependencyManagement>, without waiting for the parent artifact to publish an update.`,
    snippet: [
      "<dependencyManagement>",
      "  <dependencies>",
      "    <dependency>",
      `      <groupId>${groupId}</groupId>`,
      `      <artifactId>${artifactId}</artifactId>`,
      `      <version>${version}</version>`,
      "    </dependency>",
      "  </dependencies>",
      "</dependencyManagement>",
    ].join("\n"),
  };
}

function gradleOverride(coordinate, version, manifestPath) {
  return {
    file: path.basename(manifestPath),
    instructions: `Force ${coordinate}:${version} across all configurations, without waiting for the parent dependency to publish an update.`,
    snippet: ["configurations.all {", `    resolutionStrategy.force '${coordinate}:${version}'`, "}"].join(
      "\n"
    ),
  };
}
