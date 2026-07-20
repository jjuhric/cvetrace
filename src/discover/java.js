// Parses pom.xml (Maven) <dependency> versions into { ecosystem: "Maven", name, version }
// tuples. build.gradle/.kts supported best-effort via regex — full Gradle resolution
// requires invoking Gradle itself and is out of scope for v1.
// TODO: implement.
export async function discoverJava(manifestPath) {
  throw new Error("not implemented");
}
