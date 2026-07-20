// Walks the target directory (skipping node_modules, .git, venv, target, build, etc.),
// detects manifests per ecosystem, and dispatches to the matching parser.
// TODO: implement directory walk + dispatch to ./node.js, ./python.js, ./java.js.
export async function discover(targetPath) {
  throw new Error("not implemented");
}
