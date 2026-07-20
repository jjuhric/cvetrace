import { Command } from "commander";
import { scan } from "./index.js";

// TODO: wire up `scan <path> [--json] [--fail-on <severity>]` to src/index.js's
// discover -> trace -> report pipeline once it's implemented.
export function run(argv) {
  const program = new Command();

  program
    .name("cvetrace")
    .description(
      "Scan a Node, Java, or Python project directory for known CVEs in its dependencies."
    )
    .version("0.1.0");

  program
    .command("scan")
    .description("Scan a target directory for CVEs")
    .argument("<path>", "path to the project directory to scan")
    .option("--json", "output a machine-readable JSON report")
    .option(
      "--fail-on <severity>",
      "exit non-zero if a vulnerability at or above this severity is found"
    )
    .action(async (path, options) => {
      await scan(path, options);
    });

  program.parse(argv);
}
