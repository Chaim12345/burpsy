// Regenerates src/lib/gated-routes.ts from the Go route manifest (burpsy-react-ui-p1uz).
//   bun scripts/gen-gated-routes.ts          write the file
//   bun scripts/gen-gated-routes.ts --check  exit 1 if it is stale
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gatedTable, renderGatedRoutesModule, renderRouteRiskModule, riskTable } from "../src/lib/route-manifest";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..", "..");
const manifestGo = readFileSync(join(web, "route_manifest.go"), "utf8");
const agentToolsGo = readFileSync(join(web, "agent_tools.go"), "utf8");

// Two generated views of the one manifest: the gate table the api client enforces on, and the risk
// inventory the REST-API settings page renders (burpsy-react-ui-wt0r). Both regenerate and check here
// so a route added or reclassified in Go without regenerating fails `bun run check`.
const targets = [
 { out: join(here, "..", "src", "lib", "gated-routes.ts"), next: renderGatedRoutesModule(gatedTable(manifestGo, agentToolsGo)), label: "src/lib/gated-routes.ts" },
 { out: join(here, "..", "src", "lib", "route-risk.ts"), next: renderRouteRiskModule(riskTable(manifestGo)), label: "src/lib/route-risk.ts" },
];

const patterns = Object.keys(riskTable(manifestGo)).length;

if (process.argv.includes("--check")) {
 for (const { out, next, label } of targets) {
  let current = "";
  try {
   current = readFileSync(out, "utf8");
  } catch {
   current = "";
  }
  if (current !== next) {
   console.error(`${label} is stale: run \`bun run gen:gated-routes\``);
   process.exit(1);
  }
 }
 console.log(`Generated route tables are current (${patterns} patterns).`);
} else {
 for (const { out, next, label } of targets) {
  writeFileSync(out, next);
  console.log(`Wrote ${label}`);
 }
}
