// Regenerates src/lib/gated-routes.ts from the Go route manifest (burpsy-react-ui-p1uz).
//   bun scripts/gen-gated-routes.ts          write the file
//   bun scripts/gen-gated-routes.ts --check  exit 1 if it is stale
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gatedTable, renderGatedRoutesModule } from "../src/lib/route-manifest";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..", "..");
const out = join(here, "..", "src", "lib", "gated-routes.ts");
const table = gatedTable(readFileSync(join(web, "route_manifest.go"), "utf8"), readFileSync(join(web, "agent_tools.go"), "utf8"));
const next = renderGatedRoutesModule(table);
const gated = Object.values(table).filter(Boolean).length;

if (process.argv.includes("--check")) {
 let current = "";
 try {
  current = readFileSync(out, "utf8");
 } catch {
  current = "";
 }
 if (current !== next) {
  console.error("src/lib/gated-routes.ts is stale: run `bun run gen:gated-routes`");
  process.exit(1);
 }
 console.log(`Gated-route table is current (${Object.keys(table).length} patterns, ${gated} gated).`);
} else {
 writeFileSync(out, next);
 console.log(`Wrote ${out} (${Object.keys(table).length} patterns, ${gated} gated).`);
}
