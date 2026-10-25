// Regenerates src/lib/api-schema.d.ts — the console's typed API surface — from the server's own
// OpenAPI document (burpsy-react-ui-pg5a).
//
//   bun run gen:api-types          write the file
//   bun run check:api-types        exit 1 if it is stale
//
// The document is built by `go run ./cmd/openapi-dump` from the route manifest and schema table, so
// this file can never describe a route the server does not have: a route added in Go without
// regenerating fails `bun run check`, the same gate gen-gated-routes keeps on the risk tables.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const burpsyGo = join(here, "..", "..", "..", "..");
const out = join(here, "..", "src", "lib", "api-schema.d.ts");

const spec = execFileSync("go", ["run", "./cmd/openapi-dump"], { cwd: burpsyGo, maxBuffer: 64 * 1024 * 1024 });
const tmp = join(mkdtempSync(join(tmpdir(), "burpsy-openapi-")), "openapi.json");
writeFileSync(tmp, spec);

// The generator's own toolchain in tools/api-types: the app pins typescript@7 (native, no JS API)
// and openapi-typescript needs the TypeScript 5 JS API, so it carries its own. Install it once with
// `npm --prefix tools/api-types install`.
import { existsSync } from "node:fs";
const bin = join(here, "..", "tools", "api-types", "node_modules", ".bin", "openapi-typescript");
if (!existsSync(bin)) {
 console.error("openapi-typescript is not installed; run `npm --prefix tools/api-types install` first.");
 process.exit(1);
}
const generated = execFileSync(bin, [tmp, "--alphabetize", "--export-type"], {
 maxBuffer: 64 * 1024 * 1024,
}).toString();

const header = `/**
 * Generated from the server's OpenAPI document by scripts/gen-api-types.mjs (burpsy-react-ui-pg5a).
 * Do not edit: \`bun run gen:api-types\` rewrites this file, and \`bun run check\` fails when it is
 * stale. The document itself is generated from internal/web/route_manifest.go and
 * internal/web/route_schemas.go — change the surface there, never here.
 */
`;
const next = header + generated;

if (process.argv.includes("--check")) {
 let current = "";
 try {
  current = readFileSync(out, "utf8");
 } catch {
  current = "";
 }
 if (current !== next) {
  console.error("src/lib/api-schema.d.ts is stale: run `bun run gen:api-types`");
  process.exit(1);
 }
 console.log("Generated API types are current.");
} else {
 writeFileSync(out, next);
 console.log("Wrote src/lib/api-schema.d.ts");
}
