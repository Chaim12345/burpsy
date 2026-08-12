#!/usr/bin/env bun
/**
 * Export every component in the design file to JSX, one file each.
 *
 * `get_jsx` returns the same dialect the `render` tool accepts, so these files
 * are the design's own description of each component rather than a screenshot
 * someone has to eyeball. They are the input for hand-writing the React
 * equivalents: exact geometry, colours, sizes and copy, with no transcription
 * from a picture.
 *
 * Runs on the typed client so all ~20 exports share one connection instead of
 * paying a process launch each.
 *
 * Usage: bun export-design-jsx.ts [--doc tab-4] [--out ../design/jsx]
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createOpenpencilClient } from "./openpencil-client";

process.env.OPENPENCIL_MCP_AUTH_TOKEN = JSON.parse(
  readFileSync("/root/.openpencil/mcp.json", "utf8"),
).authToken;

const args = process.argv.slice(2);
const flag = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const DOC = flag("--doc") ?? "tab-4";
const OUT = resolve(dirname(Bun.main), flag("--out") ?? "../design/jsx");

// The client wraps results as {raw:{raw:{content:[{text}]}}}; the payload is JSON in that text.
const unwrap = (r: any) => {
  let cur = r;
  while (cur && typeof cur === "object" && "raw" in cur) cur = (cur as any).raw;
  const text = cur?.content?.[0]?.text;
  return typeof text === "string" ? JSON.parse(text) : cur;
};

const slug = (name: string) =>
  name
    .replace(/^00 Components \//, "")
    .trim()
    .replace(/\s*\/\s*/g, "-")
    .replace(/\s+/g, "-")
    .toLowerCase();

mkdirSync(OUT, { recursive: true });

const client = await createOpenpencilClient();
try {
  const { components } = unwrap(
    await client.get_components({ document_id: DOC, limit: 200 }),
  ) as { components: Array<{ id: string; name: string }> };

  console.log(`${components.length} components -> ${OUT}`);
  const index: string[] = [];

  for (const c of components) {
    const res = unwrap(await client.get_jsx({ document_id: DOC, id: c.id })) as { jsx?: string };
    const jsx = res?.jsx ?? "";
    if (!jsx) {
      console.log(`  SKIP ${c.name} (no jsx returned)`);
      continue;
    }
    const file = `${slug(c.name)}.jsx`;
    // Keep the source id in the file: when the React version and the design drift,
    // this is what lets you go straight back to the node that defined it.
    writeFileSync(
      join(OUT, file),
      `// ${c.name}\n// design node ${c.id} — exported by scripts/export-design-jsx.ts, do not hand-edit\n${jsx}\n`,
    );
    index.push(`- \`${file}\` — ${c.name} (${c.id})`);
    console.log(`  ${file.padEnd(34)} ${jsx.length} chars`);
  }

  writeFileSync(
    join(OUT, "README.md"),
    `# Design components as JSX\n\n` +
      `Exported from the OpenPencil source with \`bun scripts/export-design-jsx.ts\`.\n` +
      `This is the design's own description of each component — exact geometry,\n` +
      `colours and copy — so the React equivalents can be written from data rather\n` +
      `than transcribed from a screenshot.\n\n` +
      `Regenerate after changing the design; do not hand-edit these files.\n\n` +
      index.join("\n") + "\n",
  );
  console.log(`\nwrote ${index.length} files + README.md`);
} finally {
  await client.close();
}
