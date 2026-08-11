// Tests for the narrow transit reader. Run with `node scripts/lib/transit.test.mjs`.
//
// The cases below are the transit-format spec's own examples plus the shapes
// Penpot's file data actually uses. The cache cases matter most: a reader whose
// cache drifts one entry out of step with the writer decodes a plausible-looking
// but wrong document, which is exactly the failure mode that would poison
// penpot-export.json without anything noticing.
import { decodeTransit } from "./transit.mjs";

let failures = 0;
function check(name, actual, expected) {
  const a = JSON.stringify(actual, (_, v) => (typeof v === "bigint" ? `bigint:${v}` : v));
  const e = JSON.stringify(expected, (_, v) => (typeof v === "bigint" ? `bigint:${v}` : v));
  if (a !== e) {
    failures++;
    console.error(`FAIL ${name}\n  expected ${e}\n  actual   ${a}`);
  } else {
    console.log(`ok   ${name}`);
  }
}

check("scalars pass through", decodeTransit([1, "two", true, null]), [1, "two", true, null]);
check("keyword becomes its name", decodeTransit("~:foo"), "foo");
check("symbol becomes its name", decodeTransit("~$bar"), "bar");
check("escaped tilde", decodeTransit("~~notatag"), "~notatag");
check("escaped caret", decodeTransit("~^notacache"), "^notacache");
check("uuid keeps string form", decodeTransit("~u81f57451-85cc-819d-8008-712303b37e30"), "81f57451-85cc-819d-8008-712303b37e30");
check("integer tag", decodeTransit("~i42"), 42);
check("double tag", decodeTransit("~d1.5"), 1.5);
check("boolean tags", decodeTransit(["~?t", "~?f"]), [true, false]);
check("big integer becomes BigInt", decodeTransit("~n9007199254740993"), 9007199254740993n);
check("unknown scalar tag is left raw", decodeTransit("~Qwhatever"), "~Qwhatever");

check("empty map", decodeTransit(["^ "]), {});
check("simple map", decodeTransit(["^ ", "~:a", 1, "~:b", 2]), { a: 1, b: 2 });
check("nested map", decodeTransit(["^ ", "~:outer", ["^ ", "~:inner", "v"]]), { outer: { inner: "v" } });

check("set tag flattens to array", decodeTransit(["~#set", [1, 2, 3]]), [1, 2, 3]);
check("list tag flattens to array", decodeTransit(["~#list", ["a", "b"]]), ["a", "b"]);
check("unknown tag becomes tag/rep", decodeTransit(["~#point", [1, 2]]), { tag: "point", rep: [1, 2] });
check("cmap becomes pairs", decodeTransit(["~#cmap", [["^ ", "~:k", 1], "v"]]), [[{ k: 1 }, "v"]]);

// --- the cache ------------------------------------------------------------
// "~:page-id" is >= 4 chars and keyword-prefixed, so the writer caches it at
// index 0 on first use and emits "^0" thereafter. Both maps must come back with
// the same key.
check(
  "cached keyword key reused across maps",
  decodeTransit([["^ ", "~:page-id", 1], ["^ ", "^0", 2]]),
  [{ "page-id": 1 }, { "page-id": 2 }],
);

// Values are cached too when they are keyword-prefixed, and the cache is shared
// with keys — one counter, in encounter order. Here "~:frame-id" takes index 0
// and "~:rect" index 1, so "^0"/"^1" must resolve to key and value respectively.
check(
  "cache is shared between keys and values in encounter order",
  decodeTransit([["^ ", "~:frame-id", "~:rect"], ["^ ", "^0", "^1"]]),
  [{ "frame-id": "rect" }, { "frame-id": "rect" }],
);

// Two asymmetries that between them decide every cache index, and getting
// either wrong shifts the whole cache and silently corrupts the document.
//
// (a) A map KEY of length >= 4 is cached whatever its prefix, but a key shorter
//     than that never is. "r1" must not consume a slot; "name" must.
// (b) A plain string in a VALUE position is never cached however long it is —
//     only `~:`/`~$`/`~#`-prefixed values are. So "rect" as a bare value takes
//     no slot, while "~:rect" does.
check(
  "long keys cached, short keys not, bare string values not",
  decodeTransit([
    ["^ ", "r1", 0, "name", "a", "~:type", "rect"],
    ["^ ", "r1", 4, "^0", "b", "^1", "rect"],
  ]),
  [
    { r1: 0, name: "a", type: "rect" },
    { r1: 4, name: "b", type: "rect" },
  ],
);

check(
  "keyword values do consume a cache slot",
  decodeTransit([
    ["^ ", "name", "a", "~:type", "~:rect"],
    ["^ ", "^0", "b", "^1", "^2"],
  ]),
  [
    { name: "a", type: "rect" },
    { name: "b", type: "rect" },
  ],
);

// Two-character cache codes appear past index 43. Index 44 is "^10": the first
// char contributes 44 and the second 0.
{
  const keys = [];
  const first = ["^ "];
  for (let i = 0; i < 45; i++) {
    keys.push(`~:key-${String(i).padStart(3, "0")}`);
    first.push(keys[i], i);
  }
  const second = ["^ ", "^10", "reused"]; // index 44 -> the 45th cached key
  const [, back] = decodeTransit([first, second]);
  check("two-character cache code", back, { "key-044": "reused" });
}

// --- a realistic Penpot fragment -----------------------------------------
// Objects keyed by uuid, a fill with a colour, corner radii, and an
// applied-tokens map — the exact fields the audit reads.
check(
  "penpot-shaped fragment",
  decodeTransit([
    "^ ",
    "~:pages-index",
    [
      "^ ",
      "~u00000000-0000-0000-0000-000000000001",
      [
        "^ ",
        "~:objects",
        [
          "^ ",
          "~u00000000-0000-0000-0000-0000000000aa",
          ["^ ", "~:name", "toolbar", "~:type", "~:rect", "~:fills", [["^ ", "~:fill-color", "#414547", "~:fill-opacity", 1]], "~:r1", 4, "~:applied-tokens", ["^ ", "~:fill", "color.chrome"]],
        ],
      ],
    ],
  ]),
  {
    "pages-index": {
      "00000000-0000-0000-0000-000000000001": {
        objects: {
          "00000000-0000-0000-0000-0000000000aa": {
            name: "toolbar",
            type: "rect",
            fills: [{ "fill-color": "#414547", "fill-opacity": 1 }],
            r1: 4,
            "applied-tokens": { fill: "color.chrome" },
          },
        },
      },
    },
  },
);

// --- golden fixture from the reference implementation ---------------------
// Everything above encodes MY understanding of transit, which is worth little
// on its own — a reader and a fixture that share the same misconception agree
// perfectly and are both wrong. transit.golden.json was produced by the
// reference transit-js writer (`transit.writer("json")`) from a document shaped
// like Penpot file data: 50 shapes under uuid keys, keyword values, a set, a
// nested tokens-lib, and enough distinct keys to push the cache past index 43
// into two-character codes. transit-js is NOT a dependency of this project; it
// was installed once to generate this file and then removed, which is why the
// fixture is checked in rather than regenerated.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const golden = JSON.parse(readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "transit.golden.json"), "utf8"));
const doc = decodeTransit(golden);

check("golden: file id", doc.id, "81f57451-85cc-819d-8008-712303b37e30");
check("golden: features set", doc.features, ["fdata/objects-map"]);
check("golden: page list", doc.data.pages, ["00000000-0000-0000-0000-0000000000f1"]);

const page = doc.data["pages-index"]["00000000-0000-0000-0000-0000000000f1"];
check("golden: page name", page.name, "Tools");
check("golden: object count", Object.keys(page.objects).length, 50);
check("golden: a shape decodes whole", page.objects["00000000-0000-0000-0000-000000000007"], {
  name: "shape-7",
  type: "rect",
  fills: [{ "fill-color": "#414547", "fill-opacity": 1 }],
  r1: 1,
});
check("golden: applied-tokens survives", page.objects["00000000-0000-0000-0000-000000000010"]["applied-tokens"], { fill: "color.chrome" });
check("golden: tokens-lib survives", doc.data["tokens-lib"].sets.primitives.tokens["space.4"], { value: "12px", type: "spacing" });

// Cache integrity across the whole document: if a single index had drifted, the
// last shapes would carry keys or values belonging to earlier ones.
const ids = Object.keys(page.objects);
check("golden: every shape has the expected key set", new Set(ids.map((id) => Object.keys(page.objects[id]).slice(0, 4).join(","))).size, 1);
check(
  "golden: last shape intact (cache held to the end)",
  page.objects["00000000-0000-0000-0000-000000000049"],
  { name: "shape-49", type: "rect", fills: [{ "fill-color": "#414547", "fill-opacity": 1 }], r1: 1 },
);
check("golden: two distinct fill colours recovered", [...new Set(ids.map((id) => page.objects[id].fills[0]["fill-color"]))].sort(), ["#313335", "#414547"]);

console.log(failures ? `\n${failures} transit test(s) failed.` : "\nAll transit tests passed.");
process.exit(failures ? 1 : 0);
