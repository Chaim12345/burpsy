// Penpot-specific interpretation of a decoded transit payload.
//
// transit.mjs is deliberately generic and hands back `{ tag, rep }` for any tag
// it does not know. Everything Penpot-specific lives here, sourced from
// common/src/app/common/transit.cljc and common/src/app/common/types/tokens_lib.cljc
// on the develop branch:
//
//   ordered-map          rep is a vector of [k, v] pairs (`:wfn vec`). Becomes a
//                        plain object — JS preserves string-key insertion order,
//                        which is the whole point of the type being ordered.
//   ordered-set          rep is a vector. Becomes an array.
//   penpot/tokens-lib    rep is {sets, themes, active-themes}
//   penpot/token-set     rep is {id, name, description, modified-at, tokens}
//   penpot/token         rep is {id, name, type, value, description, modified-at}
//   penpot/token-theme   rep is {id, name, group, description, sets, ...}
//   penpot/pointer       NOT unwrapped — see below, this one must fail loudly.
//
// The pointer case is the important one. Penpot can store file data behind
// `fdata/pointer-map`, where parts of the payload are replaced by references
// that a separate `get-file-fragment` call resolves. get-file inlines them when
// the client does not declare the feature, which is why the fetch script sends
// no `features` — but if a pointer reaches us anyway, the data is incomplete.
// Silently treating a pointer as an empty map would yield a partial token
// catalogue that looks structurally fine, which is precisely the "fail closed
// into a wrong answer" outcome this pipeline must never produce. So pointers
// throw.

const PASSTHROUGH_TAGS = new Set(["penpot/tokens-lib", "penpot/token-set", "penpot/token", "penpot/token-theme"]);

export class PointerEncountered extends Error {}

export function unwrapPenpot(node) {
  if (Array.isArray(node)) return node.map(unwrapPenpot);
  if (node === null || typeof node !== "object") return node;

  if (typeof node.tag === "string" && "rep" in node) {
    if (node.tag === "penpot/pointer") {
      throw new PointerEncountered(
        "the payload contains a penpot/pointer, so file data came back as references rather than inlined data.\n" +
          "Any token catalogue extracted from it would be silently incomplete. Refusing to continue.",
      );
    }
    if (node.tag === "ordered-map") {
      const out = {};
      for (const pair of node.rep) {
        if (!Array.isArray(pair) || pair.length !== 2) throw new Error(`ordered-map entry is not a [k, v] pair: ${JSON.stringify(pair)}`);
        out[unwrapPenpot(pair[0])] = unwrapPenpot(pair[1]);
      }
      return out;
    }
    if (node.tag === "ordered-set") return unwrapPenpot(node.rep);
    if (PASSTHROUGH_TAGS.has(node.tag)) return unwrapPenpot(node.rep);
    return { tag: node.tag, rep: unwrapPenpot(node.rep) };
  }

  const out = {};
  for (const [k, v] of Object.entries(node)) out[k] = unwrapPenpot(v);
  return out;
}

// Penpot stores token sets in a path-prefixed tree, not a flat map: a set named
// "primitives" lives at sets["S-primitives"], and one named "semantic/dark" at
// sets["G-semantic"]["S-dark"] — "S-" marks a set, "G-" a group (tokens_lib.cljc's
// set-prefix/set-group-prefix). Rather than reconstruct names from those
// prefixes, this walks to the leaves and reads each set's own `name`, which
// tokens_lib.cljc stores as the full "semantic/dark" form. That way a change to
// the prefix scheme cannot silently mis-name a set.
export function collectTokenSets(setsTree) {
  const found = [];
  function walk(node) {
    if (node === null || typeof node !== "object" || Array.isArray(node)) return;
    // A leaf is a set: it carries its own name and a tokens map. A group is a
    // plain map of further nodes.
    if (typeof node.name === "string" && node.tokens !== undefined) {
      found.push(node);
      return;
    }
    for (const child of Object.values(node)) walk(child);
  }
  walk(setsTree);
  return found;
}

// Penpot stores a token's type as an internal Clojure keyword, and transit hands
// us that keyword's name — "dimensions", "font-family", "stroke-width". The
// export format this repo consumes uses the DTCG names the plugin API and the
// Tokens Studio ecosystem use — "dimension", "fontFamilies", "borderWidth". They
// are NOT mechanically convertible: `:dimensions` is plural internally and
// singular in DTCG, and `:stroke-width` becomes "borderWidth", not
// "strokeWidth". This is token-type->dtcg-token-type from
// common/src/app/common/types/token.cljc, copied rather than guessed.
const DTCG_TYPE_BY_KEYWORD = {
  boolean: "boolean",
  "border-radius": "borderRadius",
  color: "color",
  dimensions: "dimension",
  "font-family": "fontFamilies",
  "font-size": "fontSizes",
  "font-weight": "fontWeights",
  "letter-spacing": "letterSpacing",
  number: "number",
  opacity: "opacity",
  other: "other",
  rotation: "rotation",
  shadow: "shadow",
  sizing: "sizing",
  spacing: "spacing",
  string: "string",
  "stroke-width": "borderWidth",
  "text-case": "textCase",
  "text-decoration": "textDecoration",
  typography: "typography",
};

// A Penpot Token's `value` is schema'd as `::sm/any`, so nothing in the type
// system says whether a font stack arrives as a list or as one comma-joined
// string — both are plausible and only a live fetch settles it. The generator
// consumes an array, so both forms are normalised to one here rather than
// letting the shape of the answer depend on which the design tool happened to
// write. Quotes are stripped because gen-tokens.mjs adds its own where CSS needs
// them.
export function isReference(value) {
  return typeof value === "string" && /^\{[^}]+\}$/.test(value.trim());
}

// isReference for a fontFamilies value specifically: a bare reference string, OR — the shape Penpot's
// live get-file actually returns for the semantic sets' font.family.body/code — a one-element array
// whose sole entry is a reference string.
//
// This is not hypothetical. The comment on tokenToExportShape below predicted exactly this failure
// mode ("splitting that into a one-element list would turn an alias into a literal font stack") but
// the check it guarded with was string-only, so it did not actually catch the array form. It went
// undetected because fetch-penpot-file.mjs had never run against a real Penpot file with real
// credentials — the first live fetch produced `["{font.family.sans}"]` for font.family.body, a
// one-element font stack literally named "{font.family.sans}", which is precisely the wrong answer
// the comment described and precisely the case this repo's whole reason for existing is to catch
// before it reaches the export.
function isFontFamilyReference(value) {
  if (isReference(value)) return true;
  return Array.isArray(value) && value.length === 1 && isReference(value[0]);
}

function normaliseFontFamilies(value) {
  const list = Array.isArray(value) ? value : String(value).split(",");
  return list.map((f) => String(f).trim().replace(/^["']|["']$/g, "")).filter(Boolean);
}

// The export format this repo consumes wants {name, type, value}, dropping the
// ids and timestamps that change on every save and would make the export diff
// noisy for no reason.
export function tokenToExportShape(token) {
  if (token.name === undefined || token.type === undefined || token.value === undefined) {
    throw new Error(`token is missing name/type/value: ${JSON.stringify(token)}`);
  }
  // Accept a DTCG name as well as a keyword: a future Penpot might serialise the
  // DTCG form directly, and silently mistyping every token would be worse than
  // being lenient about which of two known spellings arrived.
  const known = new Set(Object.values(DTCG_TYPE_BY_KEYWORD));
  const type = DTCG_TYPE_BY_KEYWORD[token.type] ?? (known.has(token.type) ? token.type : undefined);
  if (!type) {
    throw new Error(
      `token "${token.name}" has type "${token.type}", which is neither a known Penpot token-type keyword ` +
        `nor a DTCG type name. If Penpot has added a token type, add it to DTCG_TYPE_BY_KEYWORD in ` +
        `scripts/lib/penpot-file.mjs from token.cljc's token-type->dtcg-token-type.`,
    );
  }
  // A reference is a value in its own right and must survive untouched — the semantic sets'
  // font.family.body is a fontFamilies-typed token holding one reference, and normalising it as a
  // font stack would turn the alias into a literal stack named "{font.family.sans}". Live Penpot
  // wraps that single reference in a one-element array rather than handing back the bare string, so
  // the check has to see through the wrapper — see isFontFamilyReference for how this was found.
  // A wrapped reference is also unwrapped to the bare string: the export format's readers
  // (gen-tokens.mjs's reference resolution, this file's own `resolve()` in penpot-audit.mjs) match
  // references by string equality against "{name}", and a value of `["{font.family.sans}"]` would
  // not equal that string and so would silently stop resolving as a reference at all.
  let value = token.value;
  if (type === "fontFamilies") {
    if (isFontFamilyReference(value)) {
      value = Array.isArray(value) ? value[0] : value;
    } else {
      value = normaliseFontFamilies(value);
    }
  }
  return { name: token.name, type, value };
}

// Walk every shape on every page. Returns [{ pageId, pageName, id, shape }].
// Shape field names come from common/src/app/common/types/shape.cljc:
// :name :type :selrect :width :height :fills :r1..:r4 :rx :ry :applied-tokens
// :shapes :parent-id :frame-id :opacity :strokes :content.
export function collectShapes(fileData) {
  const out = [];
  const pagesIndex = fileData["pages-index"] ?? {};
  for (const [pageId, page] of Object.entries(pagesIndex)) {
    for (const [id, shape] of Object.entries(page?.objects ?? {})) {
      out.push({ pageId, pageName: page?.name ?? "(unnamed page)", id, shape });
    }
  }
  return out;
}

// The path a shape sits at, as a "board / group / shape" string, built by
// walking :parent-id up to the page root. This is what makes the audit's output
// reviewable — "chrome / toolbar" tells you which mockup a measurement came
// from, where a bare uuid does not.
export function shapePath(shape, objects) {
  const names = [];
  let cursor = shape;
  const seen = new Set();
  while (cursor) {
    if (cursor.name && cursor.name !== "Root Frame") names.unshift(cursor.name);
    const parentId = cursor["parent-id"];
    if (!parentId || seen.has(parentId)) break;
    seen.add(parentId);
    cursor = objects[parentId];
  }
  return names.join(" / ");
}
