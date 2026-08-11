// A narrow transit-json READER. Decode only — we never write transit.
//
// Why this exists rather than a dependency: Penpot's `get-file` RPC truncates
// its response when asked for `application/json`, because clojure.data.json has
// no write handler for the TokensLib record (penpot/penpot#7540) — the tokens
// silently go missing. `application/transit+json` returns the complete payload,
// so reading transit is not optional. There is no transit library in this
// project's node_modules and adding one to decode a handful of tag types would
// be a dependency for a fetch script that CI runs at most once per design
// change. This file is ~120 lines and is tested against the transit-format
// spec's own examples in transit.test.mjs.
//
// WHAT IT DOES NOT HANDLE, deliberately:
//   * Writing. Decode only.
//   * Keywords and symbols become plain JS strings — `~:pages-index` decodes to
//     "pages-index". That loses the distinction between the keyword :foo and the
//     string "foo". Penpot's file data uses keywords for map keys and strings
//     for user content (shape names, text), and we only ever read keys we know
//     the schema for, so the collision is not reachable here. It would matter
//     if this were ever used to round-trip data back to Penpot — it is not.
//   * Big integers beyond Number.MAX_SAFE_INTEGER (`~n`) become BigInt, which
//     will throw if something later tries to JSON.stringify them. Penpot's file
//     data has no such values; if one appears, the throw is the correct
//     outcome, because silently losing precision on an id would be worse.
//   * `~#cmap` (maps with non-scalar keys) decodes to an array of [k, v] pairs
//     rather than a Map, because nothing in the file data uses it and a wrong
//     guess would be worse than an obvious shape.
//   * Unknown tags decode to `{ tag, rep }` rather than throwing, so a future
//     Penpot version adding a tag degrades to inspectable data instead of a
//     hard failure in the middle of a fetch.

// Cache mechanics, from the transit spec. The writer assigns an index to every
// cacheable string (map keys, and any `~:`/`~$`/`~#`-prefixed string of length
// >= 4) the first time it appears, then emits `^<code>` for later occurrences.
// The reader must populate its cache in exactly the same encounter order, which
// is why decoding is a single depth-first pass with no lookahead.
const MIN_SIZE_CACHEABLE = 4;
const CACHE_CODE_DIGITS = 44;
const BASE_CHAR_INDEX = 48;
const SUB = "^";
const ESC = "~";
const MAP_MARKER = "^ ";

function isCacheable(str, asMapKey) {
  return (
    str.length >= MIN_SIZE_CACHEABLE &&
    (asMapKey || (str.charAt(0) === ESC && (str.charAt(1) === ":" || str.charAt(1) === "$" || str.charAt(1) === "#")))
  );
}

function cacheIndex(code) {
  // code is the string after the leading "^"
  if (code.length === 1) return code.charCodeAt(0) - BASE_CHAR_INDEX;
  return (code.charCodeAt(0) - BASE_CHAR_INDEX) * CACHE_CODE_DIGITS + (code.charCodeAt(1) - BASE_CHAR_INDEX);
}

export function decodeTransit(json) {
  const cache = [];

  // Resolve a cache reference, or register a newly-seen cacheable string.
  function viaCache(str, asMapKey) {
    if (str.length > 1 && str.charAt(0) === SUB && str !== MAP_MARKER) {
      const hit = cache[cacheIndex(str.slice(1))];
      if (hit === undefined) throw new Error(`transit: cache miss for "${str}"`);
      return hit;
    }
    if (isCacheable(str, asMapKey)) cache.push(str);
    return str;
  }

  function scalar(str) {
    if (str.charAt(0) !== ESC) return str;
    const tag = str.charAt(1);
    const rep = str.slice(2);
    switch (tag) {
      case ESC: // "~~foo" is an escaped literal "~foo"
      case SUB: // "~^foo" is an escaped literal "^foo"
      case "`":
        return str.slice(1);
      case ":": // keyword
      case "$": // symbol
        return rep;
      case "u": // uuid
      case "r": // uri
      case "t": // ISO-8601 instant, kept as its string form
        return rep;
      case "i": // integer
      case "d": // double
      case "f": // bigdec, read as a Number — see the caveats above
        return Number(rep);
      case "m": // instant as epoch millis
        return Number(rep);
      case "n": // big integer
        return BigInt(rep);
      case "?": // boolean
        return rep === "t";
      case "_": // null
        return null;
      default:
        return str; // unknown scalar tag: hand back the raw string
    }
  }

  function value(node, asMapKey) {
    if (typeof node === "string") return scalar(viaCache(node, asMapKey));
    if (Array.isArray(node)) return composite(node);
    // transit-json represents maps as arrays, so a bare JSON object only turns
    // up as the "verbose" transit variant. Penpot does not emit it, but
    // handling it costs three lines and avoids a confusing failure if it did.
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) out[scalar(k)] = value(v, false);
      return out;
    }
    return node; // number, boolean, null
  }

  function composite(arr) {
    if (arr.length === 0) return [];

    if (arr[0] === MAP_MARKER) {
      const out = {};
      for (let i = 1; i < arr.length; i += 2) {
        out[value(arr[i], true)] = value(arr[i + 1], false);
      }
      return out;
    }

    // A tagged value is a two-element array whose head is a "~#tag" string —
    // possibly reaching us as a cache reference, so it has to go through the
    // cache before we can tell.
    if (arr.length === 2 && typeof arr[0] === "string") {
      const head = viaCache(arr[0], false);
      if (head.length > 1 && head.charAt(0) === ESC && head.charAt(1) === "#") {
        const tag = head.slice(2);
        const rep = value(arr[1], false);
        switch (tag) {
          case "set":
          case "list":
            return rep;
          case "cmap":
            // array of alternating k,v -> array of [k, v] pairs
            return Array.isArray(rep) ? rep.reduce((acc, x, i) => (i % 2 ? (acc[acc.length - 1].push(x), acc) : (acc.push([x]), acc)), []) : rep;
          default:
            return { tag, rep };
        }
      }
      // Not a tag after all: fall through, but arr[0] is already cached, so
      // decode it from the resolved string rather than re-running viaCache.
      return [scalar(head), value(arr[1], false)];
    }

    return arr.map((x) => value(x, false));
  }

  return value(json, false);
}
