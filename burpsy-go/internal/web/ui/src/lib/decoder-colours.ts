/**
 * Colour-coding for the Decoder's output, matching Burp's "The data is
 * color-coded to indicate the type of encoding or decoding that is applied."
 *
 * The colour is derived from the transform actually applied to a span — the
 * step's `value`, or, for a smart decode, the layer the server reports it
 * unwrapped — never from a decorative sequence. An encoding with no family
 * returns null so the caller shows no tint rather than an arbitrary one; a
 * smart decode that detected nothing (`layers` empty) is exactly that case.
 *
 * The nine families map one-to-one onto the console's closed nine-colour
 * highlight vocabulary (styles.css `--highlight-*`, contrast-audited in both
 * themes). styles.css binds each family name to its colour via
 * `[data-encoding="<family>"]`; this module only decides the family.
 */
import { DECODE_LAYERS, ENCODE_ENCODINGS, HASH_ALGORITHMS } from "./data.workbench";
import type { TransformKind } from "./types.workbench";

export type EncodingFamily =
  | "url"
  | "html"
  | "base64"
  | "radix"
  | "compress"
  | "jwt"
  | "ascii"
  | "rot13"
  | "hash";

/**
 * Every encoding name the three handlers accept (the DECODE_LAYERS /
 * ENCODE_ENCODINGS / HASH_ALGORITHMS arrays and the smart-detect layer names,
 * which are the same strings) mapped to its family.
 *
 * The nine families are chosen so the console's closed nine-colour highlight
 * vocabulary can carry one colour each. Encodings of the same class share a
 * family because that is the honest unit an operator reasons about: base64url
 * is base64 over the URL-safe alphabet; gzip and deflate are both compression;
 * hex, octal and binary are one byte rendered in a numeric base (`radix`); the
 * four digests are one hash. A distinct name inside a family would still tint
 * identically, so the family, not the raw name, is what a colour can mean.
 */
const VALUE_FAMILY: Record<string, EncodingFamily> = {
  url: "url",
  html: "html",
  base64: "base64",
  base64url: "base64",
  hex: "radix",
  octal: "radix",
  binary: "radix",
  gzip: "compress",
  deflate: "compress",
  jwt: "jwt",
  ascii: "ascii",
  rot13: "rot13",
  md5: "hash",
  sha1: "hash",
  sha256: "hash",
  sha512: "hash",
};

/** The family a single encoding name belongs to, or null if it is unknown. */
export function familyForValue(value: string): EncodingFamily | null {
  return VALUE_FAMILY[value] ?? null;
}

/**
 * The family that should colour a step's output.
 *
 * For a smart decode (`kind === "decode"`, `value === "auto"`) the requested
 * value is not the encoding that was applied — the server reports that in
 * `layers`. The output is the plaintext after the last layer came off, so the
 * outermost-peeled (last) layer is the encoding the output most recently wore.
 * An empty or null `layers` means nothing decoded, so there is no encoding to
 * colour and this returns null.
 */
export function encodingFamily(
  kind: TransformKind,
  value: string,
  layers: readonly string[] | null,
): EncodingFamily | null {
  if (kind === "decode" && value === "auto") {
    if (!layers || layers.length === 0) return null;
    return familyForValue(layers[layers.length - 1]!);
  }
  return familyForValue(value);
}

/** Every encoding name the console can send, for exhaustiveness tests. */
export const ALL_ENCODING_VALUES: readonly string[] = [
  ...DECODE_LAYERS,
  ...ENCODE_ENCODINGS,
  ...HASH_ALGORITHMS,
];
