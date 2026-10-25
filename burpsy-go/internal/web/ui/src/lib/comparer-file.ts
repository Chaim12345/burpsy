/**
 * Loading a Comparer side from a file (burpsy-react-ui-ppqw) — Burp's "Load: Add an item from a file".
 *
 * A text file becomes the side's text like a paste. A binary file cannot: the editor and the JSON
 * request both carry strings, and every non-UTF-8 byte would become U+FFFD before the diff ran. So a
 * binary file keeps its real bytes beside a display rendering, and the comparison sends the bytes as
 * base64 — but ONLY while the editor still shows exactly that rendering. The moment the operator
 * edits the side, the bytes are stale and the text wins (the shadow-copy rule: a cached "faithful"
 * copy must never be sent in place of what the operator can see and has changed).
 */

/** Files above this are refused with their size; well inside the console's request bound. */
export const COMPARER_FILE_MAX_BYTES = 2 * 1024 * 1024;

export interface BinarySide {
 /** The file's real bytes, compared byte-for-byte. */
 bytes: Uint8Array;
 /** What the editor was given to show them; the bytes are valid only while the text equals this. */
 shownAs: string;
}

export type LoadedFile = { kind: "text"; text: string } | { kind: "binary"; binary: BinarySide } | { kind: "refused"; reason: string };

/** One character per byte (U+0000–U+00FF), so the editor shows every byte and the length matches. */
export function byteRendering(bytes: Uint8Array): string {
 let out = "";
 for (let i = 0; i < bytes.length; i += 8192) {
  out += String.fromCharCode(...bytes.subarray(i, i + 8192));
 }
 return out;
}

export function classifyFileBytes(bytes: Uint8Array): LoadedFile {
 if (bytes.length > COMPARER_FILE_MAX_BYTES) {
  return {
   kind: "refused",
   reason: `the file is ${bytes.length} bytes; the Comparer loads files up to ${COMPARER_FILE_MAX_BYTES} bytes`,
  };
 }
 try {
  return { kind: "text", text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
 } catch {
  return { kind: "binary", binary: { bytes, shownAs: byteRendering(bytes) } };
 }
}

/** The binary side's bytes if they still describe what the editor shows, else null (use the text). */
export function liveBytes(side: BinarySide | null, editorText: string): Uint8Array | null {
 return side && side.shownAs === editorText ? side.bytes : null;
}

export function bytesToBase64(bytes: Uint8Array): string {
 let bin = "";
 for (let i = 0; i < bytes.length; i += 8192) {
  bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
 }
 return btoa(bin);
}

/**
 * The compare request for one side: text as `a`/`b`, or the live binary bytes as `a_base64`/`b_base64`
 * — never both, which the server refuses.
 */
export function sideField(name: "a" | "b", text: string, binary: BinarySide | null): Record<string, string> {
 const bytes = liveBytes(binary, text);
 return bytes ? { [`${name}_base64`]: bytesToBase64(bytes) } : { [name]: text };
}
