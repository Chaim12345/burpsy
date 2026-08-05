/**
 * Selection transforms for the message editors, matching Burp's editor hotkeys.
 *
 * These run locally rather than through /api/tools/*: an operator hitting
 * ctrl+U on a selection expects the bytes to change instantly, and a network
 * round-trip per keystroke would make the editor feel broken.
 */

/** Burp URL-encodes "key characters" rather than everything, so a readable
 *  request stays readable. This is the same conservative set. */
const URL_KEY_CHARS = new Set([..."&=?#+%;,/:@$\"'<>[]{}|\\^~` "]);

export function urlEncodeKeyChars(input: string): string {
  let out = "";
  for (const character of input) {
    if (URL_KEY_CHARS.has(character) || character.charCodeAt(0) < 0x20) {
      const bytes = new TextEncoder().encode(character);
      for (const byte of bytes) out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    } else {
      out += character;
    }
  }
  return out;
}

export function urlDecode(input: string): string {
  try {
    return decodeURIComponent(input.replace(/\+/g, " "));
  } catch {
    // A partial or invalid escape must not wipe the selection; leave it alone.
    return input;
  }
}

const HTML_ENTITIES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function htmlEncodeKeyChars(input: string): string {
  return input.replace(/[&<>"']/g, (character) => HTML_ENTITIES[character] ?? character);
}

export function htmlDecode(input: string): string {
  return input
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCodePoint(Number.parseInt(dec, 10)))
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&");
}

/** Base64 over raw bytes, so non-ASCII selections survive the round trip. */
export function base64Encode(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64Decode(input: string): string {
  try {
    const binary = atob(input.trim().replace(/\s+/g, ""));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    // Lossy on purpose: a decoded binary blob should still show something rather
    // than silently failing, matching how the server renders non-UTF8 bytes.
    return new TextDecoder().decode(bytes);
  } catch {
    return input;
  }
}
