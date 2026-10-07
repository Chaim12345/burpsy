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

// ---- Burp's Convert selection, the remaining variants (burpsy-react-ui-b2nt) --------------------

/** URL-encode every character (Burp's "all characters"), not just the key metacharacters. */
export function urlEncodeAllChars(input: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(input)) {
    out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** URL-encode every character using Burp's 2-byte Unicode form (%u0041). Only the BMP is
 * representable; a surrogate pair becomes two %uXXXX escapes, which is what Burp emits. */
export function urlEncodeAllCharsUnicode(input: string): string {
  let out = "";
  for (const character of input) {
    const code = character.codePointAt(0) ?? 0;
    if (code > 0xffff) {
      // A non-BMP code point has no %u form; encode its surrogate halves the way Burp does.
      const high = 0xd800 + ((code - 0x10000) >> 10);
      const low = 0xdc00 + ((code - 0x10000) & 0x3ff);
      out += `%u${high.toString(16).toUpperCase().padStart(4, "0")}%u${low.toString(16).toUpperCase().padStart(4, "0")}`;
      continue;
    }
    out += `%u${code.toString(16).toUpperCase().padStart(4, "0")}`;
  }
  return out;
}

/** HTML-encode every character as decimal numeric entities (&#65;). */
export function htmlEncodeAllCharsDecimal(input: string): string {
  let out = "";
  for (const character of input) {
    out += `&#${character.codePointAt(0)};`;
  }
  return out;
}

/** HTML-encode every character as hex numeric entities (&#x41;). */
export function htmlEncodeAllCharsHex(input: string): string {
  let out = "";
  for (const character of input) {
    out += `&#x${(character.codePointAt(0) ?? 0).toString(16)};`;
  }
  return out;
}

/** Base64-URL: the URL-safe alphabet, padding kept so decode is unambiguous. */
export function base64UrlEncode(input: string): string {
  return base64Encode(input).replace(/\+/g, "-").replace(/\//g, "_");
}

export function base64UrlDecode(input: string): string {
  try {
    const binary = atob(input.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return input;
  }
}

/** "Construct string" — byte-literal builders. Escapes every byte outside printable ASCII so
 * the constructed string survives any downstream encoding; ASCII passes as-is. */
export type ConstructDialect = "js_double" | "js_single" | "sql_mssql" | "sql_oracle" | "sql_mysql";

export function constructString(input: string, dialect: ConstructDialect): string {
  const chars = [...input];
  const escJS = (code: number): string => {
    if (code === 0x22) return '\\"';
    if (code === 0x27) return "\\'";
    if (code === 0x5c) return "\\\\";
    if (code >= 0x20 && code <= 0x7e) return String.fromCharCode(code);
    if (code <= 0xff) return `\\x${code.toString(16).padStart(2, "0")}`;
    return `\\u${code.toString(16).padStart(4, "0")}`;
  };
  if (dialect.startsWith("js")) {
    const quote = dialect === "js_double" ? '"' : "'";
    return quote + chars.map((character) => escJS(character.codePointAt(0) ?? 0)).join("") + quote;
  }
  // SQL: printable ASCII stays inside a normal string literal (a single quote itself
  // becomes a function call, since '' doubling is dialect-specific); everything else
  // becomes CHAR(n) (MSSQL) or CHR(n) (Oracle/MySQL) glued with the dialect's
  // concatenation operator — MSSQL's +, Oracle's and MySQL's ||. A printable run is one
  // literal, so the common case reads as a plain quoted string rather than a function
  // call per byte.
  const fn = dialect === "sql_mssql" ? "CHAR" : "CHR";
  const joiner = dialect === "sql_mssql" ? "+" : "||";
  const glued: string[] = [];
  let literal = "";
  for (const character of chars) {
    const code = character.codePointAt(0) ?? 0;
    if (code >= 0x20 && code <= 0x7e && code !== 0x27) {
      literal += character;
      continue;
    }
    if (literal) {
      glued.push(`'${literal}'`);
      literal = "";
    }
    glued.push(`${fn}(${code})`);
  }
  if (literal) glued.push(`'${literal}'`);
  return glued.join(joiner);
}
