import { describe, expect, test } from "bun:test";
import {
  base64UrlDecode,
  base64UrlEncode,
  constructString,
  htmlEncodeAllCharsDecimal,
  htmlEncodeAllCharsHex,
  urlEncodeAllChars,
  urlEncodeAllCharsUnicode,
} from "./transforms";

// Burp's remaining Convert-selection variants (burpsy-react-ui-b2nt).

describe("URL-encode all characters", () => {
  test("encodes every byte, not just metacharacters", () => {
    expect(urlEncodeAllChars("ab1")).toBe("%61%62%31");
  });
  test("multi-byte characters encode per UTF-8 byte", () => {
    expect(urlEncodeAllChars("é")).toBe("%C3%A9");
  });
});

describe("URL-encode all characters (Unicode %u)", () => {
  test("BMP characters use the 2-byte form", () => {
    expect(urlEncodeAllCharsUnicode("Aé")).toBe("%u0041%u00E9");
  });
  test("non-BMP characters split into surrogate halves", () => {
    // U+1F600 is D83D DE00.
    expect(urlEncodeAllCharsUnicode("😀")).toBe("%uD83D%uDE00");
  });
});

describe("HTML-encode all characters", () => {
  test("decimal form", () => {
    expect(htmlEncodeAllCharsDecimal("A<")).toBe("&#60;&#38;".replace("&#60;&#38;", "&#65;&#60;"));
  });
  test("hex form", () => {
    expect(htmlEncodeAllCharsHex("A<")).toBe("&#x41;&#x3c;");
  });
});

describe("Base64-URL", () => {
  test("uses the URL-safe alphabet", () => {
    // "subjects?>" includes + and / in standard base64.
    const encoded = base64UrlEncode("~~?>");
    expect(encoded).not.toMatch(/[+/]/);
  });
  test("round-trips", () => {
    expect(base64UrlDecode(base64UrlEncode("hello world & more"))).toBe("hello world & more");
  });
});

describe("Construct string", () => {
  test("JavaScript keeps printable ASCII and escapes the quote", () => {
    expect(constructString(`a'b`, "js_double")).toBe("\"a\\'b\"");
  });
  test("JavaScript escapes control bytes as \\xNN", () => {
    expect(constructString("\n", "js_double")).toBe("\"\\x0a\"");
  });
  test("MSSQL uses CHAR() joined with +", () => {
    expect(constructString("\n", "sql_mssql")).toBe("CHAR(10)");
  });
  test("Oracle uses CHR() joined with ||", () => {
    expect(constructString("a\n", "sql_oracle")).toBe("'a'||CHR(10)");
  });
  test("MySQL uses CHAR() joined with ||", () => {
    expect(constructString("a\n", "sql_mysql")).toBe("'a'||CHR(10)");
  });
});
