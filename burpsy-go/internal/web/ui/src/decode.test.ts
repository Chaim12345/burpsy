// Pure-function tests for the decode pipeline (decode.ts). These run under `bun test` — the
// tsconfig excludes *.test.ts because they are not part of the app bundle. Decompression depends
// on the runtime's DecompressionStream, so those cases skip when it is unavailable rather than
// pretending to have tested them.
import { describe, expect, test } from "bun:test";
import {
  b64ToBytes,
  charsetFromContentType,
  chooseCharset,
  decodeBytes,
  decodeMessageB64,
  headerValue,
  hexDump,
  isBinaryText,
  normalizeCharset,
  splitMessage,
} from "./decode";

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const enc = new TextEncoder();
const response = (extraHeaders = "") =>
  enc.encode(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n${extraHeaders}\r\n`);

async function gzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

describe("b64ToBytes", () => {
  test("round-trips every byte value including 0xFF without loss", () => {
    const bytes = Uint8Array.from([0, 1, 0x7f, 0x80, 0xfe, 0xff]);
    expect(Array.from(b64ToBytes(bytesToBase64(bytes)))).toEqual(Array.from(bytes));
  });

  test("decodes a body larger than one atob chunk", () => {
    const bytes = new Uint8Array(0x10000 + 7);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
    expect(Array.from(b64ToBytes(bytesToBase64(bytes)))).toEqual(Array.from(bytes));
  });
});

describe("splitMessage", () => {
  test("splits at CRLFCRLF and keeps the head verbatim", () => {
    const raw = concat(enc.encode("HTTP/1.1 200 OK\r\nX-Test: y\r\n\r\n"), enc.encode("hello"));
    const { head, body, headText } = splitMessage(raw);
    expect(headText).toBe("HTTP/1.1 200 OK\r\nX-Test: y");
    expect(head[0]).toBe(0x48); // 'H'
    expect(new TextDecoder().decode(body)).toBe("hello");
  });

  test("splits a bare-LF message", () => {
    const raw = concat(enc.encode("HTTP/1.1 200 OK\ncontent-type: text/plain\n\n"), enc.encode("hi"));
    const { headText, body } = splitMessage(raw);
    expect(headText).toBe("HTTP/1.1 200 OK\ncontent-type: text/plain");
    expect(new TextDecoder().decode(body)).toBe("hi");
  });

  test("no-body message leaves an empty body", () => {
    const { body } = splitMessage(enc.encode("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"));
    expect(body.length).toBe(0);
  });
});

describe("headerValue", () => {
  test("is case-insensitive and trims the value", () => {
    const head = "HTTP/1.1 200 OK\r\nContent-Type:  text/html; charSEt=UTF-8\r\nDate: x\r\n";
    expect(headerValue(head, "content-type")).toBe("text/html; charSEt=UTF-8");
    expect(headerValue(head, "DATE")).toBe("x");
    expect(headerValue(head, "Missing")).toBeNull();
  });
});

describe("charsetFromContentType", () => {
  test("extracts the charset parameter", () => {
    expect(charsetFromContentType("text/html; charset=iso-8859-1")).toBe("iso-8859-1");
    expect(charsetFromContentType('text/html; charset="utf-8"')).toBe("utf-8");
    expect(charsetFromContentType("application/json")).toBeNull();
    expect(charsetFromContentType(null)).toBeNull();
  });
});

describe("normalizeCharset", () => {
  test("maps legacy names to TextDecoder spellings", () => {
    expect(normalizeCharset("latin1")).toBe("windows-1252");
    expect(normalizeCharset("iso-8859-1")).toBe("windows-1252");
    expect(normalizeCharset("utf8")).toBe("utf-8");
    expect(normalizeCharset("shift_jis")).toBe("shift_jis");
  });
});

describe("chooseCharset", () => {
  test("a UTF-8 BOM beats an explicit header", () => {
    const b = Uint8Array.from([0xef, 0xbb, 0xbf, 0x61]);
    expect(chooseCharset(b, "windows-1252")).toBe("utf-8");
  });

  test("an explicit header beats sniffing", () => {
    expect(chooseCharset(Uint8Array.from([0xc3]), "windows-1252")).toBe("windows-1252");
  });

  test("valid UTF-8 with no header is UTF-8", () => {
    expect(chooseCharset(enc.encode("héllo"), null)).toBe("utf-8");
  });

  test("bytes that are not valid UTF-8 fall back to windows-1252", () => {
    // 0xE9 is the Windows-1252 "é"; it is not valid as a standalone byte in UTF-8.
    expect(chooseCharset(Uint8Array.from([0x63, 0x61, 0xe9]), null)).toBe("windows-1252");
  });
});

describe("decodeBytes", () => {
  test("windows-1252 decodes high bytes to their characters", () => {
    expect(decodeBytes(Uint8Array.from([0x63, 0x61, 0x63, 0x68, 0xe9]), "windows-1252")).toBe("caché");
  });
});

describe("isBinaryText", () => {
  test("NULs and sparse control bytes mark the body binary", () => {
    expect(isBinaryText("a\u0000b\u0001c")).toBe(true);
  });
  test("text with newlines and tabs is not binary", () => {
    expect(isBinaryText("hello\nworld\t!")).toBe(false);
  });
});

describe("hexDump", () => {
  test("renders offset, hex, and ascii columns", () => {
    const dump = hexDump(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x89]));
    expect(dump).toContain("48 65 6C 6C 6F");
    expect(dump).toContain("|Hello.|");
    expect(dump).toMatch(/^00000000/);
  });
});

describe("decodeMessageB64", () => {
  test("a Windows-1252 response renders the real characters", async () => {
    const body = Uint8Array.from([0x63, 0x61, 0x63, 0x68, 0xe8]); // "cachè"
    const head = enc.encode("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n");
    const d = await decodeMessageB64(bytesToBase64(concat(head, body)));
    expect(d.charset).toBe("windows-1252");
    expect(d.binary).toBe(false);
    expect(d.text).toContain("cachè");
    expect(d.text).toContain("charset=windows-1252");
  });

  test("a gzip body is decompressed and decoded", async () => {
    const original = "compressed body: héllo";
    const body = await gzip(enc.encode(original));
    const head = response("Content-Encoding: gzip\r\n");
    const d = await decodeMessageB64(bytesToBase64(concat(head, body)));
    expect(d.wasCompressed).toBe(true);
    expect(d.encoding).toBe("gzip");
    expect(d.binary).toBe(false);
    expect(d.text).toContain(original);
  });

  test("a binary body renders as a hex dump instead of text", async () => {
    const body = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x00]);
    const head = enc.encode("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n");
    const d = await decodeMessageB64(bytesToBase64(concat(head, body)));
    expect(d.binary).toBe(true);
    expect(d.text).toContain("|");
    expect(d.text).toMatch(/89 50 4E 47/);
  });

  test("a body with no Content-Encoding is shown unchanged", async () => {
    const d = await decodeMessageB64(bytesToBase64(concat(response(), enc.encode("plain text"))));
    expect(d.encoding).toBeNull();
    expect(d.wasCompressed).toBe(false);
    expect(d.text).toContain("plain text");
  });
});