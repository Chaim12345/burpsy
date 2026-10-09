import { describe, expect, test } from "bun:test";
import { COMPARER_FILE_MAX_BYTES, bytesToBase64, classifyFileBytes, liveBytes, sideField } from "./comparer-file";

describe("comparer file loading (ppqw)", () => {
  test("a UTF-8 file becomes plain text", () => {
    const r = classifyFileBytes(new TextEncoder().encode("GET / HTTP/1.1\r\nHost: é\r\n\r\n"));
    expect(r.kind).toBe("text");
    if (r.kind === "text") expect(r.text).toContain("Host: é");
  });

  test("a non-UTF-8 file keeps its real bytes and a one-char-per-byte rendering", () => {
    const bytes = new Uint8Array([0x00, 0xff, 0xfe, 0x78, 0x80]);
    const r = classifyFileBytes(bytes);
    expect(r.kind).toBe("binary");
    if (r.kind === "binary") {
      expect(Array.from(r.binary.bytes)).toEqual([0x00, 0xff, 0xfe, 0x78, 0x80]);
      expect(r.binary.shownAs.length).toBe(5);
      expect(r.binary.shownAs.charCodeAt(1)).toBe(0xff);
    }
  });

  test("a file over the cap is refused with its size", () => {
    const r = classifyFileBytes(new Uint8Array(COMPARER_FILE_MAX_BYTES + 1));
    expect(r.kind).toBe("refused");
    if (r.kind === "refused") expect(r.reason).toContain(String(COMPARER_FILE_MAX_BYTES + 1));
  });

  test("the bytes go out only while the editor still shows them — an edit drops them", () => {
    const r = classifyFileBytes(new Uint8Array([0x00, 0xff]));
    if (r.kind !== "binary") throw new Error("expected binary");
    expect(sideField("a", r.binary.shownAs, r.binary)).toEqual({ a_base64: bytesToBase64(new Uint8Array([0x00, 0xff])) });
    // The operator typed into the side: the stale bytes must not be sent in place of the edit.
    expect(liveBytes(r.binary, r.binary.shownAs + "x")).toBeNull();
    expect(sideField("a", r.binary.shownAs + "x", r.binary)).toEqual({ a: r.binary.shownAs + "x" });
    expect(sideField("b", "plain", null)).toEqual({ b: "plain" });
  });

  test("base64 of bytes round-trips through atob", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 254, 255]);
    const back = Uint8Array.from(atob(bytesToBase64(bytes)), (c) => c.charCodeAt(0));
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });
});
