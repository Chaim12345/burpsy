import { describe, expect, test } from "bun:test";
import { faithfulRequestBase64 } from "./message";

describe("faithfulRequestBase64", () => {
  test("concatenates the ASCII head with the exact body bytes, binary intact", () => {
    // A protobuf body: 08 96 01 12 07 'testing' — 0x96 is not valid UTF-8.
    const bodyBytes = new Uint8Array([0x08, 0x96, 0x01, 0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]);
    const bodyBase64 = btoa(String.fromCharCode(...bodyBytes));
    const head = "POST /x HTTP/1.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: 12\r\n\r\n";
    const out = faithfulRequestBase64(head /* no body in the text */, bodyBase64);
    // Decode and confirm the exact bytes: head bytes + the body bytes, 0x96 preserved.
    const decoded = Uint8Array.from(atob(out), (c) => c.charCodeAt(0));
    const expected = new Uint8Array([...new TextEncoder().encode(head), ...bodyBytes]);
    expect(Array.from(decoded)).toEqual(Array.from(expected));
    // The 0x96 byte survived (a UTF-8 round-trip would have turned it into ef bf bd).
    expect(decoded.includes(0x96)).toBe(true);
  });

  test("takes the head from the request text up to the blank line, ignoring any body already there", () => {
    const text = "GET / HTTP/1.1\r\nHost: t\r\n\r\nOLD BODY";
    const newBody = btoa("NEW");
    const out = faithfulRequestBase64(text, newBody);
    const decoded = atob(out);
    expect(decoded).toBe("GET / HTTP/1.1\r\nHost: t\r\n\r\nNEW");
  });
});
