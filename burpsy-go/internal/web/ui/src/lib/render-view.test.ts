// The Render view's renderable decision (burpsy-react-ui-n7n).
//
// The point of testing these as functions: the Render tab is offered only when the response can
// actually be rendered, and the two renderable families — HTML and image — have different
// mechanisms behind them. A content-type that looks like an image must produce a data URL whose
// bytes are exactly the body's bytes, because a QR code that differs by one pixel from what the
// server sent is a different QR code.
import { describe, expect, test } from "bun:test";
import { bodyOf, contentTypeOf } from "./message";

describe("render view content types", () => {
  test("an image content-type is detected and the body round-trips byte-exact", () => {
    // One PNG header byte sequence that is NOT valid UTF-8: if the body string mangled the bytes
    // (UTF-8 round-trip), the data URL would decode to different bytes and the image would differ
    // from the server's response.
    const bytes = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00];
    const body = String.fromCharCode(...bytes);
    const raw = `HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${body.length}\r\n\r\n${body}`;

    expect(/^image\//.test(contentTypeOf(raw))).toBe(true);
    expect(bodyOf(raw)).toBe(body);
  });
});
