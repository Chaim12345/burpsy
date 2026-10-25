// Burp's Ctrl+Up / Ctrl+Down paragraph moves (2czi): blank lines bound paragraphs, so an HTTP
// message's head and body are one key apart.
import { describe, expect, test } from "bun:test";
import { paragraphTarget } from "./editor-paragraph";

const MESSAGE = ["POST / HTTP/1.1", "Host: a", "Content-Type: x", "", "body one", "body two", "", "", "tail"];

describe("paragraphTarget", () => {
  test("down from the request line lands on the blank line before the body", () => {
    expect(paragraphTarget(MESSAGE, 1, "down")).toBe(4);
  });

  test("down again skips the blank line and walks to the next paragraph's end", () => {
    expect(paragraphTarget(MESSAGE, 4, "down")).toBe(7);
    expect(paragraphTarget(MESSAGE, 7, "down")).toBe(9);
  });

  test("down from the last paragraph stops at the last line", () => {
    expect(paragraphTarget(MESSAGE, 9, "down")).toBe(9);
  });

  test("up from the body lands on the blank line above it, then the first line", () => {
    expect(paragraphTarget(MESSAGE, 6, "up")).toBe(4);
    expect(paragraphTarget(MESSAGE, 4, "up")).toBe(1);
  });

  test("an empty document stays on line 1", () => {
    expect(paragraphTarget([], 1, "down")).toBe(1);
  });
});
