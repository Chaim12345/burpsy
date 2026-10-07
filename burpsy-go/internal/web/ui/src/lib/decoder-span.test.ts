import { describe, expect, test } from "bun:test";
import { resolveSelection, splitInput } from "./decoder-span";

describe("resolveSelection falls back to whole input unless a real span is selected", () => {
  test("no selection (null endpoints) transforms the whole input", () => {
    const span = resolveSelection(10, null, null);
    expect(span).toEqual({ from: 0, to: 10, whole: true });
  });

  test("a cursor with nothing selected transforms the whole input", () => {
    const span = resolveSelection(10, 4, 4);
    expect(span).toEqual({ from: 0, to: 10, whole: true });
  });

  test("a real selection transforms only that span", () => {
    expect(resolveSelection(10, 2, 6)).toEqual({ from: 2, to: 6, whole: false });
  });

  test("a right-to-left selection is normalised, not dropped", () => {
    expect(resolveSelection(10, 6, 2)).toEqual({ from: 2, to: 6, whole: false });
  });

  test("offsets past the ends are clamped so a stale selection cannot index out of range", () => {
    expect(resolveSelection(5, -3, 99)).toEqual({ from: 0, to: 5, whole: false });
    expect(resolveSelection(5, 8, 12)).toEqual({ from: 0, to: 5, whole: true });
  });
});

describe("splitInput leaves the unselected text untouched", () => {
  test("before + span + after reconstructs the input exactly", () => {
    const input = "prefix SELECTED suffix";
    const from = input.indexOf("SELECTED");
    const to = from + "SELECTED".length;
    const parts = splitInput(input, resolveSelection(input.length, from, to));
    expect(parts.before).toBe("prefix ");
    expect(parts.span).toBe("SELECTED");
    expect(parts.after).toBe(" suffix");
    expect(parts.before + parts.span + parts.after).toBe(input);
  });

  test("the whole-input span puts everything in span with empty before/after", () => {
    const input = "everything";
    const parts = splitInput(input, resolveSelection(input.length, null, null));
    expect(parts.before).toBe("");
    expect(parts.span).toBe(input);
    expect(parts.after).toBe("");
  });

  test("a multibyte character before the span does not shift the boundary (char indices)", () => {
    // "é" is one JS string index (one UTF-16 code unit here), same as CodeMirror offsets.
    const input = "é=aGVsbG8=&x";
    const from = input.indexOf("aGVsbG8=");
    const to = from + "aGVsbG8=".length;
    const parts = splitInput(input, resolveSelection(input.length, from, to));
    expect(parts.span).toBe("aGVsbG8=");
    expect(parts.before + parts.span + parts.after).toBe(input);
  });
});
