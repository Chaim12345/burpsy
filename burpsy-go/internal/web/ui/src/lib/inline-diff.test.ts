/** burpsy-react-ui-6ibj: the Repeater's inline "compare with previous response" (CodeMirror merge). */
import { describe, expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { getChunks, getOriginalDoc } from "@codemirror/merge";
import { inlineDiffExtension } from "./inline-diff";
import { lineSeparatorFor } from "./editor-eol";

function stateFor(current: string, previous: string): EditorState {
 return EditorState.create({
  doc: current,
  extensions: [EditorState.lineSeparator.of(lineSeparatorFor(current)), inlineDiffExtension(previous, lineSeparatorFor(current))],
 });
}

describe("inlineDiffExtension", () => {
 test("identical responses have no chunks", () => {
  const text = "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody";
  expect(getChunks(stateFor(text, text))?.chunks.length).toBe(0);
 });

 test("a changed header line is one chunk", () => {
  const state = stateFor("HTTP/1.1 200 OK\r\nA: 2\r\n\r\nbody", "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody");
  expect(getChunks(state)?.chunks.length).toBe(1);
 });

 test("the original keeps the previous response's line count under CRLF", () => {
  const state = stateFor("a\r\nb\r\nc", "a\r\nb");
  expect(getOriginalDoc(state).lines).toBe(2);
  expect(getChunks(state)?.chunks.length).toBe(1);
 });

 test("an added trailing line is one chunk ending at the end of the new text", () => {
  const current = "a\nb\nc\nd";
  const chunks = getChunks(stateFor(current, "a\nb\nc"))!.chunks;
  expect(chunks.length).toBe(1);
  expect(chunks[0]!.endB).toBe(current.length);
 });
});
