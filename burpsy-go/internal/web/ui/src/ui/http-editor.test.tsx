/**
 * The real HttpEditor in a DOM (happy-dom): a CRLF request survives an edit byte for byte
 * (burpsy-react-ui-elam, ngao, eslt). Run with `bun run test:components`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, waitFor } from "@testing-library/react";
import { renderWithProviders as render } from "../../test/render";
import { EditorView } from "@codemirror/view";
import { HttpEditor } from "./editor";

const REQUEST = "GET /a HTTP/1.1\r\nHost: x.example\r\n\r\n";

afterEach(cleanup);

function viewOf(container: HTMLElement): EditorView {
 const dom = container.querySelector(".cm-editor") as HTMLElement | null;
 const view = dom ? EditorView.findFromDOM(dom) : null;
 if (!view) throw new Error("no CodeMirror view mounted");
 return view;
}

describe("HttpEditor line endings", () => {
 test("the document holds the message's own CRLF bytes", async () => {
  const { container } = render(<HttpEditor value={REQUEST} onChange={() => {}} label="Request" views={false} />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe(REQUEST));
  expect(viewOf(container).state.lineBreak).toBe("\r\n");
 });

 test("one typed character reaches onChange with every CRLF intact", async () => {
  const seen: string[] = [];
  const { container } = render(<HttpEditor value={REQUEST} onChange={(next) => seen.push(next)} label="Request" views={false} />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe(REQUEST));
  const view = viewOf(container);
  view.dispatch({ changes: { from: view.state.doc.length, insert: "!" }, userEvent: "input.type" });
  await waitFor(() => expect(seen.length).toBeGreaterThan(0));
  expect(seen.at(-1)).toBe(`${REQUEST}!`);
 });

 test("a message that arrives later replaces the document without echoing onChange", async () => {
  const seen: string[] = [];
  const { container, rerender } = render(<HttpEditor value={"a\nb"} onChange={(next) => seen.push(next)} label="Request" views={false} />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe("a\nb"));
  rerender(<HttpEditor value={REQUEST} onChange={(next) => seen.push(next)} label="Request" views={false} />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe(REQUEST));
  expect(seen).toEqual([]);
 });
});

describe("HttpEditor inline diff (6ibj)", () => {
 test("compareWith lays the previous response over the Raw view", async () => {
  const previous = "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody";
  const current = "HTTP/1.1 200 OK\r\nA: 2\r\n\r\nbody";
  const { container } = render(<HttpEditor value={current} readOnly label="Response" compareWith={previous} />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe(current));
  await waitFor(() => expect(container.querySelector(".cm-deletedChunk")).not.toBeNull());
  expect(container.querySelector(".cm-deletedChunk")?.textContent).toContain("A: 1");
 });

 test("without compareWith there is no diff", async () => {
  const { container } = render(<HttpEditor value="x" readOnly label="Response" />);
  await waitFor(() => expect(viewOf(container).state.sliceDoc(0)).toBe("x"));
  expect(container.querySelector(".cm-deletedChunk")).toBeNull();
 });
});
