// The GraphQL editor's busy flag and generation guards (burpsy-react-ui-4xqt.3 follow-ups:
// 4xqt3-speculative-render-discard, 4xqt3-binding-tests). The unmount guard (4xqt3-unmount-setbusy)
// has no test: React 18 drops a state update on an unmounted component silently, so nothing observes it.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import type { GraphQLDocument } from "../lib/message-views";
import { GraphQLView } from "./typed-views";

const RAW =
 'POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"query":"{a}"}';
const DOC: GraphQLDocument = { source: "JSON body", operations: [{ operationName: null, query: "{a}", variables: null, extensions: null }] };
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

const originalFetch = globalThis.fetch;
let pending: ((r: Response) => void)[] = [];
beforeEach(() => {
 pending = [];
 globalThis.fetch = (async (_input: RequestInfo | URL) => await new Promise<Response>((resolve) => pending.push(resolve))) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const editor = () => screen.getByLabelText("Edit this operation's GraphQL query");
const checkButton = () => screen.getByRole("button", { name: "Check" }) as HTMLButtonElement;

async function startCheck() {
 fireEvent.change(editor(), { target: { value: "{b}" } });
 fireEvent.click(checkButton());
 await waitFor(() => expect(pending.length).toBe(1));
 expect(checkButton().disabled).toBe(true);
}

describe("the busy flag", () => {
 // A resolution the guard voids still ends its op: busy must clear, or both buttons stay disabled.
 test("a voided Check still clears busy", async () => {
  const { rerender } = renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={() => undefined} />);
  await startCheck();
  rerender(<GraphQLView document={DOC} raw={RAW + "\r\n"} onChange={() => undefined} />);
  await act(async () => pending[0]?.(ok({ ok: true, errors: [] })));
  await waitFor(() => expect(checkButton().disabled).toBe(false));
  expect(screen.queryByText("The document parses.")).toBeNull();
 });

 // The raw move and the resolution in one tick: the render-time generation bump still wins.
 test("a raw move in the same tick as the resolution voids it", async () => {
  const applied: string[] = [];
  const { rerender } = renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={(n) => applied.push(n)} />);
  fireEvent.change(editor(), { target: { value: "{b}" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply to request" }));
  await waitFor(() => expect(pending.length).toBe(1));
  await act(async () => {
   rerender(<GraphQLView document={DOC} raw={RAW + "\r\n"} onChange={(n) => applied.push(n)} />);
   pending[0]?.(ok({ request: "X", source: "body" }));
  });
  await new Promise((r) => setTimeout(r, 20));
  expect(applied).toEqual([]);
 });
});

// The render-time bump is conservative by contract (4xqt3-speculative-render-discard): any raw
// change voids a pending Apply, even one that changes back before the resolution lands, because a
// resolution computed for A cannot know what happened between A and the second A.
test("raw A -> B -> A before the resolution still voids the Apply", async () => {
 const applied: string[] = [];
 const { rerender } = renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={(n) => applied.push(n)} />);
 fireEvent.change(editor(), { target: { value: "{b}" } });
 fireEvent.click(screen.getByRole("button", { name: "Apply to request" }));
 await waitFor(() => expect(pending.length).toBe(1));
 rerender(<GraphQLView document={DOC} raw={RAW + "\r\n"} onChange={(n) => applied.push(n)} />);
 rerender(<GraphQLView document={DOC} raw={RAW} onChange={(n) => applied.push(n)} />);
 await act(async () => pending[0]?.(ok({ request: "X", source: "body" })));
 await waitFor(() => expect(screen.getByText(/draft changed while Apply was running/)).toBeTruthy());
 expect(applied).toEqual([]);
});
