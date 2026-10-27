// The GraphQL operation editor's pending-Apply guard (burpsy-react-ui-4xqt.3): a resolution
// that lands after the operator moved on - typed over the draft, edited the Raw view, or left
// the message - writes nothing and says why (the rsu2 generation guard).
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import type { GraphQLDocument } from "../lib/message-views";
import { GraphQLView } from "./typed-views";

const RAW =
 'POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"query":"{a}"}';
const DOC: GraphQLDocument = {
 source: "JSON body",
 operations: [{ operationName: null, query: "{a}", variables: null, extensions: null }],
};

const originalFetch = globalThis.fetch;
let resolveApply: ((response: Response) => void) | null = null;
let resolveCheck: ((response: Response) => void) | null = null;

beforeEach(() => {
 resolveApply = null;
 resolveCheck = null;
 globalThis.fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/repeater/graphql-query") {
   return await new Promise<Response>((resolve) => {
    resolveApply = resolve;
   });
  }
  if (path === "/api/repeater/graphql-validate") {
   return await new Promise<Response>((resolve) => {
    resolveCheck = resolve;
   });
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

function appliedResponse(request: string): Response {
 return new Response(JSON.stringify({ request, source: "body" }), {
  status: 200,
  headers: { "content-type": "application/json" },
 });
}

async function startPendingApply(onChange: (next: string) => void) {
 const view = renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={onChange} />);
 fireEvent.change(screen.getByLabelText("Edit this operation's GraphQL query"), { target: { value: "{b}" } });
 fireEvent.click(screen.getByRole("button", { name: "Apply to request" }));
 await waitFor(() => expect(resolveApply).not.toBeNull());
 return view;
}

describe("a pending Apply never overwrites a newer edit", () => {
 test("a raw prop move under the pending Apply voids the resolution", async () => {
  const applied: string[] = [];
  const { rerender } = await startPendingApply((next) => applied.push(next));
  rerender(<GraphQLView document={DOC} raw={RAW + "\r\n"} onChange={(next) => applied.push(next)} />);
  resolveApply?.(appliedResponse("POST /graphql HTTP/1.1\r\n\r\n{\"query\":\"{b}\"}"));
  await waitFor(() => expect(screen.getByText(/draft changed while Apply was running/)).toBeTruthy());
  expect(applied).toEqual([]);
 });

 test("an unmount with the Apply in flight voids the resolution", async () => {
  const applied: string[] = [];
  const { unmount } = await startPendingApply((next) => applied.push(next));
  unmount();
  resolveApply?.(appliedResponse("POST /graphql HTTP/1.1\r\n\r\n{\"query\":\"{b}\"}"));
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(applied).toEqual([]);
 });

 test("a resolution that lands before anything moved still applies", async () => {
  const applied: string[] = [];
  await startPendingApply((next) => applied.push(next));
  resolveApply?.(appliedResponse("POST /graphql HTTP/1.1\r\n\r\n{\"query\":\"{b}\"}"));
  await waitFor(() => expect(applied).toEqual(['POST /graphql HTTP/1.1\r\n\r\n{"query":"{b}"}']));
 });
});

describe("a pending Check never lands on a newer draft", () => {
 test("a raw prop move under the pending Check voids the resolution", async () => {
  const { rerender } = renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={() => undefined} />);
  fireEvent.change(screen.getByLabelText("Edit this operation's GraphQL query"), { target: { value: "{b}" } });
  fireEvent.click(screen.getByRole("button", { name: "Check" }));
  await waitFor(() => expect(resolveCheck).not.toBeNull());
  rerender(<GraphQLView document={DOC} raw={RAW + "\r\n"} onChange={() => undefined} />);
  resolveCheck?.(new Response(JSON.stringify({ ok: true, errors: [] }), {
   status: 200,
   headers: { "content-type": "application/json" },
  }));
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(screen.queryByText("The document parses.")).toBeNull();
 });

 test("a Check that lands before anything moved still reports", async () => {
  renderWithProviders(<GraphQLView document={DOC} raw={RAW} onChange={() => undefined} />);
  fireEvent.change(screen.getByLabelText("Edit this operation's GraphQL query"), { target: { value: "{b}" } });
  fireEvent.click(screen.getByRole("button", { name: "Check" }));
  await waitFor(() => expect(resolveCheck).not.toBeNull());
  resolveCheck?.(new Response(JSON.stringify({ ok: true, errors: [] }), {
   status: 200,
   headers: { "content-type": "application/json" },
  }));
  await waitFor(() => expect(screen.getByText("The document parses.")).toBeTruthy());
 });
});
