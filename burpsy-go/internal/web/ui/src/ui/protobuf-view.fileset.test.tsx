// The .proto file SET on the Protobuf tab (burpsy-react-ui-rsu2): picking several files loads them
// as one schema whose imports resolve across the set, the entry point is re-pickable, and the
// decode call sends proto_entry + proto_files rather than the single-file proto field.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { ProtobufView } from "./protobuf-view";

const originalFetch = globalThis.fetch;
let decodeCalls: Record<string, unknown>[] = [];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
const SCHEMALESS = { grpc: false, frames: [{ fields: [{ number: 1, wire_type: 2, len_kind: "string", string: "x" }] }] };

beforeEach(() => {
 decodeCalls = [];
 useApp.setState({ protoSchema: null, protoMessages: {} } as never);
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/protobuf/decode") {
   decodeCalls.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return json(SCHEMALESS);
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

async function pickFiles(files: File[]) {
 const input = (await waitFor(() => {
  const el = document.querySelector('input[type="file"]');
  if (!el) throw new Error("no file input yet");
  return el;
 })) as HTMLInputElement;
 fireEvent.change(input, { target: { files } });
}

describe("the .proto file set on the Protobuf tab", () => {
 test("several picked files load as one set and the decode sends proto_entry + proto_files", async () => {
  renderWithProviders(<ProtobufView bodyBase64="CgN4" grpc={false} direction="request" />);
  await pickFiles([
   new File(['syntax = "proto3"; package shop; import "protos/common.proto"; message GetReq { common.Id id = 1; }'], "protos/shop.proto"),
   new File(['syntax = "proto3"; package common; message Id { string value = 1; }'], "protos/common.proto"),
  ]);
  await waitFor(() => expect(useApp.getState().protoSchema?.files).toBeTruthy());
  expect(useApp.getState().protoSchema?.entry).toBe("protos/shop.proto");
  await waitFor(() => expect(decodeCalls.length).toBeGreaterThan(0));
  const last = decodeCalls[decodeCalls.length - 1] ?? {};
  expect(last.proto).toBeUndefined();
  expect(last.proto_entry).toBe("protos/shop.proto");
  expect(Object.keys(last.proto_files as Record<string, string>).sort()).toEqual(["protos/common.proto", "protos/shop.proto"]);
 });

 test("one picked file stays the single-file form", async () => {
  renderWithProviders(<ProtobufView bodyBase64="CgN4" grpc={false} direction="request" />);
  await pickFiles([new File(['syntax = "proto3"; message A { int32 a = 1; }'], "a.proto")]);
  await waitFor(() => expect(useApp.getState().protoSchema?.text).toContain("message A"));
  expect(useApp.getState().protoSchema?.files).toBeUndefined();
  await waitFor(() => expect(decodeCalls.length).toBeGreaterThan(0));
  const last = decodeCalls[decodeCalls.length - 1] ?? {};
  expect(last.proto).toContain("message A");
  expect(last.proto_files).toBeUndefined();
 });

 test("the entry point is re-pickable and the next decode uses it", async () => {
  useApp.setState({
   protoSchema: {
    name: "2 .proto files",
    text: "b",
    files: { "a.proto": "a", "b.proto": "b" },
    entry: "a.proto",
   },
  } as never);
  renderWithProviders(<ProtobufView bodyBase64="CgN4" grpc={false} direction="request" />);
  const entrySelect = await screen.findByLabelText("Entry point of the .proto file set");
  fireEvent.change(entrySelect, { target: { value: "b.proto" } });
  await waitFor(() => expect(useApp.getState().protoSchema?.entry).toBe("b.proto"));
  await waitFor(() =>
   expect(decodeCalls.some((c) => c.proto_entry === "b.proto")).toBe(true),
  );
 });
});
