// The reflection affordance on the Protobuf tab (burpsy-react-ui-mup0, API 47id): target + service
// inputs, the call, and provenance rendered visibly. Names a target served over reflection are the
// target's claims and must read differently from an operator's own .proto.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { useState } from "react";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { ProtobufView } from "./protobuf-view";

const originalFetch = globalThis.fetch;
let reflectCalls: Record<string, unknown>[] = [];
let decodeCalls = 0;
let reflectReply: () => Response;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

const SCHEMALESS = { grpc: true, frames: [{ fields: [{ number: 1, wire_type: 0, varint: "150" }] }] };
const REFLECTED = {
 grpc: true,
 frames: [{ fields: [{ number: 1, wire_type: 0, varint: "150", name: "user_id", type: "int32" }] }],
 messages: ["acme.v1.User"],
 message: "acme.v1.User",
 schema_source: "reflection",
 schema_files: ["acme/v1/user.proto", "google/protobuf/any.proto"],
};

beforeEach(() => {
 reflectCalls = [];
 decodeCalls = 0;
 reflectReply = () => json(REFLECTED);
 useApp.setState({ protoSchema: null, protoMessages: {} } as never);
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/protobuf/decode") {
   decodeCalls++;
   return json(SCHEMALESS);
  }
  if (path === "/api/protobuf/reflect-decode") {
   reflectCalls.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return reflectReply();
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const view = (props: Partial<React.ComponentProps<typeof ProtobufView>> = {}) =>
 renderWithProviders(<ProtobufView bodyBase64="CJYB" grpc={true} direction="response" {...props} />);
const openForm = async () => fireEvent.click(await screen.findByRole("button", { name: "Fetch schema by reflection" }));
const fill = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const fetchNow = () => fireEvent.click(screen.getByRole("button", { name: "Fetch and decode" }));

describe("reflect-decode on the Protobuf tab", () => {
 test("the button is offered and the fetch needs a target and a service", async () => {
  view();
  await openForm();
  const go = screen.getByRole("button", { name: "Fetch and decode" }) as HTMLButtonElement;
  expect(go.disabled).toBe(true);
  fill("Reflection target (host:port)", "api.test:443");
  expect(go.disabled).toBe(true);
  fill("gRPC service", "acme.v1.Users");
  expect(go.disabled).toBe(false);
 });

 test("says that the fetch sends a request to the target", async () => {
  view();
  await openForm();
  expect(screen.getByText(/sends one request to the target/i)).toBeTruthy();
 });

 test("posts body, grpc and the reflect object", async () => {
  view();
  await openForm();
  fill("Reflection target (host:port)", " api.test:443 ");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  await waitFor(() => expect(reflectCalls.length).toBe(1));
  expect(reflectCalls[0]).toEqual({
   body_base64: "CJYB",
   grpc: true,
   reflect: { target: "api.test:443", service: "acme.v1.Users", tls: true },
  });
 });

 test("TLS can be turned off", async () => {
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:80");
  fill("gRPC service", "acme.v1.Users");
  fireEvent.click(screen.getByLabelText("Use TLS"));
  fetchNow();
  await waitFor(() => expect(reflectCalls.length).toBe(1));
  expect(reflectCalls[0]?.reflect).toEqual({ target: "api.test:80", service: "acme.v1.Users", tls: false });
 });

 test("the service is prefilled from the gRPC call path", async () => {
  view({ rpcPath: "/acme.v1.Users/GetUser" });
  await openForm();
  expect((screen.getByLabelText("gRPC service") as HTMLInputElement).value).toBe("acme.v1.Users");
  expect((screen.getByLabelText("Reflection target (host:port)") as HTMLInputElement).value).toBe("");
 });

 test("the result names its provenance: target-claimed, with the fetched files", async () => {
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  const note = await screen.findByRole("note", { name: "Schema provenance" });
  expect(note.textContent).toContain("api.test:443");
  expect(note.textContent).toMatch(/target-claimed/i);
  expect(note.textContent).toMatch(/not your schema/i);
  const files = within(screen.getByRole("list", { name: "Files the target served" })).getAllByRole("listitem");
  expect(files.map((f) => f.textContent)).toEqual(["acme/v1/user.proto", "google/protobuf/any.proto"]);
 });

 test("reflected field names are marked, an operator's own are not", async () => {
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  const name = await screen.findByText("user_id");
  expect(name.getAttribute("data-name-source")).toBe("reflection");
  expect(name.getAttribute("title")).toMatch(/not by your schema/i);
 });

 test("no provenance note without a reflection", async () => {
  view();
  await screen.findByText(/No schema/);
  expect(screen.queryByRole("note", { name: "Schema provenance" })).toBeNull();
 });

 test("discarding the reflected names goes back to the local decode", async () => {
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  await screen.findByRole("note", { name: "Schema provenance" });
  const before = decodeCalls;
  fireEvent.click(screen.getByRole("button", { name: "Discard reflected names" }));
  await waitFor(() => expect(screen.queryByRole("note", { name: "Schema provenance" })).toBeNull());
  await waitFor(() => expect(decodeCalls).toBeGreaterThan(before));
  expect(screen.queryByText("user_id")).toBeNull();
 });

 test("a refusal is shown and the schemaless view stays", async () => {
  reflectReply = () => new Response("scope refuses api.test:443 - no fetch was attempted", { status: 403 });
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  expect(await screen.findByText(/scope refuses api.test:443/)).toBeTruthy();
  expect(screen.queryByRole("note", { name: "Schema provenance" })).toBeNull();
  expect(screen.getByLabelText("field 1 varint")).toBeTruthy();
 });

 test("a different body drops the reflected names", async () => {
  function Harness() {
   const [body, setBody] = useState("CJYB");
   return (
    <>
     <button type="button" onClick={() => setBody("CJYC")}>
      next body
     </button>
     <ProtobufView bodyBase64={body} grpc={true} direction="response" />
    </>
   );
  }
  renderWithProviders(<Harness />);
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  await screen.findByRole("note", { name: "Schema provenance" });
  fireEvent.click(screen.getByRole("button", { name: "next body" }));
  await waitFor(() => expect(screen.queryByRole("note", { name: "Schema provenance" })).toBeNull());
  expect(screen.queryByText("user_id")).toBeNull();
 });

 test("an answer from the reflect call is target-claimed even if the server left the marker off", async () => {
  reflectReply = () => json({ ...REFLECTED, schema_source: undefined, schema_files: undefined });
  view();
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  const name = await screen.findByText("user_id");
  expect(name.getAttribute("data-name-source")).toBe("reflection");
  expect(screen.getByRole("note", { name: "Schema provenance" })).toBeTruthy();
 });
 test("a reflect answer that lands after the body changed is dropped, and the fetch state resets", async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
   release = resolve;
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   if (new URL(String(input), "http://localhost").pathname === "/api/protobuf/reflect-decode") {
    await gate;
    return json(REFLECTED);
   }
   return realFetch(input, init);
  }) as typeof fetch;
  function Harness() {
   const [body, setBody] = useState("CJYB");
   return (
    <>
     <button type="button" onClick={() => setBody("CJYC")}>
      next body
     </button>
     <ProtobufView bodyBase64={body} grpc={true} direction="response" />
    </>
   );
  }
  renderWithProviders(<Harness />);
  await openForm();
  fill("Reflection target (host:port)", "api.test:443");
  fill("gRPC service", "acme.v1.Users");
  fetchNow();
  await screen.findByRole("button", { name: "Fetching…" });
  fireEvent.click(screen.getByRole("button", { name: "next body" }));
  // the busy state of the cancelled fetch is gone
  await waitFor(() => expect(screen.queryByRole("button", { name: "Fetching…" }) === null).toBe(true));
  release();
  await new Promise((r) => setTimeout(r, 100));
  // the old body's decode did not land on the new body
  expect(screen.queryByText("user_id") === null).toBe(true);
  expect(screen.queryByRole("note", { name: "Schema provenance" }) === null).toBe(true);
 });
});
