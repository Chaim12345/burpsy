import { expect, test } from "bun:test";
import {
 blankAuth,
 buildReview,
 discardStale,
 editRow,
 emptyReview,
 parameterRows,
 resetRow,
 reviewChangesRequest,
 setRowScope,
 toggleEndpoint,
 type ReviewState,
} from "./apiscan-review";
import type { APIScanOperation } from "./types.observe";

// burpsy-react-ui-vuw7: the API-details review step. The server refuses an exclusion or override that
// matches nothing, so these tests are mostly about what the dialog must NOT send.

const ops: APIScanOperation[] = [
 {
  method: "GET",
  template: "/pets",
  path: "/pets?limit=20&q=cat",
  key: "GET /pets",
  parameters: [
   { name: "limit", in: "query", value: "20", source: "default" },
   { name: "q", in: "query", value: "cat", source: "example" },
  ],
 },
 {
  method: "GET",
  template: "/pets/{petId}",
  path: "/pets/1?limit=1",
  key: "GET /pets/{petId}",
  parameters: [
   { name: "petId", in: "path", value: "1", source: "placeholder" },
   { name: "limit", in: "query", value: "1", source: "placeholder" },
  ],
 },
 { method: "DELETE", template: "/pets/{petId}", path: "/pets/1", key: "DELETE /pets/{petId}", parameters: [{ name: "petId", in: "path", value: "1", source: "placeholder" }] },
];

const row = (state: ReviewState, endpoint: string, name: string) => {
 const found = parameterRows(ops, state, "openapi-3").find((r) => r.endpoint === endpoint && r.name === name);
 if (!found) throw new Error(`no row ${endpoint} ${name}`);
 return found;
};

test("an untouched review sends no review fields at all", () => {
 const built = buildReview(ops, emptyReview);
 expect(built).toEqual({ fields: {}, missing: null, stale: [] });
 expect(reviewChangesRequest(built.fields)).toBe(false);
});

test("a removed endpoint is sent as its METHOD template key, and restoring it removes it again", () => {
 let state = toggleEndpoint(emptyReview, "DELETE /pets/{petId}");
 expect(buildReview(ops, state).fields).toEqual({ exclude_endpoints: ["DELETE /pets/{petId}"] });
 expect(parameterRows(ops, state, "openapi-3").some((r) => r.endpoint === "DELETE /pets/{petId}")).toBe(false);
 state = toggleEndpoint(state, "DELETE /pets/{petId}");
 expect(buildReview(ops, state).fields).toEqual({});
});

test("removing every endpoint is refused before the server has to", () => {
 let state = emptyReview;
 for (const op of ops) state = toggleEndpoint(state, op.key);
 expect(buildReview(ops, state).missing).toContain("Every endpoint");
});

test("a row shows its source and the document value until edited, then the operator's", () => {
 const before = row(emptyReview, "GET /pets", "q");
 expect(before).toMatchObject({ source: "example", value: "cat", mode: "dynamic", scope: "document", locked: null });
 const state = editRow(emptyReview, before, { value: "dog" });
 expect(row(state, "GET /pets", "q")).toMatchObject({ value: "dog", scope: "endpoint", documentValue: "cat" });
 expect(buildReview(ops, state).fields.parameters).toEqual([{ endpoint: "GET /pets", in: "query", name: "q", value: "dog", mode: "dynamic" }]);
});

test("editing a value back to the document's, Dynamic, drops the override instead of sending a no-op", () => {
 let state = editRow(emptyReview, row(emptyReview, "GET /pets", "q"), { value: "dog" });
 state = editRow(state, row(state, "GET /pets", "q"), { value: "cat" });
 expect(state.overrides).toEqual({});
 // Fixed with the document's own value is a real choice: it keeps the parameter out of the audit.
 state = editRow(state, row(state, "GET /pets", "q"), { mode: "fixed" });
 expect(buildReview(ops, state).fields.parameters).toEqual([{ endpoint: "GET /pets", in: "query", name: "q", value: "cat", mode: "fixed" }]);
});

test("an all-endpoints value governs every endpoint carrying the parameter and is sent with endpoint empty", () => {
 let state = editRow(emptyReview, row(emptyReview, "GET /pets", "limit"), { value: "5" });
 state = setRowScope(state, row(state, "GET /pets", "limit"), "all");
 expect(row(state, "GET /pets/{petId}", "limit")).toMatchObject({ value: "5", scope: "all" });
 expect(buildReview(ops, state).fields.parameters).toEqual([{ endpoint: "", in: "query", name: "limit", value: "5", mode: "dynamic" }]);
 // Editing any row under the shared value edits the shared value.
 state = editRow(state, row(state, "GET /pets/{petId}", "limit"), { mode: "fixed" });
 expect(row(state, "GET /pets", "limit")).toMatchObject({ mode: "fixed", scope: "all" });
});

test("an endpoint override is sent after the shared one, so the server lets it win", () => {
 let state = setRowScope(emptyReview, row(emptyReview, "GET /pets", "limit"), "all");
 state = editRow(state, row(state, "GET /pets", "limit"), { value: "5" });
 state = setRowScope(state, row(state, "GET /pets/{petId}", "limit"), "endpoint");
 state = editRow(state, row(state, "GET /pets/{petId}", "limit"), { value: "50" });
 expect(row(state, "GET /pets", "limit").value).toBe("5");
 expect(row(state, "GET /pets/{petId}", "limit").value).toBe("50");
 expect(buildReview(ops, state).fields.parameters).toEqual([
  { endpoint: "", in: "query", name: "limit", value: "5", mode: "dynamic" },
  { endpoint: "GET /pets/{petId}", in: "query", name: "limit", value: "50", mode: "dynamic" },
 ]);
 // Resetting the shared row resets it for every endpoint; the endpoint override survives.
 state = resetRow(state, row(state, "GET /pets", "limit"));
 expect(row(state, "GET /pets", "limit")).toMatchObject({ value: "20", scope: "document" });
 expect(row(state, "GET /pets/{petId}", "limit")).toMatchObject({ value: "50", scope: "endpoint" });
});

test("an override on a removed endpoint is held, not sent, and comes back with the endpoint", () => {
 let state = editRow(emptyReview, row(emptyReview, "DELETE /pets/{petId}", "petId"), { value: "9" });
 state = toggleEndpoint(state, "DELETE /pets/{petId}");
 const built = buildReview(ops, state);
 // The server applies exclusions first, so sending this override would be refused as matching nothing.
 expect(built.fields).toEqual({ exclude_endpoints: ["DELETE /pets/{petId}"] });
 expect(built.stale).toEqual([]);
 state = toggleEndpoint(state, "DELETE /pets/{petId}");
 expect(buildReview(ops, state).fields.parameters).toEqual([{ endpoint: "DELETE /pets/{petId}", in: "path", name: "petId", value: "9", mode: "dynamic" }]);
});

test("rows the edited definition no longer describes are reported as stale, not sent, until discarded", () => {
 let state = editRow(emptyReview, row(emptyReview, "GET /pets", "q"), { value: "dog" });
 state = toggleEndpoint(state, "DELETE /pets/{petId}");
 const shrunk = ops.slice(0, 2).map((op) => (op.key === "GET /pets" ? { ...op, parameters: op.parameters?.filter((p) => p.name !== "q") } : op));
 const built = buildReview(shrunk, state);
 expect(built.fields).toEqual({});
 expect(built.stale).toEqual(["excluded endpoint DELETE /pets/{petId}", "query parameter “q” on GET /pets"]);
 const cleaned = discardStale(shrunk, state);
 expect(cleaned).toEqual({ ...emptyReview });
});

test("authentication: none sends nothing, each method needs its one required field", () => {
 expect(buildReview(ops, { ...emptyReview, auth: blankAuth("none") }).fields.auth).toBeUndefined();
 expect(buildReview(ops, { ...emptyReview, auth: blankAuth("basic") }).missing).toBe("Basic authentication needs a username.");
 expect(buildReview(ops, { ...emptyReview, auth: blankAuth("bearer") }).missing).toBe("Bearer authentication needs a token.");
 expect(buildReview(ops, { ...emptyReview, auth: { type: "header", name: " ", value: "x" } }).missing).toBe("Header authentication needs a header name.");
 const basic = buildReview(ops, { ...emptyReview, auth: { type: "basic", username: "alice", password: "" } });
 expect(basic).toEqual({ fields: { auth: { type: "basic", username: "alice", password: "" } }, missing: null, stale: [] });
 expect(blankAuth("header")).toEqual({ type: "header", name: "Authorization", value: "" });
});

test("a Postman path variable is locked; its query parameters are not", () => {
 const rows = parameterRows(ops, emptyReview, "postman-2");
 expect(rows.find((r) => r.name === "petId")?.locked).toContain("Postman");
 expect(rows.find((r) => r.name === "limit")?.locked).toBeNull();
});
