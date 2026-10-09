// The API scan's API-details review step (burpsy-react-ui-vuw7): Burp's endpoints table (delete rows),
// parameters table (Fixed / Dynamic values) and authentication methods, as state the New-scan dialog
// edits and the request fields POST /api/apiscan reads (exclude_endpoints, parameters, auth).
//
// Kept out of the dialog so the part that decides what goes on the wire can be tested without a DOM.
// The server is the authority — it refuses an exclusion or an override that matches nothing, by name —
// so this module's job is to never *build* such a row from state the operator can no longer see, and
// to say so when it holds one back rather than dropping it quietly.

import type { APIScanOperation, APIScanValueSource } from "./types.observe";

export type ParamMode = "fixed" | "dynamic";

/** One override as the server reads it. `endpoint` "" applies to every endpoint carrying the parameter. */
export interface ParamOverride {
 endpoint: string;
 in: string;
 name: string;
 value: string;
 mode: ParamMode;
}

export type AuthMethod =
 | { type: "none" }
 | { type: "basic"; username: string; password: string }
 | { type: "bearer"; token: string }
 | { type: "header"; name: string; value: string };

export type AuthType = AuthMethod["type"];

export interface ReviewState {
 /** "METHOD template" keys the operator removed from the endpoints table. */
 excluded: string[];
 /** Keyed by overrideKey(endpoint, in, name). */
 overrides: Record<string, ParamOverride>;
 auth: AuthMethod;
}

export const emptyReview: ReviewState = { excluded: [], overrides: {}, auth: { type: "none" } };

/** The fields of the method a fresh pick of `type` starts with. */
export function blankAuth(type: AuthType): AuthMethod {
 switch (type) {
  case "basic":
   return { type, username: "", password: "" };
  case "bearer":
   return { type, token: "" };
  case "header":
   return { type, name: "Authorization", value: "" };
  default:
   return { type: "none" };
 }
}

export function overrideKey(endpoint: string, location: string, name: string): string {
 return JSON.stringify([endpoint, location, name]);
}

/** Where a parameter row's shown value comes from. */
export type RowScope = "document" | "endpoint" | "all";

/** One parameter of one endpoint, with the override that governs it (if any) folded in. */
export interface ParamRow {
 /** Stable React key. */
 id: string;
 endpoint: string;
 method: string;
 template: string;
 in: string;
 name: string;
 /** The value the document (or this build's placeholder) gives, before any override. */
 documentValue: string;
 source: APIScanValueSource;
 type?: string;
 required?: boolean;
 /** The value that will be sent: the governing override's, or the document's. */
 value: string;
 mode: ParamMode;
 scope: RowScope;
 /** Null when the value can be edited; otherwise why not, in a sentence. */
 locked: string | null;
}

/** Locations an override re-renders on the wire (see apidoc's SetParameter). */
const EDITABLE_LOCATIONS = new Set(["path", "query", "header", "formData"]);

function lockReason(format: string, location: string): string | null {
 if (!EDITABLE_LOCATIONS.has(location)) return `A ${location} parameter cannot be overridden.`;
 // The server refuses this by name (a Postman request's path is already substituted and cannot be
 // re-rendered); the control is locked so the refusal is read before it is earned.
 if (location === "path" && format === "postman-2") return "A Postman path variable is set in the collection, not here.";
 return null;
}

/**
 * The parameters table: every parameter of every endpoint still in the scan, in the server's order.
 * An excluded endpoint's parameters are not listed — they will not be sent — but their overrides are
 * kept in state, so restoring the endpoint restores them.
 */
export function parameterRows(operations: APIScanOperation[], state: ReviewState, format: string): ParamRow[] {
 const excluded = new Set(state.excluded);
 const rows: ParamRow[] = [];
 for (const op of operations) {
  if (excluded.has(op.key)) continue;
  (op.parameters ?? []).forEach((param, index) => {
   const specific = state.overrides[overrideKey(op.key, param.in, param.name)];
   const shared = state.overrides[overrideKey("", param.in, param.name)];
   const governing = specific ?? shared;
   rows.push({
    id: `${op.key}#${index}`,
    endpoint: op.key,
    method: op.method,
    template: op.template,
    in: param.in,
    name: param.name,
    documentValue: param.value,
    source: param.source,
    type: param.type,
    required: param.required,
    value: governing ? governing.value : param.value,
    mode: governing ? governing.mode : "dynamic",
    scope: specific ? "endpoint" : shared ? "all" : "document",
    locked: lockReason(format, param.in),
   });
  });
 }
 return rows;
}

/**
 * Edits the value or mode of whatever governs `row`: its own override, the all-endpoints override it
 * is shown under, or — on a first edit — a new override for this endpoint alone.
 *
 * An endpoint override that is edited back to the document's value and Dynamic is removed: it would
 * send exactly what the document does, and leaving it in state would mark the value as the operator's
 * in the run record when the operator changed nothing.
 */
export function editRow(state: ReviewState, row: ParamRow, patch: { value?: string; mode?: ParamMode }): ReviewState {
 const endpoint = row.scope === "all" ? "" : row.endpoint;
 const key = overrideKey(endpoint, row.in, row.name);
 const next: ParamOverride = {
  endpoint,
  in: row.in,
  name: row.name,
  value: patch.value ?? row.value,
  mode: patch.mode ?? row.mode,
 };
 const overrides = { ...state.overrides };
 if (endpoint !== "" && next.value === row.documentValue && next.mode === "dynamic") {
  delete overrides[key];
 } else {
  overrides[key] = next;
 }
 return { ...state, overrides };
}

/**
 * Moves `row`'s value between "this endpoint" and "all endpoints".
 *
 * To all: the row's current value and mode become the shared override, and this endpoint's own
 * override (if any) is dropped so the shared one governs it. To this endpoint: the shared value is
 * copied into an override for this endpoint, and the shared one is left for the other endpoints —
 * narrowing one row must not silently un-set the value on every other.
 */
export function setRowScope(state: ReviewState, row: ParamRow, scope: "endpoint" | "all"): ReviewState {
 const overrides = { ...state.overrides };
 const own = overrideKey(row.endpoint, row.in, row.name);
 const shared = overrideKey("", row.in, row.name);
 if (scope === "all") {
  delete overrides[own];
  overrides[shared] = { endpoint: "", in: row.in, name: row.name, value: row.value, mode: row.mode };
 } else {
  overrides[own] = { endpoint: row.endpoint, in: row.in, name: row.name, value: row.value, mode: row.mode };
 }
 return { ...state, overrides };
}

/** Drops the override governing `row`. A shared one is dropped for every endpoint, which the button says. */
export function resetRow(state: ReviewState, row: ParamRow): ReviewState {
 if (row.scope === "document") return state;
 const overrides = { ...state.overrides };
 delete overrides[overrideKey(row.scope === "all" ? "" : row.endpoint, row.in, row.name)];
 return { ...state, overrides };
}

export function toggleEndpoint(state: ReviewState, key: string): ReviewState {
 const excluded = state.excluded.includes(key) ? state.excluded.filter((k) => k !== key) : [...state.excluded, key];
 return { ...state, excluded };
}

/** The review fields of the POST body. Absent fields are omitted, so an untouched review sends nothing. */
export interface ReviewFields {
 exclude_endpoints?: string[];
 parameters?: ParamOverride[];
 auth?: Exclude<AuthMethod, { type: "none" }>;
}

export interface BuiltReview {
 fields: ReviewFields;
 /** Why the scan cannot launch as reviewed, or null. */
 missing: string | null;
 /**
  * Review rows held back because the definition no longer describes what they name — the document
  * was edited after they were made. Listed so the dialog can say so; sending them would be a refusal,
  * and dropping them unannounced would be a review that silently shrank.
  */
 stale: string[];
}

function describe(o: ParamOverride): string {
 return `${o.in} parameter “${o.name}”${o.endpoint ? ` on ${o.endpoint}` : " (all endpoints)"}`;
}

/**
 * Builds the review fields from state, against the operations the definition currently describes.
 *
 * Shared overrides go first and endpoint overrides after them: the server applies the list in order,
 * so this is what makes "all endpoints: limit=5, but GET /pets: limit=50" mean what the table shows.
 * An override on an excluded endpoint, or a shared one whose parameter only excluded endpoints carry,
 * is held in state but not sent — the server would refuse it as matching nothing, and it applies again
 * the moment its endpoint is restored.
 */
export function buildReview(operations: APIScanOperation[], state: ReviewState): BuiltReview {
 const known = new Set(operations.map((op) => op.key));
 const excluded = new Set(state.excluded.filter((k) => known.has(k)));
 const stale: string[] = state.excluded.filter((k) => !known.has(k)).map((k) => `excluded endpoint ${k}`);
 const carried = (o: ParamOverride, includeExcluded: boolean) =>
  operations.some(
   (op) =>
    (o.endpoint === "" || op.key === o.endpoint) &&
    (includeExcluded || !excluded.has(op.key)) &&
    (op.parameters ?? []).some((p) => p.in === o.in && p.name === o.name),
  );

 const shared: ParamOverride[] = [];
 const specific: ParamOverride[] = [];
 for (const o of Object.values(state.overrides)) {
  if (!carried(o, true)) {
   stale.push(describe(o));
   continue;
  }
  if (!carried(o, false)) continue; // only on excluded endpoints: suspended, not stale
  (o.endpoint === "" ? shared : specific).push(o);
 }
 const byName = (a: ParamOverride, b: ParamOverride) =>
  a.endpoint.localeCompare(b.endpoint) || a.in.localeCompare(b.in) || a.name.localeCompare(b.name);
 const parameters = [...shared.sort(byName), ...specific.sort(byName)];

 const fields: ReviewFields = {};
 if (excluded.size > 0) fields.exclude_endpoints = [...excluded].sort();
 if (parameters.length > 0) fields.parameters = parameters;

 let missing: string | null = null;
 if (operations.length > 0 && excluded.size === operations.length) {
  missing = "Every endpoint is removed. Restore at least one to scan.";
 }
 const auth = state.auth;
 switch (auth.type) {
  case "basic":
   if (auth.username.trim() === "") missing ??= "Basic authentication needs a username.";
   fields.auth = auth;
   break;
  case "bearer":
   if (auth.token.trim() === "") missing ??= "Bearer authentication needs a token.";
   fields.auth = auth;
   break;
  case "header":
   if (auth.name.trim() === "") missing ??= "Header authentication needs a header name.";
   fields.auth = auth;
   break;
 }
 return { fields, missing, stale };
}

/** Whether the review would change the request at all — the dialog only re-checks it when it does. */
export function reviewChangesRequest(fields: ReviewFields): boolean {
 return fields.exclude_endpoints !== undefined || fields.parameters !== undefined || fields.auth !== undefined;
}

/**
 * Removes the review rows `buildReview` reported as stale, for the dialog's "Discard" button.
 */
export function discardStale(operations: APIScanOperation[], state: ReviewState): ReviewState {
 const known = new Set(operations.map((op) => op.key));
 const overrides: Record<string, ParamOverride> = {};
 for (const [key, o] of Object.entries(state.overrides)) {
  const live = operations.some(
   (op) => (o.endpoint === "" || op.key === o.endpoint) && (op.parameters ?? []).some((p) => p.in === o.in && p.name === o.name),
  );
  if (live) overrides[key] = o;
 }
 return { ...state, excluded: state.excluded.filter((k) => known.has(k)), overrides };
}

// ---- Upload from URL, with Add auth (burpsy-react-ui-fu4l) ----------------------------------------
//
// Burp's API scan can fetch the definition from a URL, with an authentication method for that fetch.
// POST /api/apiscan/fetch does the fetch through the scope-checked sender; these helpers decide what
// the dialog sends and what it says about what came back. The credential typed here is for the
// fetch only — it is not the scan's own authentication method above, and it lives only in the
// dialog's component state, never in the persisted store.

export type FetchAuth =
 | { type: "none" }
 | { type: "basic"; username: string; password: string }
 | { type: "bearer"; token: string }
 | { type: "oauth2_client_credentials"; tokenUrl: string; clientId: string; clientSecret: string; scope: string };

export type FetchAuthType = FetchAuth["type"];

export const FETCH_AUTH_LABELS: Record<FetchAuthType, string> = {
 none: "No authentication",
 basic: "Basic",
 bearer: "Bearer token",
 oauth2_client_credentials: "OAuth2 client credentials",
};

export function blankFetchAuth(type: FetchAuthType): FetchAuth {
 switch (type) {
  case "basic":
   return { type, username: "", password: "" };
  case "bearer":
   return { type, token: "" };
  case "oauth2_client_credentials":
   return { type, tokenUrl: "", clientId: "", clientSecret: "", scope: "" };
  default:
   return { type: "none" };
 }
}

/** Why `raw` cannot be fetched, or null. The server re-checks everything; this is the early word. */
export function fetchURLProblem(raw: string, what = "The definition URL"): string | null {
 const text = raw.trim();
 if (text === "") return `${what} is empty.`;
 let url: URL;
 try {
  url = new URL(text);
 } catch {
  return `${what} is not an absolute URL.`;
 }
 if (url.protocol !== "http:" && url.protocol !== "https:") return `${what} must be http or https.`;
 if (url.username || url.password) return `${what} carries credentials; put them under Add auth instead.`;
 return null;
}

/** Why the auth method is not ready to send, or null. */
export function fetchAuthProblem(auth: FetchAuth): string | null {
 switch (auth.type) {
  case "basic":
   return auth.username.trim() === "" ? "Basic authentication needs a username." : null;
  case "bearer":
   return auth.token.trim() === "" ? "Bearer authentication needs a token." : null;
  case "oauth2_client_credentials":
   if (auth.clientId.trim() === "") return "OAuth2 client credentials needs a client ID.";
   return fetchURLProblem(auth.tokenUrl, "The token URL");
  default:
   return null;
 }
}

/** The POST body for /api/apiscan/fetch, in the server's field names. No auth key for "none". */
export function fetchRequestBody(url: string, auth: FetchAuth): { url: string; auth?: Record<string, string> } {
 const body = { url: url.trim() };
 switch (auth.type) {
  case "basic":
   return { ...body, auth: { type: "basic", username: auth.username, password: auth.password } };
  case "bearer":
   return { ...body, auth: { type: "bearer", token: auth.token.trim() } };
  case "oauth2_client_credentials":
   return {
    ...body,
    auth: {
     type: "oauth2_client_credentials",
     token_url: auth.tokenUrl.trim(),
     client_id: auth.clientId,
     client_secret: auth.clientSecret,
     ...(auth.scope.trim() ? { scope: auth.scope.trim() } : {}),
    },
   };
  default:
   return body;
 }
}

/** POST /api/apiscan/fetch's answer. */
export interface FetchedDefinition {
 definition: string;
 format: string;
 scannable: boolean;
 note?: string;
 url: string;
 status: number;
 content_type?: string;
 bytes: number;
 token_fetched?: boolean;
}

const FORMAT_NAMES: Record<string, string> = {
 "openapi-3": "OpenAPI 3",
 "swagger-2": "Swagger 2.0",
 "postman-2": "Postman collection",
 wsdl: "WSDL",
 unknown: "unrecognised",
};

/** The caption shown beside the definition box once a fetch has filled it. */
export function fetchedCaption(fetched: FetchedDefinition): string {
 const name = FORMAT_NAMES[fetched.format] ?? fetched.format;
 return `${fetched.url} — ${name}, ${fetched.bytes} bytes${fetched.token_fetched ? " (OAuth2 token obtained)" : ""}`;
}

/**
 * What the dialog says about a fetched document the scan cannot read, or null when it can. The
 * document still goes in the box — the operator may want to read it — but the reason is stated
 * rather than left to the dry run's parser message.
 */
export function fetchedWarning(fetched: FetchedDefinition): string | null {
 if (fetched.scannable) return null;
 const name = FORMAT_NAMES[fetched.format] ?? fetched.format;
 return `Fetched, but this is ${name === "unrecognised" ? "not a definition this build recognises" : `a ${name} document`}: ${fetched.note ?? "the API scan cannot read it"}`;
}
