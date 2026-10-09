// The API scan's API-details review step (burpsy-react-ui-vuw7): Burp's endpoints table with
// per-row delete, the parameters table with Fixed / Dynamic values, and one authentication method.
// The state lives in the New-scan dialog; what reaches the wire is decided in lib/apiscan-review.

import { useState } from "react";
import {
 blankAuth,
 editRow,
 parameterRows,
 resetRow,
 setRowScope,
 toggleEndpoint,
 blankFetchAuth,
 FETCH_AUTH_LABELS,
 fetchAuthProblem,
 fetchRequestBody,
 fetchURLProblem,
 type AuthType,
 type FetchAuth,
 type FetchAuthType,
 type FetchedDefinition,
 type ParamMode,
 type ReviewState,
} from "../lib/apiscan-review";
import type { APIScanOperation, APIScanValueSource } from "../lib/types.observe";
import { Badge, Button, ErrorNotice, Field, Input, Select, type Tone } from "./primitives";
import { useFetchAPIDefinition } from "../lib/data.observe";
import { SimpleTable } from "./table";

const SOURCE_TONE: Record<APIScanValueSource, Tone> = {
 example: "good",
 default: "good",
 enum: "good",
 placeholder: "warn",
 operator: "accent",
};

const SOURCE_TITLE: Record<APIScanValueSource, string> = {
 example: "The document's own example",
 default: "The schema's default",
 enum: "The first value of the schema's enum",
 placeholder: "Invented by this build: the document gives no example, default or enum",
 operator: "Set by the operator",
};

function methodTone(method: string): Tone {
 return method === "GET" ? "info" : method === "DELETE" ? "bad" : "warn";
}

export function APIScanReview({
 operations,
 format,
 state,
 onChange,
 reviewedPaths,
}: {
 operations: APIScanOperation[];
 format: string;
 state: ReviewState;
 onChange: (next: ReviewState) => void;
 /** The request path the reviewed dry run resolved for each kept endpoint, when it has answered. */
 reviewedPaths: Map<string, string> | null;
}): JSX.Element {
 const [filter, setFilter] = useState("");
 const excluded = new Set(state.excluded);
 const rows = parameterRows(operations, state, format);
 const needle = filter.trim().toLowerCase();
 const shown = needle
  ? rows.filter((r) => `${r.endpoint} ${r.in} ${r.name} ${r.value}`.toLowerCase().includes(needle))
  : rows;
 const kept = operations.length - operations.filter((op) => excluded.has(op.key)).length;

 return (
  <div className="stack apiscan-review">
   <h3 className="subheading">Endpoints</h3>
   <p className="cell-dim" style={{ margin: 0 }}>
    {kept} of {operations.length} endpoint{operations.length === 1 ? "" : "s"} will be scanned. A removed endpoint is not sent
    and not audited; it stays listed here so it can be restored.
   </p>
   <div className="apiscan-review-scroll">
    <SimpleTable headers={["Method", "Document path", "Request", "Parameters", ""]}>
     {operations.map((op) => {
      const removed = excluded.has(op.key);
      const request = reviewedPaths?.get(op.key) ?? op.path;
      return (
       <tr key={op.key} className={removed ? "apiscan-removed" : undefined}>
        <td>
         <Badge tone={removed ? "neutral" : methodTone(op.method)}>{op.method}</Badge>
        </td>
        <td>
         <code>{op.template}</code>
        </td>
        <td className="cell-dim">{removed ? "not sent" : <code>{request}</code>}</td>
        <td className="cell-dim">{op.parameters?.length ?? 0}</td>
        <td>
         <Button
          variant={removed ? "outline" : "quiet"}
          size="small"
          aria-label={`${removed ? "Restore" : "Remove"} ${op.key}`}
          onClick={() => onChange(toggleEndpoint(state, op.key))}
         >
          {removed ? "Restore" : "Remove"}
         </Button>
        </td>
       </tr>
      );
     })}
    </SimpleTable>
   </div>
   {state.excluded.length > 1 ? (
    <div className="toolbar">
     <Button variant="outline" size="small" onClick={() => onChange({ ...state, excluded: [] })}>
      Restore all endpoints
     </Button>
    </div>
   ) : null}

   <h3 className="subheading">Parameters</h3>
   {rows.length === 0 ? (
    <p className="cell-dim" style={{ margin: 0 }}>
     {kept === 0
      ? "No endpoint is left to scan, so there are no parameters to review."
      : "The endpoints left in the scan declare no path, query, header or form parameters. A request body synthesised from a schema is not editable here."}
    </p>
   ) : (
    <>
     <p className="cell-dim" style={{ margin: 0 }}>
      Dynamic values are sent and audited like any other. Fixed values are sent as set and kept out of the audit's insertion
      points — the audit matches a Fixed parameter by name, so fixing one on a single endpoint exempts that name on every
      endpoint. A request body synthesised from a schema is not listed. * marks a parameter the document requires.
     </p>
     {rows.length > 8 ? (
      <Input
       aria-label="Filter parameters"
       title="Filter parameters by endpoint, location, name or value"
       placeholder="Filter parameters"
       value={filter}
       onChange={(event) => setFilter(event.target.value)}
      />
     ) : null}
     <div className="apiscan-review-scroll">
      <SimpleTable headers={["Endpoint", "Parameter", "Source", "Value", "Mode", "Applies to", ""]}>
       {shown.map((row) => {
        const label = `${row.in} parameter ${row.name} on ${row.endpoint}`;
        const source: APIScanValueSource = row.scope === "document" ? row.source : "operator";
        return (
         <tr key={row.id}>
          <td>
           <code>{row.endpoint}</code>
          </td>
          <td>
           <span className="cell-dim">{row.in} </span>
           <code>{row.name}</code>
           {row.required ? <span className="cell-dim" title="Required by the document"> *<span className="sr-only"> required</span></span> : null}
          </td>
          <td>
           <Badge tone={SOURCE_TONE[source]} title={row.scope === "document" ? SOURCE_TITLE[source] : `${SOURCE_TITLE.operator}; the document gives “${row.documentValue}” (${row.source})`}>
            {source}
           </Badge>
          </td>
          <td>
           {row.locked ? (
            <span title={row.locked}>
             <code>{row.value}</code> <small className="field-hint">{row.locked}</small>
            </span>
           ) : (
            <Input aria-label={`Value of ${label}`} value={row.value} onChange={(event) => onChange(editRow(state, row, { value: event.target.value }))} />
           )}
          </td>
          <td>
           <Select
            aria-label={`Mode of ${label}`}
            value={row.mode}
            disabled={row.locked !== null}
            onChange={(event) => onChange(editRow(state, row, { mode: event.target.value as ParamMode }))}
           >
            <option value="dynamic">Dynamic</option>
            <option value="fixed">Fixed</option>
           </Select>
          </td>
          <td>
           <Select
            aria-label={`Scope of ${label}`}
            value={row.scope === "all" ? "all" : "endpoint"}
            disabled={row.locked !== null}
            onChange={(event) => onChange(setRowScope(state, row, event.target.value as "endpoint" | "all"))}
           >
            <option value="endpoint">This endpoint</option>
            <option value="all">All endpoints</option>
           </Select>
          </td>
          <td>
           {row.scope !== "document" ? (
            <Button variant="quiet" size="small" aria-label={`Reset ${label}${row.scope === "all" ? " on every endpoint" : ""}`} onClick={() => onChange(resetRow(state, row))}>
             {row.scope === "all" ? "Reset all" : "Reset"}
            </Button>
           ) : null}
          </td>
         </tr>
        );
       })}
      </SimpleTable>
     </div>
     {needle && shown.length < rows.length ? (
      <p className="cell-dim" style={{ margin: 0 }}>
       Showing {shown.length} of {rows.length} parameters; the filter hides rows from view only, and every override still applies.
      </p>
     ) : null}
    </>
   )}

   <h3 className="subheading">Authentication</h3>
   <AuthSection state={state} onChange={onChange} operations={operations.filter((op) => !excluded.has(op.key))} />
  </div>
 );
}

const AUTH_CHOICES: ReadonlyArray<readonly [AuthType, string, string]> = [
 ["none", "None", "send only the headers the document declares"],
 ["basic", "Basic", "Authorization: Basic with a username and password"],
 ["bearer", "Bearer", "Authorization: Bearer with a token"],
 ["header", "Header", "any one header, by name and value"],
];

function AuthSection({
 state,
 onChange,
 operations,
}: {
 state: ReviewState;
 onChange: (next: ReviewState) => void;
 operations: APIScanOperation[];
}): JSX.Element {
 const auth = state.auth;
 const headerName = auth.type === "header" ? auth.name.trim() : auth.type === "none" ? "" : "Authorization";
 // The method replaces a header of the same name the document declares (the server drops the
 // document's), so the parameters table's row for that header stops reaching the wire. Said here
 // rather than discovered in HTTP history.
 const replaces = headerName
  ? operations.filter((op) => (op.parameters ?? []).some((p) => p.in === "header" && p.name.toLowerCase() === headerName.toLowerCase()))
  : [];
 const set = (next: ReviewState["auth"]) => onChange({ ...state, auth: next });
 return (
  <>
   <div role="radiogroup" aria-label="Authentication method">
    {AUTH_CHOICES.map(([value, label, hint]) => (
     <label key={value} style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
      <input type="radio" name="apiscan-auth" checked={auth.type === value} onChange={() => set(blankAuth(value))} />
      <span>
       {label} <span className="field-hint">— {hint}</span>
      </span>
     </label>
    ))}
   </div>
   {auth.type === "basic" ? (
    <div className="metric-grid wide">
     <Field label="Username">{(id) => <Input id={id} autoComplete="off" value={auth.username} onChange={(event) => set({ ...auth, username: event.target.value })} />}</Field>
     <Field label="Password">
      {(id) => <Input id={id} type="password" autoComplete="new-password" value={auth.password} onChange={(event) => set({ ...auth, password: event.target.value })} />}
     </Field>
    </div>
   ) : auth.type === "bearer" ? (
    <Field label="Token" hint="Sent as Authorization: Bearer <token> on every request.">
     {(id) => <Input id={id} type="password" autoComplete="new-password" value={auth.token} onChange={(event) => set({ ...auth, token: event.target.value })} />}
    </Field>
   ) : auth.type === "header" ? (
    <div className="metric-grid wide">
     <Field label="Header name">{(id) => <Input id={id} autoComplete="off" value={auth.name} onChange={(event) => set({ ...auth, name: event.target.value })} />}</Field>
     <Field label="Header value">
      {(id) => <Input id={id} type="password" autoComplete="new-password" value={auth.value} onChange={(event) => set({ ...auth, value: event.target.value })} />}
     </Field>
    </div>
   ) : null}
   {auth.type !== "none" ? (
    <p className="cell-dim" style={{ margin: 0 }}>
     Added to every request this scan sends to the definition's host, and carried into its audit. It is not stored with the
     scan's settings; the requests themselves are captured in HTTP history like any other traffic.
    </p>
   ) : null}
   {replaces.length > 0 ? (
    <p className="warn-text" role="status" style={{ margin: 0 }}>
     Replaces the {headerName} header the document declares on {replaces.length} endpoint{replaces.length === 1 ? "" : "s"} (
     {replaces.map((op) => op.key).join(", ")}): that parameter's value in the table above is not sent while this method is set.
    </p>
   ) : null}
  </>
 );
}

/**
 * Upload from URL, with Add auth (burpsy-react-ui-fu4l): Burp's other definition source. The fetch
 * goes through POST /api/apiscan/fetch — scope-checked on the exact bytes, not recorded in history —
 * and what comes back fills the same definition box an uploaded file does.
 *
 * The credential is held in this component's state only: it is for this fetch, it is not the scan's
 * authentication method (set in the review below), and nothing here writes it to the persisted store.
 */
export function APIScanFetchFromURL({ onLoaded }: { onLoaded: (fetched: FetchedDefinition) => void }): JSX.Element {
 const [url, setUrl] = useState("");
 const [auth, setAuth] = useState<FetchAuth>({ type: "none" });
 const fetchDefinition = useFetchAPIDefinition();
 const problem = fetchURLProblem(url) ?? fetchAuthProblem(auth);
 const run = () => {
  if (problem) return;
  fetchDefinition.mutate(fetchRequestBody(url, auth), { onSuccess: onLoaded });
 };
 return (
  <div className="stack" style={{ gap: 8 }}>
   <div className="toolbar" style={{ alignItems: "flex-end" }}>
    <Field label="Definition URL" style={{ flex: 1 }} hint="Fetched once through the scope check — an out-of-scope URL is refused, not contacted. Redirects are not followed.">
     {(id) => (
      <Input
       id={id}
       value={url}
       onChange={(event) => setUrl(event.target.value)}
       onKeyDown={(event) => {
        if (event.key === "Enter") run();
       }}
       placeholder="https://api.example.com/openapi.json"
      />
     )}
    </Field>
    <Field label="Add auth" style={{ maxWidth: "var(--w-md)" }}>
     {(id) => (
      <Select id={id} value={auth.type} onChange={(event) => setAuth(blankFetchAuth(event.target.value as FetchAuthType))}>
       {(Object.keys(FETCH_AUTH_LABELS) as FetchAuthType[]).map((type) => (
        <option key={type} value={type}>
         {FETCH_AUTH_LABELS[type]}
        </option>
       ))}
      </Select>
     )}
    </Field>
   </div>
   {auth.type === "basic" ? (
    <div className="toolbar">
     <Field label="Username">{(id) => <Input id={id} autoComplete="off" value={auth.username} onChange={(e) => setAuth({ ...auth, username: e.target.value })} />}</Field>
     <Field label="Password">{(id) => <Input id={id} type="password" autoComplete="off" value={auth.password} onChange={(e) => setAuth({ ...auth, password: e.target.value })} />}</Field>
    </div>
   ) : auth.type === "bearer" ? (
    <Field label="Token">{(id) => <Input id={id} type="password" autoComplete="off" value={auth.token} onChange={(e) => setAuth({ ...auth, token: e.target.value })} />}</Field>
   ) : auth.type === "oauth2_client_credentials" ? (
    <div className="stack" style={{ gap: 8 }}>
     <Field label="Token URL" hint="Must be in scope too: the token request is a send like any other.">
      {(id) => <Input id={id} value={auth.tokenUrl} placeholder="https://auth.example.com/oauth/token" onChange={(e) => setAuth({ ...auth, tokenUrl: e.target.value })} />}
     </Field>
     <div className="toolbar">
      <Field label="Client ID">{(id) => <Input id={id} autoComplete="off" value={auth.clientId} onChange={(e) => setAuth({ ...auth, clientId: e.target.value })} />}</Field>
      <Field label="Client secret">{(id) => <Input id={id} type="password" autoComplete="off" value={auth.clientSecret} onChange={(e) => setAuth({ ...auth, clientSecret: e.target.value })} />}</Field>
      <Field label="Scope (optional)">{(id) => <Input id={id} value={auth.scope} onChange={(e) => setAuth({ ...auth, scope: e.target.value })} />}</Field>
     </div>
    </div>
   ) : null}
   <div className="toolbar">
    <Button variant="outline" size="small" onClick={run} disabled={problem !== null || fetchDefinition.isPending}>
     {fetchDefinition.isPending ? "Fetching…" : "Fetch definition"}
    </Button>
    {problem && url.trim() !== "" ? <span className="cell-dim">{problem}</span> : null}
   </div>
   {fetchDefinition.error ? <ErrorNotice error={fetchDefinition.error} title="The definition was not fetched" /> : null}
  </div>
 );
}
