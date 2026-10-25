import { useEffect, useRef, useState } from "react";
import { Copy } from "lucide-react";
import { copyToClipboard } from "../lib/api";
import {
 applyGraphQLQuery,
 validateGraphQLQuery,
 type GraphQLValidationError,
} from "../lib/data.tools";
import type { GraphQLDocument, GraphQLOperation, JwtReport, ParamReport } from "../lib/message-views";
import { Badge, Button, IconButton, Textarea } from "./primitives";

/**
 * The message editor's typed views: GraphQL, JWT and Params.
 *
 * Each of these is rendered only when `../lib/message-views` found something to
 * render — the availability decision lives with the detector, not here, so a view
 * cannot be opened onto nothing. What lives here is the other half of the same
 * rule: everything the detector could not do is printed. A JWT segment that would
 * not base64-decode says so where the JSON would have been, a variables blob that
 * is not JSON is shown as the text it is with the parser's complaint beside it, and
 * a body the Params parser does not split is named rather than left looking empty.
 */

function Section({ title, detail, children }: { title: string; detail?: string; children: React.ReactNode }): JSX.Element {
 return (
  <section className="typed-section">
   <h3 className="typed-section-head">
    {title}
    {detail ? <span className="typed-section-detail">{detail}</span> : null}
   </h3>
   {children}
  </section>
 );
}

function Block({ text }: { text: string }): JSX.Element {
 if (!text) return <p className="typed-empty">(no bytes)</p>;
 return <pre className="typed-block">{text}</pre>;
}

function Note({ children }: { children: React.ReactNode }): JSX.Element {
 return <p className="typed-warn">{children}</p>;
}

export function GraphQLView({
 document: doc,
 raw,
 onChange,
}: {
 document: GraphQLDocument;
 /** The request's exact bytes, when this view may edit them (4xqt.3). Absent on responses. */
 raw?: string;
 onChange?: (next: string) => void;
}): JSX.Element {
 // The edit-apply route rewrites the URL query parameter and the JSON body; every other
 // carrier it names and refuses, so the editor appears only where Apply can land.
 const carrierEditable = doc.source === "query string" || doc.source === "JSON body" || doc.source.startsWith("batched JSON body");
 const canEdit = raw !== undefined && onChange !== undefined && carrierEditable;
 return (
  <div className="typed-view">
   <p className="typed-source">Carried in the {doc.source}.</p>
   {raw !== undefined && onChange !== undefined && !carrierEditable ? (
    <Note>
     The edit path rewrites the URL query parameter and JSON body carriers only - edit this one on
     the Raw view.
    </Note>
   ) : null}
   {doc.operations.map((operation, index) => (
    <div className="typed-operation" key={index}>
     <Section
      title={operation.operationName ? `Operation ${operation.operationName}` : "Operation (anonymous)"}
      detail={doc.operations.length > 1 ? `${index + 1} of ${doc.operations.length}` : undefined}
     >
      {canEdit ? (
       <GraphQLOperationEditor
        key={`${index}:${operation.query}`}
        raw={raw}
        index={index}
        operation={operation}
        onChange={onChange}
       />
      ) : (
       <Block text={operation.query} />
      )}
     </Section>
     <Section title="Variables">
      {operation.variables === null ? (
       <p className="typed-empty">The request carried no variables.</p>
      ) : (
       <>
        {operation.variables.error ? <Note>{operation.variables.error}</Note> : null}
        <Block text={operation.variables.text} />
       </>
      )}
     </Section>
     {operation.extensions === null ? null : (
      <Section title="Extensions">
       {operation.extensions.error ? <Note>{operation.extensions.error}</Note> : null}
       <Block text={operation.extensions.text} />
      </Section>
     )}
    </div>
   ))}
   <p className="typed-foot">
    {canEdit
     ? "Applying rewrites exactly this operation's query inside its carrier - variables, operation name, extensions, formatting and header order are unchanged. The full draft stays one click away on the Raw view."
     : "Editing happens on the Raw view, which is the exact bytes. This view reads the document out of the request; it does not re-serialise it."}
   </p>
  </div>
 );
}

/**
 * One operation's editable query (burpsy-react-ui-4xqt.3). Check parses the draft with the
 * server's pinned gqlparser - the scanner's own parser and limit, so a document that passes
 * here is a document the scanner's gate would read - and Apply rewrites exactly this
 * operation's query inside the carrier, server-side, so no client re-serialisation can drift
 * the bytes around the edit. Nothing applies itself: both steps are the operator's click.
 */
function GraphQLOperationEditor({
 raw,
 index,
 operation,
 onChange,
}: {
 raw: string;
 index: number;
 operation: GraphQLOperation;
 onChange: (next: string) => void;
}): JSX.Element {
 const [draft, setDraft] = useState(operation.query);
 const [errors, setErrors] = useState<GraphQLValidationError[] | null>(null);
 const [busy, setBusy] = useState(false);
 const [applyError, setApplyError] = useState<string | null>(null);
 // The draft follows the operation the request now carries: after an Apply lands, and after
 // the editor is reused for another message, no earlier text survives (the key on this
 // component remounts it on the same change; the effect covers it inside one mount).
 useEffect(() => {
  setDraft(operation.query);
  setErrors(null);
  setApplyError(null);
 }, [operation.query]);
 // Apply resolves asynchronously; a draft the operator has since typed over must not be
 // overwritten by the older resolution (the rsu2 pick-batch generation guard).
 const applyGen = useRef(0);
 const dirty = draft !== operation.query;
 const check = () => {
  setBusy(true);
  validateGraphQLQuery(draft)
   .then((result) => setErrors(result.errors))
   .catch((failure: unknown) => setErrors([{ message: failure instanceof Error ? failure.message : String(failure) }]))
   .finally(() => setBusy(false));
 };
 const apply = () => {
  const gen = ++applyGen.current;
  setBusy(true);
  setApplyError(null);
  applyGraphQLQuery(raw, index, draft)
   .then((result) => {
    if (gen !== applyGen.current) {
     setApplyError("The draft changed while Apply was running - the request was left alone; Apply again to land it.");
     return;
    }
    onChange(result.request);
   })
   .catch((failure: unknown) => setApplyError(failure instanceof Error ? failure.message : String(failure)))
   .finally(() => setBusy(false));
 };
 return (
  <div>
   <Textarea
    name={`graphql-operation-${index}`}
    aria-label="Edit this operation's GraphQL query"
    rows={Math.min(18, Math.max(6, draft.split("\n").length + 1))}
    value={draft}
    onChange={(event) => {
     applyGen.current++;
     setDraft(event.target.value);
     setErrors(null);
    }}
   />
   <div>
    <Button variant="outline" size="small" disabled={busy} onClick={check}>
     Check
    </Button>{" "}
    <Button variant="outline" size="small" disabled={busy || !dirty} onClick={apply}>
     Apply to request
    </Button>
   </div>
   {errors !== null ? (
    errors.length === 0 ? (
     <Note>The document parses.</Note>
    ) : (
     errors.map((error, i) => (
      <Note key={i}>
       {error.line !== undefined ? `line ${error.line}, column ${error.column}: ` : ""}
       {error.message}
      </Note>
     ))
    )
   ) : null}
   {applyError !== null ? <Note>{applyError}</Note> : null}
  </div>
 );
}

export function JwtView({ report }: { report: JwtReport }): JSX.Element {
 return (
  <div className="typed-view">
   <p className="typed-source">
    {report.tokens.length} {report.tokens.length === 1 ? "token" : "tokens"} found.
    {report.truncated
     ? ` Only the first ${report.scannedBodyChars.toLocaleString()} characters of the body were searched, so there may be more below that.`
     : ""}
   </p>
   {report.tokens.map((token) => (
    <div className="typed-operation" key={token.token}>
     <Section title={token.locations.join(", ")} detail={token.alg ? `alg ${token.alg}` : undefined}>
      <div className="typed-token">
       <code className="typed-token-text">{token.token}</code>
       <IconButton label="Copy token" size="small" onClick={() => void copyToClipboard(token.token)}>
        <Copy size={13} />
       </IconButton>
      </div>
     </Section>
     <Section title="Header" detail={token.header.json ? "JSON" : "not JSON"}>
      {token.header.note ? <Note>{token.header.note}</Note> : null}
      <Block text={token.header.text} />
     </Section>
     <Section title="Payload" detail={token.payload.json ? "JSON" : "not JSON"}>
      {token.payload.note ? <Note>{token.payload.note}</Note> : null}
      <Block text={token.payload.text} />
     </Section>
     <Section title="Signature">
      {token.signature ? (
       <Block text={token.signature} />
      ) : (
       <p className="typed-empty">
        Empty. An <code>alg: none</code> token has no signature at all, which is worth a look.
       </p>
      )}
      <Note>
       Shown verbatim and not verified: burpsy holds no key for this token, and a signature it cannot check is not one it can vouch for.
       Nothing here says the token is valid.
      </Note>
     </Section>
    </div>
   ))}
   <p className="typed-foot">
    Decoded with the same tolerant base64url as <code>/api/tools/decode</code> with the <code>jwt</code> layer, so this view and that
    endpoint cannot disagree about a token. Editing happens on the Raw view.
   </p>
  </div>
 );
}

const KIND_LABEL: Record<string, string> = { query: "Query", body: "Body", cookie: "Cookie" };

export function ParamsView({ report }: { report: ParamReport }): JSX.Element {
 return (
  <div className="typed-view">
   <table className="typed-table">
    <caption className="sr-only">Parsed parameters</caption>
    <thead>
     <tr>
      <th scope="col">Type</th>
      <th scope="col">Name</th>
      <th scope="col">Value</th>
     </tr>
    </thead>
    <tbody>
     {report.rows.map((row, index) => (
      <tr key={`${row.kind}-${row.name}-${index}`}>
       <td>
        <Badge tone={row.kind === "cookie" ? "info" : row.kind === "body" ? "accent" : "neutral"}>{KIND_LABEL[row.kind] ?? row.kind}</Badge>
       </td>
       <td className="typed-name" title={row.name}>
        {row.name === "" ? <span className="cell-dim">(no name)</span> : row.name}
       </td>
       <td className="typed-value" title={row.value}>
        {row.value === "" ? <span className="cell-dim">(empty)</span> : row.value}
       </td>
      </tr>
     ))}
    </tbody>
   </table>
   {report.notes.map((note) => (
    <Note key={note}>{note}</Note>
   ))}
   <p className="typed-foot">
    Values are shown decoded — percent-escapes and <code>+</code> resolved — so a parameter reads as the server will see it. The bytes on
    the wire are on the Raw view, and that is where they are edited.
   </p>
  </div>
 );
}
