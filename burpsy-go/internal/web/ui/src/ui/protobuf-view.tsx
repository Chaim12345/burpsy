import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
 decodeProtobuf,
 encodeProtobuf,
 reflectDecodeProtobuf,
 type ProtoDecodeResponse,
 type ProtoField,
 type ProtoFrame,
 type ProtoReflectTarget,
} from "../lib/data.protobuf";
import { useApp } from "../lib/store";
import { Badge, Button, Checkbox, Input, Select, Textarea } from "./primitives";

/**
 * The schemaless protobuf / gRPC field view (burpsy-react-ui-3x2g). An opaque binary body is decoded
 * into a field tree the operator can read, and — when the editor is editable — tamper with and apply:
 * edit a leaf, press Apply, and the tree re-encodes to body bytes written back through the editor.
 *
 * Without a schema, wire types and field numbers are all the wire format carries, so that is what
 * this shows. With a .proto loaded (burpsy-react-ui-3pco) the fields are named and typed — and the
 * schema is shared by every editor in the console, so loading it once names gRPC traffic in History,
 * Repeater, Intercept and the rest. For a gRPC call the request path names its rpc, and the schema's
 * service block then names the message for each direction; otherwise the operator picks one.
 * Names are presentation only: Apply re-encodes exactly the bytes the tree describes.
 */
export function ProtobufView({
 bodyBase64,
 grpc,
 onApply,
 direction,
 rpcPath,
}: {
 bodyBase64: string;
 grpc: boolean;
 /** Which side of the exchange this body is, so the request and response read as their own types. */
 direction: "request" | "response";
 /** The gRPC call path (/pkg.Service/Method) when known, so the schema can name the message itself. */
 rpcPath?: string;
 /** Write the re-encoded body back, base64. Absent = read-only (a response, or a non-editable pane). */
 onApply?: (bodyBase64: string) => void;
}): JSX.Element {
 const [frames, setFrames] = useState<ProtoFrame[] | null>(null);
 const [error, setError] = useState<string | null>(null);
 const [dirty, setDirty] = useState(false);
 const [applying, setApplying] = useState(false);
 const protoSchema = useApp((state) => state.protoSchema);
 const chosen = useApp((state) => state.protoMessages[direction]) ?? "";
 const [messages, setMessages] = useState<string[]>([]);
 const [resolved, setResolved] = useState("");
 // Set only by a reflection fetch: the names on screen are then the target's claims, not a schema the
 // operator supplied. Any change of body, schema or message goes back to the local decode below.
 const [reflected, setReflected] = useState<{ target: string; files: string[] } | null>(null);
 const [decodeNonce, setDecodeNonce] = useState(0);

 useEffect(() => {
  let live = true;
  setError(null);
  setDirty(false);
  setReflected(null);
  const schema = protoSchema
   ? protoSchema.files
    ? { proto_entry: protoSchema.entry, proto_files: protoSchema.files, message: chosen || undefined, rpc_path: rpcPath, direction }
    : { proto: protoSchema.text, message: chosen || undefined, rpc_path: rpcPath, direction }
   : {};
  decodeProtobuf(bodyBase64, grpc, schema)
   .then((res) => {
    if (!live) return;
    setFrames(res.frames);
    setMessages(res.messages ?? []);
    setResolved(res.message ?? "");
   })
   .catch((err) => {
    if (live) setError(err instanceof Error ? err.message : String(err));
   });
  return () => {
   live = false;
  };
 }, [bodyBase64, grpc, protoSchema, chosen, rpcPath, direction, decodeNonce]);

 const patchFrame = (fi: number, fields: ProtoField[]) => {
  setFrames((cur) => (cur ? cur.map((f, i) => (i === fi ? { ...f, fields } : f)) : cur));
  setDirty(true);
 };

 const apply = () => {
  if (!frames || !onApply) return;
  setApplying(true);
  encodeProtobuf(grpc, frames)
   .then((res) => {
    onApply(res.body_base64);
    setDirty(false);
    toast.success("Protobuf body re-encoded");
   })
   .catch((err) => toast.error(err instanceof Error ? err.message : String(err)))
   .finally(() => setApplying(false));
 };

 const schemaBar = (
  <>
   <SchemaBar direction={direction} messages={messages} resolved={resolved} rpcPath={rpcPath} />
   <ReflectBar
    bodyBase64={bodyBase64}
    grpc={grpc}
    rpcPath={rpcPath}
    onResult={(res, target) => {
     setFrames(res.frames);
     setMessages(res.messages ?? []);
     setResolved(res.message ?? "");
     setError(null);
     setDirty(false);
     // Every answer from the reflect call is the target's claim, whether or not the server marked it.
     setReflected({ target, files: res.schema_files ?? [] });
    }}
   />
   {reflected ? <ReflectionProvenance reflected={reflected} onDiscard={() => setDecodeNonce((n) => n + 1)} /> : null}
  </>
 );

 if (error) {
  return (
   <div className="stack" style={{ padding: 12 }}>
    {schemaBar}
    {/* A schema error (it did not parse, or names no such message) is said as such: an operator who
        loaded a .proto and sees an unnamed tree would assume it did not match the body. */}
    <div className="notice notice-warn">
     {protoSchema ? "The body could not be read with this schema: " : "This body did not decode as protobuf: "}
     {error}
    </div>
   </div>
  );
 }
 if (!frames) {
  return (
   <div className="cell-dim" style={{ padding: 12 }}>
    Decoding…
   </div>
  );
 }

 return (
  <div className="stack" style={{ padding: 12, overflow: "auto" }}>
   {schemaBar}
   {grpc ? (
    <div className="cell-dim">
     gRPC body — {frames.length} frame{frames.length === 1 ? "" : "s"}.
    </div>
   ) : null}
   {frames.map((frame, fi) => (
    <div key={fi} style={{ borderLeft: frames.length > 1 ? "2px solid var(--border)" : undefined, paddingLeft: frames.length > 1 ? 8 : 0 }}>
     {frames.length > 1 ? (
      <div style={{ marginBottom: 4 }}>
       <Badge tone={frame.trailer ? "info" : frame.compressed ? "warn" : "neutral"}>
        frame {fi + 1}
        {frame.trailer ? " · trailer" : frame.compressed ? " · compressed" : ""}
       </Badge>
      </div>
     ) : null}
     {frame.error ? (
      <div className="notice notice-warn">frame did not decode as protobuf: {frame.error}</div>
     ) : frame.text !== undefined ? (
      <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>{frame.text}</pre>
     ) : (
      <FieldTree fields={frame.fields ?? []} claimed={reflected !== null} onChange={onApply ? (next) => patchFrame(fi, next) : undefined} />
     )}
    </div>
   ))}
   {onApply ? (
    <div>
     <Button onClick={apply} disabled={!dirty || applying}>
      Apply edits
     </Button>
    </div>
   ) : null}
  </div>
 );
}

/** The recursive field editor. `onChange` absent means read-only (every input disabled). */
function FieldTree({
 fields,
 onChange,
 claimed,
}: {
 fields: ProtoField[];
 onChange?: (fields: ProtoField[]) => void;
 /** The names came from a target's reflection service, not from the operator's schema. */
 claimed?: boolean;
}): JSX.Element {
 const patch = (i: number, changes: Partial<ProtoField>) => {
  if (!onChange) return;
  onChange(fields.map((f, j) => (j === i ? { ...f, ...changes } : f)));
 };
 return (
  <table className="proto-tree" style={{ borderCollapse: "collapse", width: "100%" }}>
   <tbody>
    {fields.map((field, i) => (
     <tr key={i}>
      <td style={{ verticalAlign: "top", whiteSpace: "nowrap", padding: "2px 8px 2px 0" }}>
       {field.name ? (
        <>
         {claimed ? (
          <code
           data-name-source="reflection"
           title={`field ${field.number} - named by the target's reflection service, not by your schema`}
           style={{ borderBottom: "1px dashed currentColor", fontStyle: "italic" }}
          >
           {field.name}
          </code>
         ) : (
          <code title={`field ${field.number}`}>{field.name}</code>
         )}{" "}
         <span className="cell-dim">
          {field.type} · #{field.number}
         </span>
        </>
       ) : (
        <>
         <code>#{field.number}</code> <span className="cell-dim">{wireLabel(field)}</span>
        </>
       )}
      </td>
      <td style={{ width: "100%", padding: "2px 0" }}>
       {field.len_kind === "message" ? (
        <FieldTree fields={field.message ?? []} claimed={claimed} onChange={onChange ? (next) => patch(i, { message: next }) : undefined} />
       ) : (
        <FieldValue field={field} disabled={!onChange} onChange={(changes) => patch(i, changes)} />
       )}
      </td>
     </tr>
    ))}
   </tbody>
  </table>
 );
}

function FieldValue({
 field,
 disabled,
 onChange,
}: {
 field: ProtoField;
 disabled: boolean;
 onChange: (changes: Partial<ProtoField>) => void;
}): JSX.Element {
 const label = field.name ? `${field.name} (field ${field.number})` : `field ${field.number}`;
 if (field.wire_type === 0) {
  return (
   <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
    <Input
     aria-label={`${label} varint`}
     value={field.varint ?? ""}
     disabled={disabled}
     // The enum name is derived from the old number; drop it on edit rather than show a stale name.
     onChange={(e) => onChange({ varint: e.target.value, enum_name: undefined })}
    />
    {field.enum_name ? <Badge tone="info">{field.enum_name}</Badge> : null}
   </span>
  );
 }
 if (field.wire_type === 1) {
  return (
   <Input aria-label={`${label} i64`} value={field.i64 ?? ""} disabled={disabled} onChange={(e) => onChange({ i64: e.target.value })} />
  );
 }
 if (field.wire_type === 5) {
  return (
   <Input
    aria-label={`${label} i32`}
    value={String(field.i32 ?? 0)}
    disabled={disabled}
    onChange={(e) => onChange({ i32: Number(e.target.value) || 0 })}
   />
  );
 }
 if (field.len_kind === "string") {
  return (
   <Input
    aria-label={`${label} string`}
    value={field.string ?? ""}
    disabled={disabled}
    onChange={(e) => onChange({ string: e.target.value })}
   />
  );
 }
 if (field.len_kind === "bytes") {
  return (
   <Input
    aria-label={`${label} bytes (hex)`}
    value={field.bytes_hex ?? ""}
    disabled={disabled}
    onChange={(e) => onChange({ bytes_hex: e.target.value })}
    placeholder="hex"
   />
  );
 }
 return <span className="cell-dim">—</span>;
}

function wireLabel(field: ProtoField): string {
 switch (field.wire_type) {
  case 0:
   return "varint";
  case 1:
   return "i64";
  case 5:
   return "i32";
  case 2:
   return field.len_kind ?? "bytes";
  default:
   return `wire ${field.wire_type}`;
 }
}

/**
 * The schema controls (burpsy-react-ui-3pco): load, paste or clear the console-wide .proto, and choose
 * the message this direction is read as. "Automatic" means the gRPC call path's rpc signature, or the
 * schema's only message; the resolved name is shown so the operator can see which was used.
 */
function SchemaBar({
 direction,
 messages,
 resolved,
 rpcPath,
}: {
 direction: "request" | "response";
 messages: string[];
 resolved: string;
 rpcPath?: string;
}): JSX.Element {
 const protoSchema = useApp((state) => state.protoSchema);
 const setProtoSchema = useApp((state) => state.setProtoSchema);
 const chosen = useApp((state) => state.protoMessages[direction]) ?? "";
 const setProtoMessage = useApp((state) => state.setProtoMessage);
 const setProtoSchemaEntry = useApp((state) => state.setProtoSchemaEntry);
 const [pasting, setPasting] = useState(false);
 const [draft, setDraft] = useState("");
 const fileRef = useRef<HTMLInputElement>(null);

 // One file is the single-file schema form; several are the rsu2 file SET, whose imports resolve
 // across the set. The entry point defaults to the first file and is re-pickable below.
 const fileInput = (
  <input
   ref={fileRef}
   type="file"
   accept=".proto,text/plain"
   multiple
   className="sr-only"
   aria-hidden="true"
   tabIndex={-1}
   onChange={(event) => {
    const picked = [...(event.target.files ?? [])];
    event.target.value = "";
    if (picked.length === 0) return;
    if (picked.length === 1) {
     const file = picked[0]!;
     void file.text().then((text) => {
      setProtoSchema({ name: file.name, text });
      toast.success(`Loaded ${file.name} — it names protobuf fields in every editor`);
     });
     return;
    }
    void Promise.all(picked.map(async (f) => [f.name, await f.text()] as const)).then((entries) => {
     const files = Object.fromEntries(entries);
     setProtoSchema({ name: `${picked.length} .proto files`, text: entries[0]![1], files, entry: entries[0]![0] });
     toast.success(`Loaded ${picked.length} .proto files — imports between them resolve`);
    });
   }}
  />
 );

 if (pasting) {
  return (
   <div className="stack">
    <Textarea
     aria-label=".proto source"
     rows={8}
     value={draft}
     onChange={(e) => setDraft(e.target.value)}
     placeholder={'syntax = "proto3";\npackage acme.v1;\nmessage User { int32 user_id = 1; string name = 2; }'}
    />
    <div style={{ display: "flex", gap: 8 }}>
     <Button
      size="small"
      disabled={!draft.trim()}
      onClick={() => {
       setProtoSchema({ name: "pasted .proto", text: draft });
       setPasting(false);
       setDraft("");
      }}
     >
      Use this schema
     </Button>
     <Button size="small" variant="outline" onClick={() => setPasting(false)}>
      Cancel
     </Button>
    </div>
   </div>
  );
 }

 return (
  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
   {fileInput}
   {protoSchema ? (
    <>
     <span className="cell-dim">Schema:</span> <code>{protoSchema.name}</code>
     {protoSchema.files ? (
      <Select
       aria-label="Entry point of the .proto file set"
       value={protoSchema.entry ?? ""}
       onChange={(e) => setProtoSchemaEntry(e.target.value)}
      >
       {Object.keys(protoSchema.files).map((path) => (
        <option key={path} value={path}>
         entry: {path}
        </option>
       ))}
      </Select>
     ) : null}
     <Select aria-label={`Message type for the ${direction}`} value={chosen} onChange={(e) => setProtoMessage(direction, e.target.value)}>
      <option value="">
       {resolved ? `Automatic (${resolved})` : rpcPath ? "Automatic — no rpc matches this call" : "Automatic — choose a message"}
      </option>
      {messages.map((m) => (
       <option key={m} value={m}>
        {m}
       </option>
      ))}
     </Select>
     <Button size="small" variant="outline" onClick={() => fileRef.current?.click()}>
      Replace .proto
     </Button>
     <Button size="small" variant="outline" onClick={() => setProtoSchema(null)}>
      Clear schema
     </Button>
    </>
   ) : (
    <>
     <span className="cell-dim">No schema — fields are shown by number and wire type.</span>
     <Button size="small" variant="outline" onClick={() => fileRef.current?.click()}>
      Load .proto file(s)
     </Button>
     <Button size="small" variant="outline" onClick={() => setPasting(true)}>
      Paste .proto
     </Button>
    </>
   )}
  </div>
 );
}

/**
 * Reflection (burpsy-react-ui-mup0, API 47id): ask the TARGET for its own schema when no .proto is to
 * hand. Never automatic: the operator names the target and the service, and the button says it sends
 * a request. The target is never guessed. The service is prefilled from a gRPC call path because that
 * is the operator's own traffic naming it.
 */
function ReflectBar({
 bodyBase64,
 grpc,
 rpcPath,
 onResult,
}: {
 bodyBase64: string;
 grpc: boolean;
 rpcPath?: string;
 onResult: (res: ProtoDecodeResponse, target: string) => void;
}): JSX.Element {
 const [open, setOpen] = useState(false);
 const [target, setTarget] = useState("");
 const [service, setService] = useState(() => serviceOf(rpcPath));
 const [tls, setTls] = useState(true);
 const [busy, setBusy] = useState(false);
 const [failure, setFailure] = useState<string | null>(null);

 if (!open) {
  return (
   <div>
    <Button size="small" variant="outline" onClick={() => setOpen(true)}>
     Fetch schema by reflection
    </Button>
   </div>
  );
 }

 const go = () => {
  const reflect: ProtoReflectTarget = { target: target.trim(), service: service.trim(), tls };
  setBusy(true);
  setFailure(null);
  reflectDecodeProtobuf(bodyBase64, grpc, reflect)
   .then((res) => onResult(res, reflect.target))
   .catch((err) => setFailure(err instanceof Error ? err.message : String(err)))
   .finally(() => setBusy(false));
 };

 return (
  <div className="stack" role="group" aria-label="Fetch schema by reflection">
   <div className="cell-dim">
    Fetching sends one request to the target you name, which must be in scope, and asks it for the schema of one service. No session
    credentials are sent. What it answers with is the target's claim.
   </div>
   <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
    <Input aria-label="Reflection target (host:port)" placeholder="host:port" value={target} onChange={(e) => setTarget(e.target.value)} />
    <Input aria-label="gRPC service" placeholder="pkg.Service" value={service} onChange={(e) => setService(e.target.value)} />
    <Checkbox label="Use TLS" checked={tls} onCheckedChange={(on) => setTls(on === true)} />
    <Button size="small" onClick={go} disabled={busy || target.trim() === "" || service.trim() === ""}>
     {busy ? "Fetching…" : "Fetch and decode"}
    </Button>
    <Button size="small" variant="outline" onClick={() => setOpen(false)}>
     Close
    </Button>
   </div>
   {failure ? <div className="notice notice-warn">{failure}</div> : null}
  </div>
 );
}

/** "/pkg.Service/Method" -> "pkg.Service"; "" when the path is not a gRPC call path. */
function serviceOf(rpcPath?: string): string {
 const m = /^\/([^/]+)\/[^/]+$/.exec(rpcPath ?? "");
 return m?.[1] ?? "";
}

/** What reads differently about reflected names: who claimed them, and the files they came from. */
function ReflectionProvenance({
 reflected,
 onDiscard,
}: {
 reflected: { target: string; files: string[] };
 onDiscard: () => void;
}): JSX.Element {
 return (
  <div className="notice notice-warn" role="note" aria-label="Schema provenance">
   <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
    <Badge tone="warn">target-claimed names</Badge>
    <span>
     These field names were served by <code>{reflected.target}</code> over gRPC reflection. This is the target's schema, not your schema.
     The target controls them: treat them as untrusted text.
    </span>
    <Button size="small" variant="outline" onClick={onDiscard}>
     Discard reflected names
    </Button>
   </div>
   {reflected.files.length > 0 ? (
    <ul aria-label="Files the target served" style={{ margin: "4px 0 0", paddingLeft: 18 }}>
     {reflected.files.map((file) => (
      <li key={file}>
       <code>{file}</code>
      </li>
     ))}
    </ul>
   ) : null}
  </div>
 );
}
