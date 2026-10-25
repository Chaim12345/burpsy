import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { decodeProtobuf, encodeProtobuf, type ProtoField, type ProtoFrame } from "../lib/data.protobuf";
import { useApp } from "../lib/store";
import { Badge, Button, Input, Select, Textarea } from "./primitives";

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

 useEffect(() => {
  let live = true;
  setError(null);
  setDirty(false);
  const schema = protoSchema ? { proto: protoSchema.text, message: chosen || undefined, rpc_path: rpcPath, direction } : {};
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
 }, [bodyBase64, grpc, protoSchema, chosen, rpcPath, direction]);

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

 const schemaBar = <SchemaBar direction={direction} messages={messages} resolved={resolved} rpcPath={rpcPath} />;

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
      <FieldTree fields={frame.fields ?? []} onChange={onApply ? (next) => patchFrame(fi, next) : undefined} />
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
function FieldTree({ fields, onChange }: { fields: ProtoField[]; onChange?: (fields: ProtoField[]) => void }): JSX.Element {
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
         <code title={`field ${field.number}`}>{field.name}</code>{" "}
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
        <FieldTree fields={field.message ?? []} onChange={onChange ? (next) => patch(i, { message: next }) : undefined} />
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
 const [pasting, setPasting] = useState(false);
 const [draft, setDraft] = useState("");
 const fileRef = useRef<HTMLInputElement>(null);

 const fileInput = (
  <input
   ref={fileRef}
   type="file"
   accept=".proto,text/plain"
   className="sr-only"
   aria-hidden="true"
   tabIndex={-1}
   onChange={(event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    void file.text().then((text) => {
     setProtoSchema({ name: file.name, text });
     toast.success(`Loaded ${file.name} — it names protobuf fields in every editor`);
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
      Load .proto
     </Button>
     <Button size="small" variant="outline" onClick={() => setPasting(true)}>
      Paste .proto
     </Button>
    </>
   )}
  </div>
 );
}
