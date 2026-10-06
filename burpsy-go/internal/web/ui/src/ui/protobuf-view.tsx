import { useEffect, useState } from "react";
import { toast } from "sonner";
import { decodeProtobuf, encodeProtobuf, type ProtoField, type ProtoFrame } from "../lib/data.protobuf";
import { Badge, Button, Input } from "./primitives";

/**
 * The schemaless protobuf / gRPC field view (burpsy-react-ui-3x2g). An opaque binary body is decoded
 * into a field tree the operator can read, and — when the editor is editable — tamper with and apply:
 * edit a leaf, press Apply, and the tree re-encodes to body bytes written back through the editor.
 *
 * No .proto: wire types and field numbers are all the wire format carries, so that is what this shows
 * (name resolution from a .proto or gRPC reflection is a separate, larger piece). A length-delimited
 * field is shown as whatever it decoded to — a nested message, a string, or hex bytes — and edited in
 * that shape.
 */
export function ProtobufView({
 bodyBase64,
 grpc,
 onApply,
}: {
 bodyBase64: string;
 grpc: boolean;
 /** Write the re-encoded body back, base64. Absent = read-only (a response, or a non-editable pane). */
 onApply?: (bodyBase64: string) => void;
}): JSX.Element {
 const [frames, setFrames] = useState<ProtoFrame[] | null>(null);
 const [error, setError] = useState<string | null>(null);
 const [dirty, setDirty] = useState(false);
 const [applying, setApplying] = useState(false);

 useEffect(() => {
  let live = true;
  setError(null);
  setDirty(false);
  decodeProtobuf(bodyBase64, grpc)
   .then((res) => {
    if (live) setFrames(res.frames);
   })
   .catch((err) => {
    if (live) setError(err instanceof Error ? err.message : String(err));
   });
  return () => {
   live = false;
  };
 }, [bodyBase64, grpc]);

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

 if (error) {
  return <div className="notice notice-warn">This body did not decode as protobuf: {error}</div>;
 }
 if (!frames) {
  return <div className="cell-dim" style={{ padding: 12 }}>Decoding…</div>;
 }

 return (
  <div className="stack" style={{ padding: 12, overflow: "auto" }}>
   {grpc ? <div className="cell-dim">gRPC body — {frames.length} frame{frames.length === 1 ? "" : "s"}.</div> : null}
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
       <code>#{field.number}</code> <span className="cell-dim">{wireLabel(field)}</span>
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

function FieldValue({ field, disabled, onChange }: { field: ProtoField; disabled: boolean; onChange: (changes: Partial<ProtoField>) => void }): JSX.Element {
 if (field.wire_type === 0) {
  return <Input aria-label={`field ${field.number} varint`} value={field.varint ?? ""} disabled={disabled} onChange={(e) => onChange({ varint: e.target.value })} />;
 }
 if (field.wire_type === 1) {
  return <Input aria-label={`field ${field.number} i64`} value={field.i64 ?? ""} disabled={disabled} onChange={(e) => onChange({ i64: e.target.value })} />;
 }
 if (field.wire_type === 5) {
  return <Input aria-label={`field ${field.number} i32`} value={String(field.i32 ?? 0)} disabled={disabled} onChange={(e) => onChange({ i32: Number(e.target.value) || 0 })} />;
 }
 if (field.len_kind === "string") {
  return <Input aria-label={`field ${field.number} string`} value={field.string ?? ""} disabled={disabled} onChange={(e) => onChange({ string: e.target.value })} />;
 }
 if (field.len_kind === "bytes") {
  return <Input aria-label={`field ${field.number} bytes (hex)`} value={field.bytes_hex ?? ""} disabled={disabled} onChange={(e) => onChange({ bytes_hex: e.target.value })} placeholder="hex" />;
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
