import { useEffect, useState } from "react";
import { GitCompare, Play, Plus, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useAuthzIdentities, useRunAuthzTest, useSaveAuthzIdentities, type AuthzIdentity, type AuthzVerdict } from "../lib/data.authz";
import { useSessionRulesFull } from "../lib/data.policy";
import { useLoadMessage } from "../lib/data.workbench";
import { useApp } from "../lib/store";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, Input, Select, Textarea } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/**
 * Access control testing (burpsy-react-ui-cr37): Autorize/AuthMatrix for burpsy. Hold named
 * identities (the high-privilege baseline plus one or more low-priv / no-auth roles), re-send a
 * captured request under each, and read the per-identity verdict — Enforced, Bypassed (the role
 * received the baseline's privileged content), or Ambiguous. The verdict engine is N-sample
 * calibration, so an endpoint whose body varies does not read as a bypass every time.
 */
export function AuthzPage(): JSX.Element {
 const { data, error, refetch } = useAuthzIdentities();
 const save = useSaveAuthzIdentities();
 const runTest = useRunAuthzTest();
 const loadMessage = useLoadMessage();
 const setComparerSlot = useApp((s) => s.setComparerSlot);
 const setRoute = useApp((s) => s.setRoute);

 const [identities, setIdentities] = useState<AuthzIdentity[]>([]);
 const sessionRules = useSessionRulesFull();
 const [exchangeId, setExchangeId] = useState("");
 const [result, setResult] = useState<AuthzVerdict[] | null>(null);

 useEffect(() => {
  if (data?.identities) setIdentities(data.identities);
 }, [data?.identities]);

 const patch = (i: number, changes: Partial<AuthzIdentity>) =>
  setIdentities((cur) => cur.map((id, j) => (j === i ? { ...id, ...changes } : id)));

 const headersText = (h: Record<string, string>) =>
  Object.entries(h)
   .map(([k, v]) => `${k}: ${v}`)
   .join("\n");
 const parseHeaders = (text: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
   const idx = line.indexOf(":");
   if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return out;
 };

 const saveIdentities = () =>
  save.mutate(identities, {
   onSuccess: () => toast.success("Identities saved"),
   onError: (err) => toast.error(err.message),
  });

 const run = () => {
  const id = Number(exchangeId.trim());
  if (!Number.isFinite(id) || id < 0) {
   toast.error("Enter the exchange id to test (from HTTP history)");
   return;
  }
  runTest.mutate(
   { exchange_id: id },
   {
    onSuccess: (res) => setResult(res.verdicts),
    onError: (err) => toast.error(err.message),
   },
  );
 };

 // One-click diff: load the baseline response and this identity's response into the Comparer's two
 // slots and go there. The baseline verdict carries the reference response id.
 const diffVsBaseline = async (row: AuthzVerdict) => {
  const baseline = result?.find((v) => v.verdict === "Baseline");
  if (!baseline?.response_id || !row.response_id) {
   toast.error("No stored responses to diff");
   return;
  }
  try {
   const [a, b] = await Promise.all([loadMessage.mutateAsync(baseline.response_id), loadMessage.mutateAsync(row.response_id)]);
   setComparerSlot("a", a.text);
   setComparerSlot("b", b.text);
   setRoute("comparer");
  } catch (err) {
   toast.error(err instanceof Error ? err.message : String(err));
  }
 };

 const verdictTone = (v: string) => (v === "Bypassed" ? "bad" : v === "Enforced" ? "good" : v === "Baseline" ? "info" : "warn");

 return (
  <div className="page">
   <PageHeader
    title="Access control"
    description="Re-send a request as each identity and see whether access control held — the BOLA/IDOR test."
   />
   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}

   <Card>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
     <h3>Identities</h3>
     <div style={{ display: "flex", gap: 8 }}>
      <Button
       variant="quiet"
       size="small"
       onClick={() =>
        setIdentities((cur) => [
         ...cur,
         { label: `identity ${cur.length + 1}`, baseline: cur.length === 0, cookie: "", headers: {}, strip_cookie: false },
        ])
       }
      >
       <Plus size={13} />
       Add
      </Button>
      <Button variant="outline" size="small" onClick={saveIdentities} disabled={save.isPending}>
       <Save size={13} />
       Save
      </Button>
     </div>
    </div>
    <p className="cell-dim">
     One identity is the baseline (the high-privilege role the others are compared against). Each other identity is a cookie, or a stripped
     cookie (no auth), plus any auth headers. A role that receives the baseline's content is a bypass.
    </p>
    {identities.length === 0 ? (
     <Empty title="No identities" detail="Add a baseline (admin) and at least one low-privilege or no-auth role." />
    ) : (
     <div className="stack">
      {identities.map((id, i) => (
       <Card key={i}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
         <Field label="Label">
          {(fid) => (
           <Input id={fid} value={id.label} onChange={(e) => patch(i, { label: e.target.value })} style={{ maxWidth: "var(--w-sm)" }} />
          )}
         </Field>
         <Checkbox
          label="Baseline"
          checked={id.baseline}
          onCheckedChange={(on) => setIdentities((cur) => cur.map((x, j) => ({ ...x, baseline: j === i ? on : on ? false : x.baseline })))}
         />
         <Checkbox label="Strip cookie (no auth)" checked={id.strip_cookie} onCheckedChange={(on) => patch(i, { strip_cookie: on })} />
         <Button variant="quiet" size="small" onClick={() => setIdentities((cur) => cur.filter((_, j) => j !== i))}>
          <Trash2 size={13} />
         </Button>
        </div>
        <Field
         label="Source from session rule"
         hint="run a logged-in session's login macro and use its fresh cookie (burpsy-react-ui-q7f8), instead of pasting one"
        >
         {(fid) => (
          <Select
           id={fid}
           value={id.session_rule_id === undefined ? "" : String(id.session_rule_id)}
           onChange={(e) => patch(i, { session_rule_id: e.target.value === "" ? undefined : Number(e.target.value) })}
          >
           <option value="">Paste a cookie below</option>
           {(sessionRules.data?.rules ?? [])
            .filter((r) => r.id !== undefined)
            .map((r) => (
             <option key={r.id} value={String(r.id)}>
              {r.name || `rule ${r.id}`}
             </option>
            ))}
          </Select>
         )}
        </Field>
        <Field label="Cookie" hint="replaces the request's Cookie header; leave blank to keep the captured one unless Strip is set">
         {(fid) => (
          <Input
           id={fid}
           value={id.cookie}
           onChange={(e) => patch(i, { cookie: e.target.value })}
           placeholder="session=...; role=user"
           disabled={id.session_rule_id !== undefined}
          />
         )}
        </Field>
        <Field label="Extra headers" hint="one per line, Name: value (Authorization, X-API-Key)">
         {(fid) => (
          <Textarea
           id={fid}
           rows={2}
           value={headersText(id.headers)}
           onChange={(e) => patch(i, { headers: parseHeaders(e.target.value) })}
          />
         )}
        </Field>
       </Card>
      ))}
     </div>
    )}
   </Card>

   <Card>
    <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }}>
     <Field label="Exchange id to test" hint="from HTTP history — the request to replay under each identity">
      {(fid) => (
       <Input
        id={fid}
        value={exchangeId}
        inputMode="numeric"
        onChange={(e) => setExchangeId(e.target.value)}
        placeholder="e.g. 42"
        style={{ maxWidth: "var(--w-xs)" }}
       />
      )}
     </Field>
     <Button onClick={run} disabled={runTest.isPending || identities.length < 2}>
      <Play size={13} />
      Test access control
     </Button>
    </div>

    {result ? (
     result.length === 0 ? (
      <Empty title="No verdicts" detail="The test returned nothing." />
     ) : (
      <SimpleTable headers={["Identity", "Verdict", "Status", "Length", "Why", ""]}>
       {result.map((v) => (
        <tr key={v.label}>
         <td>{v.label}</td>
         <td>
          <Badge tone={verdictTone(v.verdict)}>{v.verdict}</Badge>
         </td>
         <td className="cell-num">{v.status || "—"}</td>
         <td className="cell-num">{v.body_len}</td>
         <td>
          <span className="cell-dim" title={v.error || (v.reasons ?? []).join("; ")}>
           {v.error ? v.error : v.verdict === "Bypassed" ? "received the baseline's content" : (v.reasons ?? []).join("; ") || "—"}
          </span>
         </td>
         <td>
          {v.verdict !== "Baseline" && v.response_id ? (
           <Button
            variant="quiet"
            size="small"
            onClick={() => void diffVsBaseline(v)}
            title="Diff this response against the baseline in Comparer"
           >
            <GitCompare size={13} />
            Diff
           </Button>
          ) : null}
         </td>
        </tr>
       ))}
      </SimpleTable>
     )
    ) : null}
   </Card>
  </div>
 );
}
