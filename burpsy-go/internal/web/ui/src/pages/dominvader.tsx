import { useState } from "react";
import { Copy, Trash2, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { useClearDomInvaderHits, useDomInvader, useSetDomInvader, type DomInvaderHit, useScanDomPollution, type PollutionConfig } from "../lib/data.dominvader";
import { LoadingPanel, PageHeader, RefreshButton } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, Input, NeedsValueButton, Switch } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/**
 * The operator-side DOM auditor (burpsy-react-ui-wl94): Burp's DOM Invader in the shape burpsy ships
 * it. An extension loaded into the Open-browser (burpsy-react-ui-bufa) watches the canary below
 * through each page's own sources and sinks while the operator browses, and reports every flow here —
 * so DOM testing is what a tester finds by browsing with the instrumentation on, not only what a scan
 * decides to run.
 *
 * The canary watcher and bounded, opt-in prototype-pollution probe plan are separate controls.
 * postMessage interception and replay are a later stage.
 */
export function DomInvaderPage(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useDomInvader();
 const set = useSetDomInvader();
 const clear = useClearDomInvaderHits();
 const scan = useScanDomPollution();
 const [plan, setPlan] = useState<PollutionConfig | null>(null);
 const [canary, setCanary] = useState<string | null>(null);

 const pollution = plan ?? data?.pollution;
 const effectiveCanary = canary ?? data?.canary ?? "";

 const saveCanary = () => {
  const next = effectiveCanary.trim();
  if (!next) {
   toast.error("A canary cannot be empty");
   return;
  }
  set.mutate(
   { canary: next },
   {
    onSuccess: () => {
     setCanary(null);
     toast.success("Canary saved — open or relaunch the browser to watch for it");
    },
    onError: (err) => toast.error(err.message),
   },
  );
 };

 return (
  <div className="page">
   <PageHeader
    title="DOM auditor"
    description="Watch a canary through a page's own sources and sinks while you browse, in the Open browser."
    actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
   />

   {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
   {isLoading ? <LoadingPanel label="Loading the DOM auditor" /> : null}

   {data ? (
    <>
     <Card>
      <div className="stack">
       <Switch
        id="dominvader-enabled"
        label="Watch pages for the canary"
        checked={data.enabled}
        onCheckedChange={(on) =>
         set.mutate(
          { enabled: on },
          {
           onSuccess: () => toast.success(on ? "DOM auditor on — open or relaunch the browser" : "DOM auditor off"),
           onError: (err) => toast.error(err.message),
          },
         )
        }
       />
       <Field label="Canary" hint="the marker the extension watches; put it in a parameter, hash or header and browse">
        {(id) => (
         <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Input id={id} value={effectiveCanary} onChange={(event) => setCanary(event.target.value)} style={{ maxWidth: "var(--w-md)" }} />
          <NeedsValueButton
           variant="outline"
           size="small"
           onClick={saveCanary}
           disabled={set.isPending}
           missing={effectiveCanary.trim() ? null : "needs a canary"}
          >
           Save
          </NeedsValueButton>
          <Button
           variant="quiet"
           size="small"
           title="Mint a fresh random canary"
           onClick={() => {
            // A local random marker with burpsy's prefix; saving it is what makes it live.
            const next = "burpsyDI" + Math.random().toString(16).slice(2, 14);
            setCanary(next);
           }}
          >
           <Wand2 size={13} />
           Randomize
          </Button>
          <Button
           variant="quiet"
           size="small"
           title="Copy the canary"
           onClick={() => void copyToClipboard(effectiveCanary).then(() => toast.success("Canary copied"))}
          >
           <Copy size={13} />
          </Button>
         </div>
        )}
       </Field>
       <span className="cell-dim">{data.launch_note}</span>
      </div>
     </Card>

     {pollution ? <Card>
      <div className="stack">
       <h2>Prototype pollution probes</h2>
       <p>Off by default. Each probe uses a fresh isolated browser context, not your operator login. Only the target origin and current engagement scope are allowed. Workers, frames, popups and fetch/XHR/WebSocket/WebTransport network are blocked; only their wrapped sink arguments are observed.</p>
       <span>Opt into active pollution probes</span>
       <Switch id="pollution-enabled" label="Opt into active pollution probes" checked={pollution.enabled}
        onCheckedChange={(enabled) => setPlan({ ...pollution, enabled })} />
       <Field label="Target document" hint="absolute HTTP(S) URL inside explicit scope; empty scope is refused">
        {(id) => <Input id={id} value={pollution.target} onChange={(e) => setPlan({ ...pollution, target: e.target.value })} />}
       </Field>
       <Field label="Gadget property vocabulary" hint="comma-separated property names, 1 to 16; not an exhaustive gadget search">
        {(id) => <Input id={id} value={(pollution.properties ?? []).join(",")} onChange={(e) => setPlan({ ...pollution, properties: e.target.value.split(",").map((v) => v.trim()) })} />}
       </Field>
       {(["query", "hash", "json", "nested"] as const).map((key) => <div key={key} style={{display:"flex",gap:8,alignItems:"center"}}><Switch id={`pollution-${key}`} label={key === "nested" ? "Also try constructor.prototype nesting" : `Try ${key} inputs`} checked={pollution[key]}
        onCheckedChange={(on) => setPlan({ ...pollution, [key]: on })} /><span>{key === "nested" ? "Also try constructor.prototype nesting" : `Try ${key} inputs`}</span></div>)}
       <div style={{ display: "flex", gap: 8 }}>
        <Button variant="outline" disabled={set.isPending} onClick={() => set.mutate({ pollution }, { onSuccess: () => {setPlan(null); toast.success("Probe plan saved");}, onError: (e) => toast.error(e.message) })}>Save probe plan</Button>
        <Button disabled={!!plan || !data.enabled || !data.pollution.enabled || scan.isPending} onClick={() => scan.mutate(undefined, {onError: (e) => toast.error(e.message)})}>{scan.isPending ? "Probing..." : "Run saved probe plan"}</Button>
       </div>
       <span className="cell-dim">Source proof and observed sink gadgets are separate hits. No gadget hit is not proof of safety. JSON mode modifies document-parsed JSON in the isolated probe only; AJAX-loaded JSON is not exercised.</span>
       {scan.data ? <div className="stack">
        <p>{scan.data.probes} probes; {scan.data.hits.length} hits; {scan.data.blocked.length} refused requests</p>
        <p>{scan.data.limitations}</p>
        {scan.data.errors.map((e, i) => <p key={i}>{e}</p>)}
        {scan.data.blocked.map((e, i) => <code key={i}>{e}</code>)}
       </div> : null}
      </div>
     </Card> : null}

     <Card>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
       <h2>Reported flows ({data.hits.length})</h2>
       <Button variant="outline" size="small" onClick={() => clear.mutate()} disabled={clear.isPending || data.hits.length === 0}>
        <Trash2 size={13} />
        Clear
       </Button>
      </div>
      {data.hits.length === 0 ? (
       <Empty
        title="No flows reported yet"
        detail={
         data.enabled
          ? "Open the browser, put the canary in a source (a query parameter, the URL hash, window.name), and browse. A flow appears here the moment the page reads it into a sink."
          : "Turn the auditor on, then open the browser and browse with the canary in a source."
        }
       />
      ) : (
       <SimpleTable headers={["", "Sink / source", "Carried by", "Excerpt", "Frame"]}>
        {[...data.hits].reverse().map((hit) => (
         <DomInvaderRow key={hit.id} hit={hit} />
        ))}
       </SimpleTable>
      )}
     </Card>
    </>
   ) : null}
  </div>
 );
}

function DomInvaderRow({ hit }: { hit: DomInvaderHit }): JSX.Element {
 return (
  <tr title={[hit.stack || hit.url, hit.property, hit.technique, hit.limitations].filter(Boolean).join("\n")}>
   <td>
    <Badge tone={hit.kind === "sink" ? "warn" : "info"}>{hit.kind}</Badge>
   </td>
   <td>
    <code>{hit.sink}</code>
   </td>
   <td>{hit.sources.length > 0 ? hit.sources.join(", ") : <span className="cell-dim">—</span>}</td>
   <td>
    <code
     title={hit.excerpt}
     style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "inline-block", maxWidth: "var(--w-lg)" }}
    >
     {hit.excerpt}
    </code>
   </td>
   <td>
    <span className="cell-dim" title={hit.url}>
     {hit.frame}
    </span>
   </td>
  </tr>
 );
}
