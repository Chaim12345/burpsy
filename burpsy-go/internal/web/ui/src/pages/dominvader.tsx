import { useState } from "react";
import { Copy, Trash2, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { useClearDomInvaderHits, useDomInvader, useSetDomInvader, type DomInvaderHit } from "../lib/data.dominvader";
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
 * This is Stage 1: the canary, the switch, and the source/sink hit list. postMessage interception and
 * replay, and the prototype-pollution gadget scan, are later stages.
 */
export function DomInvaderPage(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useDomInvader();
 const set = useSetDomInvader();
 const clear = useClearDomInvaderHits();
 const [canary, setCanary] = useState<string | null>(null);

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

     <Card>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
       <h3>Reported flows ({data.hits.length})</h3>
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
  <tr title={hit.stack || hit.url}>
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
