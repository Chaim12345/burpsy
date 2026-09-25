// Burp's "Show details in new window" (burpsy-react-ui-wvcl) — one item, on its own, in a window
// of its own.
//
// # Why a route and not a blob
//
// The obvious cheap implementation is `window.open` on a generated `text/html` blob: a table of
// fields, no React, no fetches. It is also a different product. The detail an operator detaches is the
// *message editor* — the request and response bytes, the grep-able Inspector, the same actions the
// in-page pane carries — and a blob cannot render any of it, so the new window would show less than
// the pane it was opened from. The gap the bead names is that burpsy's detail is a pane with no
// window; replacing it with a lesser window would close the gap with a worse answer.
//
// So this is a real route on the same app. `window.open` gets a same-origin URL, the app mounts
// normally, and every capability the pane has is here because it is the same code reading the same
// store. A blocked popup (browsers allow one per user gesture; a context-menu click is a gesture, a
// timer is not) falls back to navigating the CURRENT tab to the same URL and telling the operator
// the window did not open, rather than silently doing nothing.
//
// # What it is for
//
// An operator comparing two exchanges, or holding a response open beside the tool that will act on
// it. The page is deliberately one item: a second history table in a new window would be a slower
// way to read the first one.

import { ArrowLeft, Columns3, Combine, Crosshair, Repeat2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { exchangeUrl, useExchangeActions } from "../lib/actions";
import { formatBytes, formatDuration } from "../lib/api";
import { useHistory, useMessage } from "../lib/data";
import { useApp } from "../lib/store";
import type { Exchange } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { LoadingPanel, PageHeader, SectionHeading } from "../ui/layout";
import { AttributesTab, BodyParamsTab, CookiesTab, HeadersTab, QueryParamsTab } from "../ui/message-sections";
import { Badge, Button, Card, Empty, IconButton } from "../ui/primitives";

/**
 * The exchange id this window is showing: the `exchange` query parameter, or the hash's `exchange/`
 * segment. Both spellings because a window opened by `openDetailWindow` carries the query, while an
 * operator who bookmarks or shares the URL writes the hash they can see.
 */
export function detailExchangeId(): number | null {
 const fromQuery = new URLSearchParams(location.search).get("exchange");
 if (fromQuery && /^\d+$/.test(fromQuery)) return Number(fromQuery);
 const fromHash = location.hash.slice(1);
 const tail = fromHash.split("?")[0]?.split("/").pop() ?? "";
 return /^\d+$/.test(tail) ? Number(tail) : null;
}

/**
 * Open this item in a new window, and report honestly when the browser refuses.
 *
 * The feature string is what Burp's own detached windows use to keep a window's chrome consistent
 * with its opener; a window without it opens as a bare tab in some browsers, which is not what
 * "new window" means to an operator who asked for one.
 */
export function openDetailWindow(exchange: Exchange): boolean {
 // The hash is the ROUTE, so it must be the detail leaf — `#history` here mounted the ordinary
// history table in the new window, with no exchange selected, and left this whole page unreachable
// except by hand-typing the hash (burpsy-react-ui-76ea). The query carries the id; the hash names
// the page that reads it.
const url = `${location.pathname}${location.search ? `${location.search}&` : "?"}exchange=${exchange.id}#exchange-detail`;
 const opened = window.open(url, `burpsy-exchange-${exchange.id}`, "noopener,noreferrer");
 if (opened) return true;
 // A refused popup is not an error the operator can act on except by taking the fallback, so the
 // fallback is taken HERE — in the click's own call stack, which is the only place a browser will
 // still permit a navigation — and the reason is said rather than swallowed.
 navigateToHistoryWith(exchange.id);
 toast.warning(`The browser blocked the new window, so this tab went to the exchange instead (exchange #${exchange.id})`);
 return false;
}

function navigateToHistoryWith(id: number): void {
 const route = location.hash.slice(1).split("?")[0] || "history";
 if (route === "history") {
  // The store's own focus field is what the in-page pane reads, so the fallback lands on the
  // same row the window was opened from rather than on a bare history table.
  useApp.setState({ historyFocus: id });
 }
}

/** The page itself. Mounted on its own route by the shell. */
/** Which half to open the Inspector on, before the exchange itself has loaded. */
function exchangeHasResponseHint(): boolean {
 return new URLSearchParams(location.search).get("side") === "response";
}

export function DetailWindowPage(): JSX.Element {
 const id = detailExchangeId();
 const [inspector, setInspector] = useState(true);
 // Which half the Inspector is reading, because a WebSocket-like or header-only response has no
 // request-side detail worth showing and the operator switched windows to read the RESPONSE.
 const [inspectorSide, setInspectorSide] = useState<"request" | "response">(exchangeHasResponseHint() ? "response" : "request");
 const { data: history } = useHistory("", 1000);
 const actions = useExchangeActions();
 const setRoute = useApp((state) => state.setRoute);

 // The store's own history is the lookup, because that is what the in-page pane reads: a detached
 // window showing a DIFFERENT view of the same item is a second truth, and a fetch-by-id endpoint
 // would be one more place for the two to disagree.
 const exchange = id === null ? undefined : (history ?? []).find((entry) => entry.id === id);
 const request = useMessage(exchange?.request ?? null);
 const response = useMessage(exchange?.response ?? null);

 useEffect(() => {
  document.title = exchange ? `#${exchange.id} ${exchange.method} — burpsy` : "Exchange — burpsy";
 }, [exchange]);

 if (id === null) {
  return (
   <div className="page-fill">
    <PageHeader title="No exchange selected" />
    <Card>
     <Empty
      title="This window has no exchange"
      detail="Open one from a row menu: “Show details in new window”, or double-click a history row."
     />
    </Card>
   </div>
  );
 }
 if (!history) {
  return (
   <div className="page-fill">
    <PageHeader title={`Exchange #${id}`} />
    <LoadingPanel label="Loading captured traffic…" />
   </div>
  );
 }
 if (!exchange) {
  return (
   <div className="page-fill">
    <PageHeader title={`Exchange #${id}`} />
    <Card>
     <Empty
      title={`Exchange #${id} is not in this store`}
      detail="The window was opened against a different project, or the exchange has been deleted since."
     />
     <Button onClick={() => setRoute("history")}>
      <ArrowLeft size={13} />
      Back to HTTP history
     </Button>
    </Card>
   </div>
  );
 }

 const tabs = exchange.response ? (
  <div className="editor-grid">
   <div className="tabs-fill">
    <HttpEditor
     label="Request"
     readOnly
     value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
     filename={`exchange-${exchange.id}-request.txt`}
    />
   </div>
   <div className="tabs-fill">
    <HttpEditor
     label="Response"
     readOnly
     value={response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured.")}
     filename={`exchange-${exchange.id}-response.txt`}
    />
   </div>
  </div>
 ) : (
  <div className="tabs-fill">
   <HttpEditor
    label="Request"
    readOnly
    value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
    filename={`exchange-${exchange.id}-request.txt`}
   />
  </div>
 );

 return (
  <div className="page-fill">
   <PageHeader
    title={`${exchange.method} ${exchangeUrl(exchange)}`}
    description={`Exchange #${exchange.id} in a window of its own.`}
    actions={
     <>
      <Badge tone={exchange.status != null && exchange.status < 400 ? "good" : "warn"}>
       {exchange.status ?? "pending"}
      </Badge>
      <Badge>{formatDuration(exchange.duration_ms)}</Badge>
      <Badge>{exchange.protocol}</Badge>
      <Badge>{formatBytes(exchange.response_len ?? 0)}</Badge>
      <Button variant="outline" size="small" onClick={() => void actions.sendToRepeater(exchange)}>
       <Repeat2 size={13} />
       Repeater
      </Button>
      <Button variant="outline" size="small" onClick={() => actions.sendToIntruder(exchange)}>
       <Crosshair size={13} />
       Intruder
      </Button>
      <Button variant="outline" size="small" onClick={() => void actions.sendToComparer(exchange, "a")}>
       <Combine size={13} />
       Compare
      </Button>
      <IconButton
       label={inspector ? "Hide Inspector" : "Show Inspector"}
       size="small"
       aria-pressed={inspector}
       onClick={() => setInspector((current) => !current)}
      >
       <Columns3 size={13} />
      </IconButton>
      <Button variant="quiet" size="small" onClick={() => window.close()}>
       <X size={13} />
       Close window
      </Button>
     </>
    }
   />
   <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
    {tabs}
    {inspector ? (
     <Inspector
      raw={(inspectorSide === "request" ? request.data?.text : response.data?.text) ?? ""}
      readOnlyNote="A captured exchange: this window shows the bytes as they were received."
      onSwitch={
       exchange.response
        ? () => setInspectorSide((current) => (current === "request" ? "response" : "request"))
        : undefined
      }
      switchLabel={inspectorSide === "request" ? "Response" : "Request"}
     />
    ) : null}
   </div>
   <div className="two-col">
    <Card>
     <SectionHeading title="Request headers" />
     <HeadersTab raw={request.data?.text ?? ""} />
    </Card>
    <Card>
     <SectionHeading title="Query parameters" />
     <QueryParamsTab raw={request.data?.text ?? ""} />
    </Card>
    <Card>
     <SectionHeading title="Body parameters" />
     <BodyParamsTab raw={request.data?.text ?? ""} />
    </Card>
    <Card>
     <SectionHeading title="Cookies" />
     <CookiesTab raw={request.data?.text ?? ""} />
    </Card>
    <Card>
     <SectionHeading title="Attributes" />
     <AttributesTab raw={request.data?.text ?? ""} />
    </Card>
   </div>
  </div>
 );
}
