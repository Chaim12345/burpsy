import { useCrawlLive, lockedPreview } from "../lib/data.crawllive";
import { useExchange } from "../lib/data.observe";
import { useMessage } from "../lib/data";
import { bodyOf } from "../lib/message";
import { Badge, ErrorNotice } from "./primitives";
import { SimpleTable } from "./table";

/**
 * Burp's "Live crawl view" (burpsy-react-ui-1l3x): what the crawler is on right now. A frame from the
 * render pass when a browser is configured; otherwise the reason there is none and the last page's wire
 * HTML, rendered with scripts and every load disabled — labelled as exactly that.
 */

const PHASE_LABEL: Record<string, string> = {
 starting: "starting",
 "logging-in": "logging in",
 fetching: "fetching",
 rendering: "rendering",
 "rendered-audit": "rendered-DOM audit",
 finished: "finished",
};

export function CrawlLiveView({ taskId }: { taskId: number }): JSX.Element {
 const live = useCrawlLive(taskId);
 if (live.error) return <ErrorNotice error={live.error} title="The live crawl view could not be loaded" />;
 const view = live.data;
 if (!view) return <p className="cell-dim">Loading the live crawl view…</p>;
 const running = view.state === "running";
 return (
  <div className="stack crawl-live">
   <div className="toolbar">
    <Badge tone={running ? "info" : view.state === "failed" ? "bad" : "neutral"}>{PHASE_LABEL[view.phase] ?? view.phase}</Badge>
    <span className="cell-dim">{view.fetched} fetched</span>
    {view.current ? (
     <span className="crawl-live-current">
      {view.current.method ? `${view.current.method} ` : ""}
      <code>{view.current.url}</code>
     </span>
    ) : (
     <span className="cell-dim">{running ? "waiting for the first request" : "the crawl is not running"}</span>
    )}
   </div>
   {view.frame ? (
    <figure className="crawl-live-frame">
     <img src={view.frame.image} alt={`The page the crawler rendered: ${view.frame.url}`} />
     <figcaption className="cell-dim">
      Rendered by the crawler's browser · <code>{view.frame.url}</code> · {new Date(view.frame.captured_at).toLocaleTimeString()}
     </figcaption>
    </figure>
   ) : (
    <>
     <p className="cell-dim" style={{ margin: 0 }}>
      {view.frame_note}
     </p>
     {!view.browser && view.last_page ? <WirePreview exchangeId={view.last_page.exchange_id} url={view.last_page.url} /> : null}
    </>
   )}
   <h3 className="subheading">Recent fetches</h3>
   {view.recent.length === 0 ? (
    <p className="cell-dim" style={{ margin: 0 }}>
     Nothing has been fetched yet.
    </p>
   ) : (
    <SimpleTable headers={["Time", "Status", "Method", "URL", "Depth"]}>
     {view.recent.map((fetch) => (
      <tr key={`${fetch.exchange_id}-${fetch.at}`}>
       <td className="cell-dim">{new Date(fetch.at).toLocaleTimeString()}</td>
       <td>
        <Badge tone={fetch.status >= 400 ? "warn" : fetch.status >= 300 ? "info" : "good"}>{fetch.status || "—"}</Badge>
       </td>
       <td>{fetch.method}</td>
       <td>
        <code>{fetch.url}</code>
        {fetch.found_by_render ? <Badge tone="accent"> rendered link</Badge> : null}
       </td>
       <td>{fetch.depth}</td>
      </tr>
     ))}
    </SimpleTable>
   )}
  </div>
 );
}

/** The last HTML page's wire bytes, sandboxed and CSP-locked: no script runs and nothing loads. */
function WirePreview({ exchangeId, url }: { exchangeId: number; url: string }): JSX.Element {
 const exchange = useExchange(exchangeId);
 const message = useMessage(exchange.data?.response ?? null);
 if (!message.data) return <p className="cell-dim">Loading the last page…</p>;
 return (
  <figure className="crawl-live-frame">
   <iframe
    className="render-frame crawl-live-preview"
    title={`Wire HTML of ${url}, scripts and loads disabled`}
    sandbox=""
    referrerPolicy="no-referrer"
    srcDoc={lockedPreview(bodyOf(message.data.text))}
   />
   <figcaption className="cell-dim">
    Wire HTML of <code>{url}</code>, shown with scripts and every load disabled — not what a browser would render.
   </figcaption>
  </figure>
 );
}
