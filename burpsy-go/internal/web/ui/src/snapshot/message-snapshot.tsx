// The History message section, mounted on its own for burpsy_message_screenshot
// (burpsy-go/internal/mcp/screenshot.go).
//
// This is the console's own code path, not a drawing of HTTP: the panes are the same HttpEditor,
// ReadingPane and MessageDecodeStrip the History page renders, inside the same editor-grid, under
// the same stylesheet, reading the same MessageView records /api/message/{id} served. The MCP
// server fetches those records from the console by id and embeds them as window.__BURPSY_SNAPSHOT__;
// nothing here fetches, and nothing in the payload is caller-supplied text.
//
// The page is loaded from a file by a one-shot headless rasteriser, never from the console's URL, so
// there is no session, no operator browser and no console state behind the picture: preferences that
// live in the operator's localStorage (theme, editor font, hidden headers) are the store defaults.

import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { messageReading } from "../lib/message-decoded";
import { useApp } from "../lib/store";
import type { Exchange, MessageView } from "../lib/types";
import { useThemeEffect } from "../lib/use-theme-effect";
import { HttpEditor } from "../ui/editor";
import { decodeStripShows, MessageDecodeStrip, ReadingPane } from "../ui/message-reading-pane";
import { availableVariants, variantMessageId, type MessageVariant } from "../ui/variant-picker";

/** What the MCP server embeds: the exchange row (null for a bare message id) and every stored
 *  message it fetched, keyed by message id. */
export interface MessageSnapshot {
 exchange: Exchange | null;
 messages: Record<string, MessageView>;
 /** Set when the caller named a message rather than an exchange. */
 message_id?: number;
 /** The section's size in CSS pixels. Fixed rather than the viewport's, because a headless window's
  *  viewport can be shorter than the window it was asked for; the rasteriser crops to this box. */
 width: number;
 height: number;
}

declare global {
 interface Window {
  __BURPSY_SNAPSHOT__?: MessageSnapshot;
 }
}

function Pane({
 label,
 view,
 messageId,
 absent,
 options,
 variant,
 setVariant,
 requestPath,
 filename,
}: {
 label: "Request" | "Response";
 view: MessageView | undefined;
 messageId?: number;
 absent: string;
 options: MessageVariant[];
 variant: MessageVariant;
 setVariant: (next: MessageVariant) => void;
 requestPath?: string;
 filename: string;
}): JSX.Element {
 const [preferRaw, setPreferRaw] = useState(false);
 const reading = view ? messageReading(view, preferRaw) : undefined;
 return (
  <ReadingPane
   label={label}
   options={options}
   value={variant}
   onChange={setVariant}
   decode={decodeStripShows(reading) ? <MessageDecodeStrip label={label} reading={reading} preferRaw={preferRaw} setPreferRaw={setPreferRaw} /> : null}
   editor={
    <HttpEditor
     label={label}
     readOnly
     value={reading?.text ?? absent}
     bodyBase64={view?.body_base64}
     requestPath={requestPath}
     filename={`${filename}-${variant}${reading?.decoded ? "-decoded" : ""}.txt`}
     messageId={view ? messageId : undefined}
    />
   }
  />
 );
}

function ExchangeSection({ exchange, messages }: { exchange: Exchange; messages: Record<string, MessageView> }): JSX.Element {
 const seed = useApp.getState().defaultMessageVariant;
 const [requestVariant, setRequestVariant] = useState<MessageVariant>(seed);
 const [responseVariant, setResponseVariant] = useState<MessageVariant>(seed);
 const v = exchange.variants;
 const requestId = variantMessageId(exchange.request ?? null, v?.request_original, v?.request_auto_modified, requestVariant);
 const responseId = variantMessageId(exchange.response ?? null, v?.response_original, v?.response_auto_modified, responseVariant);
 // The absent-pane texts are History's own (pages/history.tsx); keep them identical.
 return (
  <div className="editor-grid">
   <Pane
    label="Request"
    view={requestId === null ? undefined : messages[String(requestId)]}
    messageId={requestId ?? undefined}
    absent={
     exchange.request === null
      ? "No request was captured for this exchange — it is a blind tunnel, relayed without being read."
      : "No request bytes captured."
    }
    options={availableVariants(v?.request_original, v?.request_auto_modified)}
    variant={requestVariant}
    setVariant={setRequestVariant}
    filename={`exchange-${exchange.id}-request`}
   />
   <Pane
    label="Response"
    view={responseId === null ? undefined : messages[String(responseId)]}
    messageId={responseId ?? undefined}
    absent={exchange.response === null ? "No response was captured for this exchange." : "No response bytes captured."}
    options={availableVariants(v?.response_original, v?.response_auto_modified)}
    variant={responseVariant}
    setVariant={setResponseVariant}
    requestPath={exchange.path}
    filename={`exchange-${exchange.id}-response`}
   />
  </div>
 );
}

function MessageSection({ id, view }: { id: number; view: MessageView }): JSX.Element {
 const label = view.text.startsWith("HTTP/") ? "Response" : "Request";
 const [variant, setVariant] = useState<MessageVariant>("edited");
 // One message has one pane; the grid's two tracks would leave half the picture empty.
 return (
  <div className="editor-grid" style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
   <Pane label={label} view={view} messageId={id} absent="" options={["edited"]} variant={variant} setVariant={setVariant} filename={`message-${id}`} />
  </div>
 );
}

/** Marks the document once the section has mounted and painted a frame. The rasteriser dumps the DOM
 *  from the same run as the picture and refuses a picture whose document never got here. */
function Ready(): null {
 useEffect(() => {
  const frame = requestAnimationFrame(() => {
   document.documentElement.dataset.viewport = `${window.innerWidth}x${window.innerHeight}`;
   document.documentElement.dataset.snapshot = "ready";
  });
  return () => cancelAnimationFrame(frame);
 }, []);
 return null;
}

function Snapshot({ snapshot }: { snapshot: MessageSnapshot }): JSX.Element {
 useThemeEffect();
 if (snapshot.exchange) return <ExchangeSection exchange={snapshot.exchange} messages={snapshot.messages} />;
 const id = snapshot.message_id;
 const view = id === undefined ? undefined : snapshot.messages[String(id)];
 if (id === undefined || !view) throw new Error("snapshot carries neither an exchange nor the message it names");
 return <MessageSection id={id} view={view} />;
}

window.addEventListener("error", (event) => {
 document.documentElement.dataset.snapshotError = String(event.message || event.error);
});
const snapshot = window.__BURPSY_SNAPSHOT__;
const root = document.getElementById("root");
if (!snapshot || !root) throw new Error("missing snapshot payload or root");
// No retries and no refetching: the page is offline, and a query the editor makes (plugin editor
// tabs read /api/extensions) must settle as absent rather than keep the page busy.
const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, refetchOnWindowFocus: false } } });
createRoot(root).render(
 <QueryClientProvider client={client}>
  <TooltipPrimitive.Provider>
   {/* History places the editor grid in its detail pane's minmax(0, 1fr) row (.history-detail). */}
   <div style={{ width: snapshot.width, height: snapshot.height, display: "grid", gridTemplateRows: "minmax(0, 1fr)" }}>
    <Snapshot snapshot={snapshot} />
    <Ready />
   </div>
  </TooltipPrimitive.Provider>
 </QueryClientProvider>,
);
