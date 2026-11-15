// One stored message's pane in the history message section: the reading picker and decode strip over
// an HttpEditor. Shared by the History page and the server-side snapshot (src/snapshot), so the
// picture burpsy_message_screenshot returns is this markup and not a second drawing of it.

import { decodedMarker, type MessageReading } from "../lib/message-decoded";
import { Badge, Button } from "./primitives";
import { VariantPicker, type MessageVariant } from "./variant-picker";

/**
 * The picker is wrapped *only* when there is something to compare. That keeps the common case's
 * DOM exactly what it was — no extra element in the editor grid, no new chance of a layout
 * regression on the rows that have nothing to show — and it is also what makes the wrapper's
 * presence meaningful rather than decorative.
 */
export function ReadingPane({
 label,
 options,
 value,
 onChange,
 editor,
 decode,
}: {
 label: string;
 options: MessageVariant[];
 value: MessageVariant;
 onChange: (next: MessageVariant) => void;
 editor: JSX.Element;
 decode?: JSX.Element | null;
}): JSX.Element {
 return options.length < 2 && !decode ? (
  editor
 ) : (
  <div className="reading-pane">
   {options.length < 2 ? null : <VariantPicker label={label} options={options} value={value} onChange={onChange} />}
   {decode}
   {editor}
  </div>
 );
}

/** Whether MessageDecodeStrip draws anything. ReadingPane wraps an editor whenever it is handed a
 *  strip element, so a caller passes one only when this is true. */
export function decodeStripShows(reading: MessageReading | undefined): reading is MessageReading {
 return reading !== undefined && (reading.decodeError !== undefined || reading.canDecode);
}

/**
 * The strip over a pane whose message declared a Content-Encoding (burpsy-react-ui-qpfy). Nothing
 * for a message with no encoding, so the common case keeps the editor grid's DOM as it was. A
 * decoded pane says so in words — the head above the body still reads Content-Encoding: gzip and
 * a compressed Content-Length, and without the marker the pane would look like the wire.
 */
export function MessageDecodeStrip({
 label,
 reading,
 preferRaw,
 setPreferRaw,
}: {
 label: string;
 reading: MessageReading | undefined;
 preferRaw: boolean;
 setPreferRaw: (next: boolean) => void;
}): JSX.Element | null {
 if (!reading || (!reading.encoding && !reading.decodeError && !reading.canDecode)) return null;
 if (reading.decodeError) {
  return (
   <div className="decode-strip" role="status">
    <Badge tone="warn">not decoded</Badge>
    <span className="cell-dim">
     {/* The encoding is named unless the server's reason already names it ("no decoder for
         Content-Encoding \"br\""), so the sentence does not say it twice. */}
     {label} body{reading.encoding && !reading.decodeError.includes(reading.encoding) ? ` (Content-Encoding: ${reading.encoding})` : ""}{" "}
     could not be decoded: {reading.decodeError}. Showing the bytes as captured.
    </span>
   </div>
  );
 }
 if (!reading.canDecode) return null;
 return (
  <div className="decode-strip" role="status">
   {reading.decoded ? (
    <Badge
     tone="info"
     title="The body is shown decompressed; the headers are as captured. Sends and resends always use the captured bytes."
    >
     {decodedMarker(reading.encoding)}
    </Badge>
   ) : (
    <Badge tone="neutral">raw bytes as captured (Content-Encoding: {reading.encoding ?? "unknown"})</Badge>
   )}
   <Button variant="outline" size="small" onClick={() => setPreferRaw(!preferRaw)}>
    {reading.decoded ? "Show captured bytes" : "Show decoded body"}
   </Button>
  </div>
 );
}
