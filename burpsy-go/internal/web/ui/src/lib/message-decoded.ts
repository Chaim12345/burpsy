// Which rendering of a stored message a read-only pane shows (burpsy-react-ui-qpfy).
//
// The server sends a gzip/deflate message twice over: `text`, the bytes exactly as captured (a
// screenful of binary for a compressed body), and `decoded`, the same head with the body
// decompressed. This picks between them for DISPLAY ONLY. It never feeds anything that sends: a
// resend, a Repeater tab, Intruder positions and an audit selection's byte span are all defined
// against the captured bytes, and the decoded body has different bytes at different offsets.

import type { MessageView } from "./types";

export interface MessageReading {
 /** The text the pane shows. */
 text: string;
 /** True when `text` is the decoded rendering rather than the captured bytes. A caller must then
  *  withhold every affordance that turns a position in `text` into a byte offset of the message. */
 decoded: boolean;
 /** Whether a decoded rendering exists to switch to (so the pane can offer the toggle). */
 canDecode: boolean;
 /** The message's Content-Encoding, when it declared one. */
 encoding?: string;
 /** Why a compressed body could not be decoded, when it could not. */
 decodeError?: string;
}

/**
 * The reading a pane shows for `view`. `preferRaw` is the operator's "show the captured bytes"
 * choice; without it a decodable message reads decoded, because that is the only readable form.
 * A message with no `decoded` always reads as captured, whatever the preference.
 */
export function messageReading(view: Pick<MessageView, "text" | "decoded" | "decode_error" | "content_encoding">, preferRaw: boolean): MessageReading {
 const canDecode = typeof view.decoded === "string";
 const encoding = view.content_encoding?.trim() || undefined;
 const decodeError = view.decode_error?.trim() || undefined;
 const decoded = canDecode && !preferRaw;
 return { text: decoded ? (view.decoded as string) : (view.text ?? ""), decoded, canDecode, encoding, decodeError };
}

/** The marker a pane shows over a decoded rendering, naming the encoding it undid. */
export function decodedMarker(encoding: string | undefined): string {
 return `decoded view (Content-Encoding: ${encoding ?? "unknown"})`;
}
