//! WebSocket framing (RFC 6455) and the per-message index the traffic store keeps for it.
//!
//! # Why the framing lives here and not in the proxy
//!
//! Same argument `burpsy-http2` makes for its own frame layer: decoding a frame is a pure function
//! over bytes, it is the part worth testing exhaustively, and it must be reachable from anywhere
//! that inspects captured traffic — not only from the socket loop that first read it. The proxy owns
//! the relay; this owns the parse.
//!
//! # Sans-io, and incremental on purpose
//!
//! [`Reassembler`] is fed whatever bytes arrived and asked for whatever messages are now complete.
//! It never waits for a whole frame to be resident: payload is consumed as it arrives, so a peer
//! that declares a 4 GiB frame costs [`Reassembler::max_message_bytes`], not 4 GiB. That bound is
//! the whole reason this is a state machine rather than "buffer a frame, then parse it" — a proxy
//! whose resident set is chosen by the peer is a proxy that gets killed by the peer.
//!
//! # What is captured is not what is relayed
//!
//! Client→server frames are masked (RFC 6455 §5.3), and the mask is per-frame noise: an operator
//! reading history wants the payload, not the payload XOR a random key. So this yields **unmasked**
//! payloads. The relay, meanwhile, forwards the bytes it actually read, mask included. The two are
//! deliberately different views of the same frame, and conflating them would either put unreadable
//! bytes in history or silently rewrite traffic on the wire.
//!
//! # Truncation is counted, never hidden
//!
//! A message longer than the cap is captured up to the cap and its [`WsEvent::dropped`] says how
//! many bytes were not kept. This project's stated value is honest counting: a 3 MiB message shown
//! as 1 MiB with no further comment is a lie, and refusing to capture it at all loses the evidence.
//! The cap never affects the wire — the relay forwards every byte regardless.
//!
//! # Anomalies do not stop the relay
//!
//! A fragmented control frame, an oversized control frame, a continuation with nothing to continue:
//! each is a protocol error under RFC 6455, and each is exactly the thing a tester is trying to
//! provoke. They are recorded on the event ([`WsEvent::note`]) and parsing carries on. Only a frame
//! header this parser cannot get past at all — a 64-bit length with the reserved MSB set — yields
//! [`WsError`], at which point the caller stops *capturing* that connection and says so, and keeps
//! *relaying* it. Refusing to forward would turn a malformed frame into a broken browser.

use crate::{Direction, MsgId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Longest header a frame can have: 2 fixed + 8 extended length + 4 mask.
pub const MAX_FRAME_HEADER_LEN: usize = 14;

/// A control frame's payload may not exceed this (RFC 6455 §5.5).
pub const MAX_CONTROL_PAYLOAD: u64 = 125;

/// Payload bytes kept per captured message before truncation starts being counted.
///
/// One mebibyte, matching the order of magnitude of the proxy's own read caps. Deliberately not
/// unbounded: a WebSocket connection is open-ended by design, so anything unbounded per message is
/// unbounded overall.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// A frame's opcode. `Reserved` keeps the wire value rather than collapsing it, because a probe that
/// sends opcode 11 wants to see 11 in history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

impl WsOpcode {
    pub fn from_bits(b: u8) -> Self {
        match b & 0x0f {
            0x0 => WsOpcode::Continuation,
            0x1 => WsOpcode::Text,
            0x2 => WsOpcode::Binary,
            0x8 => WsOpcode::Close,
            0x9 => WsOpcode::Ping,
            0xa => WsOpcode::Pong,
            other => WsOpcode::Reserved(other),
        }
    }

    pub fn bits(self) -> u8 {
        match self {
            WsOpcode::Continuation => 0x0,
            WsOpcode::Text => 0x1,
            WsOpcode::Binary => 0x2,
            WsOpcode::Close => 0x8,
            WsOpcode::Ping => 0x9,
            WsOpcode::Pong => 0xa,
            WsOpcode::Reserved(b) => b & 0x0f,
        }
    }

    /// Control opcodes are 0x8..=0xf. They are never fragmented and carry at most 125 bytes.
    pub fn is_control(self) -> bool {
        self.bits() & 0x08 != 0
    }

    /// A name for display. `Reserved` renders with its number, so the operator sees which one.
    pub fn name(self) -> String {
        match self {
            WsOpcode::Continuation => "continuation".into(),
            WsOpcode::Text => "text".into(),
            WsOpcode::Binary => "binary".into(),
            WsOpcode::Close => "close".into(),
            WsOpcode::Ping => "ping".into(),
            WsOpcode::Pong => "pong".into(),
            WsOpcode::Reserved(b) => format!("reserved(0x{b:x})"),
        }
    }
}

/// A decoded frame header, with the number of header bytes it occupied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    /// RSV1..RSV3 as the low three bits. Non-zero means an extension is in use (or a probe is
    /// lying); kept rather than rejected, for the same reason the h2 layer keeps what it reads.
    pub rsv: u8,
    pub opcode: WsOpcode,
    pub masked: bool,
    pub payload_len: u64,
    pub mask: Option<[u8; 4]>,
    /// Bytes this header occupied, mask included. Payload starts here.
    pub header_len: usize,
}

/// The one thing that stops a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// A 64-bit length with the reserved most-significant bit set (RFC 6455 §5.2). Nothing after
    /// this point can be located, so the frame stream is no longer parseable.
    LengthMsbSet(u64),
    /// A 64-bit length larger than this platform can address. Same consequence.
    LengthExceedsUsize(u64),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::LengthMsbSet(v) => write!(
                f,
                "frame declares 64-bit length {v} with the reserved high bit set, so where the next \
                 frame starts is unknowable"
            ),
            WsError::LengthExceedsUsize(v) => write!(
                f,
                "frame declares length {v}, larger than this platform can address"
            ),
        }
    }
}

impl std::error::Error for WsError {}

/// Decode a frame header. `Ok(None)` means "not enough bytes yet", never "malformed".
pub fn parse_frame_header(buf: &[u8]) -> Result<Option<FrameHeader>, WsError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    let fin = b0 & 0x80 != 0;
    let rsv = (b0 >> 4) & 0x07;
    let opcode = WsOpcode::from_bits(b0);
    let masked = b1 & 0x80 != 0;

    let mut i = 2usize;
    let payload_len = match b1 & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            i = 4;
            u64::from(u16::from_be_bytes([buf[2], buf[3]]))
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            i = 10;
            let v = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            if v & (1 << 63) != 0 {
                return Err(WsError::LengthMsbSet(v));
            }
            if v > usize::MAX as u64 {
                return Err(WsError::LengthExceedsUsize(v));
            }
            v
        }
        n => u64::from(n),
    };

    let mask = if masked {
        if buf.len() < i + 4 {
            return Ok(None);
        }
        let m = [buf[i], buf[i + 1], buf[i + 2], buf[i + 3]];
        i += 4;
        Some(m)
    } else {
        None
    };

    Ok(Some(FrameHeader {
        fin,
        rsv,
        opcode,
        masked,
        payload_len,
        mask,
        header_len: i,
    }))
}

/// XOR `payload` with `mask`, where `offset` is how many payload bytes of this frame already went by.
///
/// `offset` exists because a frame's payload arrives in whatever pieces the network chose, and the
/// mask cycles over the frame's payload as a whole — restarting the key at every read would produce
/// garbage for every fragment after the first.
pub fn unmask(payload: &mut [u8], mask: [u8; 4], offset: usize) {
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[(offset + i) % 4];
    }
}

// ---- Handshake detection -------------------------------------------------------------------

/// True when a raw HTTP request offers a WebSocket upgrade (RFC 6455 §4.1).
///
/// Both headers are required, and both are *token lists*: browsers send
/// `Connection: keep-alive, Upgrade`, so a substring test on the whole value would miss the common
/// case while a `==` test would miss it too. Tokens are compared case-insensitively because the
/// header names and the `websocket` token both are.
///
/// This deliberately does **not** check `Sec-WebSocket-Key` or `Sec-WebSocket-Version`. Whether the
/// handshake is *valid* is the origin's decision, and it is announced by the response; a proxy that
/// second-guessed it would refuse to record exactly the malformed handshakes a tester is probing
/// with. The only question asked here is "was an upgrade requested", and the switch to frame
/// relaying additionally requires the origin to have said 101.
pub fn is_upgrade_request(raw: &[u8]) -> bool {
    let Ok(shape) = crate::parse(raw, Direction::Request) else {
        return false;
    };
    header_has_token(raw, &shape, b"connection", b"upgrade")
        && header_has_token(raw, &shape, b"upgrade", b"websocket")
}

/// True when a raw HTTP response accepted a WebSocket upgrade: status 101 plus
/// `Upgrade: websocket`.
///
/// The status alone is not enough — 101 is the generic protocol-switch code and could name any
/// protocol in `Upgrade` — and the header alone is not enough either, because a 4xx refusal may
/// still echo it. The conjunction is what means "everything after this is frames".
pub fn is_upgrade_response(raw: &[u8]) -> bool {
    let Ok(shape) = crate::parse(raw, Direction::Response) else {
        return false;
    };
    let status = span_bytes(raw, shape.second_token);
    status == b"101" && header_has_token(raw, &shape, b"upgrade", b"websocket")
}

fn span_bytes(raw: &[u8], s: crate::Span) -> &[u8] {
    let end = s.end().min(raw.len());
    let start = s.offset.min(end);
    &raw[start..end]
}

/// Whether `name` carries `token` in its comma-separated value list.
fn header_has_token(raw: &[u8], shape: &crate::MessageShape, name: &[u8], token: &[u8]) -> bool {
    shape.headers.iter().any(|h| {
        span_bytes(raw, h.name).trim_ascii().eq_ignore_ascii_case(name)
            && span_bytes(raw, h.value)
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(token))
    })
}

/// One reassembled application message, or one control frame.
#[derive(Debug, Clone)]
pub struct WsEvent {
    /// The opcode of the message's **first** frame — never `Continuation`, which is framing rather
    /// than a message type.
    pub opcode: WsOpcode,
    /// Unmasked payload, truncated to the cap.
    pub payload: Bytes,
    /// Frames this message occupied. `1` unless it was fragmented.
    pub fragments: u32,
    /// Declared payload bytes not kept, because the cap was reached.
    pub dropped: u64,
    /// A protocol anomaly seen while assembling this message. `None` on the ordinary path.
    pub note: Option<String>,
}

/// Where the payload of the frame currently being consumed is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    /// Into the fragmented message under construction.
    Data,
    /// Into the control-frame buffer, which never mixes with a fragmented data message.
    Control,
}

/// Frame-stream state machine: bytes in, complete messages out.
#[derive(Debug)]
pub struct Reassembler {
    max_message_bytes: usize,
    /// Header bytes seen but not yet sufficient to decode. At most [`MAX_FRAME_HEADER_LEN`].
    head: Vec<u8>,
    /// `Some` while a frame's payload is still being consumed.
    frame: Option<InFlight>,
    /// The fragmented data message under construction.
    partial: Vec<u8>,
    partial_opcode: Option<WsOpcode>,
    fragments: u32,
    dropped: u64,
    note: Option<String>,
    ctrl: Vec<u8>,
    /// Counted separately from `dropped`, and noted separately from `note`: a control frame
    /// interleaves with a fragmented message, so shared state here would attribute a control frame's
    /// shortfall — or its rule violation — to the data message it happened to arrive inside.
    ctrl_dropped: u64,
    ctrl_note: Option<String>,
    ready: VecDeque<WsEvent>,
}

#[derive(Debug)]
struct InFlight {
    hdr: FrameHeader,
    /// Payload bytes of this frame already consumed — also the mask offset.
    consumed: u64,
    dest: Dest,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_MESSAGE_BYTES)
    }
}

impl Reassembler {
    pub fn new(max_message_bytes: usize) -> Self {
        Self {
            max_message_bytes,
            head: Vec::with_capacity(MAX_FRAME_HEADER_LEN),
            frame: None,
            partial: Vec::new(),
            partial_opcode: None,
            fragments: 0,
            dropped: 0,
            note: None,
            ctrl: Vec::new(),
            ctrl_dropped: 0,
            ctrl_note: None,
            ready: VecDeque::new(),
        }
    }

    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Feed newly arrived bytes. Completed messages queue up for [`Self::pop`].
    ///
    /// An `Err` means the frame stream can no longer be located; the caller stops capturing this
    /// connection and keeps relaying it.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<(), WsError> {
        while !bytes.is_empty() {
            match self.frame.as_mut() {
                Some(f) => {
                    let want = (f.hdr.payload_len - f.consumed).min(bytes.len() as u64) as usize;
                    let (chunk, rest) = bytes.split_at(want);
                    self.take_payload(chunk);
                    bytes = rest;
                    let f = self.frame.as_ref().expect("frame still in flight");
                    if f.consumed == f.hdr.payload_len {
                        self.finish_frame();
                    }
                }
                None => {
                    // Take up to a maximal header rather than guessing how many bytes this one
                    // needs: the width depends on bytes that may not have arrived. Anything taken
                    // beyond the header is handed straight back below.
                    let take = (MAX_FRAME_HEADER_LEN - self.head.len()).min(bytes.len());
                    if take == 0 {
                        // Unreachable: a 14-byte prefix always decodes, since 2 + 8 + 4 is the
                        // widest header RFC 6455 defines. Guarded anyway, because the alternative
                        // to a break here is a spin.
                        debug_assert!(false, "a full-width header failed to decode");
                        break;
                    }
                    self.head.extend_from_slice(&bytes[..take]);
                    match parse_frame_header(&self.head)? {
                        Some(hdr) => {
                            // Give back everything after this header — it belongs to the payload.
                            let over = self.head.len() - hdr.header_len;
                            bytes = &bytes[take - over..];
                            self.head.clear();
                            let empty = hdr.payload_len == 0;
                            self.begin_frame(hdr);
                            // A frame with no payload completes here or never: the payload loop is
                            // only reached when there are bytes left to consume, and a close or
                            // ping frame carrying nothing has none.
                            if empty {
                                self.finish_frame();
                            }
                        }
                        None => {
                            bytes = &bytes[take..];
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The next complete message, if one is ready.
    pub fn pop(&mut self) -> Option<WsEvent> {
        self.ready.pop_front()
    }

    fn begin_frame(&mut self, hdr: FrameHeader) {
        let dest = if hdr.opcode.is_control() {
            if hdr.payload_len > MAX_CONTROL_PAYLOAD {
                self.ctrl_note(format!(
                    "control frame carries {} bytes; RFC 6455 §5.5 allows at most {MAX_CONTROL_PAYLOAD}",
                    hdr.payload_len
                ));
            }
            if !hdr.fin {
                self.ctrl_note("control frame is fragmented; RFC 6455 §5.5 forbids it".into());
            }
            self.ctrl.clear();
            Dest::Control
        } else {
            match hdr.opcode {
                WsOpcode::Continuation => {
                    if self.partial_opcode.is_none() {
                        self.note(
                            "continuation frame with no fragmented message in flight".to_string(),
                        );
                    }
                }
                _ => {
                    if self.partial_opcode.is_some() {
                        self.note(format!(
                            "a new {} frame arrived while a fragmented message was still in flight; \
                             the incomplete one is recorded as it stood",
                            hdr.opcode.name()
                        ));
                        let so_far = self.fragments;
                        self.flush_partial(so_far);
                    }
                    self.partial_opcode = Some(hdr.opcode);
                }
            }
            self.fragments += 1;
            Dest::Data
        };
        self.frame = Some(InFlight {
            hdr,
            consumed: 0,
            dest,
        });
    }

    fn take_payload(&mut self, chunk: &[u8]) {
        let Some(f) = self.frame.as_mut() else { return };
        let offset = f.consumed as usize;
        f.consumed += chunk.len() as u64;
        let dest = f.dest;
        let mask = f.hdr.mask;

        let cap = self.max_message_bytes;
        let buf = match dest {
            Dest::Control => &mut self.ctrl,
            Dest::Data => &mut self.partial,
        };
        let room = cap.saturating_sub(buf.len());
        let keep = room.min(chunk.len());
        if keep > 0 {
            let at = buf.len();
            buf.extend_from_slice(&chunk[..keep]);
            if let Some(m) = mask {
                unmask(&mut buf[at..], m, offset);
            }
        }
        let over = (chunk.len() - keep) as u64;
        if over > 0 {
            match dest {
                Dest::Control => self.ctrl_dropped += over,
                Dest::Data => self.dropped += over,
            }
        }
    }

    fn finish_frame(&mut self) {
        let Some(f) = self.frame.take() else { return };
        match f.dest {
            Dest::Control => {
                // Control frames never join a fragmented data message, even when they interleave
                // with one — which RFC 6455 §5.4 explicitly permits.
                let payload = Bytes::from(std::mem::take(&mut self.ctrl));
                self.ready.push_back(WsEvent {
                    opcode: f.hdr.opcode,
                    payload,
                    fragments: 1,
                    dropped: std::mem::take(&mut self.ctrl_dropped),
                    note: self.ctrl_note.take(),
                });
            }
            Dest::Data => {
                if f.hdr.fin {
                    let fragments = self.fragments;
                    self.flush_partial(fragments);
                }
            }
        }
    }

    /// Emit the fragmented message as it currently stands and reset for the next one.
    fn flush_partial(&mut self, fragments: u32) {
        let opcode = self.partial_opcode.take().unwrap_or(WsOpcode::Continuation);
        self.ready.push_back(WsEvent {
            opcode,
            payload: Bytes::from(std::mem::take(&mut self.partial)),
            fragments,
            dropped: std::mem::take(&mut self.dropped),
            note: self.note.take(),
        });
        self.fragments = 0;
    }

    /// Record the first anomaly seen for the message in flight. First rather than last, and never
    /// concatenated: the initial deviation is the one that explains everything after it.
    fn note(&mut self, msg: String) {
        if self.note.is_none() {
            self.note = Some(msg);
        }
    }

    /// As [`Self::note`], for the control frame in flight. See `ctrl_note`'s field comment.
    fn ctrl_note(&mut self, msg: String) {
        if self.ctrl_note.is_none() {
            self.ctrl_note = Some(msg);
        }
    }
}

/// One captured WebSocket message: an index row, never a payload.
///
/// # Why this is not `ChildRef::WsFrame` on the handshake `Exchange`
///
/// [`crate::ChildRef`] is the right shape for a *bounded* set of children — an exchange with a
/// handful of related records. A WebSocket connection is open-ended by construction, so putting one
/// `ChildRef` per message on the `Exchange` row would grow a `Vec` that
/// [`crate::TrafficStore::exchanges`] clones on every history poll: a socket that has carried 100k
/// messages would make listing history copy 1.6 MB per request, for a field the history UI never
/// reads. So messages get their own append-only index with the same "position is the id" invariant,
/// and the back-reference points the other way, from the message to its handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    /// Position is the id, exactly as for messages and exchanges.
    pub id: u64,
    /// The `Exchange` whose 101 response opened this connection.
    pub exchange: u64,
    /// The payload's handle in the same append-only log every HTTP body goes into — which is what
    /// makes a disk-backed capture bound WebSocket traffic too, with no separate treatment.
    pub payload: MsgId,
    /// `Request` is client→server, `Response` is server→client. Reusing [`Direction`] rather than
    /// inventing a second two-valued enum keeps one vocabulary for "which way was this going", and
    /// it is the same distinction the store already records per stored message.
    pub direction: Direction,
    pub opcode: WsOpcode,
    /// Payload bytes kept. Differs from the declared length exactly when `dropped` is non-zero.
    pub len: usize,
    /// Declared payload bytes not kept. Non-zero means this row is a truncated view, and the UI
    /// must say so rather than presenting `len` as the message size.
    pub dropped: u64,
    pub fragments: u32,
    pub at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame the way a peer would, so the tests exercise the decoder rather than a helper
    /// that shares its assumptions.
    fn frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let n = payload.len();
        if n < 126 {
            out.push(mask_bit | n as u8);
        } else if n <= u16::MAX as usize {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
        match mask {
            Some(m) => {
                out.extend_from_slice(&m);
                let at = out.len();
                out.extend_from_slice(payload);
                unmask(&mut out[at..], m, 0);
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    fn drain(r: &mut Reassembler) -> Vec<WsEvent> {
        let mut v = Vec::new();
        while let Some(e) = r.pop() {
            v.push(e);
        }
        v
    }

    /// WS-01: a single unmasked text frame decodes to its payload.
    #[test]
    fn a_whole_unmasked_text_frame_yields_one_message() {
        let mut r = Reassembler::default();
        r.feed(&frame(true, 0x1, None, b"hello")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev.len(), 1, "one frame is one message");
        assert_eq!(ev[0].opcode, WsOpcode::Text);
        assert_eq!(&ev[0].payload[..], b"hello");
        assert_eq!(ev[0].fragments, 1);
        assert_eq!(ev[0].dropped, 0);
        assert!(ev[0].note.is_none(), "nothing anomalous: {:?}", ev[0].note);
    }

    /// WS-01: a masked client frame is captured unmasked, because the mask is per-frame noise.
    #[test]
    fn a_masked_frame_is_captured_with_the_mask_removed() {
        let mut r = Reassembler::default();
        let wire = frame(true, 0x1, Some([0xde, 0xad, 0xbe, 0xef]), b"secret payload");
        assert_ne!(
            &wire[wire.len() - 14..],
            b"secret payload",
            "the fixture must actually be masked, or this test proves nothing"
        );
        r.feed(&wire).unwrap();
        let ev = drain(&mut r);
        assert_eq!(&ev[0].payload[..], b"secret payload");
    }

    /// WS-01: the decode must not depend on how the network split the bytes. Every single-byte
    /// split is exercised, because the failure mode is a specific seam — a header straddling a read.
    #[test]
    fn the_decoder_agrees_with_itself_at_every_possible_split() {
        let wire = [
            frame(true, 0x1, Some([1, 2, 3, 4]), b"first message here"),
            frame(true, 0x2, None, &[0xffu8; 300]),
            frame(true, 0x9, None, b"ping"),
        ]
        .concat();

        let expect: Vec<Vec<u8>> = {
            let mut r = Reassembler::default();
            r.feed(&wire).unwrap();
            drain(&mut r).into_iter().map(|e| e.payload.to_vec()).collect()
        };
        assert_eq!(expect.len(), 3);

        for split in 1..wire.len() {
            let mut r = Reassembler::default();
            r.feed(&wire[..split]).unwrap();
            r.feed(&wire[split..]).unwrap();
            let got: Vec<Vec<u8>> = drain(&mut r).into_iter().map(|e| e.payload.to_vec()).collect();
            assert_eq!(
                got, expect,
                "split at {split} decoded differently from the unsplit stream — a header or mask \
                 offset does not survive that seam"
            );
        }
    }

    /// WS-01: fragmentation. Three frames, one message, and the fragment count is reported.
    #[test]
    fn a_fragmented_message_is_reassembled_and_says_how_many_frames_it_took() {
        let mut r = Reassembler::default();
        r.feed(&frame(false, 0x1, None, b"one ")).unwrap();
        r.feed(&frame(false, 0x0, None, b"two ")).unwrap();
        assert!(
            r.pop().is_none(),
            "an unterminated message must not be emitted early"
        );
        r.feed(&frame(true, 0x0, None, b"three")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev.len(), 1);
        assert_eq!(&ev[0].payload[..], b"one two three");
        assert_eq!(ev[0].opcode, WsOpcode::Text, "the first frame names the type");
        assert_eq!(ev[0].fragments, 3);
    }

    /// WS-01: RFC 6455 §5.4 permits a control frame between the fragments of a data message. The
    /// control frame must come out on its own and must not contaminate the message being assembled.
    #[test]
    fn a_control_frame_interleaved_with_fragments_does_not_join_the_message() {
        let mut r = Reassembler::default();
        r.feed(&frame(false, 0x2, None, b"AAAA")).unwrap();
        r.feed(&frame(true, 0x9, None, b"pp")).unwrap();
        r.feed(&frame(true, 0x0, None, b"BBBB")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev.len(), 2, "the ping and the message are separate: {ev:?}");
        assert_eq!(ev[0].opcode, WsOpcode::Ping);
        assert_eq!(&ev[0].payload[..], b"pp");
        assert_eq!(ev[1].opcode, WsOpcode::Binary);
        assert_eq!(
            &ev[1].payload[..], b"AAAABBBB",
            "the ping's payload must not appear in the data message"
        );
        assert_eq!(ev[1].fragments, 2);
    }

    /// WS-01: the cap bounds what is kept, and the shortfall is stated rather than hidden.
    #[test]
    fn an_oversized_message_is_truncated_and_counts_what_it_did_not_keep() {
        let mut r = Reassembler::new(8);
        r.feed(&frame(true, 0x2, None, &[0x41u8; 20])).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev[0].payload.len(), 8, "kept exactly the cap");
        assert_eq!(
            ev[0].dropped, 12,
            "the 12 bytes not kept must be counted, or the row lies about the message size"
        );
    }

    /// WS-01: truncation must bound memory across a *fragmented* message too, not just per frame.
    #[test]
    fn the_cap_applies_to_the_reassembled_message_not_to_each_fragment() {
        let mut r = Reassembler::new(6);
        r.feed(&frame(false, 0x1, None, b"aaaa")).unwrap();
        r.feed(&frame(true, 0x0, None, b"bbbb")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(&ev[0].payload[..], b"aaaabb");
        assert_eq!(ev[0].dropped, 2);
    }

    /// WS-01: an oversized control frame is a protocol error that must not stop the capture.
    #[test]
    fn an_oversized_control_frame_is_recorded_rather_than_refused() {
        let mut r = Reassembler::default();
        r.feed(&frame(true, 0x9, None, &[0x42u8; 200])).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev.len(), 1, "still captured");
        assert_eq!(ev[0].payload.len(), 200);
        let note = ev[0].note.as_deref().unwrap_or("");
        assert!(note.contains("5.5"), "the note must cite the rule broken: {note:?}");
    }

    /// WS-01: a continuation with nothing to continue is noted, and the bytes are still captured.
    #[test]
    fn a_continuation_with_nothing_in_flight_is_noted_not_dropped() {
        let mut r = Reassembler::default();
        r.feed(&frame(true, 0x0, None, b"orphan")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev.len(), 1);
        assert_eq!(&ev[0].payload[..], b"orphan");
        assert!(
            ev[0].note.as_deref().unwrap_or("").contains("no fragmented"),
            "{:?}",
            ev[0].note
        );
    }

    /// WS-01: the reserved high bit on a 64-bit length is the one thing that stops parsing, because
    /// nothing after it can be located.
    #[test]
    fn a_length_with_the_reserved_high_bit_set_stops_the_capture_and_says_why() {
        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&(1u64 << 63).to_be_bytes());
        let e = parse_frame_header(&wire).unwrap_err();
        assert!(matches!(e, WsError::LengthMsbSet(_)));
        assert!(
            e.to_string().contains("unknowable"),
            "the message must say why this is unrecoverable: {e}"
        );
    }

    /// WS-01: `Ok(None)` is "keep reading", and must never be confused with "malformed".
    #[test]
    fn a_partial_header_asks_for_more_bytes_rather_than_failing() {
        assert_eq!(parse_frame_header(&[]), Ok(None));
        assert_eq!(parse_frame_header(&[0x81]), Ok(None));
        // 126 announces a 2-byte extended length that has not arrived.
        assert_eq!(parse_frame_header(&[0x81, 126, 0x01]), Ok(None));
        // A mask bit whose key has not arrived.
        assert_eq!(parse_frame_header(&[0x81, 0x85, 0xde, 0xad]), Ok(None));
    }

    /// WS-01: extended lengths decode at both widths, and the header length reports the mask.
    #[test]
    fn extended_lengths_and_the_mask_are_accounted_for_in_the_header_length() {
        let h = parse_frame_header(&frame(true, 0x2, None, &[0u8; 400]))
            .unwrap()
            .unwrap();
        assert_eq!((h.payload_len, h.header_len), (400, 4));

        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&70000u64.to_be_bytes());
        let h = parse_frame_header(&wire).unwrap().unwrap();
        assert_eq!((h.payload_len, h.header_len), (70000, 10));

        let h = parse_frame_header(&frame(true, 0x1, Some([9, 9, 9, 9]), b"x"))
            .unwrap()
            .unwrap();
        assert_eq!((h.header_len, h.mask), (6, Some([9, 9, 9, 9])));
    }

    /// WS-01: a reserved opcode keeps its wire value, so a probe can see what it sent.
    #[test]
    fn a_reserved_opcode_keeps_its_number() {
        let mut r = Reassembler::default();
        r.feed(&frame(true, 0xb, None, b"?")).unwrap();
        let ev = drain(&mut r);
        assert_eq!(ev[0].opcode, WsOpcode::Reserved(0xb));
        assert_eq!(ev[0].opcode.name(), "reserved(0xb)");
        assert!(ev[0].opcode.is_control(), "0xb is in the control range");
    }

    /// WS-01: RSV bits are reported, not corrected. `permessage-deflate` sets RSV1, and a tester
    /// setting it by hand needs to see that it arrived.
    #[test]
    fn rsv_bits_survive_the_decode() {
        let h = parse_frame_header(&[0xc1, 0x00]).unwrap().unwrap();
        assert_eq!(h.rsv, 0b100, "RSV1 set");
        assert!(h.fin);
        assert_eq!(h.opcode, WsOpcode::Text);
    }
}
