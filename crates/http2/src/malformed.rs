//! Deliberate malformation: frames the spec forbids, plus a report naming which rules they break.
//!
//! # Why this exists when the writer already corrects nothing
//!
//! [`crate::frame`] preserves whatever it is handed, so an operator who sets the fields of a
//! [`FrameSpec`] directly can already put an illegal frame on the wire. That is not the same thing as
//! *supporting* deliberate malformation, for three reasons.
//!
//! **A frame program cannot say what it meant.** A program with a lying length, an even
//! client-initiated stream id and an unterminated header block is, at the type level, indistinguishable
//! from a compliant one. So a probe malformed by accident looks exactly like a probe malformed on
//! purpose — and when the target answers with `RST_STREAM` you cannot tell which of the three rules it
//! objected to, or whether it objected to a fourth you did not know you had broken. [`audit`] answers
//! that question: it names every rule the program breaks and the section that forbids it.
//!
//! **Two silent corrections do exist, and they cannot be removed.** The length field is 24 bits, so a
//! `declared_len` above [`MAX_FRAME_PAYLOAD`] loses its top bits in [`FrameHeader::encode`], and a
//! payload longer than that cannot be described honestly by [`FrameSpec::header`]. No amount of
//! discipline fixes those — the field is the size it is. What is available is to *report* them, which
//! is what [`Violation::LengthFieldOverflowed`] and [`Violation::PayloadExceedsLengthField`] are for:
//! the one place the writer cannot do as it was told is stated rather than hidden.
//!
//! **Malformation is an intent, and intents are worth naming.** [`Malformation`] is the vocabulary:
//! `ClearFlags(flags::END_HEADERS)` instead of `spec.flags &= !0x04`. Applying one never refuses and
//! never touches a field it does not name — this is the deliberate path, so a "helpful" adjustment
//! here would be the same defect as one in the writer.
//!
//! # One direction
//!
//! [`audit`] judges a program as **client-to-server**, because that is the only direction this crate
//! emits. Hence an even stream id is a violation ([`Violation::EvenStreamIdFromClient`]) and a
//! `PUSH_PROMISE` is one too ([`Violation::PushPromiseFromClient`]); both are correct for a server to
//! send. Auditing captured server frames would need the mirror-image rule set, which does not exist
//! here yet.
//!
//! # This module does not send anything
//!
//! It produces octets and a report about them. Getting those octets onto a socket is
//! `burpsy_sender::AuthorisedSender`'s job and nothing else's, and the authorisation rules for a
//! frame program are stricter than for a request: a program with a dishonest length, a raw header-block
//! fragment or an unterminated block cannot have its `:path` fields authorised individually, because
//! the peer will not decode the block we decoded. That classifier and the transport behind it are a
//! separate slice. So today [`audit`] is the capability an operator can actually reach from here —
//! an emitted program still has no route to a socket, and saying otherwise would be the overclaim
//! this crate's root doc warns about.
//!
//! # What the audit does not check, and why
//!
//! Stated because a report that looks exhaustive and is not would be worse than no report:
//!
//! * **`SETTINGS_MAX_FRAME_SIZE`.** A frame larger than the peer's limit is a `FRAME_SIZE_ERROR`
//!   (§4.2), but the limit is whatever the peer's own `SETTINGS` said, which a program cannot know.
//!   Checking against the 16384 default would flag every legitimately large frame sent after a real
//!   settings exchange.
//! * **`SETTINGS` payload contents** (§6.5.2) — an out-of-range `ENABLE_PUSH` or
//!   `INITIAL_WINDOW_SIZE` is a violation this does not decode. Unknown identifiers are legal, so a
//!   report here would have to distinguish the two, and nothing needs it yet.
//! * **Flow control** (§6.9) — a `WINDOW_UPDATE` of 0, or an increment overflowing the window,
//!   requires modelling both peers' windows.
//! * **`GOAWAY`, `PRIORITY` and `RST_STREAM` payload semantics** — the shape is length-checked, the
//!   contents are not.
//! * **HPACK validity** (RFC 7541) — an index into an empty table, a bad Huffman padding, a string
//!   length overrunning the block. Those are [`crate::hpack`]'s subject, and on the emit side they are
//!   reachable only through a raw header-block fragment.
//! * **Field validity** (§8.3) — a missing `:path`, an uppercase field name, a connection-specific
//!   header. That is normalisation's subject, not framing's.
//!
//! # Length is judged twice, deliberately
//!
//! The padding and fixed-size checks read the length a **peer** will act on — the 24 bits actually
//! written — while [`Violation::DeclaredLengthDisagrees`] compares that against the payload we
//! actually wrote. A program that lies about a length therefore gets both a report of the lie and
//! checks conducted in the peer's terms, which is the only combination that describes what will
//! happen on the wire.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::frame::{
    FrameSpec, H2FrameProgram, MAX_FRAME_PAYLOAD, STREAM_ID_RESERVED_BIT, flags, types,
};

/// A spec violation requested on purpose.
///
/// Every variant is a field-level mutation, because that is the granularity the wire has. Composing
/// them is how a research payload is built: a `HEADERS` with `ClearFlags(END_HEADERS)` and a
/// `DeclareLength` shorter than its block is two intents and one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformation {
    /// Write a length field other than the payload's own length (§4.1).
    ///
    /// The single most useful lie available: a receiver frames the connection by this value, so a
    /// short one truncates the block it reads and a long one swallows the next frame's octets.
    DeclareLength(u32),
    /// Replace the type octet (§4.1), including with one the registry does not define.
    SetType(u8),
    /// Replace the whole flags octet.
    SetFlags(u8),
    /// Set the named flag bits, leaving every other bit alone. Undefined bits included — a receiver
    /// is required to ignore them, which is a requirement worth testing.
    AddFlags(u8),
    /// Clear the named flag bits. `ClearFlags(flags::END_HEADERS)` is how a header block is left open.
    ClearFlags(u8),
    /// Replace the whole 32-bit stream-id field, reserved bit included (§5.1.1).
    SetStreamId(u32),
    /// Set the reserved top bit of the stream-id field, keeping the 31-bit identifier beneath it
    /// (§5.1.1). A sender must leave it clear and a receiver must ignore it; both halves are testable.
    SetReservedBit,
}

impl Malformation {
    /// Apply exactly the mutation this variant names, and nothing else.
    ///
    /// Infallible on purpose. There is no input to reject: every `u8` is a legal type octet on the
    /// wire, every `u32` fits the stream-id field, and a length that does not fit 24 bits is reported
    /// by [`audit`] rather than refused here. A validating setter on the deliberate-malformation path
    /// would be the same defect as a self-correcting writer.
    pub fn apply(self, spec: &mut FrameSpec) {
        match self {
            Self::DeclareLength(n) => spec.declared_len = Some(n),
            Self::SetType(ty) => spec.ty = ty,
            Self::SetFlags(f) => spec.flags = f,
            Self::AddFlags(f) => spec.flags |= f,
            Self::ClearFlags(f) => spec.flags &= !f,
            Self::SetStreamId(id) => spec.stream_id = id,
            Self::SetReservedBit => spec.stream_id |= STREAM_ID_RESERVED_BIT,
        }
    }

    /// The section a compliant sender would be breaking.
    pub fn rfc(self) -> &'static str {
        match self {
            Self::DeclareLength(_) | Self::SetType(_) | Self::SetFlags(_) | Self::AddFlags(_)
            | Self::ClearFlags(_) => "RFC 9113 §4.1",
            Self::SetStreamId(_) | Self::SetReservedBit => "RFC 9113 §5.1.1",
        }
    }
}

impl FrameSpec {
    /// Apply a [`Malformation`], chainable so a frame can be malformed several ways at once.
    pub fn malformed(mut self, m: Malformation) -> Self {
        m.apply(&mut self);
        self
    }
}

/// A rule a frame program breaks, as found by [`audit`].
///
/// `frame` fields are indices into [`H2FrameProgram::frames`], so a report can be shown against the
/// frame that caused it rather than as loose prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// §3.4 — the connection did not begin with the client preface.
    MissingPreface,
    /// §4.1 — the declared length does not fit 24 bits, so the field carries a different value.
    ///
    /// `written` can coincidentally equal the payload length; the request was still not honoured, and
    /// that is the fact this reports.
    LengthFieldOverflowed {
        frame: usize,
        requested: u32,
        written: u32,
    },
    /// §4.1 — the payload is longer than the length field can describe, so no honest length exists
    /// and the header states [`MAX_FRAME_PAYLOAD`].
    PayloadExceedsLengthField { frame: usize, payload_len: usize },
    /// §4.1 — the length field disagrees with the payload actually written. The peer will frame by
    /// the field, so it decodes something we did not.
    DeclaredLengthDisagrees {
        frame: usize,
        declared: u32,
        actual: usize,
    },
    /// §5.1.1 — the reserved top bit of the stream-id field is set; a sender must leave it clear.
    ReservedBitSet { frame: usize },
    /// §6.1/§6.2/§6.3/§6.4/§6.10 — a frame that belongs to a stream names stream 0.
    StreamIdZeroOnStreamFrame { frame: usize, ty: u8 },
    /// §6.5/§6.7/§6.8 — a connection-level frame names a stream.
    StreamIdNonZeroOnConnectionFrame {
        frame: usize,
        ty: u8,
        stream_id: u32,
    },
    /// §5.1.1 — a client opened an even-numbered stream; client-initiated streams are odd.
    EvenStreamIdFromClient { frame: usize, stream_id: u32 },
    /// §5.1.1 — a newly opened stream's id must be numerically greater than every id this endpoint
    /// has already opened.
    StreamIdNotIncreasing {
        frame: usize,
        stream_id: u32,
        highest: u32,
    },
    /// §6.3/§6.4/§6.7/§6.9 — a fixed-size frame declares a length the spec does not allow.
    FixedLengthViolation {
        frame: usize,
        ty: u8,
        declared: u32,
        required: u32,
    },
    /// §6.5 — a `SETTINGS` payload is not a whole number of six-octet entries.
    SettingsLengthNotMultipleOfSix { frame: usize, declared: u32 },
    /// §6.5 — `SETTINGS` with `ACK` set must carry an empty payload.
    SettingsAckWithPayload { frame: usize, declared: u32 },
    /// §8.4 — a client sent `PUSH_PROMISE`, which only a server may send.
    PushPromiseFromClient { frame: usize },
    /// §6.10 — a `CONTINUATION` with no unterminated header block before it.
    ContinuationWithNothingToContinue { frame: usize },
    /// §6.10 — a `CONTINUATION` naming a different stream from the block it continues.
    ContinuationOnAnotherStream {
        frame: usize,
        expected: u32,
        found: u32,
    },
    /// §6.2 — a frame other than `CONTINUATION` appears between a header block's start and its
    /// `END_HEADERS`.
    FrameInterleavedInHeaderBlock {
        frame: usize,
        ty: u8,
        block_opened_at: usize,
    },
    /// §6.2 — a header block runs to the end of the program without an `END_HEADERS`.
    HeaderBlockNeverTerminated {
        block_opened_at: usize,
        stream_id: u32,
    },
    /// §5.1 — `DATA` on a stream no `HEADERS` in this program opened, so the stream is idle.
    DataOnUnopenedStream { frame: usize, stream_id: u32 },
    /// §5.1 — a frame sent on a stream this program already finished, by `END_STREAM` or
    /// `RST_STREAM`. `PRIORITY`, `WINDOW_UPDATE` and `RST_STREAM` stay legal there and are not
    /// reported.
    FrameAfterStreamClosed {
        frame: usize,
        ty: u8,
        stream_id: u32,
        closed_at: usize,
    },
    /// §6.1 — `PADDED` is set but the payload has no octet to carry the pad length.
    PadLengthOctetMissing { frame: usize },
    /// §6.1 — the pad length is the whole payload or more, so the padding runs past the frame.
    PadLengthExceedsPayload {
        frame: usize,
        pad_length: u8,
        payload_len: usize,
    },
}

impl Violation {
    /// The section that forbids this, for a report an operator can check against the spec.
    pub fn rfc(&self) -> &'static str {
        match self {
            Self::MissingPreface => "RFC 9113 §3.4",
            Self::LengthFieldOverflowed { .. }
            | Self::PayloadExceedsLengthField { .. }
            | Self::DeclaredLengthDisagrees { .. } => "RFC 9113 §4.1",
            Self::ReservedBitSet { .. }
            | Self::EvenStreamIdFromClient { .. }
            | Self::StreamIdNotIncreasing { .. } => "RFC 9113 §5.1.1",
            Self::StreamIdZeroOnStreamFrame { .. }
            | Self::StreamIdNonZeroOnConnectionFrame { .. } => "RFC 9113 §4.1",
            Self::FixedLengthViolation { .. } => "RFC 9113 §4.2",
            Self::SettingsLengthNotMultipleOfSix { .. } | Self::SettingsAckWithPayload { .. } => {
                "RFC 9113 §6.5"
            }
            Self::PushPromiseFromClient { .. } => "RFC 9113 §8.4",
            Self::ContinuationWithNothingToContinue { .. }
            | Self::ContinuationOnAnotherStream { .. } => "RFC 9113 §6.10",
            Self::FrameInterleavedInHeaderBlock { .. }
            | Self::HeaderBlockNeverTerminated { .. } => "RFC 9113 §6.2",
            Self::DataOnUnopenedStream { .. } | Self::FrameAfterStreamClosed { .. } => {
                "RFC 9113 §5.1"
            }
            Self::PadLengthOctetMissing { .. } | Self::PadLengthExceedsPayload { .. } => {
                "RFC 9113 §6.1"
            }
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPreface => write!(f, "the connection preface is not sent"),
            Self::LengthFieldOverflowed {
                frame,
                requested,
                written,
            } => write!(
                f,
                "frame {frame}: declared length {requested} does not fit 24 bits; the field carries \
                 {written}"
            ),
            Self::PayloadExceedsLengthField { frame, payload_len } => write!(
                f,
                "frame {frame}: a {payload_len}-octet payload cannot be described by a 24-bit length; \
                 the field carries {MAX_FRAME_PAYLOAD}"
            ),
            Self::DeclaredLengthDisagrees {
                frame,
                declared,
                actual,
            } => write!(
                f,
                "frame {frame}: declares {declared} octets, writes {actual}"
            ),
            Self::ReservedBitSet { frame } => {
                write!(f, "frame {frame}: the stream-id reserved bit is set")
            }
            Self::StreamIdZeroOnStreamFrame { frame, ty } => write!(
                f,
                "frame {frame}: {} names stream 0",
                TyLabel(*ty)
            ),
            Self::StreamIdNonZeroOnConnectionFrame { frame, ty, stream_id } => write!(
                f,
                "frame {frame}: {} names stream {stream_id} rather than the connection",
                TyLabel(*ty)
            ),
            Self::EvenStreamIdFromClient { frame, stream_id } => write!(
                f,
                "frame {frame}: a client opened even stream {stream_id}"
            ),
            Self::StreamIdNotIncreasing {
                frame,
                stream_id,
                highest,
            } => write!(
                f,
                "frame {frame}: opens stream {stream_id} after already opening {highest}"
            ),
            Self::FixedLengthViolation {
                frame,
                ty,
                declared,
                required,
            } => write!(
                f,
                "frame {frame}: {} declares {declared} octets, must declare {required}",
                TyLabel(*ty)
            ),
            Self::SettingsLengthNotMultipleOfSix { frame, declared } => write!(
                f,
                "frame {frame}: SETTINGS declares {declared} octets, not a multiple of six"
            ),
            Self::SettingsAckWithPayload { frame, declared } => write!(
                f,
                "frame {frame}: SETTINGS with ACK declares {declared} octets, must be empty"
            ),
            Self::PushPromiseFromClient { frame } => {
                write!(f, "frame {frame}: PUSH_PROMISE sent by a client")
            }
            Self::ContinuationWithNothingToContinue { frame } => write!(
                f,
                "frame {frame}: CONTINUATION with no open header block before it"
            ),
            Self::ContinuationOnAnotherStream {
                frame,
                expected,
                found,
            } => write!(
                f,
                "frame {frame}: CONTINUATION names stream {found}, continuing a block on {expected}"
            ),
            Self::FrameInterleavedInHeaderBlock {
                frame,
                ty,
                block_opened_at,
            } => write!(
                f,
                "frame {frame}: {} interleaved inside the header block opened at frame \
                 {block_opened_at}",
                TyLabel(*ty)
            ),
            Self::HeaderBlockNeverTerminated {
                block_opened_at,
                stream_id,
            } => write!(
                f,
                "the header block opened at frame {block_opened_at} on stream {stream_id} is never \
                 terminated"
            ),
            Self::DataOnUnopenedStream { frame, stream_id } => write!(
                f,
                "frame {frame}: DATA on stream {stream_id}, which no HEADERS opened"
            ),
            Self::FrameAfterStreamClosed {
                frame,
                ty,
                stream_id,
                closed_at,
            } => write!(
                f,
                "frame {frame}: {} on stream {stream_id}, finished at frame {closed_at}",
                TyLabel(*ty)
            ),
            Self::PadLengthOctetMissing { frame } => write!(
                f,
                "frame {frame}: PADDED is set but the payload is empty"
            ),
            Self::PadLengthExceedsPayload {
                frame,
                pad_length,
                payload_len,
            } => write!(
                f,
                "frame {frame}: pad length {pad_length} does not fit a {payload_len}-octet payload"
            ),
        }
    }
}

/// A registered type name, or the octet when the registry does not define one.
///
/// Never invents a name for an unregistered type: rendering `0xEF` as `UNKNOWN` invites reading it as
/// something the spec has an opinion about.
struct TyLabel(u8);

impl fmt::Display for TyLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match types::name(self.0) {
            Some(n) => f.write_str(n),
            None => write!(f, "type 0x{:02X}", self.0),
        }
    }
}

/// Every rule the program breaks, in the order the frames appear.
///
/// Reports rather than refuses — that is the whole point. An empty result means the framing is
/// compliant as far as the checks listed in this module's docs go; it does not mean the program is
/// well formed at the HPACK or field-validity layer, neither of which framing can see.
pub fn audit(program: &H2FrameProgram) -> Vec<Violation> {
    let mut out = Vec::new();
    if !program.preface {
        out.push(Violation::MissingPreface);
    }

    // The block a CONTINUATION would be continuing: the frame that opened it, and its stream.
    let mut open_block: Option<(usize, u32)> = None;
    let mut opened: HashSet<u32> = HashSet::new();
    let mut highest_opened: u32 = 0;
    // Streams this program finished, and the frame that finished them.
    let mut finished: HashMap<u32, usize> = HashMap::new();

    for (i, spec) in program.frames.iter().enumerate() {
        let ty = spec.ty;
        let stream = spec.stream_id & !STREAM_ID_RESERVED_BIT;
        // What a peer will read: the header's 24 bits, after any truncation the field forces.
        let declared = spec.header().len & MAX_FRAME_PAYLOAD;

        if let Some(n) = spec.declared_len {
            if n > MAX_FRAME_PAYLOAD {
                out.push(Violation::LengthFieldOverflowed {
                    frame: i,
                    requested: n,
                    written: declared,
                });
            }
        } else if spec.payload.len() > MAX_FRAME_PAYLOAD as usize {
            out.push(Violation::PayloadExceedsLengthField {
                frame: i,
                payload_len: spec.payload.len(),
            });
        }
        if let Some(n) = spec.declared_len
            && spec.length_is_dishonest()
        {
            out.push(Violation::DeclaredLengthDisagrees {
                frame: i,
                declared: n,
                actual: spec.payload.len(),
            });
        }
        if spec.stream_id & STREAM_ID_RESERVED_BIT != 0 {
            out.push(Violation::ReservedBitSet { frame: i });
        }

        match ty {
            types::DATA
            | types::HEADERS
            | types::PRIORITY
            | types::RST_STREAM
            | types::PUSH_PROMISE
            | types::CONTINUATION
                if stream == 0 =>
            {
                out.push(Violation::StreamIdZeroOnStreamFrame { frame: i, ty });
            }
            types::SETTINGS | types::PING | types::GOAWAY if stream != 0 => {
                out.push(Violation::StreamIdNonZeroOnConnectionFrame {
                    frame: i,
                    ty,
                    stream_id: stream,
                });
            }
            // WINDOW_UPDATE is legal on the connection and on a stream (§6.9), and an unregistered
            // type has no stream rule to break — a receiver must discard it whatever it names.
            _ => {}
        }

        let fixed = match ty {
            types::PRIORITY => Some(5),
            types::RST_STREAM => Some(4),
            types::PING => Some(8),
            types::WINDOW_UPDATE => Some(4),
            _ => None,
        };
        if let Some(required) = fixed
            && declared != required
        {
            out.push(Violation::FixedLengthViolation {
                frame: i,
                ty,
                declared,
                required,
            });
        }
        if ty == types::SETTINGS {
            if !declared.is_multiple_of(6) {
                out.push(Violation::SettingsLengthNotMultipleOfSix {
                    frame: i,
                    declared,
                });
            }
            if spec.flags & flags::ACK != 0 && declared != 0 {
                out.push(Violation::SettingsAckWithPayload {
                    frame: i,
                    declared,
                });
            }
        }
        if ty == types::PUSH_PROMISE {
            out.push(Violation::PushPromiseFromClient { frame: i });
        }

        if matches!(ty, types::DATA | types::HEADERS | types::PUSH_PROMISE)
            && spec.flags & flags::PADDED != 0
        {
            match spec.payload.first() {
                None => out.push(Violation::PadLengthOctetMissing { frame: i }),
                Some(&pad) => {
                    if pad as usize + 1 > spec.payload.len() {
                        out.push(Violation::PadLengthExceedsPayload {
                            frame: i,
                            pad_length: pad,
                            payload_len: spec.payload.len(),
                        });
                    }
                }
            }
        }

        match open_block {
            Some((at, block_stream)) => {
                if ty != types::CONTINUATION {
                    out.push(Violation::FrameInterleavedInHeaderBlock {
                        frame: i,
                        ty,
                        block_opened_at: at,
                    });
                } else if stream != block_stream {
                    out.push(Violation::ContinuationOnAnotherStream {
                        frame: i,
                        expected: block_stream,
                        found: stream,
                    });
                }
                // END_HEADERS closes the block whichever stream the CONTINUATION named. Holding it
                // open would report every later frame as interleaved too, burying the one violation
                // that matters under a cascade of consequences.
                if ty == types::CONTINUATION && spec.flags & flags::END_HEADERS != 0 {
                    open_block = None;
                }
            }
            None => {
                if ty == types::CONTINUATION {
                    out.push(Violation::ContinuationWithNothingToContinue { frame: i });
                } else if matches!(ty, types::HEADERS | types::PUSH_PROMISE)
                    && spec.flags & flags::END_HEADERS == 0
                {
                    open_block = Some((i, stream));
                }
            }
        }

        if let Some(&closed_at) = finished.get(&stream) {
            // PRIORITY, WINDOW_UPDATE and RST_STREAM stay legal on a stream we have finished with;
            // anything else is a send on a half-closed(local) or closed stream.
            if !matches!(
                ty,
                types::PRIORITY | types::WINDOW_UPDATE | types::RST_STREAM
            ) {
                out.push(Violation::FrameAfterStreamClosed {
                    frame: i,
                    ty,
                    stream_id: stream,
                    closed_at,
                });
            }
        }
        // Stream 0 is never opened, so DATA there is idle too — but it already earns
        // StreamIdZeroOnStreamFrame, and reporting one octet twice makes a report harder to read.
        if ty == types::DATA && stream != 0 && !opened.contains(&stream) {
            out.push(Violation::DataOnUnopenedStream {
                frame: i,
                stream_id: stream,
            });
        }

        // HEADERS on a stream already open is trailers, which is legal and opens nothing.
        if ty == types::HEADERS && stream != 0 && !opened.contains(&stream) {
            if stream.is_multiple_of(2) {
                out.push(Violation::EvenStreamIdFromClient {
                    frame: i,
                    stream_id: stream,
                });
            }
            if stream <= highest_opened {
                out.push(Violation::StreamIdNotIncreasing {
                    frame: i,
                    stream_id: stream,
                    highest: highest_opened,
                });
            }
            opened.insert(stream);
            highest_opened = highest_opened.max(stream);
        }
        if ty == types::RST_STREAM
            || (matches!(ty, types::DATA | types::HEADERS) && spec.flags & flags::END_STREAM != 0)
        {
            finished.entry(stream).or_insert(i);
        }
    }

    if let Some((block_opened_at, stream_id)) = open_block {
        out.push(Violation::HeaderBlockNeverTerminated {
            block_opened_at,
            stream_id,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// A program that breaks nothing this module checks: preface, a settings exchange, one request.
    fn compliant() -> H2FrameProgram {
        H2FrameProgram {
            preface: true,
            frames: vec![
                FrameSpec::new(types::SETTINGS, 0, 0, Bytes::new()),
                FrameSpec::new(
                    types::HEADERS,
                    flags::END_HEADERS | flags::END_STREAM,
                    1,
                    Bytes::from_static(b"block"),
                ),
            ],
            ..Default::default()
        }
    }

    fn one(frames: Vec<FrameSpec>) -> H2FrameProgram {
        H2FrameProgram {
            preface: true,
            frames,
            ..Default::default()
        }
    }

    #[test]
    fn a_compliant_program_reports_nothing() {
        assert_eq!(audit(&compliant()), Vec::new());
    }

    #[test]
    fn every_malformation_reaches_the_wire_exactly_as_asked_for() {
        // The load-bearing property of the whole crate: what the caller asked for is what is
        // written. Six intents on one frame, and the expected octets are spelled out rather than
        // computed, so a writer that "helped" would have to change this literal to pass.
        let spec = FrameSpec::new(
            types::HEADERS,
            flags::END_HEADERS | flags::END_STREAM,
            1,
            Bytes::from_static(b"block"),
        )
        .malformed(Malformation::DeclareLength(MAX_FRAME_PAYLOAD))
        .malformed(Malformation::SetType(0xEF))
        .malformed(Malformation::AddFlags(0x40))
        .malformed(Malformation::ClearFlags(flags::END_HEADERS))
        .malformed(Malformation::SetStreamId(2))
        .malformed(Malformation::SetReservedBit);

        let octets = H2FrameProgram {
            preface: false,
            frames: vec![spec],
            ..Default::default()
        }
        .encode();

        assert_eq!(
            &octets[..],
            &[
                0xFF, 0xFF, 0xFF, // declares 16777215 octets; five follow
                0xEF, // a type the registry does not define
                0x41, // END_STREAM kept, 0x40 undefined bit added, END_HEADERS cleared
                0x80, 0x00, 0x00, 0x02, // reserved bit set over an even client-initiated id
                b'b', b'l', b'o', b'c', b'k',
            ][..]
        );
    }

    #[test]
    fn a_malformation_touches_only_the_field_it_names() {
        let base = FrameSpec::new(types::HEADERS, 0x05, 1, Bytes::from_static(b"abc"));

        let flags_only = base.clone().malformed(Malformation::AddFlags(0x40));
        assert_eq!(flags_only.flags, 0x45);
        assert_eq!(flags_only.ty, base.ty);
        assert_eq!(flags_only.stream_id, base.stream_id);
        assert_eq!(flags_only.declared_len, None);
        assert_eq!(flags_only.payload, base.payload);

        // SetReservedBit keeps the identifier beneath it; SetStreamId replaces the whole field.
        let reserved = base.clone().malformed(Malformation::SetReservedBit);
        assert_eq!(reserved.stream_id, STREAM_ID_RESERVED_BIT | 1);
        assert_eq!(reserved.header().stream_id_masked(), 1);
        let replaced = base.clone().malformed(Malformation::SetStreamId(0));
        assert_eq!(replaced.stream_id, 0);
    }

    #[test]
    fn the_audit_does_not_repair_what_it_reports() {
        let program = H2FrameProgram {
            preface: false,
            frames: vec![
                FrameSpec::new(types::CONTINUATION, 0, 0, Bytes::from_static(b"x"))
                    .with_declared_len(99),
            ],
            ..Default::default()
        };
        let before = program.encode();
        assert!(!audit(&program).is_empty(), "this program is malformed");
        assert_eq!(
            program.encode(),
            before,
            "auditing a program must not change what it emits"
        );
    }

    #[test]
    fn omitting_the_preface_is_reported_rather_than_assumed_deliberate() {
        let mut p = compliant();
        p.preface = false;
        assert!(audit(&p).contains(&Violation::MissingPreface));
    }

    #[test]
    fn a_lying_length_is_named_with_both_numbers() {
        let p = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::from_static(b"abcd"))
                .malformed(Malformation::DeclareLength(1)),
        ]);
        assert_eq!(
            audit(&p),
            vec![Violation::DeclaredLengthDisagrees {
                frame: 0,
                declared: 1,
                actual: 4
            }]
        );
    }

    #[test]
    fn a_declared_length_wider_than_the_field_reports_the_truncation() {
        // The one place the writer cannot do as it was told. Silence here would be a lie.
        let p = one(vec![
            FrameSpec::new(types::DATA, 0, 1, Bytes::new())
                .malformed(Malformation::DeclareLength(MAX_FRAME_PAYLOAD + 1)),
        ]);
        let found = audit(&p);
        assert!(
            found.contains(&Violation::LengthFieldOverflowed {
                frame: 0,
                requested: MAX_FRAME_PAYLOAD + 1,
                written: 0
            }),
            "0x1000000 truncates to 0 in a 24-bit field; got {found:?}"
        );
    }

    #[test]
    fn a_payload_wider_than_the_length_field_reports_the_clamp() {
        let p = one(vec![FrameSpec::new(
            types::DATA,
            0,
            1,
            Bytes::from(vec![0u8; MAX_FRAME_PAYLOAD as usize + 1]),
        )]);
        assert!(audit(&p).contains(&Violation::PayloadExceedsLengthField {
            frame: 0,
            payload_len: MAX_FRAME_PAYLOAD as usize + 1
        }));
    }

    #[test]
    fn the_reserved_bit_is_reported_without_disturbing_the_identifier() {
        let p = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::new())
                .malformed(Malformation::SetReservedBit),
        ]);
        assert_eq!(audit(&p), vec![Violation::ReservedBitSet { frame: 0 }]);
    }

    #[test]
    fn stream_id_rules_are_judged_per_frame_type() {
        let cases: Vec<(FrameSpec, Violation)> = vec![
            (
                FrameSpec::new(types::DATA, 0, 0, Bytes::from_static(b"x")),
                Violation::StreamIdZeroOnStreamFrame {
                    frame: 0,
                    ty: types::DATA,
                },
            ),
            (
                FrameSpec::new(types::SETTINGS, 0, 3, Bytes::new()),
                Violation::StreamIdNonZeroOnConnectionFrame {
                    frame: 0,
                    ty: types::SETTINGS,
                    stream_id: 3,
                },
            ),
            (
                FrameSpec::new(types::PING, 0, 1, Bytes::from_static(b"12345678")),
                Violation::StreamIdNonZeroOnConnectionFrame {
                    frame: 0,
                    ty: types::PING,
                    stream_id: 1,
                },
            ),
            (
                FrameSpec::new(types::HEADERS, flags::END_HEADERS, 2, Bytes::new()),
                Violation::EvenStreamIdFromClient {
                    frame: 0,
                    stream_id: 2,
                },
            ),
        ];
        for (spec, want) in cases {
            let found = audit(&one(vec![spec.clone()]));
            assert!(
                found.contains(&want),
                "{spec:?} should report {want:?}, got {found:?}"
            );
        }

        // A stream-level WINDOW_UPDATE is legal, and so is a connection-level one.
        for id in [0, 1] {
            let p = one(vec![FrameSpec::new(
                types::WINDOW_UPDATE,
                0,
                id,
                Bytes::from_static(&[0, 0, 0, 1]),
            )]);
            assert_eq!(audit(&p), Vec::new(), "WINDOW_UPDATE on stream {id}");
        }
    }

    #[test]
    fn a_stream_id_that_does_not_increase_is_reported_but_trailers_are_not() {
        let p = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 3, Bytes::new()),
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::new()),
        ]);
        assert!(audit(&p).contains(&Violation::StreamIdNotIncreasing {
            frame: 1,
            stream_id: 1,
            highest: 3
        }));

        // A second HEADERS on a stream already opened is trailers, not a reopening.
        let trailers = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::new()),
            FrameSpec::new(
                types::HEADERS,
                flags::END_HEADERS | flags::END_STREAM,
                1,
                Bytes::new(),
            ),
        ]);
        assert_eq!(audit(&trailers), Vec::new());
    }

    #[test]
    fn fixed_size_frames_report_a_length_the_spec_forbids() {
        for (ty, payload_len, required) in [
            (types::PRIORITY, 4usize, 5u32),
            (types::RST_STREAM, 5, 4),
            (types::PING, 7, 8),
            (types::WINDOW_UPDATE, 0, 4),
        ] {
            let p = one(vec![FrameSpec::new(
                ty,
                0,
                1,
                Bytes::from(vec![0u8; payload_len]),
            )]);
            assert!(
                audit(&p).contains(&Violation::FixedLengthViolation {
                    frame: 0,
                    ty,
                    declared: payload_len as u32,
                    required
                }),
                "{} with {payload_len} octets",
                types::name(ty).unwrap()
            );
        }
    }

    #[test]
    fn settings_length_rules_are_checked_against_the_length_a_peer_reads() {
        let odd = one(vec![FrameSpec::new(
            types::SETTINGS,
            0,
            0,
            Bytes::from(vec![0u8; 7]),
        )]);
        assert!(
            audit(&odd).contains(&Violation::SettingsLengthNotMultipleOfSix {
                frame: 0,
                declared: 7
            })
        );

        let acked = one(vec![FrameSpec::new(
            types::SETTINGS,
            flags::ACK,
            0,
            Bytes::from(vec![0u8; 6]),
        )]);
        assert!(audit(&acked).contains(&Violation::SettingsAckWithPayload {
            frame: 0,
            declared: 6
        }));

        // The peer frames by the declared value, so that is what the rule is judged on: six real
        // octets under a declared 7 is still a SETTINGS a peer will reject.
        let lying = one(vec![
            FrameSpec::new(types::SETTINGS, 0, 0, Bytes::from(vec![0u8; 6]))
                .malformed(Malformation::DeclareLength(7)),
        ]);
        assert!(
            audit(&lying).contains(&Violation::SettingsLengthNotMultipleOfSix {
                frame: 0,
                declared: 7
            })
        );
    }

    #[test]
    fn a_header_block_left_open_is_reported_against_the_frame_that_opened_it() {
        let p = one(vec![FrameSpec::new(
            types::HEADERS,
            0,
            1,
            Bytes::from_static(b"first-fragment"),
        )]);
        assert_eq!(
            audit(&p),
            vec![Violation::HeaderBlockNeverTerminated {
                block_opened_at: 0,
                stream_id: 1
            }]
        );

        // A CONTINUATION carrying END_HEADERS closes it, and then nothing is reported.
        let closed = one(vec![
            FrameSpec::new(types::HEADERS, 0, 1, Bytes::from_static(b"first")),
            FrameSpec::new(
                types::CONTINUATION,
                flags::END_HEADERS,
                1,
                Bytes::from_static(b"rest"),
            ),
        ]);
        assert_eq!(audit(&closed), Vec::new());
    }

    #[test]
    fn a_frame_interleaved_inside_a_header_block_is_reported() {
        // The design's named research target: a frame smuggled between HEADERS and its END_HEADERS.
        let p = one(vec![
            FrameSpec::new(types::HEADERS, 0, 1, Bytes::from_static(b"first")),
            FrameSpec::new(types::DATA, 0, 1, Bytes::from_static(b"payload")),
            FrameSpec::new(
                types::CONTINUATION,
                flags::END_HEADERS,
                1,
                Bytes::from_static(b"rest"),
            ),
        ]);
        assert!(audit(&p).contains(&Violation::FrameInterleavedInHeaderBlock {
            frame: 1,
            ty: types::DATA,
            block_opened_at: 0
        }));
    }

    #[test]
    fn a_continuation_reports_whether_it_has_a_block_and_whether_it_is_the_right_stream() {
        let orphan = one(vec![FrameSpec::new(
            types::CONTINUATION,
            flags::END_HEADERS,
            1,
            Bytes::from_static(b"c"),
        )]);
        assert_eq!(
            audit(&orphan),
            vec![Violation::ContinuationWithNothingToContinue { frame: 0 }]
        );

        let wrong_stream = one(vec![
            FrameSpec::new(types::HEADERS, 0, 1, Bytes::from_static(b"first")),
            FrameSpec::new(
                types::CONTINUATION,
                flags::END_HEADERS,
                3,
                Bytes::from_static(b"rest"),
            ),
        ]);
        assert!(audit(&wrong_stream).contains(&Violation::ContinuationOnAnotherStream {
            frame: 1,
            expected: 1,
            found: 3
        }));
    }

    #[test]
    fn data_on_a_stream_nothing_opened_is_an_illegal_state_transition() {
        let p = one(vec![FrameSpec::new(
            types::DATA,
            0,
            1,
            Bytes::from_static(b"body"),
        )]);
        assert_eq!(
            audit(&p),
            vec![Violation::DataOnUnopenedStream {
                frame: 0,
                stream_id: 1
            }]
        );
    }

    #[test]
    fn sending_on_a_finished_stream_is_reported_except_where_the_spec_still_allows_it() {
        let after_end_stream = one(vec![
            FrameSpec::new(
                types::HEADERS,
                flags::END_HEADERS | flags::END_STREAM,
                1,
                Bytes::new(),
            ),
            FrameSpec::new(types::DATA, 0, 1, Bytes::from_static(b"more")),
        ]);
        assert!(
            audit(&after_end_stream).contains(&Violation::FrameAfterStreamClosed {
                frame: 1,
                ty: types::DATA,
                stream_id: 1,
                closed_at: 0
            })
        );

        let after_reset = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::new()),
            FrameSpec::new(types::RST_STREAM, 0, 1, Bytes::from_static(&[0, 0, 0, 8])),
            FrameSpec::new(types::WINDOW_UPDATE, 0, 1, Bytes::from_static(&[0, 0, 0, 1])),
        ]);
        assert_eq!(
            audit(&after_reset),
            Vec::new(),
            "WINDOW_UPDATE after RST_STREAM is legal and must not be reported"
        );
    }

    #[test]
    fn padding_that_runs_past_the_frame_is_reported() {
        let over = one(vec![FrameSpec::new(
            types::DATA,
            flags::PADDED | flags::END_STREAM,
            1,
            // pad length 9 in a four-octet payload: three octets of padding are available.
            Bytes::from_static(&[9, b'a', b'b', b'c']),
        )]);
        let found = audit(&over);
        assert!(
            found.contains(&Violation::PadLengthExceedsPayload {
                frame: 0,
                pad_length: 9,
                payload_len: 4
            }),
            "got {found:?}"
        );

        let empty = one(vec![FrameSpec::new(
            types::DATA,
            flags::PADDED,
            1,
            Bytes::new(),
        )]);
        assert!(audit(&empty).contains(&Violation::PadLengthOctetMissing { frame: 0 }));

        // pad length 2 in a four-octet payload: one data octet, two of padding. Legal.
        let fits = one(vec![
            FrameSpec::new(types::HEADERS, flags::END_HEADERS, 1, Bytes::new()),
            FrameSpec::new(
                types::DATA,
                flags::PADDED,
                1,
                Bytes::from_static(&[2, b'x', 0, 0]),
            ),
        ]);
        assert_eq!(audit(&fits), Vec::new());
    }

    #[test]
    fn push_promise_from_a_client_is_reported() {
        let p = one(vec![FrameSpec::new(
            types::PUSH_PROMISE,
            flags::END_HEADERS,
            1,
            Bytes::from_static(b"\x00\x00\x00\x02block"),
        )]);
        assert!(audit(&p).contains(&Violation::PushPromiseFromClient { frame: 0 }));
    }

    #[test]
    fn every_violation_cites_the_section_that_forbids_it_and_reads_as_a_sentence() {
        // A catalogue entry with no citation, or an empty message, is a report an operator cannot
        // check against the spec — so the shape is asserted rather than assumed.
        let all = [
            Violation::MissingPreface,
            Violation::LengthFieldOverflowed {
                frame: 0,
                requested: 1,
                written: 2,
            },
            Violation::PayloadExceedsLengthField {
                frame: 0,
                payload_len: 1,
            },
            Violation::DeclaredLengthDisagrees {
                frame: 0,
                declared: 1,
                actual: 2,
            },
            Violation::ReservedBitSet { frame: 0 },
            Violation::StreamIdZeroOnStreamFrame {
                frame: 0,
                ty: types::DATA,
            },
            Violation::StreamIdNonZeroOnConnectionFrame {
                frame: 0,
                ty: types::PING,
                stream_id: 1,
            },
            Violation::EvenStreamIdFromClient {
                frame: 0,
                stream_id: 2,
            },
            Violation::StreamIdNotIncreasing {
                frame: 0,
                stream_id: 1,
                highest: 3,
            },
            Violation::FixedLengthViolation {
                frame: 0,
                ty: types::PING,
                declared: 7,
                required: 8,
            },
            Violation::SettingsLengthNotMultipleOfSix {
                frame: 0,
                declared: 7,
            },
            Violation::SettingsAckWithPayload {
                frame: 0,
                declared: 6,
            },
            Violation::PushPromiseFromClient { frame: 0 },
            Violation::ContinuationWithNothingToContinue { frame: 0 },
            Violation::ContinuationOnAnotherStream {
                frame: 0,
                expected: 1,
                found: 3,
            },
            Violation::FrameInterleavedInHeaderBlock {
                frame: 1,
                ty: 0xEF,
                block_opened_at: 0,
            },
            Violation::HeaderBlockNeverTerminated {
                block_opened_at: 0,
                stream_id: 1,
            },
            Violation::DataOnUnopenedStream {
                frame: 0,
                stream_id: 1,
            },
            Violation::FrameAfterStreamClosed {
                frame: 1,
                ty: types::DATA,
                stream_id: 1,
                closed_at: 0,
            },
            Violation::PadLengthOctetMissing { frame: 0 },
            Violation::PadLengthExceedsPayload {
                frame: 0,
                pad_length: 9,
                payload_len: 4,
            },
        ];
        for v in &all {
            assert!(v.rfc().starts_with("RFC 9113 §"), "{v:?} cites {}", v.rfc());
            assert!(v.to_string().len() > 10, "{v:?} renders as {}", v);
        }
        // An unregistered type renders as its octet, never as a name.
        assert!(
            Violation::FrameInterleavedInHeaderBlock {
                frame: 1,
                ty: 0xEF,
                block_opened_at: 0
            }
            .to_string()
            .contains("type 0xEF")
        );
    }

    #[test]
    fn a_malformation_cites_the_section_it_breaks() {
        for m in [
            Malformation::DeclareLength(1),
            Malformation::SetType(0xEF),
            Malformation::SetFlags(0xFF),
            Malformation::AddFlags(0x40),
            Malformation::ClearFlags(flags::END_HEADERS),
            Malformation::SetStreamId(0),
            Malformation::SetReservedBit,
        ] {
            assert!(m.rfc().starts_with("RFC 9113 §"), "{m:?}");
        }
    }
}
