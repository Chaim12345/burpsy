//! The HTTP/2 frame layer: a 9-octet header, a writer that corrects nothing, and a reader that
//! reports what it could not finish.
//!
//! # Why this is hand-written
//!
//! The whole reason burpsy exists includes request smuggling, and a smuggling probe is a frame the
//! spec forbids: a length field that disagrees with the payload, stream id 0 on a stream frame, an
//! even client-initiated id, the reserved bit set, CONTINUATION with nothing to continue. A
//! spec-compliant library refuses to emit those — correctly, that is its purpose — and it equally
//! refuses to *show you* one a peer sent, because it resets the stream before you see the octets.
//!
//! So this layer's contract is the inverse of a library's: **it never corrects its input, and it
//! never discards what it cannot parse.**
//!
//! # Byte order
//!
//! Big-endian, throughout — HTTP/2 is network order. Worth stating because `burpsy_core::segment`'s
//! on-disk record header is deliberately little-endian, and the two live one crate apart.

use bytes::{BufMut, Bytes, BytesMut};

/// `length(3) + type(1) + flags(1) + stream_id(4)`.
pub const FRAME_HEADER_LEN: usize = 9;

/// The largest value a 24-bit length field can carry, and therefore the largest payload a frame can
/// declare. Not a policy choice — it is what the field can hold.
pub const MAX_FRAME_PAYLOAD: u32 = 0x00FF_FFFF;

/// The client connection preface, RFC 9113 §3.4. Sent verbatim before any frame.
pub const CONNECTION_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The reserved bit at the top of the stream-id field.
///
/// The spec says a sender must leave it clear and a receiver must ignore it. Both halves are things a
/// tester needs to violate and observe, so this crate carries the full 32 bits and never masks them
/// away — see [`FrameHeader::stream_id`].
pub const STREAM_ID_RESERVED_BIT: u32 = 0x8000_0000;

/// The registered frame type octets, RFC 9113 §11.2.
///
/// Constants rather than an enum, for the reason [`FrameHeader`] gives: an unregistered type octet
/// is a research target, and an enum would either reject it or lose it. Nothing here narrows what
/// [`FrameSpec`] accepts — `0xEF` is as valid an input as `types::DATA`, and the writer emits both.
/// These exist so a caller and a violation report can say `HEADERS` instead of `0x1`.
pub mod types {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;

    /// The registered name for a type octet, or `None` for one the registry does not define.
    ///
    /// `None` rather than a `"UNKNOWN(0xEF)"` string: a report that renders an unknown type as if it
    /// were a name invites reading it as one.
    pub fn name(ty: u8) -> Option<&'static str> {
        Some(match ty {
            DATA => "DATA",
            HEADERS => "HEADERS",
            PRIORITY => "PRIORITY",
            RST_STREAM => "RST_STREAM",
            SETTINGS => "SETTINGS",
            PUSH_PROMISE => "PUSH_PROMISE",
            PING => "PING",
            GOAWAY => "GOAWAY",
            WINDOW_UPDATE => "WINDOW_UPDATE",
            CONTINUATION => "CONTINUATION",
            _ => return None,
        })
    }
}

/// The defined flag bits.
///
/// One bit position means different things on different frame types — `0x01` is `END_STREAM` on DATA
/// and HEADERS but `ACK` on SETTINGS and PING — so these are named per meaning, not per position, and
/// a caller has to know which frame it is setting a flag on. Undefined bits (`0x02`, `0x10`, `0x40`,
/// `0x80`) have no constant precisely because their only use here is to be set deliberately.
pub mod flags {
    /// DATA, HEADERS.
    pub const END_STREAM: u8 = 0x01;
    /// SETTINGS, PING. Same bit as [`END_STREAM`], different frames.
    pub const ACK: u8 = 0x01;
    /// HEADERS, PUSH_PROMISE, CONTINUATION.
    pub const END_HEADERS: u8 = 0x04;
    /// DATA, HEADERS, PUSH_PROMISE.
    pub const PADDED: u8 = 0x08;
    /// HEADERS.
    pub const PRIORITY: u8 = 0x20;
}

/// One frame's header, exactly as it appears on the wire.
///
/// Every field is the raw wire field. `ty` and `flags` are integers rather than enums because an
/// unknown type and a reserved flag bit are both research targets — an enum would either reject them
/// or lose them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The 24-bit length field as written. May disagree with the payload that follows; that
    /// disagreement is the point of several probes.
    pub len: u32,
    pub ty: u8,
    pub flags: u8,
    /// The full 32-bit field, reserved bit included. Use [`Self::stream_id_masked`] for the 31-bit
    /// identifier and [`Self::reserved_bit_set`] to ask about the top bit.
    pub stream_id: u32,
}

impl FrameHeader {
    /// The 31-bit stream identifier, with the reserved bit cleared.
    pub fn stream_id_masked(&self) -> u32 {
        self.stream_id & !STREAM_ID_RESERVED_BIT
    }

    /// Whether the reserved top bit is set — something a compliant peer never does, and therefore
    /// worth being able to see.
    pub fn reserved_bit_set(&self) -> bool {
        self.stream_id & STREAM_ID_RESERVED_BIT != 0
    }

    /// Encode the nine octets. Big-endian. Writes `len` as given; truncates to 24 bits because the
    /// field is 24 bits, and reports nothing, because a caller who set a larger value chose to.
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = (self.len >> 16) as u8;
        out[1] = (self.len >> 8) as u8;
        out[2] = self.len as u8;
        out[3] = self.ty;
        out[4] = self.flags;
        out[5..9].copy_from_slice(&self.stream_id.to_be_bytes());
        out
    }

    /// Decode nine octets. Total — every 9-byte input is a valid header, because every field is raw.
    ///
    /// Returns `None` only when there are fewer than nine bytes, which is a framing question rather
    /// than a validity one.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FRAME_HEADER_LEN {
            return None;
        }
        Some(Self {
            len: u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
            ty: bytes[3],
            flags: bytes[4],
            stream_id: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]),
        })
    }
}

/// A frame to emit.
///
/// `payload` is bytes at this layer, deliberately. HPACK encoding is a different concern with a
/// different failure mode, so a header list becomes bytes *before* it reaches the writer — which also
/// means the writer has exactly one input shape and no branch that could treat a header block
/// specially.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameSpec {
    pub ty: u8,
    pub flags: u8,
    pub stream_id: u32,
    /// `None` writes the payload's true length. `Some(n)` writes `n` instead, whatever the payload is.
    ///
    /// This is the single most useful lie the layer can tell: a receiver frames the connection by the
    /// declared length, so a short value truncates the block it reads and a long one swallows the next
    /// frame's octets into it.
    pub declared_len: Option<u32>,
    pub payload: Bytes,
}

impl FrameSpec {
    /// A frame whose declared length is honest.
    pub fn new(ty: u8, flags: u8, stream_id: u32, payload: Bytes) -> Self {
        Self {
            ty,
            flags,
            stream_id,
            declared_len: None,
            payload,
        }
    }

    /// Declare a length other than the payload's own.
    pub fn with_declared_len(mut self, len: u32) -> Self {
        self.declared_len = Some(len);
        self
    }

    /// The header this spec will emit.
    pub fn header(&self) -> FrameHeader {
        FrameHeader {
            len: self
                .declared_len
                .unwrap_or_else(|| self.payload.len().min(MAX_FRAME_PAYLOAD as usize) as u32),
            ty: self.ty,
            flags: self.flags,
            stream_id: self.stream_id,
        }
    }

    /// Whether the declared length disagrees with the payload actually written.
    ///
    /// The authorisation layer needs this: a program that lies about a length cannot have its header
    /// block authorised field-by-field, because the peer will not decode the block we decoded.
    pub fn length_is_dishonest(&self) -> bool {
        match self.declared_len {
            Some(n) => n as usize != self.payload.len(),
            None => false,
        }
    }
}

/// An ordered list of frames to put on one fresh connection, then read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2FrameProgram {
    /// Whether to send the 24-octet client preface first. Omitting it is a research target.
    pub preface: bool,
    pub frames: Vec<FrameSpec>,
    /// How long to keep reading after the last frame is written.
    pub read_for_ms: u64,
}

impl Default for H2FrameProgram {
    fn default() -> Self {
        Self {
            preface: true,
            frames: Vec::new(),
            read_for_ms: 2_000,
        }
    }
}

impl H2FrameProgram {
    /// Serialise the whole program. Corrects nothing, reorders nothing, adds nothing.
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(
            (if self.preface {
                CONNECTION_PREFACE.len()
            } else {
                0
            }) + self
                .frames
                .iter()
                .map(|f| FRAME_HEADER_LEN + f.payload.len())
                .sum::<usize>(),
        );
        if self.preface {
            out.put_slice(CONNECTION_PREFACE);
        }
        for f in &self.frames {
            out.put_slice(&f.header().encode());
            out.put_slice(&f.payload);
        }
        out.freeze()
    }

    /// True when every frame's length field agrees with the payload actually written.
    ///
    /// A lying length makes a program's effect on a peer un-inferable from our own decode — the peer
    /// frames by the declared value, so it decodes a header block we never saw — which is why the
    /// authorisation layer treats such a program as a whole-host question rather than a per-path one.
    ///
    /// **This is one of the authorisation layer's triggers, not all of them.** An unterminated header
    /// block, a `CONTINUATION`, and a raw header-block fragment each have the same consequence and
    /// none of them is a length question; [`crate::malformed::audit`] reports those, and the
    /// classifier that combines them is the authorisation layer's own. An earlier version of this
    /// comment claimed the unterminated-block half was checked here. It was not.
    pub fn frame_layout_is_honest(&self) -> bool {
        !self.frames.iter().any(|f| f.length_is_dishonest())
    }
}

/// A frame read off the wire, with the octets it was cut from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub header: FrameHeader,
    /// Exactly `header.len` octets. What the peer framed, not what it should have.
    pub payload: Bytes,
    /// Offset of this frame's header within the stream it was read from, so a fault can name where.
    pub offset: usize,
}

/// What was left over after reading as many whole frames as possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tail {
    /// Every octet was consumed by a whole frame.
    Complete,
    /// Octets remain that do not form a whole frame.
    ///
    /// Reported rather than dropped. A truncated tail is frequently the *result* of a probe — a peer
    /// that died mid-frame is a finding — so discarding it would discard the answer.
    Incomplete {
        offset: usize,
        have: usize,
        /// `None` when there is not even a full header, so the needed total is unknowable.
        need: Option<usize>,
    },
}

/// Split a byte stream into whole frames.
///
/// Framing follows the **declared** length, because that is what a peer does. A frame declaring more
/// than remains does not consume what is there and does not error: it ends the scan and the remainder
/// comes back as [`Tail::Incomplete`], naming the offset and what was needed.
pub fn read_frames(bytes: &[u8]) -> (Vec<RawFrame>, Tail) {
    let mut frames = Vec::new();
    let mut at = 0usize;

    loop {
        let remaining = bytes.len() - at;
        if remaining == 0 {
            return (frames, Tail::Complete);
        }
        let Some(header) = FrameHeader::decode(&bytes[at..]) else {
            return (
                frames,
                Tail::Incomplete {
                    offset: at,
                    have: remaining,
                    need: None,
                },
            );
        };
        let want = FRAME_HEADER_LEN + header.len as usize;
        if remaining < want {
            return (
                frames,
                Tail::Incomplete {
                    offset: at,
                    have: remaining,
                    need: Some(want),
                },
            );
        }
        let start = at + FRAME_HEADER_LEN;
        frames.push(RawFrame {
            header,
            payload: Bytes::copy_from_slice(&bytes[start..start + header.len as usize]),
            offset: at,
        });
        at += want;
    }
}

/// Strip the client preface if present, returning the rest.
///
/// `None` when the input begins with something else — a peer that did not send it, or a program that
/// deliberately omitted it.
pub fn strip_preface(bytes: &[u8]) -> Option<&[u8]> {
    bytes.strip_prefix(&CONNECTION_PREFACE[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    use types::{CONTINUATION, DATA, HEADERS, SETTINGS};

    #[test]
    fn a_frame_header_round_trips_every_field_including_reserved_bits() {
        for (len, ty, flags, stream_id) in [
            (0u32, DATA, 0u8, 0u32),
            (1, HEADERS, 0x05, 1),
            (MAX_FRAME_PAYLOAD, 0xFF, 0xFF, u32::MAX),
            (16_384, SETTINGS, 0x01, 0x7FFF_FFFF),
        ] {
            let h = FrameHeader {
                len,
                ty,
                flags,
                stream_id,
            };
            assert_eq!(
                FrameHeader::decode(&h.encode()),
                Some(h),
                "header did not survive an encode/decode round trip"
            );
        }
    }

    #[test]
    fn the_header_is_big_endian() {
        let h = FrameHeader {
            len: 0x01_02_03,
            ty: 0x04,
            flags: 0x05,
            stream_id: 0x0607_0809,
        };
        assert_eq!(
            h.encode(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            "HTTP/2 is network order; a little-endian length would frame every peer wrongly"
        );
    }

    #[test]
    fn fewer_than_nine_octets_is_a_framing_answer_not_a_validity_one() {
        for n in 0..FRAME_HEADER_LEN {
            assert_eq!(FrameHeader::decode(&vec![0u8; n]), None);
        }
        assert!(FrameHeader::decode(&[0u8; FRAME_HEADER_LEN]).is_some());
    }

    #[test]
    fn the_reserved_bit_is_carried_not_masked_away() {
        let h = FrameHeader {
            len: 0,
            ty: DATA,
            flags: 0,
            stream_id: STREAM_ID_RESERVED_BIT | 3,
        };
        assert!(h.reserved_bit_set(), "the bit a compliant peer never sets");
        assert_eq!(h.stream_id_masked(), 3);
        // And it survives the wire, in both directions.
        let back = FrameHeader::decode(&h.encode()).expect("decode");
        assert_eq!(back.stream_id, STREAM_ID_RESERVED_BIT | 3);
        assert!(back.reserved_bit_set());
    }

    // ---- the writer does not help ----

    #[test]
    fn a_declared_length_that_disagrees_with_the_payload_is_emitted_as_written() {
        let spec =
            FrameSpec::new(DATA, 0x01, 1, Bytes::from_static(b"four")).with_declared_len(9999);
        assert!(spec.length_is_dishonest());
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![spec],
            ..Default::default()
        }
        .encode();
        // Length field says 9999; exactly four payload octets follow.
        assert_eq!(&octets[0..3], &[0x00, 0x27, 0x0F], "9999 big-endian");
        assert_eq!(octets.len(), FRAME_HEADER_LEN + 4);
        assert_eq!(&octets[FRAME_HEADER_LEN..], b"four");
    }

    #[test]
    fn stream_id_zero_on_a_data_frame_is_emitted_unchanged() {
        // Illegal per RFC 9113 §6.1, which is why it must be possible.
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(DATA, 0, 0, Bytes::from_static(b"x"))],
            ..Default::default()
        }
        .encode();
        assert_eq!(&octets[5..9], &[0, 0, 0, 0]);
    }

    #[test]
    fn an_even_client_initiated_stream_id_is_emitted_unchanged() {
        // Clients must use odd ids (§5.1.1). The writer does not renumber.
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(HEADERS, 0x04, 2, Bytes::from_static(b"h"))],
            ..Default::default()
        }
        .encode();
        assert_eq!(u32::from_be_bytes(octets[5..9].try_into().unwrap()), 2);
    }

    #[test]
    fn reserved_flag_bits_survive_the_writer() {
        // 0xFF sets every defined and every undefined flag at once.
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(HEADERS, 0xFF, 1, Bytes::new())],
            ..Default::default()
        }
        .encode();
        assert_eq!(
            octets[4], 0xFF,
            "the writer must not clear what it does not know"
        );
    }

    #[test]
    fn continuation_with_nothing_to_continue_is_emitted_anyway() {
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(
                CONTINUATION,
                0x04,
                1,
                Bytes::from_static(b"c"),
            )],
            ..Default::default()
        }
        .encode();
        assert_eq!(octets[3], CONTINUATION);
        // No preceding HEADERS. The writer has no opinion.
        assert_eq!(octets.len(), FRAME_HEADER_LEN + 1);
    }

    #[test]
    fn an_unknown_frame_type_is_emitted_unchanged() {
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(0xEF, 0, 1, Bytes::new())],
            ..Default::default()
        }
        .encode();
        assert_eq!(octets[3], 0xEF);
    }

    #[test]
    fn the_preface_is_written_verbatim_and_can_be_omitted() {
        let with = H2FrameProgram {
            preface: true,
            frames: vec![],
            ..Default::default()
        }
        .encode();
        assert_eq!(&with[..], &CONNECTION_PREFACE[..]);

        let without = H2FrameProgram {
            preface: false,
            frames: vec![],
            ..Default::default()
        }
        .encode();
        assert!(
            without.is_empty(),
            "omitting the preface is a research target"
        );
    }

    #[test]
    fn frame_layout_honesty_is_reported_for_the_authoriser() {
        let honest = H2FrameProgram {
            preface: true,
            frames: vec![FrameSpec::new(HEADERS, 0x04, 1, Bytes::from_static(b"abc"))],
            ..Default::default()
        };
        assert!(honest.frame_layout_is_honest());

        let mut lying = honest.clone();
        lying.frames[0].declared_len = Some(1);
        assert!(
            !lying.frame_layout_is_honest(),
            "a lying length means the peer decodes a block we did not"
        );

        // Some(n) that agrees with the payload is not a lie.
        let mut explicit = honest.clone();
        explicit.frames[0].declared_len = Some(3);
        assert!(explicit.frame_layout_is_honest());
    }

    // ---- the reader does not drop ----

    #[test]
    fn a_concatenated_stream_splits_at_frame_boundaries() {
        let program = H2FrameProgram {
            preface: false,
            frames: vec![
                FrameSpec::new(SETTINGS, 0, 0, Bytes::new()),
                FrameSpec::new(HEADERS, 0x04, 1, Bytes::from_static(b"hdr")),
                FrameSpec::new(DATA, 0x01, 1, Bytes::from_static(b"body-bytes")),
            ],
            ..Default::default()
        };
        let (frames, tail) = read_frames(&program.encode());
        assert_eq!(tail, Tail::Complete);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].header.ty, SETTINGS);
        assert_eq!(frames[1].payload, Bytes::from_static(b"hdr"));
        assert_eq!(frames[2].payload, Bytes::from_static(b"body-bytes"));
        // Offsets name where each frame started, for fault reporting.
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[1].offset, FRAME_HEADER_LEN);
        assert_eq!(frames[2].offset, FRAME_HEADER_LEN * 2 + 3);
    }

    #[test]
    fn write_then_read_round_trips_a_compliant_program() {
        let frames = vec![
            FrameSpec::new(
                SETTINGS,
                0,
                0,
                Bytes::from_static(b"\x00\x03\x00\x00\x00\x64"),
            ),
            FrameSpec::new(HEADERS, 0x05, 1, Bytes::from_static(b"encoded-block")),
            FrameSpec::new(DATA, 0x01, 1, Bytes::from_static(b"payload")),
        ];
        let program = H2FrameProgram {
            preface: true,
            frames: frames.clone(),
            ..Default::default()
        };
        let octets = program.encode();
        let rest = strip_preface(&octets).expect("preface present");
        let (read, tail) = read_frames(rest);
        assert_eq!(tail, Tail::Complete);
        assert_eq!(read.len(), frames.len());
        for (got, want) in read.iter().zip(&frames) {
            assert_eq!(got.header, want.header());
            assert_eq!(got.payload, want.payload);
        }
    }

    #[test]
    fn a_tail_truncated_mid_payload_is_reported_incomplete_not_dropped() {
        let program = H2FrameProgram {
            preface: false,
            frames: vec![
                FrameSpec::new(HEADERS, 0x04, 1, Bytes::from_static(b"complete")),
                FrameSpec::new(DATA, 0, 1, Bytes::from_static(b"0123456789")),
            ],
            ..Default::default()
        };
        let octets = program.encode();
        let cut = octets.len() - 4; // lose four payload octets of the last frame
        let (frames, tail) = read_frames(&octets[..cut]);

        assert_eq!(
            frames.len(),
            1,
            "the whole frame before the cut is still returned"
        );
        match tail {
            Tail::Incomplete { offset, have, need } => {
                assert_eq!(offset, FRAME_HEADER_LEN + 8);
                assert_eq!(need, Some(FRAME_HEADER_LEN + 10));
                assert_eq!(have, FRAME_HEADER_LEN + 6);
            }
            Tail::Complete => panic!("a truncated frame must not read as complete"),
        }
    }

    #[test]
    fn a_tail_too_short_for_a_header_cannot_state_what_it_needed() {
        let mut octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(DATA, 0, 1, Bytes::from_static(b"x"))],
            ..Default::default()
        }
        .encode()
        .to_vec();
        octets.extend_from_slice(&[0x00, 0x01]); // two stray octets

        let (frames, tail) = read_frames(&octets);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            tail,
            Tail::Incomplete {
                offset: FRAME_HEADER_LEN + 1,
                have: 2,
                need: None
            },
            "without nine octets the needed total is unknowable, and saying None is honest"
        );
    }

    #[test]
    fn a_frame_declaring_more_than_remains_ends_the_scan_rather_than_erroring() {
        // The shape a lying declared_len produces on the receiving side.
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![
                FrameSpec::new(DATA, 0, 1, Bytes::from_static(b"short")).with_declared_len(1000),
            ],
            ..Default::default()
        }
        .encode();
        let (frames, tail) = read_frames(&octets);
        assert!(frames.is_empty(), "no whole frame is present");
        assert_eq!(
            tail,
            Tail::Incomplete {
                offset: 0,
                have: FRAME_HEADER_LEN + 5,
                need: Some(FRAME_HEADER_LEN + 1000)
            }
        );
    }

    #[test]
    fn an_empty_stream_is_complete_not_incomplete() {
        let (frames, tail) = read_frames(&[]);
        assert!(frames.is_empty());
        assert_eq!(tail, Tail::Complete);
    }

    #[test]
    fn a_zero_length_frame_is_a_real_frame() {
        let octets = H2FrameProgram {
            preface: false,
            frames: vec![FrameSpec::new(SETTINGS, 0x01, 0, Bytes::new())],
            ..Default::default()
        }
        .encode();
        let (frames, tail) = read_frames(&octets);
        assert_eq!(tail, Tail::Complete);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].payload.is_empty());
        assert_eq!(frames[0].header.len, 0);
    }

    #[test]
    fn strip_preface_declines_a_stream_that_does_not_begin_with_it() {
        assert!(strip_preface(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert_eq!(strip_preface(CONNECTION_PREFACE), Some(&[][..]));
    }
}
