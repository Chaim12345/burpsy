//! burpsy-http2 — HTTP/2 framing, HPACK, and HTTP/1 normalisation. No sockets.
//!
//! # What this crate is for
//!
//! Three jobs, and the reason they live together is that all three are pure functions over bytes:
//!
//! 1. **A frame layer that corrects nothing** ([`frame`]), and a vocabulary for breaking the spec on
//!    purpose ([`malformed`]). Emitting a frame the spec forbids is a requirement here, not an escape
//!    hatch — request smuggling and desync research consist of exactly that. A compliant library
//!    refuses, correctly, which is why this is hand-written. What a compliant library also cannot do
//!    is tell you *which* rules your probe broke, which is [`malformed::audit`]'s job: an accidental
//!    malformation and a deliberate one produce the same `RST_STREAM`.
//! 2. **HPACK** — because a compliant library will not *show* you a malformed header block either. It
//!    resets the stream before the octets reach you, and for a proxy whose reason to exist includes
//!    smuggling, seeing what a peer sent is worth as much as sending it. The external `h2` crate's
//!    encoder and decoder are unreachable from outside that crate at every feature configuration, so
//!    there is no third option.
//! 3. **Normalisation** to and from an HTTP/1-shaped serialisation, so an h2 exchange sits in history
//!    in the same shape as an HTTP/1 one and every existing tool keeps working on it unchanged.
//!
//! # No sockets, deliberately
//!
//! Nothing here opens a connection. The one authorising path from a constructed request to a socket is
//! `burpsy_sender::AuthorisedSender`, and a workspace source scan
//! (`crates/sender/tests/no_alternate_egress.rs`) fails the build if that changes. This crate produces
//! and consumes bytes; something else decides whether they are allowed to leave.
//!
//! # The honest limit of "byte-exact"
//!
//! Worth stating at the crate root because it shapes the whole API, and because promising otherwise
//! would be the kind of overclaim this project rejects:
//!
//! **Byte-exact emission is available. Byte-exact replay of a *captured* header block is not.** A
//! HEADERS frame's octets encode indices into a dynamic table the two endpoints built together over
//! the life of the connection. Replaying those octets against a different peer, or against the same
//! peer at a different moment, decodes to something else. So "resend exactly these bytes" — which
//! HTTP/1 Repeater offers and which is meaningful there — has **no h2 analogue for headers**, and any
//! interface that implies it does is lying.
//!
//! What is total instead is **header-list-exactness**: the ordered list of fields, including
//! duplicates, unusual casing, and pseudo-headers in whatever order they appeared, is preserved and
//! re-encodable. For frames we emitted ourselves on a connection we owned from its first octet, the
//! stronger property does hold — our table starts empty and only we write to it, so a program's octets
//! are a pure function of the program.

pub mod frame;
pub mod hpack;
pub mod malformed;

pub use frame::{
    CONNECTION_PREFACE, FRAME_HEADER_LEN, FrameHeader, FrameSpec, H2FrameProgram,
    MAX_FRAME_PAYLOAD, RawFrame, STREAM_ID_RESERVED_BIT, Tail, flags, read_frames, strip_preface,
    types,
};
pub use hpack::{Decoder, HpackError};
pub use malformed::{Malformation, Violation, audit};
