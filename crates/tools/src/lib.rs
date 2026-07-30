//! burpsy-tools — the supporting tools: Decoder, Comparer, Logger, Organizer, match-and-replace.
//!
//! These are pure transformations over bytes and stored messages, deliberately free of any I/O so
//! they can be exercised directly in tests and reused by the proxy, the UI and the MCP server alike.
//!
//! # What "free of I/O" buys, and what it costs callers
//!
//! No clock, no filesystem, no sockets. Timestamps are parameters ([`logger::Started::started_ms`],
//! [`organizer::Organizer::add`]) rather than reads of `SystemTime`, which is mildly inconvenient at
//! two call sites and makes every test here deterministic and every module trivially reusable from
//! a context that has its own idea of time.
//!
//! # Shared discipline
//!
//! * **Spans, not copies.** [`comparer`] returns `Span`s into the buffers it was given, and
//!   [`decoder`]'s smart pass reports which input span produced which output span. Diffing two
//!   200 KB bodies allocates in proportion to the number of *changes*.
//! * **Refuse rather than mangle.** Every module has at least one place where it declines to guess:
//!   the decoder will not guess base64, match-and-replace will not rewrite inside chunk framing or
//!   silently repair a Content-Length, the comparer says `truncated` instead of pretending.
//! * **Errors at construction.** [`matchreplace::Rule`] compiles its regex in its only constructor,
//!   so nothing reaches the proxy's hot path uncompiled.

pub mod comparer;
pub mod decoder;
pub mod hash;
pub mod logger;
pub mod matchreplace;
pub mod organizer;

pub use comparer::{Diff, Granularity, Op, diff, diff_with_budget};
pub use decoder::{
    Confidence, DecodeError, Layer, Pass, Run, Smart, SmartOptions, decode, encode, smart_decode,
    smart_pass,
};
pub use hash::{HashAlgorithm, hash};
pub use logger::{Entry, Started, Tool, ToolLog};
pub use matchreplace::{Category, Ctx, Rule, RuleError, RuleSet, RuleSetSpec, RuleSpec, Target};
pub use organizer::{Highlight, Item, Organizer};
