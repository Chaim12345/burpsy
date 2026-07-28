//! The wire-shaped types a [`MacroSender`] sends and receives, and the trait itself.
//!
//! # Why sending is a trait, not a call to `burpsy_sender::AuthorisedSender` directly
//!
//! A login macro sends requests, which makes it a request-originating surface in the sense
//! HARD-03 uses the phrase: Phase 1 built `burpsy_sender::AuthorisedSender` as the one place a
//! constructed request is allowed to reach a socket, precisely so that no later surface has to
//! re-derive "did we remember to check scope" on its own. This crate is deliberately not where
//! that wiring happens. Depending on `burpsy-sender` directly would mean this crate's own tests
//! could only ever run against a real (or real-shaped) transport, and it would plant a second,
//! crate-local opinion about *how* a request reaches the network right next to the one Phase 1
//! already built. [`MacroSender`] is the seam instead: this crate owns the re-login policy —
//! recording, replay order, cookie carry-over, the operator's validity rule, the retry bound,
//! collapsing concurrent observers — and a later slice in `cli`/`web` implements this trait once,
//! over an `AuthorisedSender`, so the authorisation decision stays exactly where Phase 1 put it.
//! Every test in this crate runs against a fake that implements the trait, touches no socket, and
//! cannot accidentally bypass that chokepoint because it never had a path to one.

use bytes::Bytes;

/// One request to (re)send, as recorded by an operator macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroStep {
    pub method: String,
    /// A full URL (`scheme://host[:port]/path...`), not a bare path — the cookie jar keys itself
    /// by host (see `cookie::host_of`), and deriving that from a path plus some implicit base URL
    /// would just move the question of "which host" somewhere less visible.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// One response, as a [`MacroSender`] hands it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// `None` when no body was captured for this response, distinct from `Some(Bytes::new())` — a
    /// real, empty body. [`crate::ValidityRule::BodyContains`] depends on the difference:
    /// searching a body that was never captured is a fact the rule cannot evaluate, not a body
    /// that happens to be empty.
    pub body: Option<Bytes>,
}

/// Sends one [`MacroStep`] and returns its [`MacroResponse`], or a transport-level error.
///
/// The `Err` case is a failure to communicate at all — connection refused, TLS handshake failure,
/// timeout — never a response that arrived but fails the operator's validity rule. Conflating the
/// two would make "the macro couldn't run" indistinguishable from "the macro ran and we're still
/// logged out", and [`crate::RecoveryOutcome`] depends on telling them apart.
pub trait MacroSender {
    fn send(&self, step: &MacroStep) -> Result<MacroResponse, String>;
}
