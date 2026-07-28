//! burpsy-session — recorded-login re-authentication: bounded, collapsed, and honest about giving up.
//!
//! Phase 5's goal is one sentence: a recorded login survives session loss automatically, on the
//! operator's own terms for what "valid" means, without looping forever. Each clause is a module.
//!
//! # Why sending is a trait, not a call into `burpsy_sender`
//!
//! [`MacroSender`] exists in this crate for a reason with a name: HARD-03. Phase 1 built
//! `burpsy_sender::AuthorisedSender` as the one path from a constructed request to a socket, and a
//! login macro is a request-originating surface exactly like the crawler, plugins, or MCP — each
//! of HARD-03's remaining rows names one of them. This crate is not where that authorisation
//! wiring happens. It defines the re-login *policy* — record, replay order, cookie carry-over, the
//! operator's validity rule, the retry bound, collapsing concurrent observers — against a trait,
//! and a later slice in `cli`/`web` implements that trait once, over an `AuthorisedSender`, so the
//! one place a constructed request is allowed to reach a socket stays the one place. Every test
//! here runs against a fake that implements [`MacroSender`] and never had a path to a real socket
//! in the first place — see `step.rs` for the longer version of this argument.
//!
//! # What "valid" means is not this crate's call
//!
//! SESSION-02 hands session validity to the operator as a stated rule ([`ValidityRule`]), not a
//! heuristic here. A 200 with a login form, a 302 to `/login`, and a 200
//! `{"error":"unauthenticated"}` are all failed sessions that no fixed status-code check catches
//! uniformly; the operator says what "valid" looks like for their target, and
//! [`ValidityRule::evaluate`] is the only thing that reads a response and produces an answer —
//! `Valid`, `Invalid`, or, when the rule and the response disagree about what there is to check,
//! `Indeterminate`, which is never treated as `Valid`.
//!
//! # Bounded, and collapsed
//!
//! [`ReloginCoordinator`] is the other half: see its module docs for the two failure modes it
//! exists to prevent — an unbounded re-login loop against a live target, and N concurrent session
//! drops firing N logins instead of one.

mod cookie;
mod coordinator;
mod step;
mod validity;

pub use cookie::CookieJar;
pub use coordinator::{
    DEFAULT_MAX_LOGIN_ATTEMPTS, Macro, MacroStepFailure, RecoveryOutcome, ReloginCoordinator,
};
pub use step::{MacroResponse, MacroSender, MacroStep};
pub use validity::{SessionValidity, ValidityRule};
