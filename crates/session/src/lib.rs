//! burpsy-session — recorded-login re-authentication: scoped per target, bounded, collapsed, and
//! honest about giving up.
//!
//! Phase 5's goal is one sentence: a recorded login survives session loss automatically, on the
//! operator's own terms for what "valid" means, without looping forever. Each clause is a module.
//!
//! # Session handling is a rule *list*, not one always-on macro
//!
//! A real engagement has more than one login: an admin account and a user account, a staging host
//! whose form differs from production, an API subdomain that authenticates with a bearer token
//! instead of a cookie. "Which login applies here" is a property of the target, so
//! [`ReloginCoordinator`] holds an ordered list of [`SessionRule`]s, each with its own name, its own
//! optional [`burpsy_core::Scope`], its own macro, its own [`ValidityRule`] and its own retry bound.
//! The first enabled rule whose scope covers a request handles it; a request no rule covers is
//! reported as [`RecoveryOutcome::NoRuleApplies`] rather than quietly logged into with somebody
//! else's credentials. See `rule.rs` for why a per-rule scope is a *selector* and never an
//! authorisation, and `coordinator.rs` for what the list changes about single-flighting.
//!
//! # A macro can carry values forward, not just cookies
//!
//! [`CookieJar`] carries `Set-Cookie` state between steps, which covers session cookies and nothing
//! else. The other half of a real login flow is a value the application expects echoed back — a CSRF
//! token in a hidden field, a `state` parameter, a bearer token in a JSON body. [`Extraction`] names
//! one such value out of a step's response (by regex capture group, by dotted JSON path, or as a
//! whole header), and a later step writes `{{name}}` wherever it needs it. See `extract.rs` for why
//! that substitution is deliberately not a template language.
//!
//! # Why sending is a trait, not a call into `burpsy_sender`
//!
//! [`MacroSender`] exists in this crate for a reason with a name: HARD-03. Phase 1 built
//! `burpsy_sender::AuthorisedSender` as the one path from a constructed request to a socket, and a
//! login macro is a request-originating surface exactly like the crawler, plugins, or MCP — each
//! of HARD-03's remaining rows names one of them. This crate is not where that authorisation
//! wiring happens. It defines the re-login *policy* — record, replay order, cookie carry-over,
//! parameter extraction, the operator's validity rule, the retry bound, collapsing concurrent
//! observers — against a trait, and a later slice in `cli`/`web` implements that trait once, over an
//! `AuthorisedSender`, so the one place a constructed request is allowed to reach a socket stays the
//! one place. Every test here runs against a fake that implements [`MacroSender`] and never had a
//! path to a real socket in the first place — see `step.rs` for the longer version of this argument.
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
//! # Bounded, collapsed, and repairable
//!
//! [`ReloginCoordinator`] is the other half: see its module docs for the failure modes it exists to
//! prevent — an unbounded re-login loop against a live target, N concurrent session drops firing N
//! logins instead of one, and guessing which login a target belongs to.
//! [`ReloginCoordinator::update_macro`] is the repair: a login flow drifts, and the run that just
//! worked is a better recording than the one an operator made weeks ago.

mod cookie;
mod coordinator;
mod extract;
mod rule;
mod step;
mod target;
mod validity;

pub use cookie::CookieJar;
pub use coordinator::{
    MacroStepFailure, RecoveryOutcome, ReloginCoordinator, UpdateMacroOutcome,
};
pub use extract::{ExtractFrom, ExtractHow, Extraction};
pub use rule::{
    DEFAULT_MAX_LOGIN_ATTEMPTS, Macro, MacroItem, RuleError, SessionRule, SessionRuleSpec,
};
pub use step::{MacroResponse, MacroSender, MacroStep};
pub use validity::{SessionValidity, ValidityRule};
