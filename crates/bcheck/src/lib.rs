//! burpsy-bcheck — parser and evaluator for PortSwigger's BCheck DSL.
//!
//! # Why a DSL interpreter instead of hand-written checks
//!
//! Burp's scan checks are largely **data, not code**. Implementing one interpreter lets us inherit
//! PortSwigger's published corpus rather than porting hundreds of Java checks.
//!
//! Grammar established empirically against `BCheckChecker-1.9.jar` (PortSwigger's own CongoCC
//! parser, shipped in the BChecks repo) used as a conformance oracle. Four findings shaped this
//! implementation:
//!
//! 1. **v2-beta is a strict superset of v1-beta** — four added tokens, none removed. So one v2
//!    parser accepts 100% of the corpus, even though 78% of files declare v1-beta.
//! 2. **Whitespace and newlines are insignificant.** An entire check on one line parses. No offside
//!    rule, no INDENT/DEDENT — `end if` is the only block terminator.
//! 3. **There is no arithmetic.** `{{1337*1337}}` in the corpus is an SSTI payload inside a literal
//!    string, with the expected result hand-computed by the author. No expression evaluator exists.
//! 4. **Two string types**: `"…"` never interpolates, `` `…` `` does. Essential, because the
//!    80-file secret-scanner set relies on regexes like `"oy2[a-z0-9]{43}"` whose braces must not be
//!    read as interpolation.
//!
//! # Milestones
//!
//! * **M1 (this module set) — 33.3% of the corpus**: `given response`, `if`/`end if`,
//!   `report issue`, `in`/`is`/`matches`, booleans, `define`, `run for each`. No outbound traffic.
//! * M2 — 80.7%: interpolation into requests, `send request`, `given host`/`request`/`path`.
//! * M3 — 89.8%: insertion points, `send payload`. The remaining 10.2% needs Collaborator.

pub mod ast;
pub mod funcs;
pub mod eval;
pub mod lexer;
pub mod parser;

pub use ast::{
    BoolExpr, Check, CmpOp, Confidence, Frequency, IpType, Language, Metadata, ReportIssue,
    Severity, Statement, Value,
};
pub use eval::{Ctx, Finding, Unsupported, run_passive};
pub use parser::{ParseError, parse};
