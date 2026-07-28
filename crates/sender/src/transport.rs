//! The private transports. Both are `pub(crate)`: reaching a socket means going through
//! [`crate::AuthorisedSender`], which checks scope first.
//!
//! There are two implementations rather than one because the two callers genuinely differ, not
//! because the design drifted. The BCheck evaluator is deliberately synchronous and recursive — see
//! [`blocking::NetSender`]'s own notes — and making it async would force `Box::pin` through every
//! `exec`/`eval_bool` for no benefit. Repeater and Intruder are already inside a tokio runtime.
//! HARD-03 asks for one authorising *type*, meaning one place the scope decision is made and one
//! way out to the network; it does not ask for one wire implementation underneath that.

pub(crate) mod blocking;
pub(crate) mod net;
pub(crate) mod tls;
