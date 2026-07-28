//! Route modules, one per feature area.
//!
//! # Why the API is split this way
//!
//! Every new tool wants to add endpoints, and a single `lib.rs` route table makes that a serialised
//! edit — two features landing at once collide on the same lines. Each area therefore owns a file
//! and exports `routes()`, and `lib.rs` merges them. Adding a tool means adding a file, not editing
//! a shared one.

use crate::AppState;
use axum::Router;

pub mod intercept;
pub mod report;
pub mod session;
pub mod sitemap;
pub mod tools;

/// Every feature router, merged.
pub fn all() -> Router<AppState> {
    Router::new()
        .merge(sitemap::routes())
        .merge(intercept::routes())
        .merge(tools::routes())
        .merge(report::routes())
        .merge(session::routes())
}
