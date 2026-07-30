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
use std::sync::Arc;

pub mod intercept;
pub mod liveaudit;
pub mod report;
pub mod sequencer;
pub mod session;
pub mod sitemap;
pub mod tools;
pub mod websockets;

/// Every feature router, merged.
///
/// `tool_state` is threaded in rather than defaulted here, unlike every other area's routes, so
/// the binary can hold the same `ToolState` (and so the same `ToolLog`) that `AppState::tool_log`
/// points at — see `tools::ToolState`'s own docs on why the log has to be shared.
pub fn all(tool_state: Arc<tools::ToolState>) -> Router<AppState> {
    Router::new()
        .merge(sitemap::routes())
        .merge(intercept::routes())
        .merge(tools::routes_with(tool_state))
        .merge(report::routes())
        .merge(session::routes())
        .merge(liveaudit::routes())
        .merge(sequencer::routes())
        .merge(websockets::routes())
}
