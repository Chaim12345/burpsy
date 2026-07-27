//! Request interception: hold, edit, forward, drop.

use crate::AppState;
use axum::Router;

/// Shared state for held requests. Owned here rather than in `AppState` so the interception
/// feature can evolve its own storage without touching the shared struct.
#[derive(Debug, Default)]
pub struct InterceptState {}

pub fn routes() -> Router<AppState> {
    Router::new()
}
