//! Decoder, Comparer, Logger, Organizer, match-and-replace.

use crate::AppState;
use axum::Router;

pub fn routes() -> Router<AppState> {
    Router::new()
}
