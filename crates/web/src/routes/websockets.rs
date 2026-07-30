//! WebSocket history: the messages captured off upgraded connections.
//!
//! # Why this is its own area and not part of `/api/history`
//!
//! Burp's WebSockets history is a parallel surface to its HTTP history, and the reason is structural
//! rather than cosmetic: an HTTP row is a request/response *pair* keyed by an exchange, while a
//! WebSocket row is a single one-way message keyed by the connection it belongs to. Squeezing the
//! second into the first's shape means either a `direction` column that is meaningless for half the
//! rows or a fake status. So the two have separate endpoints, and the connection is the join between
//! them: every message names the `Exchange` whose `101` opened it, and that exchange is in
//! `/api/history` with its handshake headers intact.
//!
//! # Rows first, payloads on demand
//!
//! The same rule the HTTP history endpoint follows, for the same reason. `/api/ws/history` returns
//! index rows — direction, opcode, length, timestamp — and never reads a payload, so listing a
//! socket that has carried a hundred thousand messages touches no message bytes.
//! `/api/ws/message/{id}` fetches one.
//!
//! # `truncated` is a first-class field, not a footnote
//!
//! Capture bounds each message at [`burpsy_core::ws::DEFAULT_MAX_MESSAGE_BYTES`] and records the
//! shortfall. A row whose `dropped` is non-zero is a *partial* view, and this API says `truncated:
//! true` and reports both numbers rather than presenting `len` as the message size. Showing a 4 MiB
//! message as 1 MiB with no comment is the kind of quiet lie this project treats as a defect.

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use burpsy_core::{Direction, WsMessage};
use serde::{Deserialize, Serialize};

/// Rows per page. Matches `/api/history`'s cap: the browser is what falls over first.
const MAX_LIMIT: usize = 2000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ws/history", get(history))
        .route("/api/ws/message/{id}", get(message))
        .route("/api/ws/connections", get(connections))
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
    /// Restrict to one connection, identified by its handshake exchange id.
    exchange: Option<u64>,
}

fn default_limit() -> usize {
    300
}

/// One message as the UI lists it. Index data only — no payload is read to build this.
#[derive(Serialize)]
struct RowView {
    id: u64,
    /// The handshake exchange. Follow it into `/api/history` for host, path and the 101 headers.
    exchange: u64,
    /// The payload's id in the message store, for `/api/ws/message/{id}` or any HTTP-side tool.
    payload: u64,
    /// `client_to_server` or `server_to_client`. Spelled out rather than a bool, because "which way"
    /// is the column an operator reads first and `false` does not answer it.
    direction: &'static str,
    opcode: String,
    /// Payload bytes kept.
    len: usize,
    /// Declared bytes not kept. Non-zero exactly when `truncated`.
    dropped: u64,
    truncated: bool,
    fragments: u32,
    at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Request => "client_to_server",
        Direction::Response => "server_to_client",
    }
}

impl From<&WsMessage> for RowView {
    fn from(m: &WsMessage) -> Self {
        Self {
            id: m.id,
            exchange: m.exchange,
            payload: m.payload.0,
            direction: direction_name(m.direction),
            opcode: m.opcode.name(),
            len: m.len,
            dropped: m.dropped,
            truncated: m.dropped > 0,
            fragments: m.fragments,
            at_ms: m.at_ms,
            note: m.note.clone(),
        }
    }
}

#[derive(Serialize)]
struct HistoryResp {
    /// Messages captured in total, so the UI can page without asking separately.
    total: usize,
    rows: Vec<RowView>,
}

/// `GET /api/ws/history` — newest-first page of captured messages.
async fn history(State(s): State<AppState>, Query(q): Query<HistoryQuery>) -> impl IntoResponse {
    let limit = q.limit.min(MAX_LIMIT);
    let rows = match q.exchange {
        Some(ex) => s.store.ws_messages_for(ex, q.offset, limit),
        None => s.store.ws_messages(q.offset, limit),
    };
    Json(HistoryResp {
        total: s.store.ws_count(),
        rows: rows.iter().map(RowView::from).collect(),
    })
}

/// One message with its payload, rendered both ways so the caller does not have to guess.
#[derive(Serialize)]
struct MessageResp {
    #[serde(flatten)]
    row: RowView,
    /// Lossy UTF-8. Correct for a text frame, and for a binary one it is what a hex view is for —
    /// which is why `hex` is here too rather than instead.
    text: String,
    /// Lowercase hex of the same bytes. The honest rendering for a binary frame.
    hex: String,
    /// A close frame's status code and reason, decoded. Absent for every other opcode, and for a
    /// close frame that carried no code — RFC 6455 permits an empty close payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    close: Option<CloseView>,
}

#[derive(Serialize)]
struct CloseView {
    code: u16,
    reason: String,
}

/// `GET /api/ws/message/{id}` — one message's payload.
async fn message(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(row) = s.store.ws_message(id) else {
        return (StatusCode::NOT_FOUND, format!("no ws message {id}")).into_response();
    };
    let Some(stored) = s.store.get(row.payload) else {
        // The index says this payload exists and the store disagrees. Reported rather than shown as
        // an empty message, which would be indistinguishable from a genuinely empty frame.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "ws message {id} points at payload {} which the store cannot resolve",
                row.payload.0
            ),
        )
            .into_response();
    };
    let bytes = stored.raw;
    Json(MessageResp {
        close: (row.opcode == burpsy_core::WsOpcode::Close)
            .then(|| burpsy_proxy::ws::close_status(&bytes))
            .flatten()
            .map(|(code, reason)| CloseView { code, reason }),
        text: String::from_utf8_lossy(&bytes).into_owned(),
        hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        row: RowView::from(&row),
    })
    .into_response()
}

/// One upgraded connection, folded from the message index.
#[derive(Serialize)]
struct ConnectionView {
    exchange: u64,
    host: String,
    port: u16,
    tls: bool,
    path: String,
    messages: usize,
    sent: usize,
    received: usize,
    /// Milliseconds of the newest message on this connection, so the list can be sorted by activity.
    last_ms: u64,
}

/// `GET /api/ws/connections` — the sockets that carried traffic, newest activity first.
///
/// A fold over the index rather than a second stored structure. Two copies of "which connections
/// exist" could disagree; one derived view cannot, and the fold is over fixed-size rows.
async fn connections(State(s): State<AppState>) -> impl IntoResponse {
    // Every row, deliberately: this is a fold over the whole index, and paging it would produce a
    // connection list that depends on which page happened to be asked for.
    let rows = s.store.ws_messages(0, usize::MAX);
    let mut out: Vec<ConnectionView> = Vec::new();
    for m in &rows {
        match out.iter_mut().find(|c| c.exchange == m.exchange) {
            Some(c) => {
                c.messages += 1;
                match m.direction {
                    Direction::Request => c.sent += 1,
                    Direction::Response => c.received += 1,
                }
                c.last_ms = c.last_ms.max(m.at_ms);
            }
            None => {
                let ex = s.store.exchange(m.exchange);
                out.push(ConnectionView {
                    exchange: m.exchange,
                    host: ex.as_ref().map(|e| e.host.clone()).unwrap_or_default(),
                    port: ex.as_ref().map(|e| e.port).unwrap_or(0),
                    tls: ex.as_ref().is_some_and(|e| e.tls),
                    path: ex.as_ref().map(|e| e.path.clone()).unwrap_or_default(),
                    messages: 1,
                    sent: usize::from(m.direction == Direction::Request),
                    received: usize::from(m.direction == Direction::Response),
                    last_ms: m.at_ms,
                });
            }
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.last_ms));
    Json(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Exchange, TrafficStore, WsOpcode, ws::WsMessage};
    use bytes::Bytes;
    use std::sync::Arc;

    /// A store holding one upgraded connection and the messages given.
    fn store_with(msgs: &[(Direction, WsOpcode, &[u8], u64)]) -> Arc<TrafficStore> {
        let store = TrafficStore::new();
        let req = store.put(
            Bytes::from_static(b"GET /chat HTTP/1.1\r\nHost: t.test\r\nUpgrade: websocket\r\n\r\n"),
            Direction::Request,
        );
        let ex = store.add_exchange(Exchange {
            request: req,
            host: "t.test".into(),
            port: 8443,
            tls: true,
            method: "GET".into(),
            path: "/chat".into(),
            status: Some(101),
            ..Default::default()
        });
        for (i, (direction, opcode, payload, dropped)) in msgs.iter().enumerate() {
            let id = store.put(Bytes::copy_from_slice(payload), *direction);
            store.add_ws_message(WsMessage {
                id: 0,
                exchange: ex,
                payload: id,
                direction: *direction,
                opcode: *opcode,
                len: payload.len(),
                dropped: *dropped,
                fragments: 1,
                at_ms: 1000 + i as u64,
                note: None,
            });
        }
        store
    }

    fn state(store: Arc<TrafficStore>) -> AppState {
        AppState {
            store,
            ca_pem: None,
            scope: burpsy_core::SharedScope::allow_everything(),
            findings: None,
            audit: None,
            export: None,
            intercept: None,
            session: None,
            tool_log: None,
            live_audit: None,
        }
    }

    fn json(v: impl Serialize) -> serde_json::Value {
        serde_json::to_value(v).unwrap()
    }

    /// Read a handler's response as JSON. Every test below goes through the real `IntoResponse`
    /// path rather than inspecting a view struct, so a serialisation change cannot pass silently.
    async fn body_json(r: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(r.into_body(), 1024 * 1024)
            .await
            .expect("the handler's body");
        serde_json::from_slice(&bytes).expect("the handler emits JSON")
    }

    /// WS-01: the listing carries direction, opcode and length per row, newest first, and reports
    /// the whole index's size alongside the page.
    #[tokio::test]
    async fn the_listing_reports_direction_opcode_and_length_newest_first() {
        let store = store_with(&[
            (Direction::Request, WsOpcode::Text, b"hello", 0),
            (Direction::Response, WsOpcode::Binary, b"\x00\xff", 0),
        ]);
        let v = body_json(
            history(
                State(state(store)),
                Query(HistoryQuery {
                    offset: 0,
                    limit: 300,
                    exchange: None,
                }),
            )
            .await
            .into_response(),
        )
        .await;

        assert_eq!(v["total"], 2);
        let rows = v["rows"].as_array().expect("rows is an array");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0]["id"], 1,
            "newest first, matching /api/history: {v}"
        );
        assert_eq!(rows[0]["direction"], "server_to_client");
        assert_eq!(rows[0]["opcode"], "binary");
        assert_eq!(rows[0]["len"], 2);
        assert_eq!(rows[0]["truncated"], false);
        assert_eq!(rows[1]["direction"], "client_to_server");
        assert_eq!(rows[1]["opcode"], "text");
        assert!(
            rows[0].get("text").is_none() && rows[0].get("hex").is_none(),
            "a listing row must carry no payload — that is the whole point of it: {v}"
        );
    }

    /// WS-01: a truncated row says so, and reports both numbers.
    #[test]
    fn a_truncated_row_is_flagged_and_reports_what_it_lost() {
        let store = store_with(&[(Direction::Response, WsOpcode::Binary, b"kept", 900)]);
        let row = store.ws_message(0).unwrap();
        let view = json(RowView::from(&row));
        assert_eq!(view["truncated"], true);
        assert_eq!(view["len"], 4);
        assert_eq!(view["dropped"], 900);
    }

    /// WS-01: direction is a word, because `false` does not answer "which way did this go".
    #[test]
    fn direction_is_named_rather_than_encoded_as_a_bool() {
        assert_eq!(direction_name(Direction::Request), "client_to_server");
        assert_eq!(direction_name(Direction::Response), "server_to_client");
    }

    /// WS-01: fetching one message renders it both as text and as hex, and decodes a close frame's
    /// status code rather than showing its two bytes as characters.
    #[tokio::test]
    async fn a_close_frame_reports_its_status_code_as_a_number() {
        let store = store_with(&[(Direction::Response, WsOpcode::Close, b"\x03\xe9gone", 0)]);
        let out = message(State(state(store)), Path(0)).await.into_response();
        assert_eq!(out.status(), StatusCode::OK);
        let v = body_json(out).await;
        assert_eq!(v["close"]["code"], 1001);
        assert_eq!(v["close"]["reason"], "gone");
        assert_eq!(v["hex"], "03e9676f6e65");
        assert_eq!(v["opcode"], "close");
    }

    /// WS-01: an unknown id is a 404, not an empty message — the two mean different things.
    #[tokio::test]
    async fn an_unknown_message_id_is_a_404() {
        let store = store_with(&[]);
        let out = message(State(state(store)), Path(7)).await.into_response();
        assert_eq!(out.status(), StatusCode::NOT_FOUND);
    }

    /// WS-01: the connection list folds the index and joins each socket to its handshake.
    #[tokio::test]
    async fn the_connection_list_counts_each_direction_and_names_the_host() {
        let store = store_with(&[
            (Direction::Request, WsOpcode::Text, b"a", 0),
            (Direction::Response, WsOpcode::Text, b"b", 0),
            (Direction::Response, WsOpcode::Text, b"c", 0),
        ]);
        let v = body_json(connections(State(state(store))).await.into_response()).await;
        assert_eq!(v.as_array().unwrap().len(), 1, "one connection: {v}");
        assert_eq!(v[0]["host"], "t.test");
        assert_eq!(v[0]["port"], 8443);
        assert_eq!(v[0]["path"], "/chat");
        assert_eq!(v[0]["tls"], true);
        assert_eq!((v[0]["sent"].as_u64(), v[0]["received"].as_u64()), (Some(1), Some(2)));
        assert_eq!(v[0]["messages"], 3);
    }

    /// WS-01: filtering by connection returns only that connection's messages.
    #[tokio::test]
    async fn filtering_by_connection_excludes_every_other_socket() {
        let store = store_with(&[(Direction::Request, WsOpcode::Text, b"mine", 0)]);
        // A second connection with its own message.
        let other_req = store.put(Bytes::from_static(b"GET /other HTTP/1.1\r\n\r\n"), Direction::Request);
        let other = store.add_exchange(Exchange {
            request: other_req,
            host: "other.test".into(),
            path: "/other".into(),
            ..Default::default()
        });
        let p = store.put(Bytes::from_static(b"theirs"), Direction::Response);
        store.add_ws_message(WsMessage {
            id: 0,
            exchange: other,
            payload: p,
            direction: Direction::Response,
            opcode: WsOpcode::Text,
            len: 6,
            dropped: 0,
            fragments: 1,
            at_ms: 2000,
            note: None,
        });

        let out = history(
            State(state(store.clone())),
            Query(HistoryQuery {
                offset: 0,
                limit: 300,
                exchange: Some(other),
            }),
        )
        .await
        .into_response();
        let v = body_json(out).await;
        assert_eq!(v["total"], 2, "the total is the whole index, not the page");
        assert_eq!(v["rows"].as_array().unwrap().len(), 1);
        assert_eq!(v["rows"][0]["exchange"], other);
        assert_eq!(v["rows"][0]["direction"], "server_to_client");
    }
}
