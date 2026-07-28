//! Report downloads: `GET /api/report/{format}` for `html`, `json` and `sarif`.
//!
//! # Why this is a closure and not a scanner handle
//!
//! `burpsy-web` must not depend on `burpsy-scanner`. The dependency edge runs the other way round the
//! graph (`scanner → proxy → web`), and the crate boundary is a statement about what a component may
//! reach: a web layer that can call into the audit engine can start an audit, and active scanning is
//! operator-triggered by design.
//!
//! So this area takes an [`ExportHook`] — "given a format, hand me some bytes" — exactly as
//! [`crate::AuditHook`] does for `POST /api/audit/{id}`. The binary owns the wiring, which is the only
//! place that legitimately knows about both halves. Nothing about the report's *content* is decided
//! here; that lives in `burpsy_scanner::report`.
//!
//! # No hook means 501, never an empty report
//!
//! Reporting needs a loaded check set. Without one, this returns `501 Not Implemented` with the reason
//! and the flag that fixes it. It does **not** return a report with zeroes in it: a document claiming
//! a corpus of 0 files and no findings is indistinguishable from a clean scan, and manufacturing one
//! is the failure the whole reporting phase exists to prevent.
//!
//! # An unknown format is refused, not guessed
//!
//! `GET /api/report/pdf` is a `400`, listing what is supported. Falling back to a default format
//! would hand a caller who asked for one thing the bytes of another, and `Content-Type` alone is a
//! thin place to discover that.

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;

/// Which serialisation the caller asked for.
///
/// Plain data owned by this crate, so the hook's signature carries no scanner type and the crate
/// boundary above stays a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// A self-contained page for a human reader.
    Html,
    /// The versioned machine-readable export.
    Json,
    /// SARIF 2.1.0, for a code-scanning consumer.
    Sarif,
}

impl ExportFormat {
    /// Every format, in the order the error message lists them.
    pub const ALL: [ExportFormat; 3] = [ExportFormat::Html, ExportFormat::Json, ExportFormat::Sarif];

    /// Parse a path segment. `None` is refused by the caller rather than defaulted.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "html" => Some(ExportFormat::Html),
            "json" => Some(ExportFormat::Json),
            "sarif" => Some(ExportFormat::Sarif),
            _ => None,
        }
    }

    pub fn id(&self) -> &'static str {
        match self {
            ExportFormat::Html => "html",
            ExportFormat::Json => "json",
            ExportFormat::Sarif => "sarif",
        }
    }

    /// The `Content-Type` the response carries.
    ///
    /// SARIF's registered type is `application/sarif+json`, and it is worth using rather than plain
    /// `application/json`: a CI step that picks files up by media type would otherwise treat a SARIF
    /// document and the burpsy JSON export as the same thing.
    pub fn mime(&self) -> &'static str {
        match self {
            ExportFormat::Html => "text/html; charset=utf-8",
            ExportFormat::Json => "application/json",
            ExportFormat::Sarif => "application/sarif+json",
        }
    }

    /// Download filename extension.
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Html => "html",
            ExportFormat::Json => "json",
            ExportFormat::Sarif => "sarif",
        }
    }
}

/// Rendered bytes plus the format they are in, so a hook cannot return HTML labelled as SARIF.
#[derive(Debug, Clone)]
pub struct Export {
    pub format: ExportFormat,
    pub bytes: Vec<u8>,
}

/// Renders a report in one format. Blocking — the handler offloads it.
pub type ExportHook = Arc<dyn Fn(ExportFormat) -> Result<Export, String> + Send + Sync>;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/report/{format}", get(export))
}

/// Offloaded for the same reason `run_audit` is: rendering walks the whole finding store and every
/// retained audit outcome under a lock, and a runtime worker stalled there stalls every other
/// request.
async fn export(State(s): State<AppState>, Path(format): Path<String>) -> impl IntoResponse {
    let Some(fmt) = ExportFormat::parse(&format) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown report format {format:?}"),
                "supported": ExportFormat::ALL.map(|f| f.id()),
            })),
        )
            .into_response();
    };
    let Some(hook) = s.export.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "reporting is not configured",
                "reason": "a report states what was and was not checked, which needs a loaded \
                           check set; start with --bchecks",
            })),
        )
            .into_response();
    };

    match tokio::task::spawn_blocking(move || hook(fmt)).await {
        Ok(Ok(e)) => {
            if e.format != fmt {
                // A hook returning the wrong format would serve, say, HTML under
                // `application/sarif+json`. Refused rather than relabelled: guessing which of the
                // two is right is exactly the sort of quiet correction that produces a report
                // nobody can reproduce.
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "report writer returned the wrong format",
                        "requested": fmt.id(),
                        "returned": e.format.id(),
                    })),
                )
                    .into_response();
            }
            (
                [
                    (header::CONTENT_TYPE, fmt.mime().to_owned()),
                    (
                        header::CONTENT_DISPOSITION,
                        // Built from a constant and a format id, never from request input.
                        format!(
                            "attachment; filename=\"burpsy-report.{}\"",
                            fmt.extension()
                        ),
                    ),
                ],
                e.bytes,
            )
                .into_response()
        }
        Ok(Err(why)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": why })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("report task failed: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use burpsy_core::{Scope, TrafficStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A real listener and a hand-written HTTP/1.1 client, matching the convention in `tools.rs` and
    /// `lib.rs`: the tests need no extra dependency, and they exercise the same header handling a
    /// browser download will.
    async fn serve(export: Option<ExportHook>) -> String {
        let app = routes().with_state(AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: Arc::new(Scope::allow_everything()),
            findings: None,
            audit: None,
            export,
            intercept: None,
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    /// `(status, lowercased headers, body)`.
    async fn get(addr: &str, path: &str) -> (u16, Vec<(String, String)>, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
            .collect();
        (status, headers, body.to_owned())
    }

    fn hook_returning(body: &'static str) -> ExportHook {
        Arc::new(move |fmt| {
            Ok(Export {
                format: fmt,
                bytes: format!("{body}:{}", fmt.id()).into_bytes(),
            })
        })
    }

    #[tokio::test]
    async fn each_format_is_served_with_its_own_media_type_and_a_download_filename() {
        let addr = serve(Some(hook_returning("report"))).await;
        for (fmt, mime) in [
            ("html", "text/html; charset=utf-8"),
            ("json", "application/json"),
            ("sarif", "application/sarif+json"),
        ] {
            let (status, headers, body) = get(&addr, &format!("/api/report/{fmt}")).await;
            assert_eq!(status, 200, "{fmt}: {body}");
            assert!(
                headers.contains(&("content-type".to_owned(), mime.to_owned())),
                "{fmt} must be served as {mime}: {headers:?}"
            );
            assert!(
                headers.iter().any(|(k, v)| k == "content-disposition"
                    && v == &format!("attachment; filename=\"burpsy-report.{fmt}\"")),
                "{fmt} must download rather than render inline: {headers:?}"
            );
            assert_eq!(body, format!("report:{fmt}"));
        }
    }

    #[tokio::test]
    async fn an_unknown_format_is_refused_and_the_supported_set_is_named() {
        let addr = serve(Some(hook_returning("report"))).await;
        let (status, _, body) = get(&addr, "/api/report/pdf").await;
        assert_eq!(status, 400);
        assert!(body.contains("unknown report format"), "{body}");
        for f in ["html", "json", "sarif"] {
            assert!(body.contains(f), "the error must list {f}: {body}");
        }
    }

    #[tokio::test]
    async fn without_a_configured_hook_the_endpoint_refuses_rather_than_serving_an_empty_report() {
        let addr = serve(None).await;
        let (status, _, body) = get(&addr, "/api/report/json").await;
        assert_eq!(status, 501, "{body}");
        assert!(
            body.contains("--bchecks"),
            "the error must name the flag that fixes it: {body}"
        );
        assert!(
            !body.contains("findings"),
            "an empty report body would be indistinguishable from a clean scan: {body}"
        );
    }

    #[tokio::test]
    async fn a_writer_error_is_surfaced_rather_than_served_as_a_truncated_report() {
        let hook: ExportHook = Arc::new(|_| Err("finding store lock poisoned".to_owned()));
        let addr = serve(Some(hook)).await;
        let (status, _, body) = get(&addr, "/api/report/html").await;
        assert_eq!(status, 500);
        assert!(body.contains("finding store lock poisoned"), "{body}");
    }

    #[tokio::test]
    async fn a_hook_returning_the_wrong_format_is_refused_rather_than_relabelled() {
        let hook: ExportHook = Arc::new(|_| {
            Ok(Export {
                format: ExportFormat::Html,
                bytes: b"<!doctype html>".to_vec(),
            })
        });
        let addr = serve(Some(hook)).await;
        let (status, _, body) = get(&addr, "/api/report/sarif").await;
        assert_eq!(status, 500);
        assert!(body.contains("wrong format"), "{body}");
        assert!(body.contains("\"requested\":\"sarif\""), "{body}");
        assert!(body.contains("\"returned\":\"html\""), "{body}");
    }
}
