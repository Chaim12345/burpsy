//! The static UI: TypeScript source lives in `ui/src/`, bundled by Bun into a single `app.js` at
//! build time (see `build.rs`) and embedded here via `include_str!` — Bun is a build-time tool
//! only, so `cargo build` alone still produces one deployable binary. `index.html` and `style.css`
//! are embedded as-is; nothing about them needs bundling.

use crate::AppState;
use axum::Router;
use axum::http::header::CONTENT_TYPE;
use axum::response::{Html, IntoResponse};
use axum::routing::get;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const STYLE_CSS: &str = include_str!("../ui/style.css");
const APP_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/app.js"));

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/style.css", get(|| async { asset(STYLE_CSS, "text/css; charset=utf-8") }))
        .route("/app.js", get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }))
}

fn asset(body: &'static str, content_type: &'static str) -> impl IntoResponse {
    ([(CONTENT_TYPE, content_type)], body)
}

#[cfg(test)]
mod tests {
    use burpsy_core::TrafficStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve() -> String {
        let app = crate::router(TrafficStore::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn get(addr: &str, path: &str) -> (u16, Vec<(String, String)>, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes())
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

    #[tokio::test]
    async fn the_shell_and_bundle_are_served_with_the_right_content_types() {
        let addr = serve().await;

        let (status, headers, body) = get(&addr, "/").await;
        assert_eq!(status, 200);
        assert!(body.contains("<title>burpsy</title>"), "{body}");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "content-type" && v.starts_with("text/html")),
            "{headers:?}"
        );

        let (status, headers, body) = get(&addr, "/style.css").await;
        assert_eq!(status, 200);
        assert!(body.contains("--acc"), "{body}");
        assert!(
            headers.iter().any(|(k, v)| k == "content-type" && v.starts_with("text/css")),
            "{headers:?}"
        );

        let (status, headers, body) = get(&addr, "/app.js").await;
        assert_eq!(status, 200);
        assert!(!body.is_empty(), "the bundled app.js must not be empty");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "content-type" && v.starts_with("text/javascript")),
            "{headers:?}"
        );
    }
}
