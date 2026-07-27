//! burpsy-intruder — insertion-point discovery and payload attacks.
//!
//! # Design note
//!
//! Burp's insertion-point engine (`burp.Zuq`, 1479 lines) materialises every attack position as an
//! object (`Collection<Zb2q>`) and threads it through all seven check-dispatch scopes. With
//! `requests × insertion points × checks` unbounded, it must shed load — `Zq5.LIMIT_EXCEEDED`
//! exists for exactly that.
//!
//! Here an insertion point is a [`Span`] plus a kind: no allocation, pointing into bytes the store
//! already owns. Building every position for a request is therefore near-free, and a payload is
//! applied by splicing once at send time rather than by cloning the request per position per check.
//!
//! The taxonomy mirrors Burp's, recovered from its own method names
//! (`addUrlFilenameInsertionPoint`, `addUrlFoldersInsertionPoints`,
//! `addUrlAndBodyParameterInsertionPoints`, `addNewParameterNameInsertionPoint`, …) and
//! cross-checked against its config keys (`insert_url_params`, `insert_body_params`,
//! `insert_param_name`, `insert_cookies`, `insert_http_headers`, `insert_entire_body`,
//! `insert_url_path_filename`, `insert_url_path_folders`).
//!
//! # Layout
//!
//! * this module — insertion-point discovery and payload splicing;
//! * [`mod@plan`] — the four attack shapes, generated lazily from an ordinal;
//! * [`limit`] — the rate limiter and in-flight cap every send passes through;
//! * [`engine`] — the driver, and the bucketed result summary it produces.

pub mod engine;
pub mod limit;
pub mod plan;

pub use engine::{
    Attack, AttackReport, Attempt, ErrorBucket, Guard, RecordFn, ResultBucket, SendFn, SendFuture,
    Sent, run,
};
pub use limit::{RateLimit, RateLimiter};
pub use plan::{Assignment, AttackKind, AttackPlan, Slot, plan};

use burpsy_core::{Direction, Span, StoredMessage, parse};
use serde::{Deserialize, Serialize};

/// Where in a request a payload can be placed. Mirrors Burp's 8 configurable families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointKind {
    UrlParamValue,
    UrlParamName,
    UrlPathFolder,
    UrlPathFilename,
    BodyParamValue,
    BodyParamName,
    EntireBody,
    CookieValue,
    HeaderValue,
}

impl PointKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PointKind::UrlParamValue => "url_param_value",
            PointKind::UrlParamName => "url_param_name",
            PointKind::UrlPathFolder => "url_path_folder",
            PointKind::UrlPathFilename => "url_path_filename",
            PointKind::BodyParamValue => "body_param_value",
            PointKind::BodyParamName => "body_param_name",
            PointKind::EntireBody => "entire_body",
            PointKind::CookieValue => "cookie_value",
            PointKind::HeaderValue => "header_value",
        }
    }
}

/// An attack position: a span into the request plus what it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPoint {
    pub kind: PointKind,
    pub span: Span,
    /// Parameter or header name, for display. Small and bounded.
    pub label: String,
}

/// Which position families to generate. Maps 1:1 onto Burp's `insertion_point_types`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PointConfig {
    pub url_params: bool,
    pub param_names: bool,
    pub url_path_folders: bool,
    pub url_path_filename: bool,
    pub body_params: bool,
    pub entire_body: bool,
    pub cookies: bool,
    pub headers: bool,
}

impl Default for PointConfig {
    fn default() -> Self {
        // Burp's own defaults: parameter values on; names/paths/headers off, as they multiply cost.
        Self {
            url_params: true,
            param_names: false,
            url_path_folders: false,
            url_path_filename: false,
            body_params: true,
            entire_body: false,
            cookies: true,
            headers: false,
        }
    }
}

impl PointConfig {
    pub fn all() -> Self {
        Self {
            url_params: true,
            param_names: true,
            url_path_folders: true,
            url_path_filename: true,
            body_params: true,
            entire_body: true,
            cookies: true,
            headers: true,
        }
    }
}

/// Headers not worth attacking by default — they mostly produce noise.
const BORING_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "cookie",
];

/// Compute every insertion point for a stored request.
///
/// Allocation is limited to the returned `Vec` and small labels; no request bytes are copied.
pub fn find_points(msg: &StoredMessage, cfg: &PointConfig) -> Vec<InsertionPoint> {
    let mut out = Vec::new();
    let raw = &msg.raw;
    let target = msg.shape.second_token;
    let tend = target.end().min(raw.len());
    if target.offset >= tend {
        return out;
    }

    let tbytes = &raw[target.offset..tend];
    let qpos = tbytes.iter().position(|&b| b == b'?');
    let path_span = Span::new(target.offset, qpos.unwrap_or(tbytes.len()));

    if cfg.url_path_folders || cfg.url_path_filename {
        let segs: Vec<Span> = split_spans(raw, path_span, b'/')
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        for (i, s) in segs.iter().enumerate() {
            let last = i + 1 == segs.len();
            if last && cfg.url_path_filename {
                out.push(InsertionPoint {
                    kind: PointKind::UrlPathFilename,
                    span: *s,
                    label: text(raw, *s),
                });
            } else if !last && cfg.url_path_folders {
                out.push(InsertionPoint {
                    kind: PointKind::UrlPathFolder,
                    span: *s,
                    label: text(raw, *s),
                });
            }
        }
    }

    if let Some(q) = qpos
        && (cfg.url_params || cfg.param_names)
    {
        let qstart = target.offset + q + 1;
        let qspan = Span::new(qstart, tend.saturating_sub(qstart));
        push_kv_points(
            raw,
            qspan,
            cfg.url_params,
            cfg.param_names,
            PointKind::UrlParamValue,
            PointKind::UrlParamName,
            &mut out,
        );
    }

    if cfg.cookies {
        for h in &msg.shape.headers {
            if !name_eq(raw, h.name, b"cookie") {
                continue;
            }
            for pair in split_spans(raw, h.value, b';') {
                let t = trim(raw, pair);
                if t.is_empty() {
                    continue;
                }
                if let Some((name, value)) = split_once(raw, t, b'=') {
                    out.push(InsertionPoint {
                        kind: PointKind::CookieValue,
                        span: value,
                        label: text(raw, name),
                    });
                }
            }
        }
    }

    if cfg.headers {
        for h in &msg.shape.headers {
            let n = text(raw, h.name).to_ascii_lowercase();
            if BORING_HEADERS.contains(&n.as_str()) {
                continue;
            }
            out.push(InsertionPoint {
                kind: PointKind::HeaderValue,
                span: h.value,
                label: n,
            });
        }
    }

    let body = msg.shape.body;
    if !body.is_empty() {
        let is_form = msg
            .header("content-type")
            .map(|ct| {
                ct.len() >= 33
                    && ct
                        .windows(33)
                        .any(|w| w.eq_ignore_ascii_case(b"application/x-www-form-urlencoded"))
            })
            .unwrap_or(false);

        if is_form && (cfg.body_params || cfg.param_names) {
            push_kv_points(
                raw,
                body,
                cfg.body_params,
                cfg.param_names,
                PointKind::BodyParamValue,
                PointKind::BodyParamName,
                &mut out,
            );
        }
        if cfg.entire_body {
            out.push(InsertionPoint {
                kind: PointKind::EntireBody,
                span: body,
                label: "body".to_string(),
            });
        }
    }

    out
}

fn push_kv_points(
    raw: &[u8],
    region: Span,
    want_values: bool,
    want_names: bool,
    vkind: PointKind,
    nkind: PointKind,
    out: &mut Vec<InsertionPoint>,
) {
    for pair in split_spans(raw, region, b'&') {
        if pair.is_empty() {
            continue;
        }
        match split_once(raw, pair, b'=') {
            Some((name, value)) => {
                if want_values {
                    out.push(InsertionPoint {
                        kind: vkind,
                        span: value,
                        label: text(raw, name),
                    });
                }
                if want_names {
                    out.push(InsertionPoint {
                        kind: nkind,
                        span: name,
                        label: text(raw, name),
                    });
                }
            }
            None => {
                if want_names {
                    out.push(InsertionPoint {
                        kind: nkind,
                        span: pair,
                        label: text(raw, pair),
                    });
                }
            }
        }
    }
}

/// Splice `payload` into `raw` at `point`, producing the request to send.
///
/// The only place a request is copied, and it happens once per attempt — not once per insertion
/// point per check, which is where Burp's memory goes.
pub fn apply(raw: &[u8], point: &InsertionPoint, payload: &[u8]) -> Vec<u8> {
    apply_all(raw, &[(point, payload)])
}

/// Splice several payloads into one request in a single pass.
///
/// Pitchfork and cluster bomb fill *every* selected position in the same request, so the obvious
/// "call [`apply`] once per position" is wrong twice over: it copies the whole request N times, and
/// every splice invalidates the spans of the positions to its right — the second payload would land
/// at an offset computed against the pre-splice bytes and silently corrupt the request.
///
/// Overlapping positions are real input, not a hypothetical: `EntireBody` contains every
/// `BodyParamValue`, and a `UrlParamName` sits directly against its value. The rule is
/// **earliest-starting span wins, later overlapping spans are skipped**, so the output is always a
/// well-formed request and never a half-spliced one. Callers that care should reject overlapping
/// selections before getting here.
pub fn apply_all(raw: &[u8], places: &[(&InsertionPoint, &[u8])]) -> Vec<u8> {
    let mut spliced: Vec<(usize, usize, &[u8])> = places
        .iter()
        .map(|(p, payload)| {
            let start = p.span.offset.min(raw.len());
            let end = p.span.end().min(raw.len()).max(start);
            (start, end, *payload)
        })
        .collect();
    spliced.sort_by_key(|(start, end, _)| (*start, *end));

    let extra: usize = spliced.iter().map(|(_, _, p)| p.len()).sum();
    let mut out = Vec::with_capacity(raw.len() + extra);
    let mut cursor = 0usize;
    for (start, end, payload) in spliced {
        if start < cursor {
            continue;
        }
        out.extend_from_slice(&raw[cursor..start]);
        out.extend_from_slice(payload);
        cursor = end;
    }
    out.extend_from_slice(&raw[cursor..]);
    fix_content_length(&out)
}

/// Recompute `Content-Length` after splicing, else servers reject or hang.
fn fix_content_length(raw: &[u8]) -> Vec<u8> {
    let Ok(shape) = parse(raw, Direction::Request) else {
        return raw.to_vec();
    };
    let body_len = shape.body.len;
    let mut hdr: Option<Span> = None;
    for h in &shape.headers {
        if name_eq(raw, h.name, b"content-length") {
            hdr = Some(h.value);
            break;
        }
    }
    match hdr {
        None => raw.to_vec(),
        Some(v) => {
            let new = body_len.to_string();
            let mut out = Vec::with_capacity(raw.len() + 8);
            out.extend_from_slice(&raw[..v.offset.min(raw.len())]);
            out.extend_from_slice(new.as_bytes());
            out.extend_from_slice(&raw[v.end().min(raw.len())..]);
            out
        }
    }
}

// ---- span helpers ------------------------------------------------------------------------

fn split_spans(raw: &[u8], region: Span, sep: u8) -> Vec<Span> {
    let mut out = Vec::new();
    let end = region.end().min(raw.len());
    let mut start = region.offset.min(end);
    let mut i = start;
    while i < end {
        if raw[i] == sep {
            out.push(Span::new(start, i - start));
            start = i + 1;
        }
        i += 1;
    }
    out.push(Span::new(start, end.saturating_sub(start)));
    out
}

fn split_once(raw: &[u8], region: Span, sep: u8) -> Option<(Span, Span)> {
    let end = region.end().min(raw.len());
    let mut i = region.offset.min(end);
    while i < end {
        if raw[i] == sep {
            return Some((
                Span::new(region.offset, i - region.offset),
                Span::new(i + 1, end.saturating_sub(i + 1)),
            ));
        }
        i += 1;
    }
    None
}

fn trim(raw: &[u8], s: Span) -> Span {
    let end = s.end().min(raw.len());
    let mut a = s.offset.min(end);
    let mut b = end;
    while a < b && (raw[a] == b' ' || raw[a] == b'\t') {
        a += 1;
    }
    while b > a && (raw[b - 1] == b' ' || raw[b - 1] == b'\t') {
        b -= 1;
    }
    Span::new(a, b - a)
}

fn name_eq(raw: &[u8], s: Span, want: &[u8]) -> bool {
    let end = s.end().min(raw.len());
    let start = s.offset.min(end);
    let seg = &raw[start..end];
    seg.len() == want.len() && seg.eq_ignore_ascii_case(want)
}

fn text(raw: &[u8], s: Span) -> String {
    let end = s.end().min(raw.len());
    String::from_utf8_lossy(&raw[s.offset.min(end)..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::TrafficStore;
    use bytes::Bytes;

    fn store_req(raw: &'static [u8]) -> StoredMessage {
        let s = TrafficStore::new();
        let id = s.put(Bytes::from_static(raw), Direction::Request);
        s.get(id).unwrap()
    }

    #[test]
    fn finds_query_cookie_and_body_points() {
        let m = store_req(
            b"POST /app/login.php?next=/home&id=7 HTTP/1.1\r\nHost: t.test\r\nCookie: sid=abc; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 23\r\n\r\nuser=admin&pass=hunter2",
        );
        let pts = find_points(&m, &PointConfig::default());
        let k: Vec<_> = pts.iter().map(|p| (p.kind, p.label.clone())).collect();
        assert!(k.contains(&(PointKind::UrlParamValue, "next".into())));
        assert!(k.contains(&(PointKind::UrlParamValue, "id".into())));
        assert!(k.contains(&(PointKind::CookieValue, "sid".into())));
        assert!(k.contains(&(PointKind::CookieValue, "theme".into())));
        assert!(k.contains(&(PointKind::BodyParamValue, "user".into())));
        assert!(k.contains(&(PointKind::BodyParamValue, "pass".into())));
    }

    #[test]
    fn all_config_adds_paths_names_headers() {
        let m = store_req(b"GET /a/b/c.php?x=1 HTTP/1.1\r\nHost: t.test\r\nUser-Agent: ua\r\n\r\n");
        let pts = find_points(&m, &PointConfig::all());
        let ks: Vec<_> = pts.iter().map(|p| p.kind).collect();
        assert!(ks.contains(&PointKind::UrlPathFolder));
        assert!(ks.contains(&PointKind::UrlPathFilename));
        assert!(ks.contains(&PointKind::UrlParamName));
        assert!(ks.contains(&PointKind::HeaderValue));
        assert!(
            !pts.iter()
                .any(|p| p.kind == PointKind::HeaderValue && p.label == "host")
        );
    }

    #[test]
    fn apply_splices_and_fixes_content_length() {
        let m = store_req(
            b"POST / HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2",
        );
        let pts = find_points(&m, &PointConfig::default());
        let p = pts.iter().find(|p| p.label == "a").unwrap();
        let out = apply(&m.raw, p, b"XXXXXXXXXX");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("a=XXXXXXXXXX&b=2"), "spliced: {s}");
        assert!(s.contains("Content-Length: 16"), "cl not fixed: {s}");
    }

    #[test]
    fn apply_all_fills_several_positions_in_one_request() {
        let m = store_req(b"GET /?user=aaa&role=bbb HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let pts = find_points(&m, &PointConfig::default());
        let user = pts.iter().find(|p| p.label == "user").unwrap();
        let role = pts.iter().find(|p| p.label == "role").unwrap();
        // Longest payload first, so a naive left-to-right splice would shift the second one.
        let out = apply_all(&m.raw, &[(user, b"LONGPAYLOAD"), (role, b"x")]);
        assert_eq!(
            String::from_utf8_lossy(&out).lines().next().unwrap(),
            "GET /?user=LONGPAYLOAD&role=x HTTP/1.1"
        );
    }

    #[test]
    fn apply_all_is_order_independent() {
        let m = store_req(b"GET /?a=1&b=2&c=3 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let pts = find_points(&m, &PointConfig::default());
        let (a, b, c) = (
            pts.iter().find(|p| p.label == "a").unwrap(),
            pts.iter().find(|p| p.label == "b").unwrap(),
            pts.iter().find(|p| p.label == "c").unwrap(),
        );
        let forward = apply_all(&m.raw, &[(a, b"AA"), (b, b"BB"), (c, b"CC")]);
        let reverse = apply_all(&m.raw, &[(c, b"CC"), (b, b"BB"), (a, b"AA")]);
        assert_eq!(forward, reverse);
        assert!(String::from_utf8_lossy(&forward).contains("?a=AA&b=BB&c=CC"));
    }

    #[test]
    fn overlapping_positions_yield_a_valid_request_not_a_corrupt_one() {
        // `entire_body` contains both body params, so all three overlap.
        let m = store_req(
            b"POST / HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2",
        );
        let pts = find_points(&m, &PointConfig::all());
        let body = pts
            .iter()
            .find(|p| p.kind == PointKind::EntireBody)
            .unwrap();
        let a = pts
            .iter()
            .find(|p| p.kind == PointKind::BodyParamValue && p.label == "a")
            .unwrap();
        let out = apply_all(&m.raw, &[(body, b"WHOLE"), (a, b"IGNORED")]);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.ends_with("\r\n\r\nWHOLE"),
            "body should be replaced once: {s}"
        );
        assert!(
            !s.contains("IGNORED"),
            "the overlapping later span must be skipped: {s}"
        );
        assert!(
            s.contains("Content-Length: 5"),
            "and framing must still be right: {s}"
        );
    }
}
