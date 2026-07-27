//! Editable HTTP requests.
//!
//! The store keeps messages as immutable bytes plus spans, which is what makes capture cheap. But
//! every attack tool — BCheck's `send request`, Intruder, Repeater, match-and-replace — needs to
//! take a captured request apart, change one piece, and put it back together. That is this module.
//!
//! # Three details that decide whether the request you send is valid
//!
//! **Content-Length must be recomputed.** A check that appends to the body and leaves a stale
//! Content-Length either gets its body truncated by the server or hangs waiting for bytes that never
//! come. Either way the check silently fails to test what it thinks it tests, so [`to_raw`] always
//! rewrites the length.
//!
//! [`to_raw`]: RequestEdit::to_raw
//!
//! **Chunked bodies must be decoded on the way in.** A proxied request can arrive with
//! `Transfer-Encoding: chunked`, where the stored body bytes include the chunk framing. Emitting
//! those bytes under a `Content-Length` would send the framing as literal content. So chunked bodies
//! are decoded at parse time and re-emitted length-delimited.
//!
//! **Proxied requests use absolute-form targets.** `GET http://host/a HTTP/1.1` is what a client
//! sends to a proxy; `GET /a HTTP/1.1` is what an origin expects. The authority is split off and
//! kept separately so a rebuilt request is origin-form — correct for a scanner that opens its own
//! connection — while still being able to answer `{base.request.url}`.

/// A request taken apart for editing. Header order is preserved.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestEdit {
    pub method: String,
    /// Scheme and authority, when the original target was absolute-form (`http://host`).
    pub origin: Option<String>,
    /// Path only, never including the query.
    pub path: String,
    /// Query without the leading `?`. Empty means no query.
    pub query: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EditError(pub &'static str);

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for EditError {}

impl RequestEdit {
    /// Parse a raw request. Tolerates bare LF line endings, as the store's parser does.
    pub fn from_raw(raw: &[u8]) -> Result<Self, EditError> {
        let split = find_header_end(raw).ok_or(EditError("no header terminator"))?;
        let (head, body_start) = split;
        let head = std::str::from_utf8(&raw[..head])
            .map_err(|_| EditError("non-UTF-8 request head"))?;

        let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
        let start = lines.next().ok_or(EditError("empty request"))?;
        let mut parts = start.split_whitespace();
        let method = parts.next().ok_or(EditError("no method"))?.to_string();
        let target = parts.next().ok_or(EditError("no target"))?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();

        // Absolute-form: split scheme://authority from the path.
        let (origin, rest) = match target.find("://") {
            Some(i) => {
                let after = &target[i + 3..];
                match after.find('/') {
                    Some(j) => (
                        Some(target[..i + 3 + j].to_string()),
                        after[j..].to_string(),
                    ),
                    None => (Some(target.clone()), "/".to_string()),
                }
            }
            None => (None, target),
        };
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (rest, String::new()),
        };

        let mut headers = Vec::new();
        for l in lines {
            if l.is_empty() {
                continue;
            }
            if let Some((n, v)) = l.split_once(':') {
                headers.push((n.trim().to_string(), v.trim().to_string()));
            }
        }

        let raw_body = &raw[body_start..];
        let chunked = headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
        let body = if chunked { dechunk(raw_body) } else { raw_body.to_vec() };

        Ok(Self { method, origin, path, query, version, headers, body })
    }

    /// The request-line target in origin-form.
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    /// The full URL, for `{base.request.url}`.
    pub fn url(&self) -> String {
        let host = self
            .origin
            .clone()
            .or_else(|| self.header("host").map(|h| format!("http://{h}")))
            .unwrap_or_default();
        format!("{host}{}", self.target())
    }

    /// Java's `URL.getFile()`: path plus query. Corpus checks use it for extension tests.
    pub fn file(&self) -> String {
        self.target()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Replace every header with this name, or append if absent.
    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some(i) = self.headers.iter().position(|(n, _)| n.eq_ignore_ascii_case(name)) {
            self.headers[i].1 = value.to_string();
            // Drop any later duplicates so the replacement is unambiguous.
            let name_owned = name.to_ascii_lowercase();
            let mut seen = false;
            self.headers.retain(|(n, _)| {
                if n.to_ascii_lowercase() == name_owned {
                    let first = !seen;
                    seen = true;
                    first
                } else {
                    true
                }
            });
        } else {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }

    /// Add a header, keeping any existing ones of the same name.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Append one `k=v` clause, choosing `?` or `&` by whether a query already exists.
    pub fn add_query(&mut self, clause: &str) {
        let clause = clause.trim_start_matches(['?', '&']);
        if clause.is_empty() {
            return;
        }
        if self.query.is_empty() {
            self.query = clause.to_string();
        } else {
            self.query.push('&');
            self.query.push_str(clause);
        }
    }

    /// Serialise to origin-form wire bytes with a correct `Content-Length`.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(b"\r\n");

        for (n, v) in &self.headers {
            // Length and framing are rewritten below; never echo the originals.
            if n.eq_ignore_ascii_case("content-length") || n.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        // A body always gets a length. An empty body gets one only for methods where its absence
        // would be ambiguous.
        if !self.body.is_empty() || matches!(self.method.as_str(), "POST" | "PUT" | "PATCH") {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Byte offset of the end of the header block and the start of the body.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            // CRLFCRLF
            if i + 2 < raw.len() && raw[i + 1] == b'\r' && raw[i + 2] == b'\n' {
                return Some((i, i + 3));
            }
            // Bare LFLF
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                return Some((i, i + 2));
            }
            // Terminator at the very end of the buffer.
            if i + 1 == raw.len() {
                return Some((i, raw.len()));
            }
        }
        i += 1;
    }
    None
}

/// Decode a chunked body. A malformed stream yields whatever decoded cleanly, which is the same
/// tolerance the message parser applies.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        let Some(nl) = b.iter().position(|&c| c == b'\n') else { break };
        let line = std::str::from_utf8(&b[..nl]).unwrap_or("").trim();
        // Ignore any chunk extension after ';'.
        let size_hex = line.split(';').next().unwrap_or("");
        let Ok(size) = usize::from_str_radix(size_hex, 16) else { break };
        b = &b[nl + 1..];
        if size == 0 {
            break;
        }
        if b.len() < size {
            out.extend_from_slice(b);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size..];
        // Skip the CRLF that follows the chunk data.
        while !b.is_empty() && (b[0] == b'\r' || b[0] == b'\n') {
            b = &b[1..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_rebuilds_a_plain_request() {
        let raw = b"GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\nAccept: */*\r\n\r\n";
        let r = RequestEdit::from_raw(raw).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/a");
        assert_eq!(r.query, "b=1");
        assert_eq!(r.header("host"), Some("x.test"));
        assert_eq!(r.to_raw(), raw.to_vec(), "round trip must be byte-identical");
    }

    #[test]
    fn absolute_form_target_is_split_into_origin_and_path() {
        // What a client sends to a proxy. Rebuilt output must be origin-form.
        let r = RequestEdit::from_raw(b"GET http://x.test/a?b=1 HTTP/1.1\r\nHost: x.test\r\n\r\n")
            .unwrap();
        assert_eq!(r.origin.as_deref(), Some("http://x.test"));
        assert_eq!(r.path, "/a");
        assert_eq!(r.url(), "http://x.test/a?b=1");
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(out.starts_with("GET /a?b=1 HTTP/1.1"), "got {out:?}");
    }

    #[test]
    fn content_length_is_recomputed_after_a_body_change() {
        // The bug this prevents: append to the body, leave Content-Length at 3, and the server
        // reads a truncated body while the check believes it sent the full payload.
        let mut r =
            RequestEdit::from_raw(b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\na=1")
                .unwrap();
        r.body.extend_from_slice(b"&b=2");
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(out.contains("Content-Length: 7"), "got {out:?}");
        assert!(out.ends_with("a=1&b=2"));
        assert_eq!(out.matches("Content-Length").count(), 1, "no duplicate length header");
    }

    #[test]
    fn chunked_bodies_are_decoded_and_re_emitted_length_delimited() {
        let raw = b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let r = RequestEdit::from_raw(raw).unwrap();
        assert_eq!(r.body, b"Wikipedia".to_vec(), "chunk framing must not survive");
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(out.contains("Content-Length: 9"), "got {out:?}");
        assert!(!out.to_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with("Wikipedia"));
    }

    #[test]
    fn add_query_picks_question_mark_then_ampersand() {
        let mut r = RequestEdit::from_raw(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        r.add_query("p=1");
        assert_eq!(r.target(), "/a?p=1");
        r.add_query("q=2");
        assert_eq!(r.target(), "/a?p=1&q=2");
    }

    #[test]
    fn set_header_replaces_all_duplicates_add_header_keeps_them() {
        let mut r =
            RequestEdit::from_raw(b"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n").unwrap();
        r.set_header("X-A", "9");
        assert_eq!(r.headers.iter().filter(|(n, _)| n == "X-A").count(), 1);
        assert_eq!(r.header("x-a"), Some("9"));
        r.add_header("X-B", "1");
        r.add_header("X-B", "2");
        assert_eq!(r.headers.iter().filter(|(n, _)| n == "X-B").count(), 2);
    }

    #[test]
    fn bare_lf_line_endings_parse() {
        let r = RequestEdit::from_raw(b"GET /a HTTP/1.1\nHost: x\n\nbody").unwrap();
        assert_eq!(r.path, "/a");
        assert_eq!(r.body, b"body".to_vec());
    }

    #[test]
    fn a_get_with_no_body_gets_no_content_length() {
        let r = RequestEdit::from_raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(!out.contains("Content-Length"), "got {out:?}");
    }

    #[test]
    fn a_post_with_an_empty_body_keeps_an_explicit_zero_length() {
        let r = RequestEdit::from_raw(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(out.contains("Content-Length: 0"), "got {out:?}");
    }
}
