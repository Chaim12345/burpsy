//! Insertion points — the places in a request where a payload can be placed.
//!
//! `given insertion point` runs a check once per point, and `send payload` mutates **exactly one** of
//! them per send. That one-at-a-time rule is the whole value of the construct: it is what lets a
//! finding say *which parameter* is injectable. A run that changed two parameters would report a
//! vulnerability without saying where it is, which is not a finding, it is a rumour.
//!
//! # A point is an offset, not a copy
//!
//! Each point holds a byte range into one component of the base [`RequestEdit`] — the query string,
//! one header's value, or the body. Enumerating every point for a request therefore costs a few
//! small labels, not a request clone per position, which is the same discipline `burpsy-intruder`
//! applies to its own attack positions. A payload is applied by splicing that one range.
//!
//! Because the ranges address the **base** request, [`InsertionPoint::apply`] must always be handed
//! the base request. Applying twice, or applying to an already-mutated request, would splice at
//! offsets that no longer mean what they meant. The evaluator enforces this by building every
//! `send payload` from `base.request`.
//!
//! # Which families exist, and why only four
//!
//! Burp's scanner exposes eight insertion-point families, named by its own configuration keys
//! (recovered as string constants from `burp.Zb1q` in the decompiled build):
//! `insert_url_params`, `insert_body_params`, `insert_cookies`, `insert_http_headers`,
//! `insert_param_name`, `insert_entire_body`, `insert_url_path_filename`,
//! `insert_url_path_folders`.
//!
//! BCheck's `given … insertion point` grammar can name exactly four of them — `query`, `body`,
//! `cookie`, `header` — which is why [`IpType`] has those four and no more. Parameter *names*, the
//! entire body, and URL path segments are attackable by Burp's scanner but unaddressable from the
//! DSL, so enumerating them here would send probes at positions no check asked for and no `given`
//! line can constrain. `burpsy-intruder` covers those families for the tools that *can* name them.
//!
//! **`any` includes headers.** The evidence is `other/tokens/jwt-none-algorithm.bcheck`, which is a
//! bare `given insertion point` and carries the author's own comment: *"Authorization header is
//! treat differently as the base value may be prefixed with 'Bearer'"*. A JWT check whose `any`
//! skipped headers would never fire on the one place JWTs live.
//!
//! **Nested points are not enumerated.** Burp audits inside an already-decoded parameter — a JSON
//! blob inside a base64 cookie, say — and reports `"Skipped as nested insertion points not enabled"`
//! (`burp.Zq5`) when that is switched off. Four corpus checks comment that they rely on it. Not
//! implementing it is a miss, never a false positive: fewer positions get probed, and every position
//! that does get probed is still exactly one.
//!
//! # Encoding: escape the payload, never re-encode the base value
//!
//! A payload dropped raw into a query parameter can carry `&` or `=` and silently become *two*
//! parameters — at which point the check is testing something nobody asked for. So the payload is
//! percent-escaped for the byte set that decides how the container is parsed, and only that set.
//!
//! The base value is left byte-identical. The alternative — decode the base value, splice, re-encode
//! the whole thing, which is what Burp's insertion points do — rewrites bytes the check never asked
//! to change (`a+b` would go out as `a%20b`), and a probe that differs from the baseline in ways the
//! check did not cause is a false positive waiting to happen.

use crate::ast::IpType;
use burpsy_core::edit::RequestEdit;
use std::ops::Range;

/// One place a payload can go, plus the value already there.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertionPoint {
    /// Never [`IpType::Any`] — `any` is a selector in the `given` line, not a location.
    pub kind: IpType,
    /// Parameter, header or cookie name. For JSON, the key (or `key[i]` inside an array).
    pub name: String,
    /// The value as it appears on the wire, still encoded. What `{insertion_point_base_value}`
    /// resolves to, and what `appending:` appends to.
    ///
    /// Burp registers the same thing in the BCheck *variable* map rather than the request map
    /// (`Zpao.java:69`, taking it from the point's own accessor), guarded on both a v1-beta-or-later
    /// language and a non-null insertion point — which is why the name is simply absent outside an
    /// insertion-point check rather than empty inside one.
    pub base_value: String,
    loc: Loc,
    coding: Coding,
}

/// Which component of the base request the value lives in, and where.
#[derive(Debug, Clone, PartialEq)]
enum Loc {
    /// Range within `RequestEdit::query`.
    Query(Range<usize>),
    /// Index into `RequestEdit::headers`; the whole value is the point.
    Header(usize),
    /// Range within the value of header `index`.
    Cookie { index: usize, value: Range<usize> },
    /// Range within `RequestEdit::body`.
    Body(Range<usize>),
}

/// How a payload must be escaped so the surrounding container still parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    /// Header values: no container to break, so the payload goes out verbatim.
    Raw,
    /// `k=v` pairs in a query string, a cookie header or a form body.
    Form,
    /// Inside a JSON string literal.
    Json,
}

/// A place the enumerator refused to build insertion points for, and why.
///
/// The body case is the one that matters: splicing a payload into a container whose framing is not
/// modelled (multipart, XML, a non-UTF-8 body) produces a request the server rejects before the
/// code under test ever sees it. Returning nothing in that case made the refusal indistinguishable
/// from "this request genuinely has nowhere to inject" — so a `given body insertion point` check
/// against a multipart form reported a clean bill of health while testing nothing. That is the
/// silent false negative this type exists to prevent: a declined body is surfaced as skipped, never
/// as tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declined {
    /// What was declined, named for the operator ("request body").
    pub what: String,
    /// Why no points were built ("multipart body: framing not modelled").
    pub reason: String,
}

impl Declined {
    /// One line naming both what was declined and why, for a report row or an `Unsupported`
    /// payload. Neither field alone is enough: `reason` without `what` reads as an unattributed
    /// error, and a check with several `given … insertion point` clauses can decline more than
    /// one kind of place.
    pub fn describe(&self) -> String {
        format!("{}: {}", self.what, self.reason)
    }
}

/// Headers a payload must not be placed in.
///
/// `Host` selects the virtual host, so a payload there tests a different application and the finding
/// would be misattributed. `Content-Length` and `Transfer-Encoding` are rewritten by
/// [`RequestEdit::to_raw`], so a payload in them is discarded before it reaches the wire — a silent
/// no-op probe, which is worse than no probe. `Connection` is hop-by-hop. `Cookie` is enumerated as
/// individual cookie points instead, because a payload appended to the whole cookie blob is not
/// attributable to any one cookie.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "cookie",
];

/// Every point of the requested kinds, in a fixed order: query, headers, cookies, body — plus the
/// places that were *declined* rather than enumerated.
///
/// The order is pinned because it is observable — a check reports one finding per point, and a
/// scanner that reordered them between runs would reorder its own output.
///
/// An empty point list with no declines is normal (a bare `GET /` with no interesting headers has
/// nowhere to inject) and means the check simply has nothing to do here. An empty point list *with*
/// declines is different: the request had somewhere to inject that this enumerator refuses to
/// splice into, and the caller must report that as skipped rather than clean — see [`Declined`].
pub fn enumerate(req: &RequestEdit, kinds: &[IpType]) -> (Vec<InsertionPoint>, Vec<Declined>) {
    let want = |k: IpType| kinds.contains(&IpType::Any) || kinds.contains(&k);
    let mut out = Vec::new();
    let mut declined = Vec::new();

    if want(IpType::Query) {
        for (name, value) in kv_pairs(&req.query, b'&') {
            out.push(InsertionPoint {
                kind: IpType::Query,
                name: req.query[name].to_string(),
                base_value: req.query[value.clone()].to_string(),
                loc: Loc::Query(value),
                coding: Coding::Form,
            });
        }
    }

    if want(IpType::Header) {
        for (i, (n, v)) in req.headers.iter().enumerate() {
            if RESERVED_HEADERS.contains(&n.to_ascii_lowercase().as_str()) {
                continue;
            }
            out.push(InsertionPoint {
                kind: IpType::Header,
                name: n.clone(),
                base_value: v.clone(),
                loc: Loc::Header(i),
                coding: Coding::Raw,
            });
        }
    }

    if want(IpType::Cookie) {
        for (i, (n, v)) in req.headers.iter().enumerate() {
            if !n.eq_ignore_ascii_case("cookie") {
                continue;
            }
            for (name, value) in kv_pairs(v, b';') {
                out.push(InsertionPoint {
                    kind: IpType::Cookie,
                    name: v[name].to_string(),
                    base_value: v[value.clone()].to_string(),
                    loc: Loc::Cookie { index: i, value },
                    coding: Coding::Form,
                });
            }
        }
    }

    if want(IpType::Body) {
        body_points(req, &mut out, &mut declined);
    }

    (out, declined)
}

/// Body points, if the body is a container we can splice into without corrupting it — otherwise a
/// [`Declined`] entry naming what was refused and why.
///
/// Multipart, XML and plain-text bodies yield nothing. Splicing into a container whose framing we do
/// not model would produce a body the server rejects before the code under test ever sees the
/// payload, and a check whose probe is rejected reports nothing while looking like it ran. The
/// refusal is therefore recorded, not swallowed: a silent empty result here was how a `given body
/// insertion point` check against a multipart form used to report a clean bill of health while
/// testing nothing.
fn body_points(req: &RequestEdit, out: &mut Vec<InsertionPoint>, declined: &mut Vec<Declined>) {
    if req.body.is_empty() {
        return;
    }
    let Ok(body) = std::str::from_utf8(&req.body) else {
        declined.push(Declined {
            what: "request body".into(),
            reason: "non-UTF-8 body: cannot splice without corrupting it".into(),
        });
        return;
    };
    let ctype = req
        .header("content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let trimmed = body.trim_start();

    if ctype.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('[') {
        for (name, value) in json_string_values(body) {
            out.push(InsertionPoint {
                kind: IpType::Body,
                name,
                base_value: body[value.clone()].to_string(),
                loc: Loc::Body(value),
                coding: Coding::Json,
            });
        }
        return;
    }

    // A missing Content-Type on a `k=v&k=v` body is still a form as far as every server is
    // concerned; requiring the header would leave those bodies untested.
    let is_form =
        ctype.contains("x-www-form-urlencoded") || (ctype.is_empty() && body.contains('='));
    if is_form {
        for (name, value) in kv_pairs(body, b'&') {
            out.push(InsertionPoint {
                kind: IpType::Body,
                name: body[name].to_string(),
                base_value: body[value.clone()].to_string(),
                loc: Loc::Body(value),
                coding: Coding::Form,
            });
        }
    } else {
        declined.push(Declined {
            what: "request body".into(),
            reason: "body matches no modelled container (multipart, XML or plain text): \
                     splicing would corrupt framing the server rejects before the code under test \
                     sees the payload"
                .into(),
        });
    }
}

impl InsertionPoint {
    /// Splice `payload` into this point of `req`, which must be the request the point was enumerated
    /// from. `appending` keeps the existing value and adds to it; otherwise it is overwritten.
    ///
    /// Everything else in the request is untouched, which is what makes a resulting finding
    /// attributable to [`InsertionPoint::name`].
    pub fn apply(&self, req: &mut RequestEdit, payload: &str, appending: bool) {
        let escaped = match self.coding {
            Coding::Raw => payload.to_string(),
            Coding::Form => percent_escape(payload),
            Coding::Json => json_escape(payload),
        };
        // The base value is already in wire form, so the escaped payload concatenates onto it
        // directly — no decode/re-encode round trip.
        let new = if appending {
            format!("{}{escaped}", self.base_value)
        } else {
            escaped
        };

        match &self.loc {
            Loc::Query(r) => req.query = splice(&req.query, r.clone(), &new),
            Loc::Header(i) => {
                if let Some(h) = req.headers.get_mut(*i) {
                    h.1 = new;
                }
            }
            Loc::Cookie { index, value } => {
                if let Some(h) = req.headers.get_mut(*index) {
                    h.1 = splice(&h.1, value.clone(), &new);
                }
            }
            Loc::Body(r) => {
                let start = r.start.min(req.body.len());
                let end = r.end.min(req.body.len()).max(start);
                let mut b = Vec::with_capacity(req.body.len() + new.len());
                b.extend_from_slice(&req.body[..start]);
                b.extend_from_slice(new.as_bytes());
                b.extend_from_slice(&req.body[end..]);
                req.body = b;
            }
        }
    }
}

fn splice(s: &str, r: Range<usize>, new: &str) -> String {
    // Ranges address the base request's bytes, and `InsertionPoint::apply` is public, so a caller
    // can hand in an offset that lands mid-codepoint. Slicing there would panic; flooring to the
    // preceding char boundary splices at the nearest legal position instead. (`floor_char_boundary`
    // is still unstable on this toolchain, so the walk is manual.)
    let mut start = r.start.min(s.len());
    while !s.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = r.end.min(s.len()).max(start);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(s.len() + new.len());
    out.push_str(&s[..start]);
    out.push_str(new);
    out.push_str(&s[end..]);
    out
}

/// Byte ranges of the name and value of each `k=v` clause in `s`, split on `sep`.
///
/// A clause with no `=` is skipped. It has no value to append to, and turning `?debug` into
/// `?debug=<payload>` invents a parameter the application was never sent — a different request,
/// tested under the original's name.
fn kv_pairs(s: &str, sep: u8) -> Vec<(Range<usize>, Range<usize>)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= b.len() {
        if i == b.len() || b[i] == sep {
            // Cookie clauses are `; `-separated, so leading space is part of the delimiter.
            let mut cs = start;
            while cs < i && (b[cs] == b' ' || b[cs] == b'\t') {
                cs += 1;
            }
            if let Some(eq) = b[cs..i].iter().position(|&c| c == b'=') {
                let name = cs..cs + eq;
                if !name.is_empty() {
                    out.push((name, cs + eq + 1..i));
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    out
}

/// Ranges of every JSON **string** value, with the key that names it.
///
/// Only strings. Splicing into a number or a boolean (`{"n":1}` → `{"n":1'}`) yields JSON the server
/// rejects at parse time, so the payload never reaches the code being tested and the check quietly
/// finds nothing — the exact silent-negative this codebase refuses to ship.
///
/// The scanner is deliberately structural rather than a full parser: it needs positions in the
/// original text, which a value-tree parser throws away.
fn json_string_values(s: &str) -> Vec<(String, Range<usize>)> {
    struct Frame {
        object: bool,
        /// The key this container was reached by, for naming values nested inside it.
        label: String,
        key: String,
        index: usize,
        /// In an object, whether the next string is a value rather than a key.
        expect_value: bool,
    }

    let b = s.as_bytes();
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < b.len() {
        match b[i] {
            b'{' | b'[' => {
                let label = match stack.last() {
                    Some(f) if f.object => f.key.clone(),
                    Some(f) => format!("{}[{}]", f.label, f.index),
                    None => String::new(),
                };
                stack.push(Frame {
                    object: b[i] == b'{',
                    label,
                    key: String::new(),
                    index: 0,
                    // Array elements are always values; object members start on a key.
                    expect_value: b[i] == b'[',
                });
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b':' => {
                if let Some(f) = stack.last_mut() {
                    f.expect_value = true;
                }
                i += 1;
            }
            b',' => {
                if let Some(f) = stack.last_mut() {
                    if f.object {
                        f.expect_value = false;
                    } else {
                        f.index += 1;
                    }
                }
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                let end = j.min(b.len());
                match stack.last_mut() {
                    Some(f) if f.object && !f.expect_value => f.key = s[start..end].to_string(),
                    Some(f) => {
                        let name = if f.object {
                            f.key.clone()
                        } else {
                            format!("{}[{}]", f.label, f.index)
                        };
                        out.push((name, start..end));
                    }
                    // A bare top-level string is the whole body, not a parameter.
                    None => {}
                }
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// Percent-escape the bytes that decide how a `k=v` container is read.
///
/// `&`, `=` and `;` are the separators; `+` and `%` change how the value itself decodes, so leaving
/// them raw would hand the application a payload other than the one the check wrote; `#` truncates a
/// URL; and anything outside printable ASCII — space included — cannot appear in a request line at
/// all. Everything else is passed through, so an injection payload arrives looking like itself.
fn percent_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if matches!(c, b'&' | b'=' | b'+' | b';' | b'#' | b'%') || c <= 0x20 || c >= 0x7f {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(c as char);
        }
    }
    out
}

/// Escape a payload for use inside a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(raw: &[u8]) -> RequestEdit {
        RequestEdit::from_raw(raw).unwrap()
    }

    fn names(ps: &[InsertionPoint]) -> Vec<(IpType, &str)> {
        ps.iter().map(|p| (p.kind, p.name.as_str())).collect()
    }

    #[test]
    fn any_enumerates_query_headers_and_cookies_in_a_fixed_order() {
        let r = req(b"GET /s?q=cat&page=2 HTTP/1.1\r\nHost: x.test\r\nUser-Agent: burpsy\r\nCookie: sid=abc; theme=dark\r\n\r\n");
        let ps = enumerate(&r, &[IpType::Any]).0;
        assert_eq!(
            names(&ps),
            vec![
                (IpType::Query, "q"),
                (IpType::Query, "page"),
                (IpType::Header, "User-Agent"),
                (IpType::Cookie, "sid"),
                (IpType::Cookie, "theme"),
            ],
            "Host and Cookie must not appear as header points"
        );
        assert_eq!(ps[0].base_value, "cat");
        assert_eq!(ps[4].base_value, "dark");
    }

    #[test]
    fn a_query_clause_with_no_equals_is_not_a_point() {
        // `?debug` has no value; inventing `?debug=payload` would send a parameter the application
        // was never given, under the original's name.
        let r = req(b"GET /s?debug&q=1 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            names(&enumerate(&r, &[IpType::Query]).0),
            vec![(IpType::Query, "q")]
        );
    }

    #[test]
    fn a_form_body_yields_one_point_per_field() {
        let r = req(b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo");
        let ps = enumerate(&r, &[IpType::Body]).0;
        assert_eq!(
            names(&ps),
            vec![(IpType::Body, "a"), (IpType::Body, "user")]
        );
        assert_eq!(ps[1].base_value, "bo");
    }

    #[test]
    fn json_string_values_are_points_and_numbers_are_not() {
        let r = req(
            b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n{\"user\":\"bo\",\"age\":31,\"tags\":[\"a\",\"b\"],\"ok\":true}",
        );
        let ps = enumerate(&r, &[IpType::Body]).0;
        assert_eq!(
            names(&ps),
            vec![
                (IpType::Body, "user"),
                (IpType::Body, "tags[0]"),
                (IpType::Body, "tags[1]"),
            ],
            "a payload spliced into `31` or `true` makes the body unparsable"
        );
        assert_eq!(ps[2].base_value, "b");
    }

    #[test]
    fn a_multipart_body_yields_no_points() {
        // We do not model multipart framing, and a payload spliced blind into it produces a body the
        // server rejects before the application sees the payload.
        let r = req(b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n");
        assert!(
            enumerate(&r, &[IpType::Any])
                .0
                .iter()
                .all(|p| p.kind != IpType::Body)
        );
    }

    #[test]
    fn appending_to_a_query_point_leaves_every_other_parameter_byte_identical() {
        let mut r = req(b"GET /s?q=cat&page=2&sort=asc HTTP/1.1\r\nHost: x\r\n\r\n");
        let ps = enumerate(&r, &[IpType::Query]).0;
        ps[1].apply(&mut r, "'", true);
        assert_eq!(r.query, "q=cat&page=2'&sort=asc");
    }

    #[test]
    fn replacing_overwrites_only_the_targeted_value() {
        let mut r = req(b"GET /s?q=cat&page=2 HTTP/1.1\r\nHost: x\r\n\r\n");
        enumerate(&r, &[IpType::Query]).0[0].apply(&mut r, "X", false);
        assert_eq!(r.query, "q=X&page=2");
    }

    #[test]
    fn a_payload_carrying_separators_cannot_split_a_parameter() {
        // Raw, `evil&admin=1` would become a second parameter and the check would be testing a
        // request nobody wrote.
        let mut r = req(b"GET /s?q=cat HTTP/1.1\r\nHost: x\r\n\r\n");
        enumerate(&r, &[IpType::Query]).0[0].apply(&mut r, "evil&admin=1", false);
        assert_eq!(r.query, "q=evil%26admin%3D1");
    }

    #[test]
    fn a_header_payload_is_not_percent_escaped() {
        // There is no k=v container in a header value, so escaping would only corrupt the payload.
        let mut r = req(b"GET / HTTP/1.1\r\nHost: x\r\nX-Probe: base\r\n\r\n");
        let ps = enumerate(&r, &[IpType::Header]).0;
        ps[0].apply(&mut r, " a=b&c ", true);
        assert_eq!(r.header("X-Probe"), Some("base a=b&c "));
    }

    #[test]
    fn a_cookie_payload_touches_one_cookie_and_keeps_the_separators() {
        let mut r = req(b"GET / HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n");
        let ps = enumerate(&r, &[IpType::Cookie]).0;
        ps[0].apply(&mut r, "';", true);
        assert_eq!(r.header("cookie"), Some("sid=abc'%3B; theme=dark"));
    }

    #[test]
    fn a_json_payload_is_escaped_so_the_body_stays_well_formed() {
        let mut r = req(
            b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"user\":\"bo\",\"role\":\"u\"}",
        );
        let ps = enumerate(&r, &[IpType::Body]).0;
        ps[0].apply(&mut r, "\"}); drop", true);
        assert_eq!(
            String::from_utf8(r.body.clone()).unwrap(),
            r#"{"user":"bo\"}); drop","role":"u"}"#
        );
    }

    #[test]
    fn the_content_length_follows_a_body_payload() {
        // A stale length truncates the probe server-side, so the payload never arrives whole.
        let mut r = req(b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1");
        enumerate(&r, &[IpType::Body]).0[0].apply(&mut r, "234", true);
        let out = String::from_utf8(r.to_raw()).unwrap();
        assert!(out.contains("Content-Length: 6"), "got {out:?}");
        assert!(out.ends_with("a=1234"), "got {out:?}");
    }

    #[test]
    fn qualifiers_select_which_families_are_enumerated() {
        let r = req(b"POST /s?q=1 HTTP/1.1\r\nHost: x\r\nX-A: v\r\nCookie: c=1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nb=2");
        let ps = enumerate(&r, &[IpType::Query, IpType::Body]).0;
        assert_eq!(names(&ps), vec![(IpType::Query, "q"), (IpType::Body, "b")]);
    }

    #[test]
    fn a_request_with_nowhere_to_inject_yields_no_points() {
        let r = req(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(enumerate(&r, &[IpType::Any]).0, vec![]);
    }

    #[test]
    /// C-1: a body the enumerator refuses to splice into is reported as a decline, not swallowed.
    fn a_multipart_body_is_reported_as_declined_not_silently_empty() {
        // The old behaviour returned no points and no record of the refusal, so a `given body
        // insertion point` check against a multipart form reported "tested, found nothing" while
        // testing nothing at all — the silent false negative C-1 closes.
        let r = req(b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n");
        let (points, declined) = enumerate(&r, &[IpType::Body]);
        assert!(points.is_empty(), "multipart framing is not spliced into");
        assert_eq!(declined.len(), 1, "the refusal is recorded, not swallowed");
        assert_eq!(declined[0].what, "request body");
        assert!(
            declined[0].reason.contains("multipart"),
            "the reason names what was refused: {:?}",
            declined[0].reason
        );
    }

    #[test]
    /// C-1: a non-UTF-8 body is reported as a decline, not swallowed.
    fn a_non_utf8_body_is_reported_as_declined() {
        let mut raw = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        let r = req(&raw);
        let (points, declined) = enumerate(&r, &[IpType::Body]);
        assert!(points.is_empty());
        assert_eq!(declined.len(), 1);
        assert!(
            declined[0].reason.contains("UTF-8"),
            "the reason names the encoding problem: {:?}",
            declined[0].reason
        );
    }

    #[test]
    /// C-1: a form body that IS spliced into yields points and no decline.
    fn a_form_body_is_enumerated_with_no_decline() {
        let r = req(b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1");
        let (points, declined) = enumerate(&r, &[IpType::Body]);
        assert_eq!(names(&points), vec![(IpType::Body, "a")]);
        assert!(declined.is_empty(), "a modelled container is not declined");
    }

    #[test]
    /// C-2: splicing at an offset inside a multi-byte char floors to the boundary instead of panicking.
    fn splice_at_a_mid_codepoint_offset_floors_to_the_char_boundary() {
        // "é" is two bytes (0xC3 0xA9), so the char boundaries of "aéb" are {0,1,3,4}. Offsets 1
        // and 2 are not both legal: 1 is the boundary before é, 2 lands inside it. Flooring moves
        // an interior offset to the preceding boundary rather than panicking on a mid-codepoint
        // slice.
        let s = "a\u{e9}b"; // a, é (2 bytes), b — len 4
        assert_eq!(splice(s, 1..2, "X"), "aX\u{e9}b", "end=2 floors to 1, so é survives");
        assert_eq!(splice(s, 2..3, "X"), "aXb", "start=2 floors to 1, so é is replaced");
    }

    #[test]
    /// C-2: a splice range entirely past a multi-byte char leaves it intact.
    fn splice_past_a_multi_byte_char_does_not_corrupt_it() {
        let s = "\u{e9}ab"; // é (2 bytes), a, b — len 4
        assert_eq!(splice(s, 3..4, "X"), "\u{e9}aX", "the trailing byte splice leaves é whole");
    }
}
