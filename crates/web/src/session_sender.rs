//! [`burpsy_session::MacroSender`] over [`AuthorisedSender`] — the wiring that puts a recorded login
//! macro behind the Phase 1 chokepoint.
//!
//! # Why the implementation is here and not in `burpsy-session`
//!
//! `burpsy-session` owns only the re-login *policy* and states the send as a trait, so every test in
//! that crate runs against a fake that has no path to a socket and therefore cannot bypass the
//! chokepoint by accident (the full argument is in `burpsy_session::step`). This module is the one
//! place that closes that seam, and it closes it onto [`AuthorisedSender`] rather than onto a
//! transport: a macro step is a constructed request in exactly the sense HARD-03 means, so
//! [`burpsy_core::Scope`] has to authorise it, and the only way to be certain of that is to have no
//! other way to send.
//!
//! # Why the recorded framing headers are not echoed
//!
//! A macro is recorded from traffic that already happened, so its `Content-Length` describes the body
//! it had *then*. Replaying that number against the body actually being sent is how a probe gets
//! truncated server-side — the server reads the number of bytes it was told about and stops — and the
//! failure surfaces as "the login macro didn't log us in" with nothing in the response to explain it.
//! Framing is therefore recomputed from the bytes going out, which is the precedent
//! [`burpsy_core::edit::RequestEdit::to_raw`] already set for the repeater. `Connection` is dropped
//! for a different reason: the blocking transport in `burpsy-sender` rewrites it per probe to keep
//! its keep-alive pool sound, so a recorded value is at best ignored and at worst pins a connection
//! against what the pool decided.

use burpsy_sender::{AuthorisedSender, Sender, Target, parse_target};
use burpsy_session::{MacroResponse, MacroSender, MacroStep};
use bytes::Bytes;
use std::sync::Arc;

/// Sends recorded macro steps through the one authorising path from a constructed request to a
/// socket.
pub struct AuthorisedMacroSender {
    sender: Arc<AuthorisedSender>,
}

impl AuthorisedMacroSender {
    /// Shares the caller's sender rather than building one, because the `sent`/`refused` counters on
    /// it are the audit trail for a whole run: a private sender per surface would split that trail
    /// and a re-login refused for being out of scope would not show up where an operator looks.
    pub fn new(sender: Arc<AuthorisedSender>) -> Self {
        Self { sender }
    }
}

impl MacroSender for AuthorisedMacroSender {
    fn send(&self, step: &MacroStep) -> Result<MacroResponse, String> {
        let target = parse_target(&step.url).map_err(|e| e.to_string())?;
        let raw = build_request(step, &target);
        // The blocking `Sender` impl, which authorises the bytes above before any transport sees
        // them. There is deliberately no second method here that could skip it.
        let response = self.sender.send(&target, &raw)?;
        parse_response(Bytes::from(response))
    }
}

/// Origin-form HTTP/1.1 request bytes for one recorded step.
fn build_request(step: &MacroStep, target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + step.body.len());
    out.extend_from_slice(step.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request_target(&step.url).as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // Synthesised only when the recording has none: a macro recorded through the proxy normally
    // carries the exact `Host` the application saw, and overwriting it with one derived from the
    // target would silently change which virtual host is being logged into.
    if !has_header(step, "host") {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(host_header(target).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (name, value) in &step.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // A body always gets a length. An empty body gets one only for the methods where its absence is
    // ambiguous — a login `POST` with an empty body is a real thing to record, and a server that is
    // told no length at all is entitled to wait for one.
    if !step.body.is_empty() || method_expects_a_body(&step.method) {
        out.extend_from_slice(format!("Content-Length: {}\r\n", step.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&step.body);
    out
}

fn has_header(step: &MacroStep, name: &str) -> bool {
    step.headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// Does this method's empty body still need a stated length?
///
/// Case-insensitive where [`burpsy_core::edit::RequestEdit::to_raw`] matches exactly, because a
/// method here comes from a recording rather than from an operator's edit buffer.
fn method_expects_a_body(method: &str) -> bool {
    ["POST", "PUT", "PATCH"]
        .iter()
        .any(|m| method.eq_ignore_ascii_case(m))
}

/// `host` when the port is the scheme's default, `host:port` otherwise.
///
/// The default port is omitted rather than always written out because a `Host` header is a string the
/// application reads: `example.test` and `example.test:443` are equivalent to a well-behaved server
/// and are two different values to anything that routes, signs, or compares on it — including the
/// login form we are trying to reach.
fn host_header(target: &Target) -> String {
    let default_port = if target.tls { 443 } else { 80 };
    if target.port == default_port {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

/// The origin-form request target of a recorded URL: path and query, `/` when it names neither.
///
/// Strips the scheme exactly the way [`parse_target`] does, so the host half and the path half of one
/// URL are never read by two parsers that could disagree about where the host ends. The fragment is
/// dropped because it never goes on the wire.
fn request_target(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => rest[i..].to_string(),
        // `http://host?a=1` states a query and no path. The request line still needs one.
        Some(i) => format!("/{}", &rest[i..]),
        None => "/".to_string(),
    }
}

/// Parse raw response bytes into a [`MacroResponse`].
///
/// Hand-rolled rather than delegating to [`burpsy_core::parse`], which reports a missing header
/// terminator as an error: that collapses "the head arrived and the body did not" into the same
/// outcome as unreadable bytes, and [`MacroResponse::body`] exists precisely to keep those apart.
/// `None` means no body was captured, `Some(empty)` means the response genuinely had none (a `204`
/// does), and `burpsy_session::ValidityRule::BodyContains` answers differently for the two — a body
/// it never saw is a question it cannot evaluate, not a body that failed to match.
fn parse_response(raw: Bytes) -> Result<MacroResponse, String> {
    let terminator = find_header_terminator(&raw);
    let head = &raw[..terminator.map_or(raw.len(), |(head_end, _)| head_end)];
    let mut lines = head.split(|&b| b == b'\n');
    let status = parse_status_line(lines.next().unwrap_or_default())?;
    Ok(MacroResponse {
        status,
        headers: lines.filter_map(parse_header_line).collect(),
        // Zero-copy: `Bytes::slice` bumps a refcount rather than copying the body.
        body: terminator.map(|(_, body_start)| raw.slice(body_start..)),
    })
}

/// `(end of the head, start of the body)` for the first CRLFCRLF or LFLF, if there is one.
///
/// Bare LF is tolerated for the reason [`burpsy_core::parse`] gives: real targets emit it, and a
/// strict parser refuses to look at exactly the traffic worth looking at. CRLFCRLF is searched first,
/// so a head containing a bare LF continuation does not end the response early.
fn find_header_terminator(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((i, i + 4));
    }
    raw.windows(2)
        .position(|w| w == b"\n\n")
        .map(|i| (i, i + 2))
}

/// The status code of a response start line, or an error when the line is not one.
///
/// Refused rather than synthesised, because a caller handed a made-up `200` cannot tell a successful
/// re-login from bytes that were never a response, and `burpsy_session` spends one of its bounded
/// login attempts on the answer.
fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    let line = String::from_utf8_lossy(strip_cr(line));
    let mut tokens = line.split_whitespace();
    if !tokens.next().is_some_and(|v| v.starts_with("HTTP/")) {
        return Err(format!("response has no status line: {:?}", snippet(&line)));
    }
    let code = tokens
        .next()
        .ok_or_else(|| format!("status line states no status code: {:?}", snippet(&line)))?;
    let status: u16 = code
        .parse()
        .map_err(|_| format!("unreadable status code {code:?}"))?;
    if !(100..=999).contains(&status) {
        return Err(format!("status code {status} is not a status code"));
    }
    Ok(status)
}

/// One `Name: value` header line, or `None` for a line without a colon.
///
/// A colon-less line is dropped rather than made an error, matching [`burpsy_core::parse`]: an
/// obsolete continuation line or a stray blank is not a reason to discard a response the operator's
/// validity rule still needs to see.
fn parse_header_line(line: &[u8]) -> Option<(String, String)> {
    let line = strip_cr(line);
    let colon = line.iter().position(|&b| b == b':')?;
    let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = String::from_utf8_lossy(&line[colon + 1..])
        .trim()
        .to_string();
    Some((name, value))
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

/// A bounded excerpt for an error message. A malformed "response" can be a megabyte of anything.
fn snippet(s: &str) -> String {
    s.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Scope, ScopeRule};
    use burpsy_sender::NetSender;

    fn step(method: &str, url: &str, headers: &[(&str, &str)], body: &'static [u8]) -> MacroStep {
        MacroStep {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: Bytes::from_static(body),
        }
    }

    fn raw_of(step: &MacroStep) -> String {
        let target = parse_target(&step.url).expect("target");
        String::from_utf8(build_request(step, &target)).expect("utf-8 request")
    }

    /// HARD-03 for the session surface: the macro sender has no path to a socket that does not pass
    /// the scope check first. No network is involved because the refusal happens before the
    /// transport — which is the property being asserted.
    #[test]
    fn refuses_a_macro_step_whose_url_is_out_of_scope_and_sends_nothing() {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("in-scope.test"));
        let sender = Arc::new(AuthorisedSender::blocking(
            Arc::new(scope),
            NetSender::default(),
        ));
        let macro_sender = AuthorisedMacroSender::new(Arc::clone(&sender));

        let err = macro_sender
            .send(&step(
                "POST",
                "https://elsewhere.test/login",
                &[],
                b"user=a&pass=b",
            ))
            .expect_err("an out-of-scope login macro must not be sent");

        // The gate authorises the bytes this module built, not the URL it was handed: the request
        // target only appears in the refusal if the built request is what scope actually saw.
        assert!(err.contains("/login"), "unexpected refusal: {err}");
        assert_eq!(sender.refused(), 1, "the refusal must be counted");
        assert_eq!(sender.sent(), 0, "nothing may reach a socket");
    }

    /// The other half of the HARD-03 claim: an *authorised* step does reach the wire, carrying the
    /// bytes this module built. Without this, the refusal test above would also pass for a sender
    /// that refuses everything.
    #[test]
    fn sends_an_in_scope_step_through_the_chokepoint_and_parses_what_comes_back() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            // Read the head plus the six body bytes this step sends, so the assertions below see the
            // whole request rather than whatever happened to arrive in the first packet.
            while !find_header_terminator(&seen).is_some_and(|(_, start)| seen.len() >= start + 6) {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            sock.write_all(b"HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 2\r\n\r\nhi")
                .expect("write response");
            let _ = sock.flush();
            seen
        });

        let mut scope = Scope::new();
        scope.add(ScopeRule::include("127.0.0.1"));
        let sender = Arc::new(AuthorisedSender::blocking(
            Arc::new(scope),
            NetSender::default(),
        ));
        let response = AuthorisedMacroSender::new(Arc::clone(&sender))
            .send(&step(
                "POST",
                &format!("http://127.0.0.1:{port}/login"),
                &[("Content-Length", "9999")],
                b"user=a",
            ))
            .expect("the loopback server answers");

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers.first(),
            Some(&("Location".to_string(), "/home".to_string()))
        );
        assert_eq!(response.body.as_deref(), Some(&b"hi"[..]));
        assert_eq!(
            sender.sent(),
            1,
            "an authorised step is handed to the transport"
        );
        assert_eq!(sender.refused(), 0);

        let on_the_wire = String::from_utf8(server.join().expect("server thread")).expect("utf-8");
        assert!(
            on_the_wire.starts_with("POST /login HTTP/1.1\r\n"),
            "{on_the_wire}"
        );
        assert!(
            on_the_wire.contains(&format!("Host: 127.0.0.1:{port}\r\n")),
            "{on_the_wire}"
        );
        assert!(
            on_the_wire.contains("Content-Length: 6\r\n"),
            "{on_the_wire}"
        );
        assert!(on_the_wire.ends_with("user=a"), "{on_the_wire}");
    }

    #[test]
    fn synthesises_a_host_header_when_the_recording_has_none() {
        let raw = raw_of(&step("GET", "http://login.test:8080/a", &[], b""));
        assert!(
            raw.starts_with("GET /a HTTP/1.1\r\nHost: login.test:8080\r\n"),
            "{raw}"
        );
    }

    #[test]
    fn keeps_the_recorded_host_header_instead_of_deriving_a_second_one() {
        let raw = raw_of(&step(
            "GET",
            "http://10.0.0.1/a",
            &[("host", "vhost.test")],
            b"",
        ));
        assert!(raw.contains("host: vhost.test\r\n"), "{raw}");
        assert!(
            !raw.contains("10.0.0.1"),
            "a second Host was synthesised: {raw}"
        );
    }

    #[test]
    fn omits_the_default_port_from_a_synthesised_host_header() {
        let https = raw_of(&step("GET", "https://login.test/a", &[], b""));
        assert!(https.contains("Host: login.test\r\n"), "{https}");
        let http = raw_of(&step("GET", "http://login.test:80/a", &[], b""));
        assert!(http.contains("Host: login.test\r\n"), "{http}");
        let odd = raw_of(&step("GET", "https://login.test:8443/a", &[], b""));
        assert!(odd.contains("Host: login.test:8443\r\n"), "{odd}");
    }

    #[test]
    fn recomputes_content_length_from_the_body_being_sent_not_the_recorded_one() {
        let raw = raw_of(&step(
            "POST",
            "https://login.test/login",
            &[("Content-Length", "9999"), ("Content-Type", "text/plain")],
            b"user=a",
        ));
        assert!(raw.contains("Content-Length: 6\r\n"), "{raw}");
        assert!(
            !raw.contains("9999"),
            "the recorded length was echoed: {raw}"
        );
        assert!(raw.ends_with("\r\n\r\nuser=a"), "{raw}");
    }

    #[test]
    fn states_a_zero_length_for_an_empty_post_body_and_none_for_an_empty_get() {
        let post = raw_of(&step("post", "https://login.test/login", &[], b""));
        assert!(post.contains("Content-Length: 0\r\n"), "{post}");
        let get = raw_of(&step("GET", "https://login.test/login", &[], b""));
        assert!(!get.contains("Content-Length"), "{get}");
    }

    #[test]
    fn drops_recorded_transfer_encoding_and_connection_headers() {
        let raw = raw_of(&step(
            "POST",
            "https://login.test/login",
            &[
                ("Transfer-Encoding", "chunked"),
                ("Connection", "keep-alive"),
                ("Accept", "*/*"),
            ],
            b"u=a",
        ));
        assert!(!raw.contains("Transfer-Encoding"), "{raw}");
        assert!(!raw.contains("Connection"), "{raw}");
        assert!(raw.contains("Accept: */*\r\n"), "{raw}");
    }

    #[test]
    fn takes_the_request_target_from_the_url_path_and_query() {
        assert_eq!(request_target("https://h.test/a/b?q=1&r=2"), "/a/b?q=1&r=2");
        assert_eq!(request_target("http://h.test:8080/a"), "/a");
        assert_eq!(request_target("https://h.test/"), "/");
    }

    #[test]
    fn uses_a_bare_slash_when_the_url_names_no_path() {
        assert_eq!(request_target("https://h.test"), "/");
        assert_eq!(request_target("h.test:8443"), "/");
        assert_eq!(request_target("http://h.test?a=1"), "/?a=1");
    }

    #[test]
    fn drops_the_fragment_because_it_never_goes_on_the_wire() {
        assert_eq!(request_target("https://h.test/a?q=1#top"), "/a?q=1");
    }

    #[test]
    fn parses_the_status_and_headers_of_a_response() {
        let r = parse_response(Bytes::from_static(
            b"HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: s=1; Path=/\r\n\r\nbye",
        ))
        .expect("parse");
        assert_eq!(r.status, 302);
        assert_eq!(
            r.headers,
            vec![
                ("Location".to_string(), "/home".to_string()),
                ("Set-Cookie".to_string(), "s=1; Path=/".to_string()),
            ]
        );
        assert_eq!(r.body.as_deref(), Some(&b"bye"[..]));
    }

    #[test]
    fn tolerates_bare_lf_framing_and_a_missing_reason_phrase() {
        let r = parse_response(Bytes::from_static(b"HTTP/1.1 204\nX: y\n\n")).expect("parse");
        assert_eq!(r.status, 204);
        assert_eq!(r.headers, vec![("X".to_string(), "y".to_string())]);
    }

    #[test]
    fn reports_a_genuinely_empty_body_as_some_empty_rather_than_none() {
        let r =
            parse_response(Bytes::from_static(b"HTTP/1.1 204 No Content\r\n\r\n")).expect("parse");
        assert_eq!(
            r.body,
            Some(Bytes::new()),
            "an empty body is a body; BodyContains must be able to answer about it"
        );
    }

    #[test]
    fn reports_a_response_with_no_header_terminator_as_no_body_captured() {
        let r = parse_response(Bytes::from_static(b"HTTP/1.1 200 OK\r\nX: y")).expect("parse");
        assert_eq!(r.status, 200);
        assert_eq!(r.headers, vec![("X".to_string(), "y".to_string())]);
        assert_eq!(
            r.body, None,
            "nothing was captured, which is not an empty body"
        );
    }

    #[test]
    fn refuses_a_response_with_no_parseable_status_line() {
        for raw in [
            &b"not http at all\r\n\r\nbody"[..],
            &b""[..],
            &b"HTTP/1.1\r\n\r\n"[..],
            &b"HTTP/1.1 wat\r\n\r\n"[..],
        ] {
            let err = parse_response(Bytes::copy_from_slice(raw))
                .expect_err("a synthesised status would be a lie about what arrived");
            assert!(!err.is_empty());
        }
    }
}
