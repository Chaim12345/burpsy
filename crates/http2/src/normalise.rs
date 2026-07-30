//! Render an h2 exchange (or an `H2Request` about to become one) into HTTP/1 shape, so it sits in
//! history exactly like an HTTP/1 record and every existing tool — history, filters, Repeater,
//! `find_points`, the passive scanner — keeps working on it unchanged.
//!
//! # Why this lives in `burpsy-http2`, not in the proxy
//!
//! The proxy renders a decoded stream for the history record; the sender's egress authoriser (a
//! later slice) must extract a `:path` from the *same* rendering before it authorises a send. If
//! those were two functions — one in `proxy`, one in `sender` — nothing would stop them drifting,
//! and a drift here is not cosmetic: an operator could name an in-scope host, and a caller could
//! then authorise against a path the proxy's history disagrees with. `AuthorisedSender::authorise`'s
//! own doc comment already makes this argument for HTTP/1: "the actual outbound bytes, not the
//! target that was named… a caller can name an in-scope host and then write a request line for
//! somewhere else" [`crates/sender/src/lib.rs:223-225` at the time this was written]. Putting the
//! renderer here, where both `proxy` and `sender` already depend on it, makes drift a compile
//! error rather than a discipline problem: there is exactly one `render_request`, and both the
//! history record and the authoriser call it.
//!
//! # What "header-list-exactness" means here
//!
//! `headers` is the plain field list — pseudo-headers (`:method`, `:path`, `:authority`,
//! `:status`) are not part of it; they arrive as this module's other, typed parameters, because an
//! `http::HeaderMap`-shaped input could not represent them anyway (see the crate root's "honest
//! limit of byte-exact" section). Every regular field is written in the order given, verbatim name
//! and value bytes, duplicates included. No case-folding, no comma-joining a duplicate away, no
//! reordering. That guarantee is total for the input list; it says nothing about pseudo-headers,
//! which this module never sees as fields.
//!
//! **A field name or value containing a bare CR or LF is emitted verbatim, uninspected.**
//! Sanitising it would be a second, silent violation of the exactness guarantee this module exists
//! to provide, for precisely the bytes an operator most wants to see: h2-to-h1 desync via a header
//! value that decodes to two HTTP/1 header lines is a real smuggling primitive, and laundering it
//! here would hide the one thing this renderer is supposed to expose. Producing a *self-consistent*
//! record in that case is the caller's job, not this function's — `render_request` and
//! `render_response` are infallible by contract (the egress authoriser and the history renderer
//! must agree on one value-in, bytes-out shape with no error path to diverge over). Today's only
//! caller, `burpsy-proxy`'s h2 relay, builds this list from `http::HeaderValue`, which rejects CR
//! and LF at construction — so the case cannot arise from real traffic yet. A future caller
//! building the list straight from [`crate::hpack::Decoder`] output, which does not restrict byte
//! content, must decide separately (and per the design's §7 malformed-frame surface, deliberately)
//! whether such a field is refused before it ever reaches this module.
//!
//! # `content-length` is reconstructed, not passed through
//!
//! h2 strips `content-length` on the way in — DATA framing carries the length instead — so an
//! incoming field under that name (any case) is dropped and replaced with one computed from the
//! rendered body's actual length. The alternative — keep whatever the peer sent — can only produce
//! bytes that disagree with the body they precede, which is the exact defect this renderer exists
//! to avoid: a record that claims one length and contains another is unparseable in the way that
//! matters most.
//!
//! # `Host` is synthesised only when absent
//!
//! `:authority` has no HTTP/1 analogue of its own; it travels as a `host` field. If the field list
//! already carries one (any case — a peer is free to send both `:authority` and `host`, and that
//! duplication is a finding worth keeping, not tidying away), it is left alone and nothing is
//! added. Otherwise `Host: {authority}` is appended so the record still names a target the way
//! every HTTP/1 tool expects.

use bytes::Bytes;

/// Render an h2 request as `{method} {path} HTTP/2\r\n` followed by the field list, a
/// reconstructed `Content-Length`, and the body — parseable by `burpsy_core::parse` into the same
/// ordered field list it was given (see the module doc for what "same" does and does not cover).
///
/// `HTTP/2` is a label, not a transport switch: nothing downstream routes on it, because
/// `Exchange.protocol` already carries that decision. Writing `HTTP/1.1` here would claim the
/// wire spoke a protocol it did not.
pub fn render_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(Bytes, Bytes)],
    body: &[u8],
) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/2\r\n").as_bytes());

    let mut saw_host = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b"content-length") {
            continue; // reconstructed below from the actual body length
        }
        if name.eq_ignore_ascii_case(b"host") {
            saw_host = true;
        }
        write_field(&mut out, name, value);
    }
    if !saw_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(authority.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Render an h2 response as `HTTP/2 {status}\r\n` followed by the field list, a reconstructed
/// `Content-Length`, and the body. No reason phrase, ever — h2 has none to give one, and
/// `burpsy_core::parse` tolerates a missing third start-line token.
pub fn render_response(status: u16, headers: &[(Bytes, Bytes)], body: &[u8]) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/2 {status}\r\n").as_bytes());

    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b"content-length") {
            continue; // reconstructed below from the actual body length
        }
        write_field(&mut out, name, value);
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Append one `name: value\r\n` line, verbatim — see the module doc's exactness section for why
/// this does not case-fold, reorder, or inspect the bytes it is given.
fn write_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    #[test]
    fn duplicate_field_names_field_order_and_unusual_casing_survive_a_request_render() {
        let headers = [(b("X-Foo"), b("1")), (b("x-foo"), b("2")), (b("Set-COOKIE"), b("a=b"))];
        let out = render_request("GET", "/x", "example.com", &headers, b"hi");
        assert_eq!(
            &out[..],
            b"GET /x HTTP/2\r\n\
              X-Foo: 1\r\n\
              x-foo: 2\r\n\
              Set-COOKIE: a=b\r\n\
              Host: example.com\r\n\
              Content-Length: 2\r\n\
              \r\n\
              hi"
                .as_slice(),
            "two X-Foo lines with different casing must both survive, in the order given, and the \
             field's own casing must be untouched"
        );
    }

    #[test]
    fn duplicate_field_names_and_casing_survive_a_response_render() {
        let headers = [(b("Set-Cookie"), b("a=1")), (b("set-cookie"), b("b=2"))];
        let out = render_response(204, &headers, b"");
        assert_eq!(
            &out[..],
            b"HTTP/2 204\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nContent-Length: 0\r\n\r\n"
                .as_slice(),
            "both Set-Cookie lines must appear, in order, with their original casing intact"
        );
    }

    #[test]
    fn a_supplied_content_length_disagreeing_with_the_body_is_replaced_by_the_true_length() {
        let headers = [(b("Content-Length"), b("999")), (b("X-A"), b("1"))];
        let out = render_request("POST", "/", "h.example", &headers, b"ab");
        let rendered = String::from_utf8_lossy(&out);
        assert!(
            !rendered.contains("999"),
            "a stale incoming Content-Length must not survive into the record: {rendered:?}"
        );
        assert!(
            rendered.contains("Content-Length: 2\r\n"),
            "the rendered length must match the actual 2-byte body, not the peer's claim: \
             {rendered:?}"
        );
    }

    #[test]
    fn a_content_length_disagreeing_with_the_body_is_also_replaced_on_a_response() {
        let headers = [(b("content-length"), b("0"))];
        let out = render_response(200, &headers, b"hello");
        let rendered = String::from_utf8_lossy(&out);
        assert!(
            rendered.contains("Content-Length: 5\r\n"),
            "the response body is 5 bytes; a stale 0 from the peer must not survive: {rendered:?}"
        );
        assert_eq!(
            rendered.matches("ontent-").count(),
            1,
            "the peer's content-length field and the reconstructed one must not both appear: \
             {rendered:?}"
        );
    }

    #[test]
    fn host_is_synthesised_when_no_host_field_is_present() {
        let headers = [(b("Accept"), b("*/*"))];
        let out = render_request("GET", "/", "target.example:8443", &headers, b"");
        let rendered = String::from_utf8_lossy(&out);
        assert!(
            rendered.contains("Host: target.example:8443\r\n"),
            "with no host field in the list, Host must be synthesised from the authority: \
             {rendered:?}"
        );
    }

    #[test]
    fn host_is_not_synthesised_when_a_host_field_is_already_present_in_any_case() {
        let headers = [(b("hOsT"), b("original.example"))];
        let out = render_request("GET", "/", "different.example", &headers, b"");
        let rendered = String::from_utf8_lossy(&out);
        assert_eq!(
            rendered,
            "GET / HTTP/2\r\nhOsT: original.example\r\nContent-Length: 0\r\n\r\n",
            "an existing host field (any case) must be preserved untouched, and no second Host \
             line synthesised from the (here, deliberately different) authority argument"
        );
    }

    #[test]
    fn a_response_has_no_reason_phrase_ever() {
        let out = render_response(404, &[], b"");
        assert_eq!(
            &out[..],
            b"HTTP/2 404\r\nContent-Length: 0\r\n\r\n".as_slice(),
            "h2 carries no reason phrase, so the start line must stop at the status code"
        );
    }
}
