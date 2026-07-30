//! The h2 egress request as a **value**, and the classifier that decides what a frame program is
//! allowed to ask for.
//!
//! # Why a value and not bytes
//!
//! `Scope::authorise_request` extracts the path with `request_path`, which reads an HTTP/1 start
//! line and returns `None` — meaning *refuse* — for anything else. Hand it an HPACK block and every
//! h2 send is refused. That has to be solved rather than worked around, and the tempting fix is a
//! sibling entry point taking a caller-supplied `path: &str`. That fix is wrong: the existing
//! authoriser reads the outbound bytes precisely because "a caller can name an in-scope host and
//! then write a request line for somewhere else", and a `path` parameter reintroduces exactly that
//! gap with the compiler's blessing.
//!
//! So the egress API takes an [`H2Request`]. The chokepoint renders it through
//! [`burpsy_http2::normalise::render_request`] — the *same* function the proxy uses for its history
//! record — and authorises those bytes. [`H2Request::field_list`] is the sole input to the writer.
//! Authorisation and transmission therefore read the same field of the same value and cannot
//! disagree, and `tests::the_authorised_path_is_the_path_the_writer_encodes` proves it rather than
//! asserting it in prose.

use burpsy_http2::frame::{flags, types};
use burpsy_http2::{Decoder, H2FrameProgram, normalise};
use bytes::Bytes;

/// An h2 request described by its fields, before anything is encoded.
///
/// `scheme` is deliberately absent: it is derived from the connection's TLS state at lowering time,
/// so a caller cannot state `https` and then be sent over cleartext. One less thing that can
/// disagree with the wire.
#[derive(Debug, Clone)]
pub struct H2Request {
    pub method: String,
    /// Origin-form path including any query, e.g. `/search?q=1`. Becomes `:path` verbatim.
    pub path: String,
    /// `host[:port]`. Becomes `:authority` verbatim.
    pub authority: String,
    /// Ordinary fields in caller order, verbatim. Order, duplicates and casing are preserved
    /// because controlling them is the whole point of a testing client.
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Bytes,
}

impl H2Request {
    /// A GET with no extra fields and no body.
    pub fn get(authority: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: "GET".to_string(),
            path: path.into(),
            authority: authority.into(),
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    /// The ordered field list the writer HPACK-encodes: the four pseudo-headers in RFC 9113 §8.3
    /// order, then the caller's fields untouched.
    ///
    /// Pseudo-headers must precede ordinary fields, so they are prepended here rather than left to
    /// the caller to remember. Everything after them is verbatim.
    pub(crate) fn field_list(&self, tls: bool) -> Vec<(Bytes, Bytes)> {
        let scheme = if tls { "https" } else { "http" };
        let mut out = Vec::with_capacity(4 + self.headers.len());
        out.push((
            Bytes::from_static(b":method"),
            Bytes::from(self.method.clone()),
        ));
        out.push((Bytes::from_static(b":scheme"), Bytes::from(scheme)));
        out.push((
            Bytes::from_static(b":authority"),
            Bytes::from(self.authority.clone()),
        ));
        out.push((Bytes::from_static(b":path"), Bytes::from(self.path.clone())));
        out.extend(self.headers.iter().cloned());
        out
    }

    /// The HTTP/1-shaped rendering the authoriser reads, and the same bytes history would store.
    ///
    /// `pub`, not `pub(crate)`: a caller recording its own history entry for an h2 send (the web
    /// crate's Repeater route, so an h2 resend sits in history in the same shape `h2_relay`
    /// produces for captured traffic) needs the exact bytes this authorises, not a second
    /// rendering that could drift from it.
    pub fn render(&self) -> Bytes {
        normalise::render_request(
            &self.method,
            &self.path,
            &self.authority,
            &self.headers,
            &self.body,
        )
    }
}

/// What a frame program's header blocks say it will request.
///
/// Three cases and not two, because "we could not read the headers" is a different authorisation
/// question from "there are no headers", and collapsing them would either refuse legitimate probes
/// or wave through unreadable ones.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProgramPaths {
    /// Every header block decoded. These are the `:path` values, in program order.
    Paths(Vec<String>),
    /// A header block is present but cannot be read as HPACK — a deliberate malformation, a
    /// Huffman-coded string this decoder refuses, or a framing lie. Not a failure: emitting these is
    /// what H2-03 exists for. It does mean the path is unknown.
    Opaque,
    /// No header block at all — a SETTINGS-only or DATA-only probe, say.
    None,
}

/// Read the `:path` values a program will send, or report that they cannot be read.
///
/// One [`Decoder`] across the whole program, not one per block: HPACK's dynamic table is
/// connection-scoped, and a program owns its connection from the first octet, so later blocks
/// legitimately index entries earlier ones inserted. A fresh decoder per block would misread
/// exactly the multi-request programs most worth checking.
///
/// Refuse-by-default drives every uncertain case to [`ProgramPaths::Opaque`], which the caller must
/// then satisfy with whole-host authorisation:
///
/// * `PADDED` or `PRIORITY` set — the payload is not a bare HPACK block (a pad-length octet, or five
///   octets of priority, sit in front) and mis-parsing it would produce a *confident wrong* path,
///   which is worse than admitting ignorance.
/// * `declared_len` disagreeing with the payload — the receiver frames by the declared length, so
///   what it decodes is not what we can see.
/// * Any HPACK error.
pub(crate) fn program_paths(program: &H2FrameProgram) -> ProgramPaths {
    let mut decoder = Decoder::new(4096);
    let mut paths = Vec::new();
    let mut saw_block = false;
    // Header blocks are per-stream: HEADERS opens one and CONTINUATION frames on the same stream
    // extend it until END_HEADERS.
    let mut open: Option<(u32, Vec<u8>)> = None;

    for frame in &program.frames {
        let is_headers = frame.ty == types::HEADERS;
        let is_continuation = frame.ty == types::CONTINUATION;
        if !is_headers && !is_continuation {
            continue;
        }
        saw_block = true;

        if frame
            .declared_len
            .is_some_and(|n| n as usize != frame.payload.len())
        {
            return ProgramPaths::Opaque;
        }
        if is_headers && frame.flags & (flags::PADDED | flags::PRIORITY) != 0 {
            return ProgramPaths::Opaque;
        }
        if is_continuation && frame.flags & flags::PADDED != 0 {
            return ProgramPaths::Opaque;
        }

        // A CONTINUATION for a stream we never opened, or a second HEADERS while one is still open,
        // is a framing violation. Legal to emit, unreadable to us.
        match (&mut open, is_headers) {
            (None, true) => open = Some((frame.stream_id, frame.payload.to_vec())),
            (Some((sid, buf)), false) if *sid == frame.stream_id => {
                buf.extend_from_slice(&frame.payload)
            }
            _ => return ProgramPaths::Opaque,
        }

        if frame.flags & flags::END_HEADERS != 0 {
            let Some((_, buf)) = open.take() else {
                return ProgramPaths::Opaque;
            };
            match decoder.decode(&buf) {
                Ok(fields) => {
                    for (name, value) in fields {
                        if name.as_ref() == b":path" {
                            match std::str::from_utf8(&value) {
                                Ok(p) => paths.push(p.to_string()),
                                // A non-UTF-8 path is legal on the wire and unmatchable by a rule.
                                Err(_) => return ProgramPaths::Opaque,
                            }
                        }
                    }
                }
                Err(_) => return ProgramPaths::Opaque,
            }
        }
    }

    // A block left open at the end of the program never reached END_HEADERS.
    if open.is_some() {
        return ProgramPaths::Opaque;
    }
    if !saw_block {
        return ProgramPaths::None;
    }
    ProgramPaths::Paths(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_http2::{Encoder, FrameSpec};

    fn block_for(fields: &[(Bytes, Bytes)]) -> Bytes {
        Encoder::new(4096).encode(fields)
    }

    fn headers_frame(payload: Bytes, flags: u8) -> FrameSpec {
        FrameSpec {
            ty: types::HEADERS,
            flags,
            stream_id: 1,
            declared_len: None,
            payload,
        }
    }

    fn program(frames: Vec<FrameSpec>) -> H2FrameProgram {
        H2FrameProgram {
            preface: true,
            frames,
            read_for_ms: 10,
        }
    }

    /// The invariant the design asks to be made checkable rather than claimed: whatever path the
    /// authoriser reads out of the rendered bytes is the path the writer puts on the wire. If these
    /// The invariant the design asks to be made checkable rather than claimed: the authoriser and
    /// the writer both read `req.path`, so they cannot be made to disagree. With no query the two
    /// derivations are byte-identical; with a query the authoriser sees the path component (it
    /// stops at `?`), which is a prefix of the full origin-form the wire carries — so the scope
    /// decision is always made on no more than what is actually sent, never on a path that could
    /// be longer than the real one.
    #[test]
    fn the_authorised_path_is_the_path_the_writer_encodes() {
        let req = H2Request {
            method: "POST".to_string(),
            path: "/admin".to_string(),
            authority: "example.com".to_string(),
            headers: vec![(Bytes::from_static(b"accept"), Bytes::from_static(b"*/*"))],
            body: Bytes::from_static(b"hi"),
        };

        let rendered = req.render();
        let authorised = burpsy_core::scope::request_path(&rendered)
            .expect("the rendered request must expose a path to the authoriser");
        let encoded = req.field_list(true);
        let on_the_wire = encoded
            .iter()
            .find(|(n, _)| n.as_ref() == b":path")
            .map(|(_, v)| v.clone())
            .expect("the field list must carry a :path");

        assert_eq!(
            authorised.as_bytes(),
            on_the_wire.as_ref(),
            "with no query, the authoriser and the writer must agree on the exact path, or scope \
             could be checked against one target while another is contacted"
        );

        // The same value with a query: the wire carries the full origin-form, the authoriser the
        // path component, and the latter is a prefix of the former.
        let with_query = H2Request { path: "/admin?x=1".to_string(), ..req };
        let rendered_q = with_query.render();
        let authorised_q = burpsy_core::scope::request_path(&rendered_q)
            .expect("a request with a query still exposes a path");
        let wire_q = with_query
            .field_list(true)
            .into_iter()
            .find(|(n, _)| n.as_ref() == b":path")
            .map(|(_, v)| v)
            .expect("the field list must carry a :path");
        assert_eq!(
            wire_q.as_ref(),
            b"/admin?x=1".as_ref(),
            "the wire must carry the full origin-form, query included"
        );
        assert!(
            wire_q.starts_with(authorised_q.as_bytes()),
            "the authoriser must see a prefix of the path actually sent, so a scope decision can \
             never rest on a path longer than the real one"
        );
    }

    #[test]
    fn pseudo_headers_precede_ordinary_fields_and_scheme_follows_the_connection() {
        let req = H2Request {
            method: "GET".to_string(),
            path: "/".to_string(),
            authority: "h".to_string(),
            headers: vec![(Bytes::from_static(b"a"), Bytes::from_static(b"b"))],
            body: Bytes::new(),
        };

        let tls = req.field_list(true);
        let names: Vec<&[u8]> = tls.iter().map(|(n, _)| n.as_ref()).collect();
        assert_eq!(
            names,
            vec![
                b":method".as_ref(),
                b":scheme".as_ref(),
                b":authority".as_ref(),
                b":path".as_ref(),
                b"a".as_ref()
            ],
            "pseudo-headers must come first and in RFC 9113 order, or a peer rejects the block"
        );
        assert_eq!(tls[1].1.as_ref(), b"https");
        assert_eq!(
            req.field_list(false)[1].1.as_ref(),
            b"http",
            "scheme must follow the actual connection so a caller cannot claim https over cleartext"
        );
    }

    #[test]
    fn a_program_whose_header_block_decodes_reports_every_path_it_requests() {
        let one = block_for(&[(Bytes::from_static(b":path"), Bytes::from_static(b"/first"))]);
        let two = block_for(&[(
            Bytes::from_static(b":path"),
            Bytes::from_static(b"/second"),
        )]);
        let p = program(vec![
            headers_frame(one, flags::END_HEADERS),
            headers_frame(two, flags::END_HEADERS),
        ]);
        assert_eq!(
            program_paths(&p),
            ProgramPaths::Paths(vec!["/first".to_string(), "/second".to_string()]),
            "both paths must be reported, because authorising only the first would let the second \
             reach an unauthorised target"
        );
    }

    #[test]
    fn a_program_with_no_header_block_reports_none_rather_than_an_empty_path_list() {
        let p = program(vec![FrameSpec {
            ty: types::SETTINGS,
            flags: 0,
            stream_id: 0,
            declared_len: None,
            payload: Bytes::new(),
        }]);
        assert_eq!(
            program_paths(&p),
            ProgramPaths::None,
            "no headers is a different authorisation question from headers requesting nothing"
        );
    }

    #[test]
    fn an_undecodable_header_block_is_opaque_rather_than_treated_as_pathless() {
        // 0xff starts a never-terminating prefix integer, so this is not valid HPACK.
        let p = program(vec![headers_frame(
            Bytes::from_static(&[0xff, 0xff, 0xff, 0xff]),
            flags::END_HEADERS,
        )]);
        assert_eq!(
            program_paths(&p),
            ProgramPaths::Opaque,
            "an unreadable block must not be mistaken for one that requests no path"
        );
    }

    #[test]
    fn a_padded_or_prioritised_header_block_is_opaque_because_its_payload_is_not_bare_hpack() {
        let block = block_for(&[(Bytes::from_static(b":path"), Bytes::from_static(b"/x"))]);
        for flag in [flags::PADDED, flags::PRIORITY] {
            let p = program(vec![headers_frame(block.clone(), flags::END_HEADERS | flag)]);
            assert_eq!(
                program_paths(&p),
                ProgramPaths::Opaque,
                "decoding past a pad-length or priority prefix would yield a confidently wrong path"
            );
        }
    }

    #[test]
    fn a_declared_length_that_lies_makes_the_block_opaque() {
        let block = block_for(&[(Bytes::from_static(b":path"), Bytes::from_static(b"/x"))]);
        let mut f = headers_frame(block, flags::END_HEADERS);
        f.declared_len = Some(1);
        assert_eq!(
            program_paths(&program(vec![f])),
            ProgramPaths::Opaque,
            "the receiver frames by the declared length, so what it decodes is not what we can read"
        );
    }

    #[test]
    fn a_block_split_across_continuation_frames_decodes_as_one_block() {
        let block = block_for(&[(Bytes::from_static(b":path"), Bytes::from_static(b"/split"))]);
        let (a, b) = block.split_at(1);
        let p = program(vec![
            headers_frame(Bytes::copy_from_slice(a), 0),
            FrameSpec {
                ty: types::CONTINUATION,
                flags: flags::END_HEADERS,
                stream_id: 1,
                declared_len: None,
                payload: Bytes::copy_from_slice(b),
            },
        ]);
        assert_eq!(
            program_paths(&p),
            ProgramPaths::Paths(vec!["/split".to_string()]),
            "a block split across CONTINUATION must be reassembled before decoding"
        );
    }

    #[test]
    fn a_header_block_left_open_at_the_end_of_the_program_is_opaque() {
        let block = block_for(&[(Bytes::from_static(b":path"), Bytes::from_static(b"/x"))]);
        assert_eq!(
            program_paths(&program(vec![headers_frame(block, 0)])),
            ProgramPaths::Opaque,
            "a block that never reaches END_HEADERS was never fully stated, so its path is unknown"
        );
    }
}
