//! burpsy-sender — the one authorising path from a constructed request to a socket.
//!
//! # Why this crate exists
//!
//! Before it, every surface that built a request was individually responsible for remembering to
//! ask [`Scope`] whether it was allowed. The scanner did it correctly, in a private wrapper.
//! `repeater::send` was a public async function with no scope awareness at all, and both of its
//! callers hand-wired a check around it — one inline, one through an `Option`al guard closure that
//! compiled fine when you forgot to attach it. Three independent places to get the same thing
//! right is three places it can drift, and "did the new surface remember to check scope?" was a
//! question only a reviewer could answer.
//!
//! [`AuthorisedSender`] makes it a question the type system answers for constructed requests. It
//! owns the transports as private fields, so there is no public path to a socket that does not pass
//! through [`Scope::authorise_request`] first.
//!
//! # What that guarantee is, exactly
//!
//! Stated honestly, because overclaiming here would be worse than not claiming it:
//!
//! * **Structural, for this crate's transports.** The transports are `pub(crate)`. Nothing outside
//!   can construct or reach them, so the scope check cannot be skipped by a caller who forgets.
//!   This is the part that genuinely holds at the type level.
//! * **Not structural for `std::net`.** `std::net::TcpStream` is in the standard library and is
//!   reachable from any crate regardless of Cargo features. Nothing at the type or feature level can
//!   close it.
//! * **Not structural for `tokio::net` either — and this was measured, not assumed.** `intruder`
//!   narrows its `tokio` features so `net` is absent, and that *does* fail to compile a
//!   `tokio::net::TcpStream` under `cargo build -p burpsy-intruder`. It does **not** hold under
//!   `cargo build --workspace`: cargo unifies features across the graph, `web`/`sender`/`cli` enable
//!   `tokio`'s `full`, so one tokio rlib is compiled with `net` and every crate linking it can name
//!   `tokio::net` again. Verified by adding a `tokio::net::TcpStream::connect` to `intruder` and
//!   watching the workspace build succeed. The narrowing is kept because it records intent and
//!   catches the mistake in an isolated build, but it is not the guarantee earlier notes on this
//!   phase claimed it was.
//!
//! So `tests/no_alternate_egress.rs` is the **primary** mechanism for both `std::net` and
//! `tokio::net`, not a supplement covering only the former. It reads the source and fails the build
//! when a new connect call appears outside this crate. A test is weaker than a compile error, and
//! describing it as one would be exactly the "looks done but isn't" claim this project rejects.
//!
//! The proxy's own upstream forwarding is deliberately **outside** this chokepoint, and that is a
//! considered boundary rather than an omission. It relays the client's own bytes for ordinary
//! browsing — not a constructed request in the sense HARD-03 means — and `Scope` there governs
//! whether an exchange is paused for operator review, never whether it is forwarded. Putting
//! browsing traffic behind an authorisation gate would turn the proxy into a blocklist, which is
//! not what it is for.
//!
//! # Deliberately not a sealed trait
//!
//! [`burpsy_bcheck::eval::Sender`] stays open. It is implemented by test doubles across the
//! workspace precisely so tests can prove traffic did or did not reach a socket, and sealing it
//! would destroy the mechanism that makes this feature testable. The property worth enforcing is
//! "nothing reaches a *real* socket except through here", which is a private-field property, not a
//! sealed-trait one.

mod transport;

use burpsy_core::Scope;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Re-exported so a caller can reach the blocking send without depending on `burpsy-bcheck` for a
/// trait. The blocking path exists only as this impl, and a second inherent method beside it would
/// be a second way to do the one thing the chokepoint is supposed to have exactly one way to do.
pub use burpsy_bcheck::eval::Sender;
pub use burpsy_bcheck::eval::Target;
pub use transport::blocking::NetSender;
pub use transport::net::SendResult;

/// Default per-send ceiling for the async path.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Parse `host:port`, `https://host/path`, or a bare host into a [`Target`].
///
/// Lives here rather than beside a transport because a target is what a caller states *before*
/// asking to send, and the chokepoint is the only thing that then acts on it.
pub fn parse_target(s: &str) -> anyhow::Result<Target> {
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        (false, s)
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(if tls { 443 } else { 80 })),
        None => (hostport, if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        anyhow::bail!("empty host in target {s:?}");
    }
    Ok(Target {
        host: host.to_string(),
        port,
        tls,
    })
}

/// Why a send did not produce a response.
///
/// The two cases are kept apart because callers must be able to tell them apart: a refusal is the
/// authorisation gate doing its job and nothing left the machine, while a transport failure means
/// scope allowed the request and the network or the peer went wrong. Collapsing both into one error
/// would make an out-of-scope request indistinguishable from a broken server, which is exactly the
/// distinction an operator needs.
#[derive(Debug)]
pub enum SendError {
    /// Scope refused it. Nothing was sent.
    Refused(String),
    /// Scope allowed it; the network or the peer failed.
    Transport(anyhow::Error),
}

impl SendError {
    /// True when the authorisation gate refused, so nothing reached a socket.
    pub fn is_refused(&self) -> bool {
        matches!(self, SendError::Refused(_))
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Refused(why) => write!(f, "{why}"),
            SendError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SendError {}

/// Which wire implementation an [`AuthorisedSender`] uses.
///
/// Private on purpose: the variants name the two transports, and exposing them would hand callers a
/// way to talk about the transport without going through the scope check.
enum Transport {
    /// Blocking `std::net` + `rustls`, with a keep-alive pool. Serves the synchronous BCheck
    /// evaluator.
    Blocking(NetSender),
    /// `tokio` + `tokio-rustls`. Serves Repeater and Intruder.
    Async { timeout: Duration },
}

/// The only authorising path from a constructed request to a socket.
///
/// `scope` is bound at construction and never swapped out. Every send asks it first; a refusal is
/// counted and returned, and the transport is never reached.
pub struct AuthorisedSender {
    scope: Arc<Scope>,
    transport: Transport,
    // Atomics, not `Cell`. The wrapper this generalises used `Cell<u32>`, which compiled only
    // because it was built fresh per audit item and never shared. This type is meant to be held
    // behind one `Arc` across concurrent scanner/repeater/intruder callers, and `Cell` is not
    // `Sync` — carrying that pattern over unchanged would have failed to compile the first time two
    // callers shared one.
    sent: AtomicU32,
    refused: AtomicU32,
}

impl AuthorisedSender {
    /// A blocking sender over the given transport, for the synchronous BCheck evaluator.
    pub fn blocking(scope: Arc<Scope>, net: NetSender) -> Self {
        Self {
            scope,
            transport: Transport::Blocking(net),
            sent: AtomicU32::new(0),
            refused: AtomicU32::new(0),
        }
    }

    /// An async sender, for Repeater and Intruder.
    pub fn asynchronous(scope: Arc<Scope>, timeout: Duration) -> Self {
        Self {
            scope,
            transport: Transport::Async { timeout },
            sent: AtomicU32::new(0),
            refused: AtomicU32::new(0),
        }
    }

    /// Requests that passed scope and were handed to the transport.
    pub fn sent(&self) -> u32 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Requests refused for being out of scope. Never reached a socket.
    pub fn refused(&self) -> u32 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The scope this sender authorises against.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Ask what scope would say, without sending and without touching the counters.
    ///
    /// For callers that need the answer *before* they do something else — the web repeater records
    /// the request in history first, and an out-of-scope request should not land there at all. This
    /// is a query, not the gate: the gate is inside every send and runs regardless of whether anyone
    /// called this. Skipping it can change what gets logged; it cannot get an unauthorised request
    /// onto the wire.
    pub fn check_scope(&self, target: &Target, raw: &[u8]) -> Result<(), String> {
        self.scope
            .authorise_request(&target.host, target.port, target.tls, raw)
    }

    /// The scope decision, in one place.
    ///
    /// Note what is checked: the actual outbound bytes, not the target that was named. A caller can
    /// name an in-scope host and then write a request line for somewhere else, so authorising the
    /// bytes is the only version of this check that means anything.
    fn authorise(&self, target: &Target, raw: &[u8]) -> Result<(), String> {
        match self
            .scope
            .authorise_request(&target.host, target.port, target.tls, raw)
        {
            Ok(()) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(why) => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                Err(why)
            }
        }
    }

    /// Send raw bytes, asynchronously.
    ///
    /// Errors if this sender was built for the blocking transport — the two are not
    /// interchangeable, and silently bridging between them with a blocking runtime call would undo
    /// the reason the blocking path exists.
    pub async fn send_async(&self, target: &Target, raw: &[u8]) -> Result<SendResult, SendError> {
        let timeout = match &self.transport {
            Transport::Async { timeout } => *timeout,
            Transport::Blocking(_) => {
                return Err(SendError::Transport(anyhow::anyhow!(
                    "this AuthorisedSender was built for the blocking transport; use send() instead \
                     of send_async()"
                )));
            }
        };
        self.authorise(target, raw).map_err(SendError::Refused)?;
        transport::net::send(target, raw, timeout)
            .await
            .map_err(SendError::Transport)
    }
}

/// So the scanner's audit path — which takes a `&dyn Sender` — gets the scope check for free.
///
/// This is the whole point of the migration: the scanner no longer needs its own wrapper to
/// remember the check, because the thing it is handed cannot skip it.
impl Sender for AuthorisedSender {
    fn send(&self, target: &Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        // Transport mismatch is checked before authorising, so a caller's programming error never
        // lands in the sent/refused counters — those exist to describe traffic decisions, and a
        // request that was never eligible to go anywhere is neither.
        let Transport::Blocking(net) = &self.transport else {
            return Err(
                "this AuthorisedSender was built for the async transport; use send_async() instead \
                 of the blocking Sender impl"
                    .to_string(),
            );
        };
        self.authorise(target, raw)?;
        net.send(target, raw)
    }
}

impl std::fmt::Debug for AuthorisedSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorisedSender")
            .field(
                "transport",
                &match &self.transport {
                    Transport::Blocking(_) => "blocking",
                    Transport::Async { .. } => "async",
                },
            )
            .field("sent", &self.sent())
            .field("refused", &self.refused())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::ScopeRule;

    fn scope_of(host: &str) -> Arc<Scope> {
        let mut s = Scope::new();
        s.add(ScopeRule::include(host));
        Arc::new(s)
    }

    fn target(host: &str) -> Target {
        Target {
            host: host.to_string(),
            port: 443,
            tls: true,
        }
    }

    #[test]
    fn an_out_of_scope_request_is_refused_and_counted_without_reaching_a_transport() {
        let s = AuthorisedSender::blocking(scope_of("shop.test"), NetSender::default());
        let err = s
            .send(
                &target("evil.test"),
                b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            )
            .expect_err("out of scope must be refused");
        assert!(
            err.contains("evil.test"),
            "the refusal must name what was refused: {err}"
        );
        assert_eq!(s.refused(), 1);
        assert_eq!(s.sent(), 0, "a refused request must not count as sent");
    }

    /// The path is taken from the request bytes, not from anything the caller said alongside them.
    ///
    /// This is the property that matters for an Intruder payload spliced into a path position or a
    /// BCheck `replacing path:` — the host is in scope, and the request still has to be refused
    /// because of where the *bytes* point. Note the bound: `authorise_request` pairs the path it
    /// reads with the host it was given, so it does not re-derive the host from an absolute request
    /// URI. That is a property of `Scope`, not of this gate, and worth not overclaiming here.
    #[test]
    fn the_path_that_is_judged_comes_from_the_request_bytes() {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("shop.test"));
        scope.add(ScopeRule::exclude("shop.test").with_path_prefix("/admin"));
        let s = AuthorisedSender::blocking(Arc::new(scope), NetSender::default());

        // Same named target both times; only the bytes differ. The in-scope case is checked without
        // sending, so this test never touches DNS or a socket.
        assert!(
            s.check_scope(
                &target("shop.test"),
                b"GET /search?q=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"
            )
            .is_ok(),
            "an in-scope path must be allowed"
        );

        let err = s
            .send(
                &target("shop.test"),
                b"POST /admin/delete-all HTTP/1.1\r\nHost: shop.test\r\n\r\n",
            )
            .expect_err("an excluded path must be refused");
        assert!(
            err.contains("/admin/delete-all"),
            "the refusal must name the path it read from the bytes: {err}"
        );
        assert_eq!(s.refused(), 1);
    }

    #[test]
    fn a_request_with_no_readable_start_line_is_refused_rather_than_waved_through() {
        let s = AuthorisedSender::blocking(scope_of("shop.test"), NetSender::default());
        assert!(s.send(&target("shop.test"), b"\x00\x01garbage").is_err());
        assert_eq!(s.refused(), 1);
    }

    #[tokio::test]
    async fn the_async_path_refuses_out_of_scope_bytes_before_connecting() {
        let s = AuthorisedSender::asynchronous(scope_of("shop.test"), DEFAULT_SEND_TIMEOUT);
        // 127.0.0.1:1 would fail to connect anyway; the point is that the refusal happens first, so
        // the error names scope rather than a connection failure.
        let err = s
            .send_async(
                &Target {
                    host: "evil.test".into(),
                    port: 1,
                    tls: false,
                },
                b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            )
            .await
            .expect_err("out of scope must be refused");
        let msg = err.to_string();
        assert!(msg.contains("evil.test"), "got: {msg}");
        assert!(
            !msg.contains("connect"),
            "the scope check must run before any connect attempt: {msg}"
        );
        assert_eq!(s.refused(), 1);
    }

    #[tokio::test]
    async fn the_two_transports_are_not_interchangeable() {
        let blocking = AuthorisedSender::blocking(scope_of("shop.test"), NetSender::default());
        let err = blocking
            .send_async(
                &target("shop.test"),
                b"GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n",
            )
            .await
            .expect_err("a blocking sender has no async path");
        assert!(err.to_string().contains("blocking transport"));

        let asynchronous =
            AuthorisedSender::asynchronous(scope_of("shop.test"), DEFAULT_SEND_TIMEOUT);
        let err = Sender::send(
            &asynchronous,
            &target("shop.test"),
            b"GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n",
        )
        .expect_err("an async sender has no blocking path");
        assert!(err.contains("async transport"));

        // Neither mistake touches the counters: they describe traffic decisions, and a request that
        // was never eligible to go anywhere is neither sent nor refused.
        assert_eq!(blocking.sent(), 0);
        assert_eq!(blocking.refused(), 0);
        assert_eq!(asynchronous.sent(), 0);
        assert_eq!(asynchronous.refused(), 0);
    }

    #[test]
    fn an_in_scope_request_passes_the_gate_and_is_counted() {
        // Port 1 on localhost refuses fast, so this exercises "scope allowed it, the transport was
        // reached, the network said no" — which must read as a transport error, not a refusal.
        let s = AuthorisedSender::blocking(scope_of("127.0.0.1"), NetSender::default());
        let t = Target {
            host: "127.0.0.1".into(),
            port: 1,
            tls: false,
        };
        let result = s.send(&t, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(result.is_err(), "nothing is listening on port 1");
        assert_eq!(s.sent(), 1, "scope allowed it, so it counts as sent");
        assert_eq!(
            s.refused(),
            0,
            "a connection failure is not a scope refusal"
        );
    }

    #[test]
    fn a_target_parses_from_a_url_a_host_port_or_a_bare_host() {
        let t = parse_target("https://example.test/a/b").expect("url");
        assert_eq!(
            (t.host.as_str(), t.port, t.tls),
            ("example.test", 443, true)
        );
        let t = parse_target("h.test:8080").expect("host:port");
        assert_eq!((t.host.as_str(), t.port, t.tls), ("h.test", 8080, false));
        let t = parse_target("http://h.test").expect("http url");
        assert_eq!((t.host.as_str(), t.port, t.tls), ("h.test", 80, false));
        assert!(
            parse_target("http://").is_err(),
            "an empty host is not a target"
        );
    }

    /// The reason the transport is raw TCP rather than a typed client: request smuggling and
    /// parser-differential work depend on the bytes arriving exactly as typed. Routing them through
    /// the authorisation gate must not change that.
    #[tokio::test]
    async fn the_gate_passes_bytes_through_verbatim() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; 1024];
            let n = sock.read(&mut got).await.unwrap();
            got.truncate(n);
            sock.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
            got
        });

        // Deliberately odd casing, spacing and ordering: must arrive unchanged.
        let raw = b"GeT /x HTTP/1.1\r\nhOsT: verbatim.test\r\nX-Odd:  1 \r\n\r\n";
        let s = AuthorisedSender::asynchronous(scope_of("127.0.0.1"), DEFAULT_SEND_TIMEOUT);
        let t = Target {
            host: "127.0.0.1".into(),
            port: addr.port(),
            tls: false,
        };
        let r = s.send_async(&t, raw).await.expect("send");

        assert_eq!(r.status, Some(201));
        assert!(r.raw_response.ends_with(b"hi"));
        assert_eq!(s.sent(), 1);

        let received = server.await.unwrap();
        assert_eq!(
            &received[..],
            &raw[..],
            "the authorisation gate altered the bytes in transit"
        );
    }

    #[tokio::test]
    async fn a_stalled_peer_is_reported_as_a_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _s = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let s = AuthorisedSender::asynchronous(scope_of("127.0.0.1"), Duration::from_millis(150));
        let t = Target {
            host: "127.0.0.1".into(),
            port: addr.port(),
            tls: false,
        };
        let e = s
            .send_async(&t, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect_err("must time out");
        assert!(e.to_string().contains("timeout"), "got: {e}");
    }

    #[test]
    fn a_sender_can_be_shared_across_threads() {
        // The `Cell` -> `AtomicU32` correction is what makes this compile at all; it is a test
        // because the failure mode is a compile error that only appears once something shares one.
        let s = Arc::new(AuthorisedSender::blocking(
            scope_of("shop.test"),
            NetSender::default(),
        ));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    let _ = s.send(&target("evil.test"), b"GET / HTTP/1.1\r\n\r\n");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
        assert_eq!(
            s.refused(),
            100,
            "every refusal across every thread counted"
        );
        assert_eq!(s.sent(), 0);
    }
}
