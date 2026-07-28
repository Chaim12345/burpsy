//! The backstop for HARD-03: no crate but this one opens a socket for a constructed request.
//!
//! # Why a source scan and not a type
//!
//! Exactly one of the three routes to the network is closed structurally: the transports in this
//! crate are `pub(crate)`, so nothing outside can reach them.
//!
//! The other two are not, and it is worth being precise about why, because the obvious fix does not
//! work here:
//!
//! * `std::net::TcpStream` is in the standard library, reachable from any crate, ungated by any
//!   Cargo feature. Nothing in the type system or the build graph can close it.
//! * `tokio::net` looks closeable by narrowing features, and `intruder` does narrow them — but
//!   cargo unifies features across the dependency graph. `web`, `sender` and `cli` all enable
//!   `tokio`'s `full`, so one tokio rlib is compiled with `net` present and every crate linking it
//!   can name `tokio::net` again. Narrowing only bites under `cargo build -p burpsy-intruder`.
//!   Measured, not assumed: a `tokio::net::TcpStream::connect` added to `intruder` fails an isolated
//!   build and compiles cleanly under `cargo build --workspace`.
//!
//! So this test is the primary mechanism for both, not a supplement covering only `std::net`. A test
//! is weaker than a compile error and this file does not pretend otherwise. What it buys is that the
//! drift is caught in CI on the commit that introduces it, naming the line and the reason, rather
//! than in a review six months later.
//!
//! # What it deliberately does not scan
//!
//! **`#[cfg(test)]` modules are stripped before scanning.** Test code legitimately opens listeners
//! and sockets to prove traffic did or did not reach the wire — that is the same reason
//! `burpsy_bcheck::eval::Sender` is not sealed. Scanning them would make the test fire constantly
//! and get deleted, which is worse than scoping it honestly.
//!
//! **`examples/` and `tests/` are not scanned**, for the same reason.

use std::path::{Path, PathBuf};

/// Call shapes that mean "a socket is being opened".
const EGRESS: &[&str] = &[
    "TcpStream::connect",
    "TlsConnector::connect",
    "ClientConnection::new",
];

/// Production sites outside this crate that are allowed to open a socket, and why.
///
/// Every entry is a considered decision, not a suppression. A new hit that is not listed here fails
/// the build; adding to this list should require the same argument the existing entry makes.
const ALLOWED: &[(&str, &str)] = &[(
    "crates/proxy/src/lib.rs",
    "MITM upstream forwarding. The proxy relays the client's *own* bytes for ordinary browsing — not \
     a constructed request — and Scope there governs whether an exchange is paused for operator \
     review, never whether it is forwarded. Putting browsing traffic behind an authorisation gate \
     would turn the proxy into a blocklist, which is not what it is for.",
)];

#[test]
fn no_crate_outside_the_chokepoint_opens_a_socket_for_a_constructed_request() {
    let root = workspace_root();
    let mut offences: Vec<String> = Vec::new();

    for file in rust_sources_under(&root.join("crates")) {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");

        // This crate *is* the chokepoint; its transports are the intended egress.
        if rel.starts_with("crates/sender/") {
            continue;
        }
        if ALLOWED.iter().any(|(path, _)| rel == *path) {
            continue;
        }

        let src = std::fs::read_to_string(&file).expect("read source");
        let production = strip_cfg_test_modules(&src);

        for (i, line) in production.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            for pattern in EGRESS {
                if code.contains(pattern) {
                    offences.push(format!(
                        "{rel}:{} — {pattern}\n      {}",
                        i + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "\n{} production site(s) outside burpsy-sender open a socket directly:\n\n    {}\n\n\
         Every constructed request must go through burpsy_sender::AuthorisedSender, which checks \
         Scope::authorise_request against the actual outbound bytes before reaching a transport. If \
         one of these is genuinely not a constructed request — the way the proxy's MITM forwarding \
         is not — add it to ALLOWED in this file with the argument for why.\n",
        offences.len(),
        offences.join("\n    ")
    );
}

/// The allowlist must describe reality: an entry naming a file that no longer opens a socket is
/// stale permission, and stale permission is how a list like this stops meaning anything.
#[test]
fn every_allowlist_entry_still_names_a_real_egress_site() {
    let root = workspace_root();
    for (path, reason) in ALLOWED {
        let full = root.join(path);
        assert!(
            full.exists(),
            "allowlist names {path}, which does not exist — remove the entry"
        );
        let src = std::fs::read_to_string(&full).expect("read allowlisted source");
        let production = strip_cfg_test_modules(&src);
        assert!(
            EGRESS.iter().any(|p| production.contains(p)),
            "allowlist grants {path} permission to open a socket, but it no longer does — remove \
             the entry rather than leaving unused permission behind.\n  stated reason: {reason}"
        );
    }
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sender; the workspace is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/sender")
        .to_path_buf()
}

/// Every `.rs` file under a crate's `src/`, skipping `examples/`, `tests/` and `target/`.
fn rust_sources_under(crates_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(crates_dir).expect("read crates dir");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Remove `#[cfg(test)]`-gated modules, by brace counting from the `{` that opens the item.
///
/// Deliberately conservative: if the opening brace cannot be found, the text is left in place, so a
/// parse failure means the scan errs toward reporting rather than toward silence.
fn strip_cfg_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;

    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at..];
        let Some(open) = after.find('{') else {
            // No block to strip (e.g. a `#[cfg(test)]` on a `use`). Keep going past the attribute.
            out.push_str(&after[..12]);
            rest = &after[12..];
            continue;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => rest = &after[e..],
            None => {
                // Unbalanced braces: keep the remainder so nothing is silently dropped.
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn the_scanner_strips_test_modules_and_keeps_production_code() {
    let src = r#"
fn production() { let _ = TcpStream::connect("a"); }

#[cfg(test)]
mod tests {
    fn helper() { let _ = TcpStream::connect("b"); if true { } }
}

fn also_production() { }
"#;
    let stripped = strip_cfg_test_modules(src);
    assert!(
        stripped.contains(r#"TcpStream::connect("a")"#),
        "production code must survive"
    );
    assert!(
        !stripped.contains(r#"TcpStream::connect("b")"#),
        "test-module code must be stripped, including past nested braces"
    );
    assert!(
        stripped.contains("also_production"),
        "code after the module must survive"
    );
}
