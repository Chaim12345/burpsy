//! burpsy-browser — a browser process burpsy spawns and owns, not one the operator configures.
//!
//! # Why this crate exists, and why it opens no socket of its own
//!
//! `sender` is "the one authorising path from a constructed request to a socket" — every request
//! this project *builds* (Repeater, Intruder, the scanner) goes through `AuthorisedSender`, which
//! checks [`burpsy_core::Scope`] against the actual outbound bytes before it reaches a transport.
//! A crawler needs something structurally different: it does not construct requests at all. It
//! drives a real browser, and the browser decides what bytes to send — redirects, `fetch()` calls,
//! service workers, prefetches a page triggers on its own. There is no "constructed request" for
//! `Scope::authorise_request` to inspect.
//!
//! So this crate takes the same shape `sender`'s own docs use to justify the proxy's MITM relay
//! being outside its chokepoint: a spawned browser's traffic is **configured to egress through
//! burpsy's own proxy listener** (`--proxy-server=host:port` at launch), the same way ZAP's AJAX
//! Spider and Client Spider both do. Scope enforcement for that traffic lives where it already
//! lives — the proxy deciding what gets captured, and `Scope` at every attack path — not here.
//! This crate is not itself an egress path in the sense `sender/tests/no_alternate_egress.rs`
//! polices; it launches an operating-system process, and that process's TCP connections are the
//! browser's, not bytes this crate assembled and sent.
//!
//! # Why real Chromium, not a from-scratch Rust engine, right now
//!
//! Several from-scratch options exist (Servo, as of its April 2026 `servo` 0.1.0 embeddable
//! release; Obscura and BrowserOxide, both V8-via-`deno_core`). None is adopted here yet:
//!
//! * Servo's embedding API is documented for GUI pixel readback (screenshot/PDF generation), and
//!   whether it exposes the headless automation primitives a crawler needs — script evaluation,
//!   DOM introspection, network-event hooks — with CDP-equivalent fidelity is unconfirmed. That
//!   needs a small spike against the Servo Book before it can replace this crate's engine.
//! * Obscura and BrowserOxide are single-maintainer, pre-1.0, and neither has a confirmed
//!   crates.io publish or a real layout/paint pipeline as far as could be verified — meaning no
//!   confirmed headed mode or screenshot support, which the live-view requirement (below) needs.
//! * Lightpanda is ruled out entirely for this crate: it has no paint/compositor pipeline at all,
//!   so headed mode and `Page.startScreencast`-equivalent output are architecturally impossible,
//!   not just unimplemented.
//!
//! Real Chromium via `chromiumoxide` is the only option that is provable *today*: a genuine CDP
//! implementation, headed-mode support proven to defeat anti-bot fingerprinting better than
//! headless Chrome, and `Page.startScreencast`/`screencastFrame` for the live view a human
//! operator needs when a target fights back. If a from-scratch engine's automation surface is
//! later confirmed sufficient, it becomes a second variant here — not a rewrite of this module,
//! because [`BrowserSession`]'s public surface (`goto`, `content`, `screenshot`) is already the
//! engine-agnostic shape a second implementation would need to satisfy.
//!
//! # What is not built yet
//!
//! `Page.startScreencast` (the live-view relay into the web UI) is deliberately not in this first
//! cut. Stubbing it out with a function that returns nothing meaningful would be a worse failure
//! than not having it: this project counts coverage honestly, and a fake screencast is a defect,
//! not a placeholder. It is recorded here as the next real piece of work, not as a TODO buried in
//! a function body.

use anyhow::{Context, Result};
use chromiumoxide::browser::{Browser, BrowserConfig as CdpBrowserConfig, HeadlessMode};
use futures::StreamExt;
use std::net::SocketAddr;
use std::path::PathBuf;

/// How to launch the spawned browser process.
///
/// Deliberately holds no [`burpsy_core::Scope`] — this crate does not make authorisation
/// decisions, it only wires the browser's traffic to the place that already does (see the module
/// header). A caller that wants scope-aware navigation composes this with `burpsy-crawler`'s
/// `Frontier`, which checks scope *before* ever calling [`BrowserSession::goto`].
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// burpsy's own proxy listener. When set, the spawned process is launched with
    /// `--proxy-server` pointed at it, so its HTTP(S) traffic lands in `TrafficStore` the same way
    /// ordinary browsing does.
    pub proxy: Option<SocketAddr>,
    /// Trust burpsy's own CA for TLS interception. Without this, every HTTPS navigation through
    /// the proxy fails a certificate check the browser is right to make.
    pub ca_cert_path: Option<PathBuf>,
    /// Headed (visible, under a real or virtual display) vs headless. Headed measurably defeats
    /// more anti-bot fingerprinting and is required for the live-view feature; headless is the
    /// default because most crawl targets don't need it and it costs less.
    pub headed: bool,
    /// Explicit path to a Chromium/Chrome binary. `None` lets `chromiumoxide` search `PATH`.
    pub executable: Option<PathBuf>,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            ca_cert_path: None,
            headed: false,
            executable: None,
        }
    }
}

/// A spawned, burpsy-owned Chromium process and its CDP connection.
///
/// Holds the `chromiumoxide::Browser` handle plus the join handle for the event-loop task that
/// `chromiumoxide` requires running alongside it. Dropping this session lets both end; there is no
/// explicit `close()` because `chromiumoxide::Browser`'s own `Drop` already asks the process to
/// quit, and adding a second shutdown path here would be exactly the "two ways to do one thing"
/// this project's own docs warn against elsewhere (see `sender`'s two-transport rationale for the
/// same argument applied to a different pair of paths).
pub struct BrowserSession {
    browser: Browser,
    handler: tokio::task::JoinHandle<()>,
}

impl BrowserSession {
    /// Launch a new browser process per `config`.
    pub async fn launch(config: &BrowserConfig) -> Result<Self> {
        let mut builder = CdpBrowserConfig::builder();

        builder = if config.headed {
            builder.with_head()
        } else {
            builder.headless_mode(HeadlessMode::New)
        };

        if let Some(exe) = &config.executable {
            builder = builder.chrome_executable(exe);
        }

        let mut args: Vec<String> = Vec::new();
        if let Some(addr) = config.proxy {
            args.push(format!("--proxy-server={addr}"));
        }
        if let Some(ca) = &config.ca_cert_path {
            // Chromium's own flag for trusting an additional root, so the proxy's TLS
            // interception is not rejected as a MITM by the browser it is meant to drive.
            args.push(format!(
                "--ignore-certificate-errors-spki-list={}",
                ca.display()
            ));
        }
        if !args.is_empty() {
            builder = builder.args(args.iter().map(String::as_str));
        }

        let cdp_config = builder
            .build()
            .map_err(anyhow::Error::msg)
            .context("building chromiumoxide launch config")?;

        let (browser, mut handler_stream) = Browser::launch(cdp_config)
            .await
            .context("spawning browser process")?;

        // chromiumoxide requires its event stream to be polled continuously or CDP responses
        // never resolve. This task is the browser's heartbeat, not incidental logging.
        let handler = tokio::spawn(async move {
            while let Some(event) = handler_stream.next().await {
                if let Err(e) = event {
                    tracing::debug!(error = %e, "chromiumoxide handler event error");
                }
            }
        });

        Ok(Self { browser, handler })
    }

    /// Navigate a fresh page to `url` and wait for it to finish loading.
    pub async fn goto(&self, url: &str) -> Result<chromiumoxide::Page> {
        let page = self
            .browser
            .new_page(url)
            .await
            .with_context(|| format!("navigating to {url}"))?;
        page.wait_for_navigation()
            .await
            .with_context(|| format!("waiting for {url} to finish loading"))?;
        Ok(page)
    }

    /// The rendered page's current HTML, after JS execution — what a crawler diffs against the
    /// raw response the proxy already captured, to find DOM-injected links a static parse can't.
    pub async fn content(&self, page: &chromiumoxide::Page) -> Result<String> {
        page.content().await.context("reading page content")
    }

    /// PNG screenshot of the current page. The first, minimal proof that this engine's paint
    /// pipeline works — the same capability the eventual live-view screencast builds on.
    pub async fn screenshot(&self, page: &chromiumoxide::Page) -> Result<Vec<u8>> {
        page.screenshot(chromiumoxide::page::ScreenshotParams::builder().build())
            .await
            .context("capturing screenshot")
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        self.handler.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chromium_available() -> Option<PathBuf> {
        for candidate in ["/usr/local/bin/chromium", "/usr/bin/google-chrome-stable"] {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// This is the one test that actually spawns a process and drives real CDP — everything else
    /// in this crate is a thin wrapper, and the wrapper is only worth trusting if this passes.
    #[tokio::test]
    async fn a_headless_session_can_launch_navigate_and_read_content() {
        let Some(exe) = chromium_available() else {
            eprintln!("skipping: no chromium/chrome binary found on this machine");
            return;
        };
        let config = BrowserConfig {
            executable: Some(exe),
            ..Default::default()
        };
        let session = BrowserSession::launch(&config)
            .await
            .expect("chromium must launch headless");
        let page = session
            .goto("data:text/html,<html><body><h1 id=x>hi</h1></body></html>")
            .await
            .expect("data: URL navigation must succeed");
        let html = session.content(&page).await.expect("content must be readable");
        assert!(
            html.contains("id=\"x\"") || html.contains("id='x'"),
            "rendered content missing expected element: {html}"
        );
    }
}
