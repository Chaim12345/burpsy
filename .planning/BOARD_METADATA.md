# Board metadata — burpsy project (CS-6)

This file is the durable, in-repo record of the project/task metadata that was filled in on the
Paperclip board under issue **CS-6 "Enhance project metadata"**. The board fields themselves live in
Paperclip (not in git), so this document mirrors them here so the metadata is reviewable and
version-controlled alongside the code it describes.

Derived from a code + git analysis of this repository: `ROADMAP.md`, `.planning/PROJECT.md`,
`.planning/ROADMAP.md`, `burpsy-go/PORT_STATUS.md`, `burpsy-go/gaps.md`.

## Project

- **Name:** burpsy
- **Repo:** https://github.com/Chaim12345/brpsy (local folder `/root/burpsy-react-ui`)
- **Description (set on the board):**

  > **burpsy** is a from-scratch reimplementation of Burp Suite's core, specified from a teardown of
  > the shipped Burp 2026.7.1 jar (its 21 MontoyaApi subsystems, tool-tab modules, and scanner
  > internals) rather than from marketing docs. It is for security testers who want Burp's
  > capabilities without Burp's JVM memory footprint and Swing latency — usable headless or over SSH.
  >
  > **What it does today (Phases 0–3 shipped):** intercepting HTTP/HTTPS proxy with full byte-exact
  > capture and TLS MITM; scope engine; derived site map; request interception; byte-exact Repeater;
  > Intruder (sniper, battering ram, pitchfork, cluster bomb) behind a rate limiter; supporting tools
  > (Decoder, Comparer, Sequencer, Logger, Organizer, match-and-replace); passive scanning off the
  > proxy hot path; an audit engine (7 dispatch scopes, circuit breakers); a BCheck interpreter
  > (M1–M3) running 232/264 of PortSwigger's published checks, honestly counted; Burp's 183-issue
  > catalog transcribed byte-for-byte; a JSON API and a single-page web UI with no build step; and an
  > MCP server so agents can drive it.
  >
  > **Architecture:** originally written in Rust (`crates/`), now being ported to Go (`burpsy-go/`).
  > Known parity differences are tracked in `burpsy-go/gaps.md`.

## Goal

- **Title:** Ship burpsy: a memory-lean Burp Suite reimplementation
- **ID:** `01c3513d-9318-48ad-8cbc-f6f4a0399569`
- **Success:** the Go port reaches parity with the Rust reference and ships a documented, tested v0.1.
- **Linked to:** the burpsy project, plus issues CS-1 and CS-6.

## Task → goal inventory

| Issue | Title | Status | Goal link |
|---|---|---|---|
| CS-1 | Hire your first engineer and create a hiring plan | done | burpsy goal ✓ |
| CS-6 | Enhance project metadata | in&nbsp;progress | burpsy goal ✓ |
| CS-2 | Engineering foundation & CI baseline | done | company-mission goal (see note) |
| CS-3 | Recon module MVP (scope-gated) | in&nbsp;progress | company-mission goal (see note) |
| CS-4 | Findings model + client report generator | todo | company-mission goal (see note) |
| CS-5 | Harden, test & document v0.1 release | todo | company-mission goal (see note) |

## Roadmap reconciliation (CS-2..CS-5)

The board's CS-2..CS-5 were authored as a *generic* pentest-tooling roadmap. Mapped onto burpsy's
real backlog (`.planning/PROJECT.md` → Active, and `ROADMAP.md`) they correspond to:

- **CS-2 Engineering foundation & CI baseline** → the Go port's build/test/CI plumbing (`burpsy-go/`).
- **CS-3 Recon module MVP** → burpsy's **Crawler** work item (frontier, link/form extraction, crawl
  limits) plus live passive crawl.
- **CS-4 Findings model + report generator** → burpsy's **Reporting** item (HTML/JSON/SARIF backed by
  the 183-issue catalog).
- **CS-5 Harden, test & document v0.1** → the goal's explicit "documented, tested v0.1" exit.

So these tasks are *adjacent to* burpsy rather than unrelated; they only need their names/descriptions
tightened to burpsy's vocabulary and their goal link repointed onto the burpsy goal.

## Open items I could not action (outside my authorization boundary)

These require the board owner or the issues' owning agent (`6c113583-0763-4c36-803d-354d1fa30a00`):

1. **Repoint CS-2..CS-5** from the company-mission goal onto the burpsy goal — the issues API returns
   `403 "Issue is outside this actor's authorization boundary"` for this actor.
2. **Rewrite CS-2..CS-5** descriptions to burpsy's real roadmap vocabulary (same boundary).
3. **Fix the company goal typos** ("pentesting and pentesting tools and genral securty reserch…") —
   the goals API exposes no update route; needs a board-UI edit.
