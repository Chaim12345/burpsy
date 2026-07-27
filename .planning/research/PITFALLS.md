# Pitfalls Research

**Domain:** Rust web-security testing platform — attack-tool feature expansion (crawler, plugin
API, MCP server, Bambda/rhai filters, session handling, mmap store, reporting/dashboard)
**Researched:** 2026-07-27
**Confidence:** MEDIUM overall — see per-item confidence; several claims are single-source and
marked LOW rather than laundered into MEDIUM

**Scope note:** every item below concerns work not yet started in this codebase (crawler, plugin
API, MCP server, Bambda, session handling, mmap store, reporting, dashboard, WebSockets). Nothing
here restates `.planning/codebase/CONCERNS.md` — the O(n²) `set_response` scan, the `debug_assert_eq!`
partition check, the fixture-dependent corpus test, and the three unreviewed branches are that
document's territory and are only referenced here where the *new* surfaces risk repeating the
same class of mistake in code that doesn't exist yet.

**Grounding.** Claims about this project's own current code (scope call sites, function signatures)
are read directly from source and cited by path:line — these are facts, not web claims, and are not
confidence-tagged. Claims about other tools/ecosystems are web research and are tagged
LOW (single source, uncorroborated) or MEDIUM (corroborated across ≥2 independent sources) per the
`classify-confidence` seam. **Never treat a LOW item as authoritative** — it is a lead to verify
against the actual mitmproxy/ZAP/Caido/PortSwigger source or docs before a phase plan relies on it.

---

## Critical Pitfalls

### Pitfall 1: Crawler follows state-changing links and forms with no operator-visible gate

**What goes wrong:**
A crawler that follows every link and submits every form it finds will click logout links, submit
"delete account", "unsubscribe", "cancel order", or admin "delete user" forms, and follow
password-reset/account-recovery flows — during an authorised engagement, against a real target,
with real side effects. This is not hypothetical for this project: a crawler is landing this
milestone with (per the codebase concerns) *no safeguards designed yet*.

**Why it happens:**
Crawling is framed as a link/form *discovery* problem, and "click everything, submit everything"
maximizes coverage. The state-changing risk is orthogonal to coverage and easy to omit from a
first design. GET-only assumptions are also wrong in practice — some applications implement
logout/delete as a plain GET, which no "avoid POST/PUT/DELETE" rule would catch. [MEDIUM — corroborated:
this GET-logout-as-CSRF-surface pattern is documented independently by OWASP's CSRF page and
multiple CSRF write-ups.]

**How to avoid:**
- Form submission must be an explicit, off-by-default toggle, not an implicit consequence of
  crawling (Burp's crawler exposes exactly this as a binary "submit forms" control — [MEDIUM,
  PortSwigger docs]).
- Maintain a link/form denylist by *semantic signal* (link text/form action containing
  logout/signout/delete/remove/unsubscribe/deactivate), not just HTTP method, because destructive
  actions are not reliably gated behind non-GET methods.
- Respect `Scope`'s exclude list as a hard filter on crawl targets, and default-exclude common
  logout/session-teardown paths the way Burp does out of the box [MEDIUM, PortSwigger docs].
- Give the operator a crawl-time report of every form the crawler declined to submit and every
  link it declined to follow, categorized by reason — silently skipping is exactly the "bound
  applied without being reported" failure this project already rejects elsewhere (see PROJECT.md
  Constraints). A crawler that silently avoids destructive paths gives no signal that coverage was
  reduced for safety, which is indistinguishable from a crawl that simply missed them.

**Warning signs:**
- Crawler design doc has a "follow links, submit forms" data flow with no branch for
  destructive/session-ending actions.
- No crawl-summary field reporting forms-not-submitted / links-not-followed with reasons.
- Manual test: point the crawler at a fixture app with a GET-based logout link and an unprotected
  "delete item" form; if the crawl session dies mid-crawl or the item disappears, the gate is missing.

**Phase to address:** Crawler phase (Tool parity leftovers, per PROJECT.md Active list).

---

### Pitfall 2: Session-handling re-authentication becomes an unbounded retry loop

**What goes wrong:**
Session macros / recorded logins that "re-auth on session loss" (a stated requirement in
PROJECT.md's Active list) can spiral: a request fails auth → macro re-logs-in → the *new* session
is also treated as invalid by some stateful check (CSRF token mismatch, one-time-use tokens,
concurrent-session invalidation) → re-auth fires again, indefinitely, generating a stream of login
requests against the real target.

**Why it happens:**
Re-auth-on-loss is reactive by construction: it has no notion of "I already tried this and it
didn't help." Combined with a crawler or scanner that itself retries failed requests, two retry
loops can compound (request fails → session macro retries login → original caller retries the
original request → fails again on a race with token issuance → repeat). ZAP's own docs and issue
tracker document exactly this class of "infinite loop" in spider/active-scan, arising from dynamic
form fields or pages that re-serve the same content for unrecognized paths [MEDIUM — corroborated
across ZAP GitHub issues, mailing list, and official docs].

**How to avoid:**
- Cap re-auth attempts per logical session with a hard ceiling (e.g. 1–2 consecutive re-auths
  before giving up and surfacing an explicit "session handling failed" state to the operator,
  never a silent stall or silent infinite retry).
- Track re-auth *causally* — attach a monotonic session generation counter to outgoing requests so
  a request that already triggered one re-auth in its causal chain cannot trigger a second.
  Treat rapid repeated logins to the same account as an operator-visible event, not a background
  detail — the target's account-lockout mechanism can itself be triggered by the tool's own retry
  behavior (see Pitfall 3).
- Session-handling failure must be a first-class, surfaced state (mirroring the existing
  `AttackPlan::truncated` / `AuditOutcome` pattern of counting and reporting bounds rather than
  swallowing them), not an exception that aborts silently or a loop that never terminates.

**Warning signs:**
- No explicit re-auth attempt counter in the session-macro design.
- Load-test the macro against a fixture with a login endpoint returning a session that fails a
  downstream check; watch request volume to the login endpoint — if it climbs unbounded, the loop
  exists.

**Phase to address:** Session handling phase (Platform, Phase 4 per PROJECT.md).

---

### Pitfall 3: Intruder payload processing chains generate requests the operator never previewed

**What goes wrong:**
The stated requirement is prefix/suffix, case transforms, encode/hash, and match-replace as
chained processing rules, plus loading Burp's own `.pay` lists. Chaining several rules means the
*final* bytes sent are several transformations removed from what the operator typed into the
payload field. A chain that (for example) base64-encodes then URL-encodes then prefixes can
produce a request that legitimately differs from what scope/preview showed, or that repeats the
exact class of bug this project already fixed once: a transformation landing bytes in a position
(e.g. path) that changes which scope rule applies, evaluated *before* the last transformation runs
rather than after.

**Why it happens:**
Payload processing is usually built and tested rule-by-rule; the chained, end-to-end byte sequence
is what actually reaches the network, and it's easy for a scope check or a preview UI to run
against an intermediate representation instead of the fully-processed final bytes — the identical
root cause as the fixed fail-open ("scope checked against the target that was named... rather than
the bytes actually sent"), just relocated to a different pipeline stage.

**How to avoid:**
- The `Metered`-style pattern already used in the scanner (`crates/scanner/src/lib.rs:587-631`,
  calling `Scope::authorise_request` on `raw` bytes at line 624) must be the *only* place Intruder's
  processed payloads are authorised — after every processing rule in the chain has run, never
  before. Any code path that checks scope on a template/pre-processed payload and then applies
  further transforms afterward reintroduces the exact bug class from `ced8e22`.
- Provide operators a "show me the exact bytes for insertion point N after all processing rules"
  preview before firing an attack — chained transforms make eyeballing the payload list
  insufficient without this.
- Test with an intentionally adversarial processing chain (e.g. an encode step that produces `../`
  sequences) to confirm authorisation still runs against final bytes.

**Warning signs:**
- Scope/authorisation call sits before the processing-rule pipeline in the request-construction
  code, rather than immediately before the socket write.
- No test exercises a payload-processing chain whose *output* differs in path/host/authority from
  its unprocessed input.

**Phase to address:** Intruder payload processing phase (Tool parity leftovers, per PROJECT.md).

---

### Pitfall 4: Every new request-originating surface re-derives its own scope check instead of sharing one chokepoint

**What goes wrong (the general principle behind Q2):**
This project's own history shows the shape of the bug: scope authorised against the *named*
target instead of the bytes actually sent. The milestone adds four more places that can originate
or mutate outgoing bytes — crawler, session macros, plugin API, MCP server — each a candidate to
reintroduce the same class of bug independently, because each is naturally built by asking "what
does this feature need to send" rather than "how does this route through the one function that
decides what's allowed to be sent."

**Why it happens:**
Scope enforcement isn't a feature with its own PR — it's a property every sender must inherit.
Every currently-correct call site (repeater, intruder, scanner/BCheck) got there because each was
individually wired to `Scope::authorise_request(host, port, tls, raw)`
(`crates/core/src/scope.rs:238-256`) on the actual outbound bytes. Nothing enforces that a *fifth*
sender does the same thing except code review — precisely the process this project has already
flagged as its weakest link (three of six merged branches unreviewed).

**How to avoid:**
- Treat "may this crate open a socket and write bytes" as a capability, not a default. Structurally,
  the crawler, session-macro executor, plugin backend, and MCP server should not hold a raw
  TCP/TLS sender at all — they should hold a handle to the *one* metered/authorising sender type
  the scanner already uses, so bypassing scope requires bypassing the type system, not just
  forgetting a function call.
- Authorise at the **last point before bytes hit the socket**, strictly after the last thing
  capable of mutating the request (processing chains, plugin rewrite hooks, session-macro
  substitution). If authorisation runs anywhere earlier in a pipeline that can still mutate the
  request afterward, the chokepoint is provably wrong regardless of how careful the code between
  the check and the send appears to be.
- No prior-art shortcut exists here: [LOW confidence, uncorroborated by official security-model
  docs] — public documentation for mitmproxy, ZAP, and Caido plugin/addon boundaries describes
  *capability* (what a plugin's API can do — HTTP calls, intercept hooks, rewriting) but not a
  scope/authorization gate the host process interposes on plugin-originated traffic. mitmproxy
  addons run in-process as Python with direct access to flow objects; Caido backend plugins get an
  SDK with direct HTTP operations; ZAP add-ons run on the JVM classpath. None of the three
  publicly documents an enforced scope boundary between "what the plugin asked for" and "what
  actually goes on the wire" — the plugin *is* trusted code once loaded. Treat this as a genuine
  gap to design for from scratch, not a solved problem to copy; do not represent any of these three
  tools as having a scope chokepoint to model this project's plugin API on.

**Warning signs:**
- Grep for direct `TcpStream`/`TlsStream`/socket-open calls outside the existing metered-sender
  call sites once the crawler/plugin/MCP code lands — any hit is a candidate fifth path.
- A design doc for the plugin API or MCP server that describes "the plugin can send HTTP requests"
  without naming which authorising type mediates that.

**Phase to address:** Cross-cutting — should be settled architecturally *before* the crawler phase
begins (crawler is next in PROJECT.md's Active list and is the first new sender), and re-verified
at the plugin API and MCP phases (Platform, Phase 4; Agent surface, Phase 5).

---

### Pitfall 5: WebSocket traffic authorised once at Upgrade, then unchecked for the connection's lifetime

**What goes wrong:**
`Scope::authorise_request` (`crates/core/src/scope.rs:238-256`) parses an HTTP request line via
`request_path(raw)` and refuses bytes with none (`scope.rs:245-247`, pinned by the existing test
`a_request_with_no_readable_start_line_is_refused_not_waved_through`). A WebSocket frame has no
request line — once the HTTP Upgrade handshake is authorised, every subsequent WS frame on that
connection has no HTTP-shaped bytes for this function to check. If WebSocket send paths (repeater-
style WS replay, a WS-aware plugin hook) route frame bytes through this same function unmodified,
they either get incorrectly refused (breaking WS entirely) or the call is skipped altogether
(silently unchecked for the connection's life) — and either way, nobody has decided which, because
the WS feature doesn't exist yet.

**Why it happens:**
Scope enforcement was designed and tested against an HTTP-shaped byte stream. WebSockets change
the wire format after the same TCP connection is already authorised, and "the connection is already
inside scope" is an easy, wrong shortcut — the connection was authorised for one purpose (the
handshake); WS frames sent later can carry payloads to different logical endpoints (e.g. a
WS-tunneled protocol multiplexing multiple back-end targets over one socket) that the original
Upgrade authorisation never considered.

**How to avoid:**
- Decide explicitly (not by default) what "scope" means for a WebSocket connection: authorise once
  at Upgrade against the negotiated host/path, and treat the whole connection's lifetime as scoped
  to that decision — but document this as a deliberate design choice with its own test, not an
  accidental consequence of `authorise_request` being unreachable for frame bytes.
  For any WS-based replay/injection surface (WS repeater), require the same explicit re-authorisation
  discipline as HTTP repeater: check host/path before *and after* any frame-content mutation the
  feature performs, not before only.
- Add a regression test mirroring the existing scope test suite (`scope.rs:303-478`) but for the
  WS case: a WS connection Upgraded inside scope, later used to reach something an excluded rule
  would refuse if it were a fresh HTTP request, must not be silently permitted just because the
  underlying TCP connection was once authorised.

**Warning signs:**
- No test in the WebSockets phase plan exercises "connection authorised at Upgrade, then reused for
  a purpose the Upgrade path never checked."
- Any WS send path that does not call an authorising function at all (grep for WS frame writes with
  no adjacent scope call).

**Phase to address:** WebSockets phase (Platform, Phase 4).

---

### Pitfall 6: Bambda/rhai filter expressions become either a self-inflicted DoS or an unaudited request originator

**What goes wrong:**
Two distinct failure modes for choosing `rhai` to evaluate Bambda-style filters:
1. **Self-DoS.** `rhai` supports `max_operations`, `max_string_size`, `max_array_size`, and
   `max_map_size` sandboxing limits specifically because unconstrained scripts can loop/allocate
   without bound [MEDIUM — corroborated by rhai's own README/crates.io docs and independent
   write-ups]. A filter expression evaluated live across every proxied exchange (a stated
   requirement: "live passive crawl and live audit fed from proxy traffic") with these limits left
   at their defaults is a script author's footgun that becomes the *tool's* footgun at scale — a
   single expensive filter evaluated per-message on a multi-GB capture can stall the UI or eat all
   CPU, silently, with no visible cause pointing back to the expression.
2. **Unaudited originator.** If the rhai engine is ever extended with registered functions that can
   issue HTTP requests (a natural ask: "let a Bambda filter also trigger a lookup"), a filter
   expression becomes a fifth sender in the sense of Pitfall 4 — one that operators think of as
   "just a filter," not as something capable of generating traffic, and therefore not something
   anyone thinks to scope-check.

**Why it happens:**
Embedding a scripting engine for expressions is treated as a UI/filtering feature; its resource
limits and its function-registration surface are engine configuration decisions made once at
integration time and easy to leave at defaults, especially since rhai's defaults favor
permissiveness for general embedding use, not this project's live-evaluated-over-history use case.

**How to avoid:**
- Set `max_operations`, `max_string_size`, `max_array_size`, and `max_map_size` explicitly and
  restrictively for the Bambda evaluation context from day one; treat "why did this filter hang"
  as untestable if these are left unset.
- Never register a function on the Bambda rhai `Engine` that can open a network connection.
  If a future requirement genuinely needs that, it re-enters Pitfall 4's chokepoint discipline —
  don't let it in through a scripting side door.
- Track and surface evaluation time/operation count per filter, especially for anything advertised
  as running live over the full history or over active proxy traffic.

**Warning signs:**
- Bambda integration code constructs `rhai::Engine::new()` (permissive defaults) rather than
  `Engine::new_raw()` plus explicit limits, or never calls the `set_max_*` family.
- No registered-function inventory documented for what the Bambda engine can call into.

**Phase to address:** Bambda filter expressions phase (Platform, Phase 4).

---

### Pitfall 7: Plugin API has no peer-tool capability model to borrow — sandboxing must be designed, not assumed

**What goes wrong:**
The Active requirements list the plugin API as "WASM or a JSON-RPC child process, deliberately not
an embedded JVM" — a supply-chain and sandboxing problem for third-party code that reads and
rewrites live traffic. Searches for how ZAP, Caido, and Burp's own BApp ecosystem handle
plugin/extension sandboxing turned up **no documented incident and no documented sandbox/capability
model** to borrow:
- No publicly attested BApp Store supply-chain incident was found in this research; PortSwigger
  states it reviews submissions before listing, but this is a curation gate, not a runtime sandbox
  — an installed BApp still runs with full JVM privileges inside Burp's process. [LOW —
  absence of a documented incident is not evidence of absence of risk; it just means the failure
  mode here is structural (full in-process trust) rather than incident-attested.]
- ZAP's own documentation available to this research did not describe an extension sandboxing
  model; ZAP add-ons run as Java on the same classpath as ZAP itself. [LOW — search did not
  surface ZAP's internal security model; do not treat this absence as confirmation ZAP has none,
  only that public docs found here don't describe one.]
- Caido's plugin SDK gives backend plugins direct HTTP operations, storage, and GraphQL access
  from a Node-based backend process [MEDIUM — Caido developer docs]; this is a capability grant,
  not a sandboxing boundary as documented.

The honest finding: **none of the three peer tools researched here documents enforcing scope or a
capability boundary at the plugin runtime boundary.** A plugin that can rewrite traffic in any of
these ecosystems is, once installed, effectively as trusted as the host application.

**Why it happens:**
Plugin ecosystems for security tools are built for *power*, by and for people who understand the
risk of what they're installing — extensibility is the product feature that gets invested in;
the trust boundary around third-party code is not, because the assumed threat model is "the
operator chose to install this."

**How to avoid (capability model this project should design for, since none exists to copy):**
- Choose the child-process/JSON-RPC or WASM boundary *because* it is enforceable, and use it: a
  plugin should receive a narrow, typed API (read this exchange, propose this modification, emit
  this finding) rather than a raw socket, raw scope object, or raw filesystem handle.
- Any plugin-proposed request modification must re-enter the single authorising chokepoint from
  Pitfall 4 before it reaches the wire — the plugin API is exactly the kind of surface that
  reintroduces the fixed fail-open if it's granted its own sender.
- Treat plugin manifest/capability declarations (network access, filesystem access, which crates'
  data it can read) as an explicit, operator-visible install-time decision, not an implicit
  consequence of the plugin loading successfully.
- WASM specifically buys memory isolation and a deny-by-default host-function surface (the host
  decides what's callable) — if WASM is chosen over JSON-RPC child process, the security payoff is
  precisely in keeping that host-function surface minimal, not in WASM's mere existence.

**Warning signs:**
- Plugin API design grants direct access to the scope object, the raw sender, or the traffic store
  rather than mediated read/propose operations.
- No plugin manifest/capability declaration exists at all — anything installed can do anything the
  host process can do.

**Phase to address:** Plugin API phase (Platform, Phase 4) — design the capability model before
the first plugin type ships, since retrofitting a capability boundary onto an already-shipped raw
API is a breaking change for every existing plugin.

---

### Pitfall 8: MCP server turns scanned/crawled content into an indirect prompt-injection vector against the operator's own agent

**What goes wrong:**
Exposing this tool's JSON API to an LLM agent over MCP means content this tool *fetched from the
target* (a scanned page, a crawled response body) can flow back into the agent's context as a tool
result. A documented case against Burp's own MCP server [LOW — single source, one blog post by
darkdrag0nite; treat specifics as a lead to verify against the actual Burp MCP server code/changelog,
not as established fact] describes exactly this chain: a malicious page's content, returned through
an MCP tool call, contained instructions that overrode the user's original prompt and caused the
agent to call Burp's own MCP tools — including configuration-*read* tools that had no filtering
(only configuration-*edit* tools carried warnings), leaking credentials, and with no domain
scoping on where the agent's own HTTP-capable tool calls could be directed. Burp's fix added
configurable domain scoping for such calls.

The general class this instance belongs to — **MCP tool poisoning / indirect prompt injection**,
where instructions embedded in tool metadata or tool *responses* land in the LLM's context and are
treated as trusted — is corroborated independently by OWASP's own community page and academic
threat-modeling of MCP [MEDIUM — OWASP MCP Tool Poisoning page + arXiv threat-modeling paper,
independent of the Burp-specific blog post above].

**Why it happens:**
An MCP server designed as "expose the existing JSON API" (per PROJECT.md's own framing: "near-free")
treats every existing endpoint as equally safe to expose verbatim to an agent. Read endpoints feel
lower-risk than write/action endpoints and get less scrutiny, but a read endpoint that returns
attacker-influenced content (a scanned response body, a crawled page) is exactly the injection
vector — the risk is in what's *returned*, not just what's invoked.

**How to avoid:**
- Any MCP tool that can widen scope, launch an attack (audit/intruder/active scan), or read
  configuration/credentials must require a fresh, explicit confirmation *at the point of the call*
  — not a one-time "allow this server" grant at connection time. This project's own stated position
  ("scope-widening as privileged, mirroring Burp marking `add_to_scope` as always-escalate," per
  PROJECT.md) is the right instinct; extend the same always-escalate treatment to: attack-launch
  tools, credential/config-read tools, and any tool whose HTTP-capable side effects can reach a
  destination the operator didn't name.
- These guards belong in the **MCP server itself**, not in agent-side prompting — an injected
  instruction cannot be trusted to respect agent-side politeness, and a compromised or confused
  agent is exactly the threat model. Concretely: the server should refuse to execute a
  scope-widening or attack-launching tool call without a fresh out-of-band confirmation (a
  human-in-the-loop gate the server enforces, not merely requests), and should not return raw
  scanned/crawled response bodies to the agent without being explicit in the tool description that
  this content is untrusted and must not be treated as instructions — description-level mitigation
  alone is weak, but the server enforcing execution gates for privileged tools is not.
- Treat "domain scoping" for any tool that can itself originate HTTP calls (not just proxy/replay
  existing captured traffic) as the same chokepoint problem as Pitfall 4 — an MCP tool that sends
  requests is a sender, full stop, and must route through the one authorising path.

**Warning signs:**
- Any MCP tool description that reads config, credentials, or scan results without a documented
  confirmation gate for the corresponding *write*-side tool.
- No tool-risk classification (read vs. destructive/scope-widening) documented for the MCP tool
  set before it ships.

**Phase to address:** MCP server phase (Agent surface, Phase 5) — but the always-escalate list
(scope-widening, attack-launch, credential/config-read) should be drafted as part of that phase's
design, not discovered after an incident.

---

### Pitfall 9: Headless-browser-executed JavaScript (DOM/JS analysis) can originate requests no Rust-side scope check ever sees

**What goes wrong:**
DOM/JS analysis (sequenced last in PROJECT.md, "needs an embedded JS engine") most plausibly pairs
with the crawler to execute page JavaScript for realistic link/form discovery. Once a real JS
engine executes page script, that script can call `fetch()`/`XMLHttpRequest` to arbitrary origins
directly from the browser/JS-engine process — a request path that never touches this project's
`Scope::authorise_request` at all, because it isn't made by any Rust sender this project controls.

**Why it happens:**
DOM/JS analysis is framed as a discovery/parsing feature ("what does this page do"), not as "a new
network-capable process." The scope model this project has built (author it once in
`crates/core/src/scope.rs`, call it from every sender) implicitly assumes every sender is Rust code
this project wrote. A JS engine executing arbitrary page script is not that.

**How to avoid:**
- Force any headless-browser or JS-engine network egress through this project's own proxy, with no
  other network path available to the browser process (no direct interface access, proxy env vars
  enforced and not overridable by page script, `localhost`/loopback exceptions considered
  carefully since SSRF-style loopback fetches are a known browser-automation risk pattern).
- Scope enforcement then happens where it already does — on the proxied bytes — rather than
  requiring the JS engine's own network stack to understand this project's scope rules.
- This is the same "identify every sender before it exists" discipline as Pitfall 4, just for a
  sender that isn't Rust code and therefore won't be caught by grepping for `TcpStream`.

**Warning signs:**
- DOM/JS phase design doc doesn't specify how the embedded browser/engine's outbound network path
  is constrained.
- No test exercises "page JS attempts to fetch an out-of-scope origin" and confirms it either fails
  or is captured/authorised through the existing scope path.

**Phase to address:** DOM/JS analysis phase (deliberately sequenced last, per PROJECT.md) — but the
network-egress constraint should be decided as an architectural precondition before this phase
starts, since it determines whether a browser engine is even embeddable safely.

---

### Pitfall 10: mmap migration corrupts or silently loses data, and "it didn't crash" is treated as verification

**What goes wrong:**
Moving the live append-only store to mmap risks several distinct failure modes, not one:
- **Torn writes.** A crash or unclean shutdown mid-write can leave a page partially flushed;
  `MAP_SHARED` + `msync` specifically can expose a *mix* of old and new bytes to a concurrent
  reader because flushing is page-granular, not atomic across a whole write [MEDIUM — corroborated
  by transaction-processing/crash-consistency literature describing exactly this pattern].
- **Stale mappings on growth.** An append-only file that grows needs either periodic remapping or
  a fixed-size-with-headroom design; a reader holding an old mapping across a grow-and-remap event
  can read stale or invalid memory if the remap discipline isn't airtight.
- **Shrink/truncate is not a catchable Rust error.** If any code path truncates or shrinks the
  backing file while it's still mapped, accessing the now-invalid mapped range raises `SIGBUS`,
  which Rust cannot catch as a `Result` — it's a process-level signal, not an error value. Any
  migration or compaction logic that shrinks the file live must guarantee no reader ever holds a
  mapping into the truncated region, or must never truncate in place at all (write a new file
  instead).

**Why it happens:**
mmap's appeal (zero-copy reads, cheap random access — exactly why this project wants it, per its
own memory-cost rationale) comes precisely from exposing raw memory semantics instead of a
buffered API that would otherwise absorb these failure modes. The append-only store's *entire
design premise* — "a message is stored once as bytes plus span offsets; never clone a body" — is
what makes mmap attractive, but it's also what makes stale-offset and stale-mapping bugs plausible:
offsets computed against one mapping generation must remain valid (or be recomputed) against the
next.

**How to avoid:**
- Add a checksum (or equivalent) per record/segment, verified on open and after any remap, so a
  torn write is *detected*, not silently read as valid data — mirroring this project's own stated
  position that bounds must be observable, extended to storage integrity.
- Never truncate/shrink the live mmap'd file in place; if compaction is needed, write to a new
  file and atomically swap, so no reader can ever observe a shrink into memory it's currently
  holding.
- **Make the migration verifiable, not hoped-for**: build a read-back equivalence test that, for a
  real captured history, asserts every exchange's bytes and span offsets are byte-identical when
  read through the new mmap-backed store versus the old append-only store, run over the actual
  corpus/fixture data this project already has, not just "the migration didn't panic in CI."
  Treat "didn't crash" and "verified equivalent" as different claims — the latter is what the
  Constraints section's own honesty standard requires.

**Warning signs:**
- No checksum/integrity field exists per stored record in the mmap design.
- No test compares old-store output to new-store output field-by-field over a real capture.
- Any code path that resizes the backing file without first confirming no other mapping exists
  into the resized region.

**Phase to address:** mmap-backed store phase (Platform, Phase 4) — this should be the very first
Phase 4 item, since Session handling, WebSockets, Bambda, and Reporting all likely read through
whatever store abstraction results.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|--------------------|-----------------|------------------|
| Crawler ships with a hard-coded destructive-path denylist instead of a general classifier | Fast to build, covers common cases (logout, delete) | Misses app-specific destructive actions (e.g. "revoke API key", custom admin actions); false confidence that "safety" is solved | Only as a v1 alongside an operator-visible "form not submitted" report — never silently, and only until a semantic-signal approach lands |
| Session-handling re-auth with no attempt cap, "for now" | Simpler state machine, ships faster | Unbounded retry loop against a real target (Pitfall 2) | Never — the cap is cheap to add and the failure mode is a live-traffic incident |
| MCP server exposes the full existing JSON API 1:1, deferring tool-risk classification | "Near-free" per PROJECT.md's own framing; fastest path to agent-drivable | Read tools that return attacker-influenced content become injection vectors with no server-side gate (Pitfall 8) | Only for genuinely read-only, non-attacker-influenced data (e.g. static config schema) — never for scan/crawl results or scope-widening/attack-launch tools |
| Bambda/rhai integrated with default `Engine::new()` limits | Zero extra integration work | Unbounded script becomes a live-evaluation DoS at scale (Pitfall 6) | Never for anything evaluated over live proxy traffic or full history; acceptable only for a one-shot manual filter over a small, bounded result set during initial prototyping |
| Plugin API v1 grants direct sender/scope access "to keep the API simple" | Faster plugin API ship, less design work up front | Reintroduces the fixed fail-open class through a fifth, plugin-controlled sender (Pitfall 4, 7) | Never — this is the one shortcut this project has already paid for once |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|--------------|------------------|--------------------|
| `rhai` (Bambda) | Leaving `max_operations`/`max_string_size`/`max_array_size`/`max_map_size` at defaults because the engine "just evaluates a filter" | Set explicit, restrictive limits for the live-evaluation context from first integration; treat unset limits as a phase-blocking gap, not a follow-up |
| MCP client permission model (e.g. Claude Desktop "always allow") | Treating a one-time "allow this MCP server" grant as sufficient authorization for every subsequent tool call, including destructive ones | Design the MCP *server* to demand fresh confirmation for privileged tool calls regardless of client-side allow-always settings — don't rely on the client's consent model, since it wasn't designed with this tool's risk profile in mind |
| WASM/JSON-RPC plugin host functions | Registering broad host functions (e.g. "make an HTTP request") because it's the simplest way to give plugins power | Register the narrowest possible host functions (read exchange, propose modification) and route any resulting request through the existing metered sender, never let a plugin hold its own socket |
| mmap + `msync` | Assuming `msync` completing means all readers see consistent data immediately | Understand `msync`'s page-granularity; pair with the checksum/read-back verification pattern in Pitfall 10 rather than assuming atomicity |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Bambda filter evaluated per-message over full history with no per-call budget | UI stalls or CPU spikes with no visible cause tied back to a specific filter | Per-evaluation operation/time budget, surfaced to the operator when exceeded (bounded + reported, per this project's own standard) | Any capture large enough that "evaluate this filter over every exchange" is a real cost — likely at the multi-thousand-exchange scale this project already targets |
| mmap file remapped on every append rather than pre-grown in chunks | Latency spikes on ingestion proportional to append frequency, worse than the append-only design it replaced | Grow the backing file in geometric chunks and remap only when capacity is exhausted, not on every append | Once ingestion rate exceeds whatever the remap syscall overhead can absorb — should be caught in the same benchmark that currently measures the O(n²) `set_response` cost |
| Crawler with no concurrency/rate limit tied to the scope's rate-limiting config | Crawler traffic to the target arrives fast enough to independently trigger the target's rate limiting or WAF blocking, contaminating a subsequent scan's results | Route crawler-issued requests through the same rate-limited sender path used elsewhere (Intruder's `RateLimiter`, per the existing conservative-by-design pattern in `crates/intruder/src/limit.rs`) rather than building a separate, unthrottled crawl loop | Any target with connection-rate-based defenses — common enough that this should be assumed, not discovered |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Treating "the crawler only follows GET links" as sufficient destructive-action protection | Misses GET-based logout/delete endpoints entirely — a documented real pattern, not a theoretical one | Semantic-signal denylist (Pitfall 1) plus operator-visible skip reporting, not an HTTP-method heuristic alone |
| Granting a plugin or MCP tool its own network sender "for flexibility" | Reintroduces the fixed scope fail-open through a new sender that was never subject to the original fix's review (Pitfall 4, 7, 8) | Every sender — plugin, MCP tool, crawler, session macro — must hold the shared authorising sender type, never a raw socket |
| Returning raw scanned/crawled page content to an MCP-connected agent with no framing that the content is untrusted | Indirect prompt injection turns the agent into an attacker-directed actor against the operator's own tool (Pitfall 8) | Server-side execution gates on privileged tool calls (not description-level warnings alone); treat this as the primary mitigation, with description framing as defense-in-depth only |
| Assuming an authorised connection (WS Upgrade, an already-scoped TCP session) stays authorised for its whole lifetime | A connection scoped for one purpose gets reused for traffic the original check never considered (Pitfall 5) | Re-authorise at every logical request/frame boundary that can carry a new destination or effect, not just once at connection setup |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-------------------|
| Crawl summary reports only "N pages crawled" with no count of forms/links skipped for safety | Operator can't tell "nothing destructive was found" from "we didn't look for destructive things" — the exact honesty failure this project already rejects for scan bounds | Report skipped-for-safety counts as a first-class field, mirroring `AuditOutcome`'s disposition-counter pattern |
| Dashboard aggregates "issues found" without a visible count of checks refused/skipped/incomplete | Operator reads a low number as "clean" when it may mean "we stopped looking" (see Pitfall 11 below) | Every summary view surfaces the disposition breakdown (ran / refused / skipped / truncated), not just a headline finding count |
| MCP tool call silently fails closed on a scope-widening request with no explanation surfaced to the operator's chat session | Operator (or their agent) can't tell "the server refused this for safety" from "something broke" | Server returns an explicit, human-readable refusal reason for any always-escalate tool call it declines, distinct from a generic error |

## "Looks Done But Isn't" Checklist

- [ ] **Crawler:** Often missing an operator-visible report of destructive links/forms it declined
      to follow — verify the crawl summary has a skipped-for-safety field, not just a page count.
- [ ] **Session handling:** Often missing a hard cap on consecutive re-auth attempts — verify
      against a fixture whose session is designed to always look invalid after re-login.
- [ ] **Plugin API:** Often missing a capability/manifest model — verify a plugin cannot obtain a
      raw sender or bypass `Scope::authorise_request` by construction, not just by convention.
- [ ] **MCP server:** Often missing action-time (not connection-time) confirmation for
      scope-widening, attack-launch, and credential/config-read tools — verify each such tool
      individually, since "the server requires approval" as a blanket claim often means only some
      tools actually enforce it.
- [ ] **Bambda/rhai integration:** Often missing explicit resource limits — verify
      `max_operations`/`max_string_size`/`max_array_size`/`max_map_size` are set, not left at
      engine defaults.
- [ ] **mmap store:** Often missing a read-back equivalence test against the prior append-only
      store over real data — verify the migration claim is "byte-identical read-back, tested,"
      not "ran without crashing."
- [ ] **Reporting/dashboard:** Often missing a place in the export/summary schema to record an
      incomplete or partially-refused run — verify a report generated from a bounded/incomplete
      audit is visibly distinguishable from one generated from a complete run, not just a lower
      issue count.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|-----------------|
| Crawler triggered logout/session teardown mid-engagement | LOW | Session-handling re-auth (once capped per Pitfall 2) recovers automatically; if no session handling exists yet, operator re-authenticates manually and resumes crawl from frontier state |
| Crawler triggered a destructive action (delete/unsubscribe) against a real target | HIGH — cannot be undone by this tool | Immediate operator notification is the only real "recovery"; this is why Pitfall 1's prevention (never let it happen) matters more than recovery — treat any occurrence as an incident to report to the engagement owner, not a bug to patch quietly |
| Scanner/session-macro locked out a test account via repeated login attempts | MEDIUM | Manual unlock via the target's own admin path (outside this tool's control); prevention (Pitfall 2's attempt cap) is cheaper than any recovery path, since recovery depends on the target providing one at all |
| mmap store corruption detected via checksum mismatch on open | LOW–MEDIUM (if append-only source retained during migration) | Keep the prior append-only file as the source of truth until the mmap store passes read-back equivalence in production use, not just in CI, so a corrupted mmap file can be regenerated rather than representing unrecoverable data loss |
| MCP-connected agent executed an unintended tool call due to injected content | MEDIUM | Server-side action log (what tool, what args, what triggered it) is the only way to reconstruct what happened after the fact — this is itself an argument for logging every MCP tool invocation with its triggering context, not just its result |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|-------------------|----------------|
| 1. Crawler destructive actions | Crawler (Tool parity leftovers) | Fixture app with GET-logout and unprotected delete form; crawl completes with session/item intact and a non-zero skipped-for-safety count |
| 2. Session re-auth loop | Session handling (Platform, Phase 4) | Fixture whose session always fails a downstream check post-login; request volume to login endpoint stays bounded and a failure state surfaces |
| 3. Payload processing scope bypass | Intruder payload processing (Tool parity leftovers) | Adversarial processing chain producing path-traversal-shaped output; authorisation call confirmed to run on final bytes via test |
| 4. Scope re-derivation across new senders | Cross-cutting, settle before Crawler phase; re-verify at Plugin API and MCP phases | Grep audit for direct socket opens outside the shared authorising sender at each phase boundary |
| 5. WebSocket scope gap | WebSockets (Platform, Phase 4) | New regression test class mirroring `scope.rs:303-478` for WS Upgrade-then-reuse scenarios |
| 6. Bambda/rhai self-DoS or covert sender | Bambda filter expressions (Platform, Phase 4) | Confirm explicit `rhai` resource limits set; confirm no network-capable host function registered |
| 7. Plugin API capability model | Plugin API (Platform, Phase 4) | Design review confirming plugins receive mediated operations only, never a raw sender/scope handle; manifest/capability declaration exists |
| 8. MCP indirect prompt injection / missing confirmation | MCP server (Agent surface, Phase 5) | Per-tool risk classification documented; always-escalate tools individually tested to confirm server-side (not client-side) enforcement |
| 9. DOM/JS engine bypassing scope via direct fetch | DOM/JS analysis (deliberately sequenced last) | Test confirming embedded browser/engine has no network path except through this project's own proxy |
| 10. mmap migration corruption/unverifiable | mmap-backed store (Platform, Phase 4, first item) | Read-back equivalence test against real captured history; checksum verified on open; no in-place shrink of a live mapping |
| 11. Reporting/dashboard honesty collapse | Reporting (Platform, Phase 4) | Report/dashboard schema has a dedicated field for incomplete/refused/skipped counts, distinguishable at a glance from a complete clean run |

---

### Pitfall 11 (folded into mapping above, detailed here): Reporting and dashboards collapse "we stopped looking" into "we found nothing"

**What goes wrong:**
This project already builds honest, disposition-counted internals (`AuditOutcome`,
`AttackPlan::truncated`, `unbucketed`, `MAX_OCCURRENCES`/`times_seen` — all verified sound in
`.planning/codebase/CONCERNS.md`). Reporting and dashboards are new consumers of that data, and
they are exactly where the discipline classically breaks: an HTML/JSON/SARIF report or a dashboard
summary tile that shows "N issues found" without also surfacing "M checks refused/skipped/timed
out" reproduces the dishonesty this project has explicitly rejected, just one layer up the stack —
the internal data stays honest, but the *view* on top of it lies by omission.

**Why it happens:**
Summarization is lossy by nature — a headline number is the point of a dashboard tile. The
discipline of also surfacing the "didn't finish" signal has to be a deliberate design decision in
the reporting/dashboard schema, because the natural default (show the count of things found) drops
exactly the information that distinguishes "clean" from "incomplete." Real-world scanner tooling
demonstrates this failure concretely: Nuclei's own issue tracker documents runs where an aggressive
timeout produces a context-deadline-exceeded condition that surfaces indistinguishably from "no
results found" [MEDIUM — corroborated by Nuclei's own docs on timeout/false-negative tradeoffs plus
a specific GitHub issue showing the deadline-exceeded-as-empty-result pattern] — exactly the
"absent data read as evidence" failure this project's Constraints section names as the thing to
never do.

**How to avoid:**
- Every report and dashboard view must carry the disposition breakdown forward from
  `AuditOutcome`/`AttackPlan`/etc., not just the positive-finding count — if the export format has
  no field for it, that's a schema gap to fix before shipping, not a follow-up.
- If SARIF is used for export (per the Active requirements list — "HTML/JSON/SARIF backed by the
  issue catalog"), use SARIF's own `invocation` object fields for this purpose: `executionSuccessful`
  and `toolExecutionNotifications` exist precisely to let a SARIF consumer distinguish "the tool
  process succeeded and analyzed everything" from "something prevented complete analysis" [MEDIUM —
  corroborated by the OASIS SARIF 2.1.0 spec and multiple tools' (semgrep, GCC, GitLab) documented
  handling of these fields, including known bugs elsewhere where tools incorrectly reported
  `executionSuccessful: true` despite failures — a cautionary example of exactly the mistake to
  avoid replicating]. This is a concrete, schema-level place to put the honesty this project
  already has internally — don't build a bespoke incomplete-run signal when the target format
  already has one.
- Dashboard summary tiles specifically (not just full reports) should carry the same discipline —
  a single "0 issues" tile with no accompanying "N checks did not complete" is the single most
  dangerous surface for this failure, since it's the view most likely to be glanced at rather than
  read.

**Warning signs:**
- Report/export schema has fields for findings but no field anywhere for disposition
  counts/incomplete-run status.
- SARIF export sets `executionSuccessful: true` unconditionally rather than deriving it from
  whether any checks were refused/truncated.
- Dashboard tile design mockups show only positive counts (issues found, requests sent) with no
  accompanying "did not complete" indicator.

**Phase to address:** Reporting phase (Platform, Phase 4) — the schema decision (what field carries
incompleteness) should be made before HTML/JSON/SARIF generation code is written, since retrofitting
a schema field after export format code exists is more disruptive than deciding it up front.

---

## Sources

**Corroborated (MEDIUM confidence — ≥2 independent sources):**
- OWASP CSRF page + multiple independent CSRF write-ups on GET-based logout as a real destructive-action pattern: [OWASP CSRF](https://owasp.org/www-community/attacks/csrf), [Wiz CSRF guide](https://www.wiz.io/academy/application-security/cross-site-request-forgery-csrf)
- PortSwigger's own crawl-settings and Spider-options documentation on form-submission toggles and scope exclusion: [Burp crawl settings](https://portswigger.net/burp/documentation/scanner/scan-configurations/crawl-settings), [Cyberly Burp crawler guide](https://www.cyberly.org/en/how-do-you-use-burp-suites-crawler-effectively/index.html)
- ZAP spider/active-scan infinite-loop reports across GitHub issues and mailing list: [zaproxy/zaproxy#4084](https://github.com/zaproxy/zaproxy/issues/4084), [ZAP users group thread](https://groups.google.com/g/zaproxy-users/c/CPuEr36mfd4), [ZAP Automation Guide — Target Scanning Issues](https://www.zaproxy.org/docs/getting-further/automation/target-scanning-issues/)
- Account-lockout-as-DoS from scanning: [Alert Logic support](https://support.alertlogic.com/hc/en-us/articles/360032841651-Managing-Accounts-Locked-by-Scanning), [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks), [OWASP Testing for Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- MCP Tool Poisoning as a general class: [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning), [arXiv:2603.22489 MCP threat modeling](https://arxiv.org/abs/2603.22489), [Invariant Labs MCP tool poisoning notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- MCP action-time confirmation for destructive tools: [Towards Data Science MCP Security Survival Guide](https://towardsdatascience.com/the-mcp-security-survival-guide-best-practices-pitfalls-and-real-world-lessons/), [Checkmarx MCP Security](https://checkmarx.com/learn/mcp-security-risks-real-world-incidents-and-security-controls/)
- rhai resource-limit sandboxing features: [rhai GitHub README](https://github.com/rhaiscript/rhai), [crates.io rhai](https://crates.io/crates/rhai)
- Torn-write/checksum crash-consistency pattern and mmap page-granular flush semantics: transaction-processing and crash-consistency patent literature retrieved via search (USPTO-indexed technical descriptions of torn-write detection via checksum)
- Nuclei timeout-as-false-negative and deadline-exceeded-as-empty-result: [Nuclei mass-scanning docs](https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli), [ProjectDiscovery Nuclei guide](https://projectdiscovery.io/blog/ultimate-nuclei-guide)
- SARIF `invocation.executionSuccessful` / `toolExecutionNotifications` semantics and known misuse: [OASIS SARIF 2.1.0 spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), [semgrep#2954](https://github.com/returntocorp/semgrep/issues/2954), [GitLab report MR !52](https://gitlab.com/gitlab-org/security-products/analyzers/report/-/merge_requests/52)

**Single-source (LOW confidence — verify before relying on for phase planning):**
- Burp MCP server indirect-prompt-injection specifics (credential leak PoC, missing config-read filtering, v1.1.0 domain-scoping fix): [darkdrag0nite — Analyzing security of Burp MCP](https://darkdrag0nite.medium.com/analyzing-security-of-burp-mcp-ee206feaf338) — one blog post; verify against Burp's actual MCP server changelog/docs before treating specifics as fact.
- Absence of a documented BApp Store supply-chain incident, and absence of a documented ZAP extension sandbox model — these are **negative findings** (search did not surface either), not confirmed absences; do not represent them as "ZAP/Burp extensions are proven safe."
- Caido plugin SDK capability description: [Caido Plugin Architecture](https://developer.caido.io/plugins/concepts/package.html), [Caido Backend Plugins vs Workflows](https://developer.caido.io/concepts/workflow.html) — official docs, but only one ecosystem's own documentation, not independently corroborated against a third-party security analysis.
- mitmproxy addon event-hook model and in-process trust: [mitmproxy addon overview](https://docs.mitmproxy.org/stable/addons/overview/) — official docs describing capability, not a security analysis of the trust boundary.

**Project-internal (grounded in source, not a web claim):**
- `Scope::authorise_request` signature and behavior: `crates/core/src/scope.rs:238-256`
- `Metered` sender pattern: `crates/scanner/src/lib.rs:587-631`
- `RateLimiter::acquire` conservative-permit-holding behavior: `crates/intruder/src/limit.rs:138-150` (per `.planning/codebase/CONCERNS.md`, referenced here only as a pattern to reuse for crawler rate-limiting, not re-reported as a concern)

---
*Pitfalls research for: burpsy — Rust web-security testing platform (subsequent milestone: mmap
store, WebSockets, plugin API, Bambda, session handling, reporting, dashboard, MCP server, HTTP/2,
DOM/JS analysis, crawler, Sequencer, Intruder payload processing)*
*Researched: 2026-07-27*
