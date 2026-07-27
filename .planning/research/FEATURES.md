# Feature Research

**Domain:** Web application security testing platform (proxy + scanner + tester tooling), post-teardown milestone
**Researched:** 2026-07-27
**Confidence:** MEDIUM overall (HIGH where cross-checked against primary specs/docs; LOW where a single source was available — flagged inline)

This file deliberately does not re-list what `ROADMAP.md` already inventories from the Burp 2026.7.1
teardown (the 21 MontoyaApi subsystems, 183 issue types, 7 dispatch scopes, etc.). Every entry below
adds something the teardown cannot: what "good" looks like, how Caido/ZAP/mitmproxy actually solved
the same problem, and which of the 18 remaining ROADMAP items are genuinely load-bearing versus
droppable.

## Feature Landscape

### Table Stakes (Users Expect These)

Missing these on a tool that already has a working proxy + scanner makes it *unusable on a real
engagement*, not merely less polished.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Intruder payload processing (prefix/suffix, case, encode/hash, match-replace, load `.pay` lists) | Sniper without payload transforms can't do the encoding-aware fuzzing every engagement needs (double-URL-encode, base64-wrap, hash-then-send for signed params) | MEDIUM | Chain-of-transforms over a `&str`→`Vec<u8>` pipeline; the `.pay` list format is just newline-delimited strings, cheap to load |
| Intruder grep-match / grep-extract | Without it, a 5,000-request sniper run is unreadable — testers scan for a marker string or size delta by eye today only because Burp gives them nothing better; extract is what turns Intruder output into a data column (e.g. captured CSRF token from each response) | LOW–MEDIUM | Regex over response bytes/headers; extract needs a capture-group-to-column result view |
| Proxy history filters (host/status/method/MIME/search) | Once history exceeds a few hundred entries — one browsing session — an unfiltered flat list stops being usable. This is a UI/query feature, not a scanner feature, and it's needed *before* Sequencer or WebSockets are | LOW | Can share the same query surface being considered for Bambda/filter-expression work (see Differentiators) — don't build two filter languages |
| Repeater tabs (multiple named, per-tab history) | Testers keep 10–30 requests open in parallel across a single engagement; a single-buffer Repeater is a dealbreaker within the first hour of use | LOW | Mostly a UI/state-management item given Repeater's send path already exists |
| Some form of session handling that survives multi-step auth | Without it, any active scan or Intruder run against an authenticated app degrades mid-run as soon as the session expires — the scanner silently starts probing a login page instead of the target | MEDIUM–HIGH | See Expected Behaviour section below — the *minimum* viable version is a login macro + re-run-on-failure, which is simpler than Burp's full rule editor |
| Basic crawler (frontier + link/form extraction, request/time limits) | Without it, scan coverage is limited to whatever the tester manually clicked through — for anything past a handful of pages this misses most of the attack surface | MEDIUM | Already scoped in ROADMAP 3.9; the differentiator is doing this *live* off proxy traffic (see below), not the frontier walk itself |
| WebSockets capture + repeater | WS-heavy apps (chat, live dashboards, trading, most modern SPA frameworks) have real attack surface in message framing/authorization that a WS-blind proxy simply never sees. This isn't a nice-to-have anymore — it went table-stakes as apps moved off polling | MEDIUM–HIGH | Needs the mmap store's incremental design extended to a message stream rather than one request/response pair |
| mmap-backed store | Not a user-visible "feature," but a hard prerequisite: the crawler, live passive crawl, and live audit all *accumulate* items against a store whose `set_response` is already documented as O(n²) (PROJECT.md). Shipping those three features before the store is fixed compounds the existing debt rather than paying it down | HIGH | Sequence this **before**, not alongside, the three traffic-accumulating features it's meant to support |
| Minimal HTML + JSON reporting | Testers need to hand off *something* structured per engagement even before SARIF/CI integration matters; JSON is also what feeds a future report pipeline or ticketing integration | LOW–MEDIUM | See Expected Behaviour section for what belongs in each format |

### Differentiators (Competitive Advantage)

Genuinely a place to win, given burpsy's memory thesis and the "web UI over SSH" positioning —
not obligatory, but where the project can beat both Burp and its open-source peers.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| A small typed filter/query DSL (Caido-HTTPQL shape) instead of a `rhai`-embedded Bambda clone | Caido's HTTPQL (`docs.caido.io/app/reference/httpql`, single source, confidence LOW on details but the shape is well documented) is `namespace.field operator value` with AND/OR, comparison/containment/regex operators, and savable presets. It reads like a `WHERE` clause and is trivially indexable/pushdownable against the traffic store. `rhai` is a **general-purpose scripting language** — reproducing Bambda's actual problem (slow to write correctly, can't be pushed into an index, requires knowing the whole host API surface) in different syntax. This directly contradicts the ROADMAP's "consider `rhai`" note. | MEDIUM | Recommend: a small typed predicate grammar over known fields (host/path/method/status/mime/header/body-contains/tag), AND/OR/NOT + parens, reused for proxy history filters, match-and-replace scope, and live-audit/crawl inclusion — one grammar, four consumers |
| Full-spec-compliant SARIF, including `webRequest`/`webResponse` | SARIF 2.1.0's `Result.webRequest` (§3.46) and `Result.webResponse` (§3.47) are **core object-model properties**, purpose-built for DAST/web-analysis tools — this is not an extension bag, confirmed against the OASIS spec directly. ZAP's own SARIF exporter populates these but the *GitHub code-scanning* ingestion path ignores them entirely (it only reads `physicalLocation`+`partialFingerprints` resolved against real repo files). Building both — a properly populated `webRequest`/`webResponse` for SARIF-aware consumers, plus a synthetic `physicalLocation` (URL as `artifactLocation.uri`, `region.startLine=1`, payload as snippet — the pattern ZAP uses) for GitHub compatibility — gets burpsy correct SARIF for the tool's actual audience (findings pipelines, other DAST tooling) *and* passable GitHub Code Scanning ingestion, which most competitors treat as an afterthought | MEDIUM | See Expected Behaviour below for the exact required/size-limited fields |
| MCP server | ROADMAP already flags this as near-free given the JSON API; the differentiation is against Caido and ZAP specifically — neither publishes a first-class MCP server as of this research (Burp itself shipped one, `mcp-proxy-all.jar`, so this is parity with Burp, not novelty against it, but it is real distance from the open-source competition) | LOW | Already scoped correctly in ROADMAP Phase 5 |
| Declarative session-handling verification (ZAP Automation Framework shape) instead of a Burp-style rule editor | ZAP's model (zaproxy.org docs, cross-checked): a context declares an auth method, a **verification strategy** (`loggedInIndicator`/`loggedOutIndicator` regex against responses, or a poll), and a session-management method (cookie/HTTP-auth); on verification failure it automatically reruns the login flow. Burp's session-handling-rule editor requires hand-building a Scope tab + an Actions tab that chains "check session is valid" → "run macro" → "update cookie jar" *per rule* — widely documented in community writeups as confusing (informally, "the macro maze"). Copy ZAP's shape: one declarative block (login macro + a match/regex indicator + auto-rerun), not a rule-builder UI | MEDIUM–HIGH | This is the single highest-leverage "don't copy Burp's legacy design" finding in this research — see Competitive Reality below |
| Live passive crawl + live audit fed from proxy traffic | Deriving sitemap coverage and audit findings continuously from traffic already flowing through the proxy, with **no separate crawl action**, is more valuable than either Caido's or ZAP's model (both treat crawling as a distinct, user-triggered action — ZAP's Spider, Caido's Automate). This is already scoped in ROADMAP 3.10/3.11; the point is it's a genuine differentiator, not just parity, precisely because it composes with the zero-copy store instead of bolting a second copy of the traffic model on top | MEDIUM | Sequence strictly after the mmap store fix (see Feature Dependencies) |
| mmap store enabling multi-GB captures | Burp's own project files reportedly reach the multi-GB range and Burp needs to discard scan work under memory pressure (PROJECT.md's Core Value statement). A tool that stays responsive at that scale on the *same offset design already built* is a structural advantage neither Caido nor Burp currently offers as their core storage model | HIGH | This is the payoff of Phase 0's design, not a new feature — frame it that way in the roadmap, not as "one more platform item" |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|------------------|-------------|
| WYSIWYG report template designer / layout engine | Feels like it completes the "reporting" story, and Burp Enterprise has one | Testers overwhelmingly assemble final client deliverables in SysReptor, Dradis, or a Word/Confluence template that already encodes their firm's branding and structure — a layout engine duplicates tooling the customer already owns and is a maintenance sink for a two-person project | Export clean, complete structured data (JSON with full issue detail, HTML as a readable default, SARIF for CI) and stop there. Let downstream reporting tools own layout |
| `rhai`-embedded general filter/scripting language for Bambda-equivalent | Feels powerful — "just like Bambda, but in Rust" | Reproduces Bambda's actual failure mode (slow to author correctly, can't be indexed/pushed down, requires learning a full host API) in different syntax; Caido deliberately built a small typed DSL instead and it is the thing testers reach for first in that product | The typed filter/query DSL above, reused across history filters, match-and-replace, and crawl/audit inclusion |
| A rule-editor GUI for session handling (Burp's Scope-tab + Actions-tab model) | It's what Burp does, so it looks like the reference design | It's the specific piece of Burp's UX most often called out as confusing in the community; a GUI rule builder is also disproportionate effort for a project that's explicitly headless/SSH-first | ZAP's declarative model: one config block per context (login macro + verification indicator + auto re-auth), editable as text/JSON, not a modal-dialog builder |
| Full embedded-JS-engine DOM/JS static analysis, scoped broadly | "Burp AT has it, so should we" | Neither Caido nor ZAP has a comparable deep static DOM/JS analysis engine either (ZAP's DOM XSS coverage leans on a Selenium-driven spider, not static analysis) — this is a large, precedent-thin investment for a two-person project, and it's already sequenced last in ROADMAP for good reason | Keep it sequenced last; consider scoping it down further (e.g. RetireJS-style pattern matching over shipped JS plus a narrow DOM-XSS sink/source heuristic) rather than a general JS analysis engine, if it's built at all |
| Sequencer as a *core, high-priority* build item | Burp has it, feels like a parity gap | Both Caido and ZAP ship a Sequencer-equivalent, but **neither bundles it in core** — Caido's is a community plugin (`caido-community/sequencer`), ZAP's is a separate Marketplace add-on ("Token Generation and Analysis"). Real demand exists (both ecosystems produced one), but neither vendor considered it core-priority. Building it as a Phase-2-blocking core feature over-invests relative to what the market signal actually supports | Build it, but as low priority (P2) work that can slip without blocking the milestone, and treat it as the natural first dogfood case for the plugin API once that exists |
| A JSON-RPC child-process or WASM plugin API that assumes free body access | Feels like the obvious "give plugins full power" design | Both transports force a copy of the message body across a process/VM boundary (WASM: proxy-wasm-style host/guest calls copy into/out of linear memory; a JSON-RPC child process serializes to another process entirely) — this directly collides with the project's own "never clone a body" thesis (PROJECT.md Constraints). A plugin ecosystem that silently reintroduces the copy the whole rest of the codebase was built to avoid is a real architectural regression, not a minor cost | Design the plugin surface so read-only/metadata-only hooks (filters, headers, routing decisions) never touch the body at all, and only plugins that explicitly request body access pay the copy cost — make the cost visible and opt-in rather than universal |

## Feature Dependencies

```
mmap-backed store
    └──blocks──> Crawler (frontier accumulation)
    └──blocks──> Live passive crawl (continuous sitemap growth)
    └──blocks──> Live audit (continuous audit-item accumulation)
    └──blocks──> WebSockets history (long-lived connections, many small messages)

Session handling (macro + verification + re-auth)
    └──required by──> Live audit (a scan that outlives one session must reauth automatically)
    └──required by──> Crawler (an authenticated crawl needs the same session survival)

Filter/query DSL (HTTPQL-shape)
    └──shared by──> Proxy history filters
    └──shared by──> Match-and-replace scope
    └──shared by──> Live crawl/audit inclusion rules
    (build once, do not build a second language for Bambda-equivalent later)

Issue catalog (Phase 3, DONE) + issue dedup (Phase 3, DONE)
    └──required by──> Reporting (HTML/JSON/SARIF all read from the same issue records)

Plugin API (WASM or JSON-RPC child process)
    └──enables──> Sequencer-as-plugin (deprioritize core build once this exists)
    └──conflicts with──> zero-copy body thesis, unless read-only/metadata hooks are a separate, cheaper path (see Anti-Features)

HTTP/2 (currently "sequenced late" per ROADMAP)
    └──affects──> smuggling/desync-class active checks (an h1-only ALPN offer silently downgrades every h2-capable target, which changes what's actually being tested — see Competitive Reality)
```

### Dependency Notes

- **mmap store blocks the three traffic-accumulating features:** the ROADMAP already documents `TrafficStore::set_response` as O(n²); shipping Crawler, live passive crawl, or WebSockets history *before* fixing the store means every one of them inherits the same quadratic blowup at exactly the scale where they're supposed to prove the memory thesis. This should be a hard phase-ordering constraint, not a suggestion.
- **Session handling is a dependency of live audit and crawler, not a peer feature.** A live audit that runs for hours against an authenticated app without automatic re-auth just silently starts auditing a login redirect. Sequence session handling no later than the phase that first runs an unattended multi-request scan.
- **One filter DSL, four consumers.** Building a Bambda-style expression language separately from proxy-history-filter syntax duplicates work and gives testers two things to learn. Converge on one grammar early.
- **HTTP/2 sequencing deserves a second look, not necessarily a re-order.** The ROADMAP defers h2 because "it reaches into core, proxy and capture" and destabilizes in-flight work — that's a legitimate engineering reason. But the stated fallback ("`http/1.1` only ALPN at first, which is what most testing wants anyway," ROADMAP Phase 1) is a claim worth re-examining before the milestone locks: h2-only origins (many modern APIs/CDNs) will simply be downgraded by the client's ALPN offer, and downgrade-based testing changes the actual protocol behavior under test — which matters specifically for the smuggling/desync work HTTP/2 is needed for. Recommend keeping the *build* sequenced late, but flagging in the roadmap that the interim h1-only stance has a coverage cost that should be named explicitly, not assumed away.

## MVP Definition

### Launch With (this milestone's "tool parity leftovers")

- [ ] Intruder payload processing + grep-match/extract — Intruder is not usable on real targets without these
- [ ] Proxy history filters — History becomes unusable past one browsing session without this
- [ ] Repeater tabs — parallel investigation is how testers actually work
- [ ] A *minimal* session-handling mechanism (login macro + regex verification + auto re-run) — build ZAP's declarative shape now, not Burp's rule editor, even in a v1 form
- [ ] mmap-backed store, landed **before** crawler/live-crawl/live-audit/WebSockets history

### Add After Validation (Phase 4 platform)

- [ ] Crawler + live passive crawl + live audit (once the store fix has landed)
- [ ] WebSockets capture + repeater
- [ ] Filter/query DSL, generalized from the proxy-history-filter grammar to also cover match-and-replace and live-audit scoping — one DSL, introduced once, not per-feature
- [ ] Reporting: JSON (issue-catalog-backed, complete) and HTML (readable default) first; SARIF once the issue catalog's fields (CWE, remediation, severity) are stable enough to map cleanly
- [ ] MCP server — genuinely near-free once the JSON API and the above are stable

### Future Consideration (v2+ / plugin-era)

- [ ] Sequencer — keep it, but P2; real but modest demand (both competitors have it only as an add-on/plugin), good first dogfood case once the plugin API exists
- [ ] RetireJS integration — actively maintained upstream (`RetireJS/retire.js`, last release v5.4.3 within the last ~2 months of this research, cross-checked via GitHub release/commit activity) so shipping it is low-risk, but treat the bundled `jsrepository.json` as something to *refresh from upstream*, not freeze at build time — a stale snapshot silently rots into false negatives
- [ ] JWT secret wordlist checks — straightforward: extract the JWT's payload+signature, run the same HMAC-brute-force approach `hashcat -m 16500` and `jwt_tool` use (a wordlist attack against the HS256 key), reusing the same wordlist-loading path Intruder's payload processing already needs
- [ ] Plugin API (WASM/JSON-RPC) — do this once there's a concrete plugin to justify it (Sequencer is the natural first one), not speculatively
- [ ] Bambda-DSL-as-general-scripting — don't build; the typed filter DSL above should absorb this use case instead
- [ ] Full DOM/JS static analysis engine — sequenced last per ROADMAP; reconsider scope (narrow heuristic vs. general engine) before committing real effort, given neither major competitor has solved this well either

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|----------------------|----------|
| Intruder payload processing + grep-match/extract | HIGH | MEDIUM | P1 |
| Proxy history filters | HIGH | LOW | P1 |
| Repeater tabs | HIGH | LOW | P1 |
| mmap-backed store | HIGH (enabling) | HIGH | P1 |
| Session handling (declarative, ZAP-shape) | HIGH | MEDIUM–HIGH | P1 |
| Crawler + live passive crawl + live audit | HIGH | MEDIUM | P2 (after mmap store) |
| WebSockets capture + repeater | HIGH | MEDIUM–HIGH | P2 |
| Filter/query DSL (HTTPQL-shape) | MEDIUM–HIGH | MEDIUM | P2 |
| Reporting: JSON + HTML | HIGH | LOW–MEDIUM | P1 |
| Reporting: SARIF (webRequest/webResponse + GitHub-compatible location) | MEDIUM | MEDIUM | P2 |
| MCP server | MEDIUM–HIGH (differentiator) | LOW | P2 |
| RetireJS | MEDIUM | LOW | P2 |
| JWT secret wordlist checks | MEDIUM | LOW | P2 |
| Sequencer | LOW–MEDIUM (both competitors treat as plugin-tier) | MEDIUM | P3 |
| Plugin API | MEDIUM (enabling, but only once a plugin exists to justify it) | HIGH | P3 |
| Dashboard (task list, progress, event/activity log — kept minimal) | MEDIUM | LOW–MEDIUM | P2 |
| HTTP/2 | MEDIUM–HIGH (coverage risk while deferred) | HIGH | P3 (build), but name the interim coverage gap explicitly |
| DOM/JS analysis | LOW–MEDIUM (thin precedent even among competitors) | HIGH | P3, reconsider scope |

**Priority key:** P1 must-have this milestone · P2 should-have, sequenced after P1 dependencies land · P3 real but deferrable, revisit scope before committing

## Competitor Feature Analysis

| Feature | Caido | ZAP | mitmproxy | Our Approach |
|---------|-------|-----|-----------|--------------|
| Filter/query language | HTTPQL: small typed DSL, `req.`/`resp.` namespaces, comparison/containment/regex operators, AND/OR w/ precedence, savable presets (docs.caido.io — single source, LOW confidence on exact field list but the shape is clear) | Standard UI filters, no equivalent expression language found in this research | N/A (Python addon events, not a query language) | Build a small typed DSL in the HTTPQL shape, reused across history filters/match-replace/live-scan scoping — not `rhai`, not Bambda-Java |
| Plugin architecture | Client/server model: `manifest.json` + separate frontend (JS/CSS, UI) and backend (JS runtime, data/API access) plugin packages, single distributable package (developer.caido.io — single source) | Java add-ons via the ZAP Marketplace, higher barrier than JS | Python addon files, hot-reloaded automatically for the main script on file-mtime change (docs.mitmproxy.org — single source but a well-documented, unambiguous mechanism) | Prefer a scripting-language plugin surface (WASM guest or JS/TS-in-sandbox) over embedding a JVM, per ROADMAP's own note — but budget explicitly for the body-copy cost at the host/guest boundary (see Anti-Features) |
| Session handling / auth | No dedicated built-in mechanism surfaced in this research beyond general request replay; likely plugin territory | Automation Framework: declarative context config — auth method + verification strategy (loggedIn/loggedOut regex or poll) + session management method; auto re-auth on verification failure (zaproxy.org, cross-checked with community examples — MEDIUM confidence) | N/A (proxy-layer tool, no session-management concept) | Copy ZAP's declarative shape, not Burp's rule-editor/macro-maze shape |
| Token randomness analysis (Sequencer) | Community plugin (`caido-community/sequencer`) — not bundled in core | Marketplace add-on ("Token Generation and Analysis") — not bundled in core | None | Build it, but as P2/plugin-tier work, matching how both competitors actually prioritize it |
| Reporting formats | Not deeply researched here; out of this pass's scope | Native SARIF JSON report add-on: populates `webRequest`/`webResponse` (core SARIF DAST fields) alongside a synthetic `physicalLocation` for GitHub-style consumers (zaproxy.org + OASIS spec cross-check — MEDIUM confidence) | N/A | Follow ZAP's dual-representation pattern: real `webRequest`/`webResponse` for SARIF-native consumers, synthetic `physicalLocation`+`partialFingerprints.primaryLocationLineHash` for GitHub code-scanning ingestion |
| HTTP/2 | Not deeply researched here | Supported | Supported | Currently deferred per ROADMAP; flag the interim h1-only-ALPN coverage gap for smuggling/desync work rather than treating it as cost-free |

## Sources

- SARIF 2.1.0 OASIS specification, `docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html` (fetched directly) — confidence MEDIUM (single primary source, but authoritative/normative)
- GitHub code scanning SARIF support docs, `docs.github.com/.../sarif-support-for-code-scanning` (fetched directly) — confidence MEDIUM, cross-checked against the OASIS spec for field names
- ZAP SARIF JSON report add-on docs, `zaproxy.org/docs/desktop/addons/report-generation/report-sarif-json/` (fetched directly) — confidence LOW–MEDIUM (single source, but a working reference implementation, not a claim)
- Caido HTTPQL reference, `docs.caido.io/app/reference/httpql` (fetched directly) — confidence LOW (single source; official docs but no independent corroboration in this pass)
- Caido plugin architecture, `developer.caido.io/concepts/package.html` (fetched directly) — confidence LOW (single source)
- ZAP Automation Framework authentication/session docs, `zaproxy.org` pages (search + cross-checked against community configuration examples) — confidence MEDIUM
- Burp Sequencer documentation, `portswigger.net/burp/documentation/desktop/tools/sequencer` and the character-level/effective-entropy results pages (fetched + search) — confidence MEDIUM (primary vendor docs)
- FIPS 140-2 statistical test suite (monobit/poker/runs/long-run tests) — general cryptographic-engineering references (search, multiple independent sources) — confidence MEDIUM
- `caido-community/sequencer` and ZAP's "Token Generation and Analysis" add-on (GitHub + ZAP Marketplace references, search) — confidence MEDIUM (corroborated by two independent ecosystem sources)
- mitmproxy addon/event-hook and hot-reload documentation, `docs.mitmproxy.org` (search) — confidence LOW–MEDIUM (official docs, single source per claim)
- RetireJS maintenance status, `github.com/RetireJS/retire.js` releases/commits/npm (search) — confidence MEDIUM
- JWT weak-HMAC-secret attack methodology (`jwt_tool` wiki, hashcat mode 16500 usage) (search, multiple independent sources) — confidence MEDIUM
- Proxy-Wasm / Envoy Wasm extensibility docs and general WASM sandbox performance discussion (search, multiple sources) — confidence LOW–MEDIUM, used only to support the architectural caution about plugin body-copy cost, not a specific benchmark claim
- Burp session-handling-rules documentation, `portswigger.net/support/configuring-burp-suites-session-handling-rules` and related community blog posts (search) — confidence MEDIUM

---
*Feature research for: web application security testing platform (burpsy)*
*Researched: 2026-07-27*
