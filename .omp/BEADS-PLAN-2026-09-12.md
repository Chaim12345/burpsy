# Beads completion plan — the working to-do list (advisor-audited 2026-09-12)

Source: Opus advisor audit (read-only, evidence-based) + Wave 0 executed same day.
Honest state: **55 open** (48 ready, 7 decision/released), **0 blocked**. NOT close to done.

## Corrections now applied (Wave 0 — done)
- sessionRulesChanged blocker: never existed. Ignore any handoff claiming it.
- ruw closed (premise false — matchreplace Draft-test card IS the preview).
- 7nh2, rfgs stale claims released.
- Epics oco4, takx, i4fa CLOSED with recorded caveats.
- New beads: **jvyw** (scanner 18/78 scan-config keys), **63jg** (intruder XML/multipart entire-body fallback).
- c09 retitled: globs/prefixes vs per-component regex + IP ranges.
- Released issues reparented: 6ex, k3a7 → srzn; e23c, n29, sn3j, d18r, us12, 7nh2 → a09g.

## Wave 1 — HUMAN DECISIONS (gate Wave 3; cannot be done by agents)
- [ ] ayi — rule actions: which of Burp's actions are permanently declined? Data model: ordered Actions[] vs bolt-on fields. GATES us12 + most of n29's value. (L)
- [ ] kal — licensing call for shipping wordlists (wordlist manager already shipped as 016). Then close. (S)
- [ ] wkkz — extension model architecture + licensing. Multi-week if approved. (L)
- [ ] sel6 — sender architecture: NTLM needs per-connection affinity; Negotiate needs Kerberos creds. (M-L)
- [ ] 6dt — should proxy traffic join the tool log (UX divergence call). (unverified size)
- [ ] c05 — retain original message bytes (storage cost). BLOCKS n10e. (unverified size)

## Wave 2 — cheap, independent (do first, all S)
- [ ] f3k — multi-seed New scan. Wire already takes an array (dashboard.tsx:491); only the input is single. (S)
- [ ] 3fr — wire PUT/DELETE /api/issues/{id} (exist since fgv8) into the Issues row menu. (S)
- [ ] 7nh2 — stop dropping path/port/protocol in dtoToRule (api_session.go:373); add suite-scope binding. (S-M)
- [ ] so3 — ScopeTools on SessionRule; thread tool identity through MatchingRuleFor + 4 call sites. Do with 7nh2. (M)

## Wave 3 — substantive (dependency order)
- [ ] rfgs — in-scope-only Match&Replace. HIDDEN OBSTACLES: Apply lacks request identity (4 proxy sites + WS relay); request-side Apply runs BEFORE scope verdict (proxy.go:1073 vs :1107); SaveMatchRules has no scope column. (M)
- [ ] e2j6 — enable Crawl-and-audit + API-only scan (dashboard.tsx:474/476 ready:false). (M)
- [ ] d18r — re-key jar to (domain,path,name) + attributes + RFC 6265 §5.4, then 7 columns. REOPENS dkb's tests. (M)
- [ ] escl — macro recorder from Proxy history (picker + MacroStep converter). (M)
- [ ] sn3j — per-tool absorption call sites FIRST (only proxy.go:1758 today), then the toggle. (M)
- [ ] n29 — session tracer (ring + /api/session/trace + view). AFTER ayi. (M→L)
- [ ] e23c — macro parameter analyzer + Re-analyze. Ship whole or not at all. (L)
- [ ] us12 — validate-every-N. HARD DEP on ayi (no proactive check exists to throttle). (S)
- [ ] 6ex — WebSocket Repeater (new tab type, live-connection manager, direction control). (L)
- [ ] k3a7 — Compare site maps (needs crawl-run TaskID attribution + Comparer diff view). (L)
- [ ] t94i — editor tab show/hide/reorder (persisted prefs + settings popover). (L)
- [ ] jvyw — scanner: remaining scan-config keys (size per chosen target set). (M est.)
- [ ] 63jg — intruder: XML/multipart-aware insertion points. (M est.)

## Wave 4 — 29 UNVERIFIED leaves (re-run the 4 killed audits before planning)
vs9k, xvo, ww5, akv, wvcl, fkj, amu · js1, 6fq, whr, wv5, f6a, mwq, yy2, adrh · a13, dao, voc, 6dt, c05, hmp1, n10e, jcdm, sf8o, j7t · d2g, boq, i4u, fmxv
- Partial signals: xvo likely real (no per-tab attention in app.tsx); vs9k no surface found. Both need the proper audit.

## Answer to "can we exit with all-approved?"
NO. Five reasons: (1) 6 human decisions outstanding; (2) released-with-design is not a bd status — parked items (6ex, k3a7, t94i, wkkz, sel6) need explicit close-with-reason or they read as open; (3) 2 blocking edges (hmp1←ww5, n10e←c05); (4) 29 leaves unaudited; (5) Wave 3 is ~8–12 working days of real work.
