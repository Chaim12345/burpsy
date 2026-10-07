# Burp TOOL SURFACES -> burpsy gap map (2026-09-26)

**Oracle:** `/root/burp-re`, Burp Suite 2026.7.1 (build 51467). Method: the four-layer
protocol in `SOURCE-OF-TRUTH.md` (Montoya javadoc -> IMPL-BRIDGE -> recovered names ->
decompiled internals), with `map_root.tsv` as ground truth for string constants.

Scope: the request/response tools — Proxy, Intruder, Repeater, Comparer, Sequencer,
Collaborator, Organizer, Logger, Decoder, Replayer, Discover. Produced by a read-only
scout; every claim cites a decompiled `file:line` or a `map_root.tsv` line.

## Per-tool verdicts

| tool | verdict | gap | burp evidence | burpsy evidence |
|---|---|---|---|---|
| Proxy (interception rules) | PARTIAL | 18 match types vs burpsy's 7 — no port, protocol, IP, body or header axis | `out/clean/jdt_src/burp/Zero.java:18-54`; `map_root.tsv:27646-27654` | `internal/intercept/intercept.go:80-129`; `pages/intercept.tsx:53-61` |
| Proxy (match & replace) | LANDED | all 9 Burp targets present incl. both WS directions | `tools/proxy/match-and-replace/index.html:39-45` | `internal/matchreplace/matchreplace.go:25-31,399-400`; `pages/matchreplace.tsx:18-28` |
| Proxy (listener certificate) | PARTIAL | no per-listener cert (self-signed/CA-signed/fixed-hostname/PKCS#12) and no TLS-protocol set | `settings/tools/proxy.html:166-218` | `ui/src/lib/proxy-listener.ts:18-24` (5 fields, no cert) |
| Proxy (response modification) | PARTIAL | 7 of 9 rules; "Prominently highlight unhidden fields" absent | `settings/tools/proxy.html:322-353` | `pages/proxysettings.tsx:37-85` |
| Proxy (TLS passthrough) | PARTIAL | cannot apply to out-of-scope items; never auto-adds on a TLS failure | `settings/tools/proxy.html:408-412,448-474` | `internal/proxy/proxy.go:69-146` |
| Intruder | PARTIAL | DoS mode absent (stated as unimplemented in the UI) | `tools/intruder/configure-attack/settings.html:107` | `pages/intruder.tsx:2826-2836` |
| Repeater | PARTIAL | no per-tab "Restore global default", no default tab group, no streaming timeout | `settings/tools/repeater.html:79-86,163-200`; `tools/repeater/tab-settings.html:56-59` | `internal/web/repeater_options.go:26-47`; `pages/repeater.tsx:1599-1660` |
| Repeater (groups) | LANDED | 3-mode group send incl. synchronized Parallel | `tools/repeater/groups.html` | `internal/web/api_repeater_group.go:49-55,281-297` |
| Comparer | PARTIAL | no sync-view scroll lock | `settings/tools/comparer.html` | `internal/tools/comparer.go:45-53,109-113` |
| Sequencer | PARTIAL | no Analysis-settings surface: tests cannot be individually disabled, no "Redo analysis" | `settings/tools/sequencer.html:91-111` | `internal/sequencer/advanced.go:113-163` |
| Collaborator | PARTIAL | no custom-data payload mint, no WITHOUT_SERVER_LOCATION, no secret-key re-create | `collaborator/CollaboratorClient.java:42-54`; `PayloadOption.java:19` | `internal/web/api_collaborator.go:619-638` |
| Organizer | PARTIAL | no CSV import; no Param-count/Query columns | `tools/organizer/index.html:88,200` | `pages/organizer.tsx:655-677` |
| Logger | PARTIAL | capture filter has no per-item size limit and no "discard items without responses" | `tools/logger/filter/capture.html:71-77,96,134-136` | `pages/logger.tsx:216-232,590-598` |
| Decoder | PARTIAL | hash set is 4 of Burp's 62 digests | `utilities/DigestAlgorithm.java:16-77` | `internal/web/api_toolkit.go:1964-1976` |
| Replayer | MISSING | no recorded-login *recording* surface (session macros are the analogue) | `map_root.tsv:26998`; `adding-recorded-logins.html:36-70` | `internal/session/AGENTS.md:8-12` |
| Discover | LANDED (by decision) | burpsy's DISCOVER tab is an in-app reference; the crawler is Target->Content discovery | `map_root.tsv:23997-24004` | `pages/discover.tsx:32-49`; `pages/contentdiscovery.tsx:32-73` |

## Ready-to-file beads

### 1. proxy: interception rules expose 7 match types to Burp's 18 - no port, protocol, IP, body or header axis
- **Claim:** Burp's rule dialog has 18 match types per direction; burpsy has 7
  (host/path/extension/method/url/status_code/content_type), so "hold requests to port 8443"
  or "hold responses whose body contains X" cannot be written.
- **Evidence:** Burp `out/clean/jdt_src/burp/Zero.java:18-54` (18-case factory, 0-17) +
  `map_root.tsv:27646-27654`; burpsy `internal/intercept/intercept.go:80-129`, UI list
  `pages/intercept.tsx:53-61`.
- **Fix direction:** add `port`/`protocol`/`ip` (and response-body/headers for the response
  list) as `Field` constants with `ParseField` + `FieldValue` branches, then rows in the UI
  FIELDS list; a rule naming a field the direction cannot supply stays dead-weight, which the
  existing ladder already handles.
- **Why it matters:** port- and protocol-scoped interception is how an operator holds one
  service's traffic without stopping the rest of a session.

### 2. proxy settings: TLS passthrough cannot be applied to out-of-scope items, and never auto-adds on a TLS failure
- **Claim:** Burp couples the passthrough list to scope ("Apply to out-of-scope items", only
  enabled when out-of-scope logging is) and can add a server automatically when a client TLS
  negotiation fails; burpsy's TlsPolicy is a flat host+port list with neither.
- **Evidence:** Burp `settings/tools/proxy.html:408-412,448-474`; burpsy
  `internal/proxy/proxy.go:69-146` (`passthrough []string`, `passthroughPorts []uint16`, no
  scope, no auto-add), UI `ui/src/lib/data.policy.ts:368-389`.
- **Fix direction:** add `ApplyOutOfScope bool` to TlsPolicy checked in `interceptTLS`, and a
  `NoteFailedNegotiation(host)` called from the handshake-error branch writing the pattern
  through the existing Add path.
- **Why it matters:** a client that pins certificates currently costs a probe-and-retry loop;
  Burp turns the failure itself into the passthrough entry.

### 3. repeater: no per-tab "Restore global default" and no default tab group, so a group send silently uses per-tab options
- **Claim:** Burp lets a tab override global settings wholesale and then "Restore global
  default"; burpsy's per-tab options are always live and a tab always looks overridden even
  when it holds only defaults.
- **Evidence:** Burp `tools/repeater/tab-settings.html:56-59` (blue icon + restore item),
  `settings/tools/repeater.html:182-199`; burpsy `internal/web/repeater_options.go:26-47` (no
  `inherits_global` flag), `pages/repeater.tsx:1599-1653`.
- **Fix direction:** an `inherits_global bool` on the tab options; the panel shows a "Restore
  global default" row that clears it, and `repeaterSendSpec` skips per-tab options when set.
- **Why it matters:** today an operator cannot tell "this tab uses the defaults" from "this tab
  was tuned yesterday", which is exactly the state a group send depends on.

### 4. sequencer: no Analysis settings tab - the tests cannot be individually enabled or the analysis re-run
- **Claim:** Burp's Analysis settings tab lets an operator switch individual tests off and
  "Redo analysis"; burpsy's battery is a fixed set, so a known token characteristic cannot be
  excluded from the verdict.
- **Evidence:** Burp `settings/tools/sequencer.html:91-111`; burpsy
  `internal/sequencer/advanced.go:182-217` (four tests hard-wired), `internal/sequencer/report.go`
  (`AnalyseWith` takes only significance).
- **Fix direction:** a `tests []string` (or `disabled_tests`) field on the analyse request
  threaded into `advancedFor` and `AnalyseFips`, with a test that disabling the compression test
  removes it from `advanced.tests` while `Grade` and `Fips` stay byte-identical.
- **Why it matters:** a test that does not apply to a token class currently drags the verdict
  toward a false negative with no way to say so.

### 5. collaborator: a payload cannot carry custom data and the server location cannot be excluded
- **Claim:** Burp's `generatePayload(String customData, ...)` attaches up to 16 alphanumeric
  characters recoverable from any resulting interaction, and `PayloadOption.WITHOUT_SERVER_LOCATION`
  drops the location; burpsy's mint takes a count only, so a payload is never self-identifying.
- **Evidence:** Burp `out/burp/api/montoya/collaborator/CollaboratorClient.java:42-54`,
  `PayloadOption.java:19`; burpsy `internal/web/api_collaborator.go:619-638` (`struct{ Count int }`).
- **Fix direction:** accept `custom_data` (alphanumeric, <=16, 400 otherwise) and
  `without_server_location bool`, splice the custom data into the minted marker so `attributeTo`
  still correlates, and carry both on the wire.
- **Why it matters:** an operator minting five payloads for five parameters cannot tell which
  one fired without custom data; it is the difference between "something interacted" and "the
  search parameter is the injectable one".
