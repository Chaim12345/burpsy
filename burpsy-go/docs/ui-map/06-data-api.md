# Burpsy React UI — API/Data Layer Mapping

## Endpoint Inventory

| Method | Path | Go handler | Frontend caller | Query params | Request body | Response type |
|--------|------|-----------|-----------------|--------------|--------------|---------------|
| GET | `/api/history` | `handleHistory` | `useHistory()` | `q` (filter DSL), `limit` | — | `Exchange[]` |
| GET | `/api/message/{id}` | `handleMessage` | `useMessage(id)` | — | — | `MessageView` |
| GET | `/api/exchange/{id}` | `handleExchange` | `useExchange(id)` | — | — | `Exchange` |
| GET | `/api/exchanges/{id}` | `handleExchange` | — | — | — | `Exchange` |
| GET | `/api/stats` | `handleStats` | `useStats()` | — | — | `Stats` |
| GET/HEAD | `/ca.crt` | `handleCACert` | `useCaCert()` (HEAD only) | — | — | PEM binary or 404 |
| GET/POST | `/api/scope` | `handleScope` | `useScopeView()`, `useUpdateScope()` | — | `ScopeUpdate` | `ScopeView` |
| GET | `/api/issues` | `handleIssues` | `useIssuesDetailed()`, `useIssues()` | — | — | `IssuesDetail` / `Issues` |
| GET | `/api/findings` | `handleFindings` | — | — | — | `Issues` |
| POST | `/api/repeater/send` | `handleRepeaterSend` | `useRepeaterSend()` | — | `{target, request, protocol, from_exchange}` | `RepeaterResult` |
| GET | `/api/protocols` | `handleProtocols` | `useProtocols()` | — | — | `ProtocolReport` |
| POST | `/api/http2/program` | `handleHTTP2Program` | `useSendFrameProgram()` | — | `FrameProgramRequest` | `FrameProgramResponse` |
| POST | `/api/intruder/points` | `handleIntruderPoints` | `useIntruderPoints()` | — | `{msg_id, all}` | `PointView[]` |
| POST | `/api/intruder/run` | `handleIntruderRun` | `useIntruderRun()` | — | `IntruderRunRequest` | — |
| GET/POST | `/api/scanner/live` | `handleScannerLive` | `useScannerLive()`, `useSetScannerLive()` | — | `{enabled, query}` | `LiveAuditState` |
| GET | `/api/scanner/coverage` | `handleScannerCoverage` | `useScannerCoverage()` | — | — | `ScannerCoverage` |
| GET | `/api/scanner/configs` | `handleScannerConfigs` | `useScannerConfigs()` | — | — | `ScannerConfigsResponse` |
| POST | `/api/scanner/audit` | `handleScannerAudit` | — | — | `{exchange_id, config}` | `AuditResult` |
| POST | `/api/audit/{id}` | `handleAuditByPath` | `useRunAudit()` | — | `{config}` (optional) | `AuditResult` |
| POST | `/api/sequencer/analyse` | `handleSequencerAnalyse` | `useSequencerAnalyse()`, `useSequencerAnalyseTokens()` | — | `{text, encoding}` or `{tokens, encoding}` | `SequencerAnalysis` |
| GET | `/api/sequencer/capture/{id}` | `handleSequencerCapture` | `useSequencerCapture(id)` | — | — | `SequencerCapture` |
| POST | `/api/sequencer/capture/stop` | `handleSequencerCapture` | `useStopSequencerCapture()` | — | `{}` | `{stopped}` |
| GET/POST | `/api/session/rules` | `handleSessionRules` | `useSessionRulesFull()`, `useSaveSessionRule()` | — | `SessionRule` | `SessionRulesResponse` |
| GET/PUT/POST | `/api/session/rules/{id}` | `handleSessionRuleDetail` | `useSaveSessionRule()`, `useDeleteSessionRule()`, `useUpdateSessionMacro()` | — | `SessionRule` | `{rule: SessionRule}` |
| DELETE | `/api/session/rules/{id}` | `handleSessionRuleDetail` | `useDeleteSessionRule()` | — | — | — |
| POST | `/api/session/rules/{id}/update-macro` | `handleSessionRuleDetail` | `useUpdateSessionMacro()` | — | `{}` | `{steps: SessionMacroStep[]}` |
| GET | `/api/session/cookies` | `handleSessionCookies` | `useSessionCookies()` | — | — | `SessionCookiesResponse` |
| POST | `/api/session/login` | `handleSessionLogin` | `useSessionLogin()` | — | `{probe: SessionMacroStep}` | `SessionLoginResponse` |
| GET | `/api/intercept` | `handleIntercept` | `useInterceptDetailed()`, `useIntercept()` | — | — | `InterceptStateDetail` / `InterceptState` |
| POST | `/api/intercept/enable` | `handleInterceptEnable` | `useInterceptControls().setEnabled()` | — | `{enabled}` | — |
| GET/PUT | `/api/intercept/rules/{dir}` | `handleInterceptRules` | `useInterceptRules()`, `useSaveInterceptRules()` | — | `{active, rules}` | `InterceptListState` |
| POST | `/api/intercept/{id}/forward` | `handleInterceptHeld` | `useInterceptControls().forward()`, `useForwardHeld()` | — | `{raw, fix_content_length}` | — |
| POST | `/api/intercept/{id}/drop` | `handleInterceptHeld` | `useInterceptControls().drop()` | — | `{reason}` | — |
| GET | `/api/sitemap` | `handleSitemap` | `useSitemapDetailed()`, `useSitemap()` | `host`, `path` | — | `SiteMapDetail` / `SiteMap` |
| GET | `/api/dashboard` | `handleDashboard` | `useDashboard()` | — | — | `Dashboard` |
| GET | `/api/events` | `handleEvents` | `useEventStream()` (SSE) | — | — | Server-Sent Events (streaming) |
| GET | `/api/events/stats` | `handleEventsStats` | `useEventHubStats()` | — | — | `EventHubStats` |
| GET/PUT | `/api/tools/rules` | `handleMatchReplaceRules` | `useMatchReplace()`, `useSaveMatchReplace()` | — | `MatchReplaceConfig` | `MatchReplaceResponse` |
| POST | `/api/tools/rules/test` | `handleMatchReplaceTest` | `useTestMatchReplace()` | — | `MatchReplaceTestRequest` | `MatchReplaceTestResponse` |
| GET/DELETE | `/api/tools/log` | `handleToolLog` | `useToolLog()`, `useClearToolLog()` | `limit`, `filter`, `search` | — | `ToolLog` / `ToolLogView` |
| POST | `/api/tools/decode` | `handleToolsDecode` | `useTransformPipeline()` (step runner) | — | `{input, encoding, guess_alphabets}` | `DecodeResponse` |
| POST | `/api/tools/encode` | `handleToolsEncode` | `useTransformPipeline()` (step runner) | — | `{input, encoding}` | `EncodeResponse` |
| POST | `/api/tools/hash` | `handleToolsHash` | `useTransformPipeline()` (step runner) | — | `{input, algorithm}` | `HashResponse` |
| POST | `/api/tools/compare` | `handleToolsCompare` | `useCompare()` | — | `{a, b}` | `CompareResponse` |
| GET/POST | `/api/tools/organizer` | `handleOrganizer` | `useOrganizerMutations().add()` | — | `{exchange}` | `OrganizerItem` |
| POST/DELETE | `/api/tools/organizer/{id}` | `handleOrganizerItem` | `useOrganizerMutations().save()`, `remove()` | — | `OrganizerItem` | — |
| GET | `/api/ws/connections` | `handleWSConnections` | `useWsConnections()` | — | — | `WsConnection[]` |
| GET | `/api/ws/history` | `handleWSHistory` | `useWsHistory()` | `exchange`, `limit` | — | `WsHistory` |
| GET | `/api/ws/message/{id}` | `handleWSMessage` | `useWsMessageDetailed()` | — | — | `WsMessageDetail` / `WsMessage` |
| GET | `/api/report/{format}` | `handleReport` | — | — | — | HTML/JSON/SARIF |
| GET | `/` | `handleUI` | — | — | — | HTML (embedded UI) |

## React Query Keys

| Key factory | Key shape | Used by | Invalidated by |
|-------------|-----------|---------|----------------|
| `keys.stats` | `["stats"]` | `useStats()` | `history`, `capture`, `scanner` events |
| `keys.scope` | `["scope"]` | `useScope()`, `useScopeView()` | `scope` event |
| `keys.dashboard` | `["dashboard"]` | `useDashboard()` | `history`, `capture`, `issues`, `scanner`, `toollog`, `task`, `tasks`, `dashboard` events |
| `keys.history(q, limit)` | `["history", q, limit]` | `useHistory()` | `history`, `capture`, `sitemap` events |
| `keys.message(id)` | `["message", id]` | `useMessage()` | — (read-only) |
| `keys.exchange(id)` | `["exchange", id]` | `useExchange()` | — (read-only) |
| `keys.issues` | `["issues"]` | `useIssuesDetailed()`, `useIssues()` | `issues`, `scanner` events |
| `keys.intercept` | `["intercept"]` | `useIntercept()`, `useInterceptDetailed()` | `intercept` event, polling every 1.5s |
| `keys.sitemap` | `["sitemap"]` | `useSitemapDetailed()`, `useSitemap()` | `sitemap` event |
| `keys.wsConnections` | `["ws", "connections"]` | `useWsConnections()` | `ws` event |
| `keys.wsHistory(exchange)` | `["ws", "history", exchange]` | `useWsHistory()` | `ws` event |
| `keys.wsMessage(id)` | `["ws", "message", id]` | `useWsMessageDetailed()` | — (read-only) |
| `keys.toolLog(filter, search)` | `["toollog", filter, search]` | `useToolLog()` | `toollog` event |
| `keys.organizer` | `["organizer"]` | `useOrganizer()` | `organizer` event |
| `keys.rules` | `["rules"]` | `useMatchReplace()` | `rules` event |
| `keys.sessionRules` | `["session", "rules"]` | `useSessionRulesFull()`, `useSaveSessionRule()`, `useDeleteSessionRule()` | `session` event |
| `keys.sessionCookies` | `["session", "cookies"]` | `useSessionCookies()` | `session` event |
| `keys.protocols` | `["protocols"]` | `useProtocols()` | — (rarely changes) |
| `keys.scannerConfigs` | `["scanner", "configs"]` | `useScannerConfigs()` | — (config list) |
| `keys.scannerCoverage` | `["scanner", "coverage"]` | `useScannerCoverage()` | — (read-only coverage) |
| `keys.scannerLive` | `["scanner", "live"]` | `useScannerLive()` | `scanner` event, polling every 2s |
| `attackKeys.interceptRules(dir)` | `["intercept", "rules", dir]` | `useInterceptRules()` | `intercept` event |
| `policyKeys.eventStats` | `["events", "stats"]` | `useEventHubStats()` | — (stats only) |
| `policyKeys.caCert` | `["ca-cert"]` | `useCaCert()` | — (read-only, probed via HEAD) |
| `workbenchKeys.toolLog(filter, search, limit)` | `["toollog", "logger", filter, search, limit]` | `useToolLogView()` | `toollog` event |
| `workbenchKeys.sequencerCapture(id)` | `["sequencer", "capture", id]` | `useSequencerCapture()` | polling every 1s |

## Mutations

| Mutation hook | Endpoint | On success | On error | What it invalidates |
|---------------|----------|-----------|----------|-----------------------|
| `useSaveMatchReplace()` | PUT `/api/tools/rules` | Invalidate `keys.rules` | Toast error | `["rules"]` |
| `useSaveSessionRule()` | POST/PUT `/api/session/rules[/{id}]` | Invalidate `["session"]` | Toast error | `["session"]` |
| `useDeleteSessionRule()` | DELETE `/api/session/rules/{id}` | Invalidate `["session"]` | Toast error | `["session"]` |
| `useOrganizerMutations().add()` | POST `/api/tools/organizer` | Invalidate `keys.organizer` | Toast error | `["organizer"]` |
| `useOrganizerMutations().save()` | POST `/api/tools/organizer/{id}` | Invalidate `keys.organizer` | Toast error | `["organizer"]` |
| `useOrganizerMutations().remove()` | DELETE `/api/tools/organizer/{id}` | Invalidate `keys.organizer` | Toast error | `["organizer"]` |
| `useClearToolLog()` | DELETE `/api/tools/log` | Invalidate `[["toollog"], keys.dashboard]` | Toast error | `["toollog"]`, `["dashboard"]` |
| `useInterceptControls().setEnabled()` | POST `/api/intercept/enable` | Invalidate `keys.intercept` | Toast error | `["intercept"]` |
| `useInterceptControls().forward()` | POST `/api/intercept/{id}/forward` | Invalidate `keys.intercept` | Toast error | `["intercept"]` |
| `useInterceptControls().drop()` | POST `/api/intercept/{id}/drop` | Invalidate `keys.intercept` | Toast error | `["intercept"]` |
| `useSaveInterceptRules()` | PUT `/api/intercept/rules/{dir}` | Invalidate `attackKeys.interceptRules(dir)`, `keys.intercept` | Toast error | `["intercept", "rules", dir]`, `["intercept"]` |
| `useForwardHeld()` | POST `/api/intercept/{id}/forward` | Invalidate `keys.intercept` | Toast error | `["intercept"]` |
| `useTestMatchReplace()` | POST `/api/tools/rules/test` | Return response | Toast error | — (no cache) |
| `useSessionLogin()` | POST `/api/session/login` | Invalidate `["session"]` | Toast error | `["session"]` |
| `useUpdateSessionMacro()` | POST `/api/session/rules/{id}/update-macro` | Invalidate `["session"]` | Toast error | `["session"]` |
| `useSendFrameProgram()` | POST `/api/http2/program` | Return response | Toast error | — (no cache) |
| `useUpdateScope()` | POST `/api/scope` | Invalidate `keys.scope` | Toast error | `["scope"]` |
| `useRepeaterSend()` | POST `/api/repeater/send` | Return response | Toast error | — (no cache, logged to toolLog) |
| `useIntruderPoints()` | POST `/api/intruder/points` | Return response | Toast error | — (no cache) |
| `useIntruderRun()` | POST `/api/intruder/run` | Return response | Toast error | — (no cache, async job) |
| `useRunAudit()` | POST `/api/audit/{id}` | Invalidate `keys.issues`, `keys.dashboard` | Toast error | `["issues"]`, `["dashboard"]` |
| `useSetScannerLive()` | POST `/api/scanner/live` | Invalidate `keys.scannerLive` | Toast error | `["scanner", "live"]` |
| `useSequencerAnalyse()` | POST `/api/sequencer/analyse` | Return response | Toast error | — (no cache) |
| `useSequencerAnalyseTokens()` | POST `/api/sequencer/analyse` | Return response | Toast error | — (no cache) |
| `useStopSequencerCapture()` | POST `/api/sequencer/capture/stop` | Invalidate `["sequencer", "capture"]` | Toast error | `["sequencer", "capture"]` |
| `useTransformPipeline()` | POST chain of `/api/tools/{decode,encode,hash}` | Return pipeline result | Toast error, return partial | — (no cache) |
| `useCompare()` | POST `/api/tools/compare` | Return response | Toast error | — (no cache) |
| `useLoadMessage()` | GET `/api/message/{id}` | Return message text | Toast error | — (no cache) |

## Live Updates (Event Stream)

**Endpoint:** `GET /api/events` (Server-Sent Events)

The event stream (EventSource at `/api/events`) sends frames with `{ kind: string }`. Events are coalesced into batches with a 350ms flush timer to prevent request storms. Frame kinds and their cache invalidations:

| Event kind | Invalidates | Source |
|-----------|------------|--------|
| `hello` | — | Connection handshake (ignored) |
| `ping` | — | Keep-alive (ignored) |
| `history` | `["history"]`, `["stats"]`, `["sitemap"]`, `["dashboard"]` | Exchange captured |
| `capture` | `["history"]`, `["stats"]`, `["sitemap"]`, `["dashboard"]` | Same as history (synonym) |
| `issues` | `["issues"]`, `["dashboard"]`, `["scanner"]` | Finding created/updated |
| `scanner` | `["issues"]`, `["dashboard"]`, `["scanner"]` | Scanner state changed |
| `toollog` | `["toollog"]`, `["dashboard"]` | Tool action logged |
| `dashboard` | `["dashboard"]` | Task started/finished or event logged |
| `task` | `["dashboard"]` | Task lifecycle event |
| `tasks` | `["dashboard"]` | Multiple tasks changed |
| `ws` | `["ws"]`, `["stats"]`, `["dashboard"]` | WebSocket message captured |
| `intercept` | `["intercept"]` | Held message added/resolved |
| `scope` | `["scope"]` | Scope rules changed |
| `session` | `["session"]` | Session rules/cookies changed |
| `sitemap` | `["sitemap"]`, `["dashboard"]` | Site map node updated |
| `organizer` | `["organizer"]` | Organizer item added/changed |
| `rules` | `["rules"]` | Match/replace rules changed |

**Polling endpoints** (not on event stream):
- `useIntercept()`: polls every 1.5s for held messages
- `useScannerLive()`: polls every 2s for sweep progress
- `useSequencerCapture()`: polls every 1s for capture progress

## Cross-tool Actions (`lib/actions.ts`)

**`useExchangeActions()`** — returns 8 actions all reading `Exchange`:

| Action | What it fetches | Store writes | Navigation | Success toast | Error toast |
|--------|-----------------|--------------|-----------|---------------|------------|
| `sendToRepeater` | `GET /api/message/{exchange.request}` | `openRepeaterTab`, `setRoute` | → `repeater` | `"Exchange #N sent to Repeater"` | `"Could not load request bytes: ..."` |
| `sendToIntruder` | — | `setIntruderSeed`, `setRoute` | → `intruder` | `"Exchange #N sent to Intruder"` | — |
| `sendToComparer(ex, slot)` | `GET /api/message/{exchange.request}` | `setComparerSlot`, `setRoute` | → `comparer` | `"Exchange #N loaded into slot X"` | `"Could not load request bytes: ..."` |
| `addToOrganizer` | Mutates via `useOrganizerMutations().add()` | — | — | `"Exchange #N added to Organizer"` | `"Could not organize exchange: ..."` |
| `copyUrl` | — | — | — | `"URL copied"` | — |
| `copyCurl` | `GET /api/message/{exchange.request}` | — | — | `"curl command copied"` | `"Could not build curl: ..."` |
| `filterByHost` | — | `setHistoryQuery` | → `history` | — | — |
| `menu` | — | — | — | — | — |

All actions use `exchangeUrl()` and `exchangeAuthority()` to construct URLs from `{tls, host, port, path}` and infer scheme from `tls` boolean or port 443.

## Zustand Store (`lib/store.ts`)

**Store:** `useApp()` with `zustand/persist` middleware

| Field | Type | Default | Persisted? | Written by | Read by |
|-------|------|---------|-----------|-----------|---------|
| `route` | `string` | `"dashboard"` | ✓ No | `setRoute()` | UI navigation, page components |
| `theme` | `"light" \| "dark" \| "system"` | `"system"` | ✓ Yes | `setTheme()` | Theme provider |
| `density` | `"comfortable" \| "compact"` | `"comfortable"` | ✓ Yes | `setDensity()` | Layout components |
| `paletteOpen` | `boolean` | `false` | ✓ No | `setPaletteOpen()` | Palette modal |
| `shortcutsOpen` | `boolean` | `false` | ✓ No | `setShortcutsOpen()` | Keyboard help modal |
| `repeaterTabs` | `RepeaterTab[]` | `[]` | ✓ Yes | `openRepeaterTab()`, `updateRepeaterTab()`, `closeRepeaterTab()` | Repeater pane |
| `activeRepeaterTab` | `string \| null` | `null` | ✓ Yes | `setActiveRepeaterTab()` | Repeater tab bar |
| `intruderSeed` | `IntruderSeed \| null` | `null` | ✓ No | `setIntruderSeed()` | Intruder form (seed one request) |
| `comparerSlots` | `{ a: string; b: string }` | `{ a: "", b: "" }` | ✓ No | `setComparerSlot()` | Comparer view |
| `historyFocus` | `number \| null` | `null` | ✓ No | `focusExchange()` | History scroll-to |
| `historyQuery` | `string` | `""` | ✓ No | `setHistoryQuery()` | History filter DSL |

**Persisted fields** (survive reload via localStorage key `"burpsy.workspace"`):
- `theme`
- `density`
- `repeaterTabs` (so drafts survive reload)
- `activeRepeaterTab` (so the active tab is restored)

**Transient fields** (cleared on reload):
- `route`, `paletteOpen`, `shortcutsOpen`, `intruderSeed`, `comparerSlots`, `historyFocus`, `historyQuery`

**Special behavior:**
- `setRoute(route)` also sets `paletteOpen: false` to close any open palette
- `openRepeaterTab()` generates unique IDs (`t${Date.now().toString(36)}${sequence}`) and keeps only the last 12 tabs
- `closeRepeaterTab()` auto-switches to the previous tab if the active tab was closed

## Risks

### 1. **ID validation (zero check)**
- **Files:** `data.ts`, `data.observe.ts`
- **Risk:** Guards use `id >= 0`, NOT `id > 0`, because message 0, exchange 0, and ws message 0 are all real rows (position-is-the-id counters from zero).
- **Mitigation:** Comments note this explicitly; DO NOT change to `> 0` or first captures will show "No request bytes captured".

### 2. **Absence encoded as zero**
- **Files:** `data.observe.ts`, `data.attack.ts`
- **Risk:** ID parameters can be `null | undefined`, passed as `id ?? 0` or `id ?? -1` to the query key factory.
  - `useMessage(id)` checks `typeof id === "number" && id >= 0` before enabling fetch
  - `useExchange(id)` uses `id ?? -1` in key but only enables when `typeof id === "number"`
  - `useWsMessage(id)` same pattern
- **Mitigation:** Enabled flags prevent fetch for undefined IDs; **watch that `null` values never result in a fetch with id=0 that returns the wrong row**.

### 3. **Undefined/empty string params in mutations**
- **File:** `data.workbench.ts`
- **Risk:** `useSequencerAnalyse()` omits the `encoding` field when it's falsy, letting the server detect. If an empty string is sent, the handler rejects it. A caller sending `undefined` will work; sending `""` will fail.

### 4. **Async action without awaited result**
- **File:** `actions.ts`
- **Risk:** `sendToRepeater`, `sendToComparer`, `copyCurl`, `addToOrganizer` all call `await fetchRaw()` or mutations, but can throw. Callers wrap in try/catch and toast the error. **If a caller forgets try/catch, the error is silent**.

### 5. **Repeater tab overflow**
- **File:** `store.ts` line 87
- **Risk:** `openRepeaterTab()` keeps only the last 12 tabs (`.slice(-12)`). Tabs 1–N are silently discarded if the user opens 13 or more. **No warning to the operator**.

### 6. **Match/Replace rule compilation**
- **File:** `data.attack.ts`, comment line 56
- **Risk:** `useSaveInterceptRules()` refuses the ENTIRE list if one pattern fails to compile. The server compiles every pattern and returns the error verbatim. A rejected save leaves the operator's edit on screen untouched. **Watch: a bad regex can be frustrating to debug if the error message is opaque**.

### 7. **Intercept fixed Content-Length**
- **File:** `data.attack.ts` line 81
- **Risk:** `useInterceptControls().forward()` hard-codes `fix_content_length: true`, silently correcting a mismatched Content-Length. `useForwardHeld()` makes it a parameter. **Different behavior between two forward paths—watch for operator confusion**.

### 8. **Event stream burst coalescing**
- **File:** `data.ts` lines 121–131
- **Risk:** Event kinds are collected into a Set and flushed every 350ms. A burst of events that arrives within that window is deduplicated by kind. A crawl emitting hundreds of `history` frames per second becomes one fetch. **Watch: a UI showing stale data for up to 350ms is by design; document this in UX text**.

### 9. **Unhandled race: fetch abort and overwrite**
- **File:** `data.ts` line 202
- **Risk:** `useResource()` passes a signal to abort in-flight requests when the key changes. A slow earlier response can never overwrite a newer one. **This is actually GOOD—but if a handler doesn't abort on signal cancellation, an old response can still land. Check server-side if cancellation is handled properly.**

### 10. **CA certificate availability encoded as 404**
- **File:** `data.policy.ts` line 67
- **Risk:** `useCaCert()` probes `/ca.crt` with HEAD. A 404 means TLS interception is off. Any other error (500, 503) is reported as-is. **If the proxy crashes, the error message will confuse the operator**.

### 11. **Repeater protocol inference**
- **File:** `actions.ts` line 23
- **Risk:** `schemeOf()` checks `exchange.tls` (boolean), but if `tls` is `null` or another falsy value, it falls back to checking `port === 443`. `exchange.protocol` on the wire is the HTTP version ("Http1"/"Http2"), NOT the scheme. **A captured exchange with `tls: null` and port not 443 will be sent to Repeater as `http://`, which may fail silently.**

### 12. **Organizer mutation without cache key**
- **File:** `data.ts` line 214
- **Risk:** `useOrganizer()` reads from `/api/tools/organizer` with key `["organizer"]`. The mutation doesn't cache the posted item; it invalidates the list. **If the POST fails, the item never lands on screen, but the UI might try to re-send from an optimistic update.**

### 13. **Session rule update with 409 conflict**
- **File:** `data.policy.ts` line 113
- **Risk:** `useUpdateSessionMacro()` answers 409 when nothing was observed. The frontend does not check for this status; the error handler will show "Conflict" as a toast. **Watch: the operator needs to know the last login run had no captures before attempting update—the error message is unhelpful.**

### 14. **Audit result not cached**
- **File:** `data.attack.ts` line 128
- **Risk:** `useRunAudit()` returns the result to the caller but does NOT cache it (no `queryKey`, direct mutationFn return). Re-running the same exchange can produce a different result (real traffic, no idempotency). **This is intentional, but watch: the UI does not keep a history of audit runs—each new run overwrites the previous.**

### 15. **Message fetch has no error boundary**
- **File:** `actions.ts` line 40, `useLoadMessage()` in `data.workbench.ts`
- **Risk:** `fetchRaw()` calls `api<MessageView>()` which throws `ApiError` on non-200. The caller must wrap in try/catch. **If the message was deleted on the server after the exchange list was fetched, the UI shows "No request bytes captured" instead of "message was deleted"—no distinction between 404 and other errors.**

### 16. **Query DSL syntax errors**
- **File:** `data.ts` line 41
- **Risk:** History query filter (DSL-02) compilation errors are returned as `http.StatusBadRequest` with the error rendered as `query.Render(err)` (caret + source line). The UI shows this verbatim in a white-space:pre box. **If the DSL parser has a bug, the operator sees the parser's internal error, not a user-facing message.**

### 17. **Repeater draft loss on navigation**
- **File:** `store.ts`
- **Risk:** `repeaterTabs` is persisted, but only the request text and name. If the UI crashes mid-draft, the draft is recovered. **But if the operator closes a tab, it's gone—no "unsaved changes" warning.**

### 18. **Browser history not tied to route**
- **File:** `store.ts`
- **Risk:** `setRoute()` updates store state but does NOT call `window.history.pushState()`. Pressing browser back does NOT navigate between pages. **This is likely by design (SPA), but watch for confusion if the route state is ever out of sync with the component tree.**

### 19. **Comparér slot overwrite without warning**
- **File:** `actions.ts` line 116
- **Risk:** `setComparerSlot()` overwrites the slot without checking if it already has content. If the operator loads slot A, then sends another exchange to slot A, the first is silently discarded. **No undo, no warning.**

### 20. **Tool log "clear" invalidates all toollog keys**
- **File:** `data.ts` line 315
- **Risk:** `useClearToolLog()` invalidates `["toollog"]` (a prefix), so every parameterized variant (filter, search) is refetched. But `keys.toolLog(filter, search)` and `workbenchKeys.toolLog(filter, search, limit)` are DIFFERENT keys (different limit defaults). **If the Workbench page is open while Dashboard's tool log is cleared, the Workbench will not refetch (wrong prefix match).**

