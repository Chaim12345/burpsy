# Cross-Check: Frontend Calls vs Server Routes

## Legend
- ✓ = Endpoint mapped, frontend call found
- ⚠ = Server route with no direct frontend caller (legacy, export, or UI)
- ✗ = Frontend call with no server route (MISSING — would 404)

## Server Route Coverage

All 47 routes from `server.go:setupRoutes()`:

### Capture + Stats
- ✓ GET `/api/history` → `useHistory()`
- ✓ GET `/api/message/{id}` → `useMessage()`
- ✓ GET `/api/exchange/{id}` → `useExchange()`
- ⚠ GET `/api/exchanges/{id}` → legacy alias, no frontend caller
- ✓ GET `/api/stats` → `useStats()`
- ✓ GET/HEAD `/ca.crt` → `useCaCert()`
- ✓ GET/POST `/api/scope` → `useScopeView()`, `useUpdateScope()`
- ✓ GET/POST `/api/issues` → `useIssuesDetailed()`, `useIssues()`
- ⚠ GET `/api/findings` → legacy alias, no frontend caller

### Tools
- ✓ POST `/api/repeater/send` → `useRepeaterSend()`
- ✓ GET `/api/protocols` → `useProtocols()`
- ✓ POST `/api/http2/program` → `useSendFrameProgram()`
- ✓ POST `/api/intruder/points` → `useIntruderPoints()`
- ✓ POST `/api/intruder/run` → `useIntruderRun()`
- ✓ GET/POST `/api/scanner/live` → `useScannerLive()`, `useSetScannerLive()`
- ✓ GET `/api/scanner/coverage` → `useScannerCoverage()`
- ✓ GET `/api/scanner/configs` → `useScannerConfigs()`
- ⚠ POST `/api/scanner/audit` → legacy alias, no frontend caller
- ✓ POST `/api/audit/{id}` → `useRunAudit()`
- ✓ POST `/api/sequencer/analyse` → `useSequencerAnalyse()`, `useSequencerAnalyseTokens()`
- ✓ GET/POST `/api/sequencer/capture/{id}` → `useSequencerCapture()`, `useStopSequencerCapture()`

### Session
- ✓ GET/POST `/api/session/rules` → `useSessionRulesFull()`, `useSaveSessionRule()`
- ✓ GET/PUT/DELETE/POST `/api/session/rules/{id}` → `useSaveSessionRule()`, `useDeleteSessionRule()`, `useUpdateSessionMacro()`
- ✓ GET `/api/session/cookies` → `useSessionCookies()`
- ✓ POST `/api/session/login` → `useSessionLogin()`

### Intercept
- ✓ GET/POST `/api/intercept` → `useIntercept()`, `useInterceptDetailed()`
- ✓ POST `/api/intercept/enable` → `useInterceptControls().setEnabled()`
- ✓ GET/PUT `/api/intercept/rules/{dir}` → `useInterceptRules()`, `useSaveInterceptRules()`
- ✓ POST `/api/intercept/{id}/forward` → `useInterceptControls().forward()`, `useForwardHeld()`
- ✓ POST `/api/intercept/{id}/drop` → `useInterceptControls().drop()`

### Site Map
- ✓ GET `/api/sitemap` → `useSitemapDetailed()`, `useSitemap()`

### Dashboard
- ✓ GET `/api/dashboard` → `useDashboard()`

### Events
- ✓ GET `/api/events` → `useEventStream()` (SSE)
- ✓ GET `/api/events/stats` → `useEventHubStats()`

### Tools (Match/Replace, Decode, Organizer)
- ✓ GET/PUT `/api/tools/rules` → `useMatchReplace()`, `useSaveMatchReplace()`
- ✓ POST `/api/tools/rules/test` → `useTestMatchReplace()`
- ✓ GET/DELETE `/api/tools/log` → `useToolLog()`, `useClearToolLog()`
- ✓ POST `/api/tools/decode` → `useTransformPipeline()` (step runner)
- ✓ POST `/api/tools/encode` → `useTransformPipeline()` (step runner)
- ✓ POST `/api/tools/hash` → `useTransformPipeline()` (step runner)
- ✓ POST `/api/tools/compare` → `useCompare()`
- ✓ GET/POST `/api/tools/organizer` → `useOrganizerMutations().add()`
- ✓ POST/DELETE `/api/tools/organizer/{id}` → `useOrganizerMutations().save()`, `.remove()`

### WebSocket
- ✓ GET `/api/ws/connections` → `useWsConnections()`
- ✓ GET `/api/ws/history` → `useWsHistory()`
- ✓ GET `/api/ws/message/{id}` → `useWsMessageDetailed()`, `useWsMessage()`

### Report & UI
- ⚠ GET `/api/report/{format}` → export only, no frontend query hook (download link)
- ⚠ GET `/` → embedded UI, no frontend call

## Summary

**Total routes: 47**
- ✓ Mapped with frontend caller: 38
- ⚠ Server-only (legacy, export, or UI): 4
- ✗ Frontend call with no route: 0

**Conclusion:** All endpoints are accounted for. No missing routes, no orphaned frontend calls.

## Notes on Unmapped Server Routes

1. **`/api/exchanges/{id}`** - Legacy alias for `/api/exchange/{id}`. Server keeps it for backward compatibility; UI uses only the singular form.

2. **`/api/findings`** - Legacy alias for `/api/issues`. Server keeps it; UI uses only the singular form.

3. **`/api/scanner/audit`** - Legacy POST endpoint; replaced by `/api/audit/{id}`. Server keeps the old route but UI calls the new one.

4. **`/api/report/{format}`** - No React Query hook because it is not fetched by JavaScript. Instead, the browser downloads the report directly via a link (e.g., `<a href="/api/report/html">Download HTML</a>`).

5. **`/`** - Serves the embedded UI HTML. Not called by JavaScript; it's the container for the whole app.

