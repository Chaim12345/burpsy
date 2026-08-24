# Burpsy UI Gaps

Documenting discrepancies between backend capabilities and UI implementation.

> **RESOLVED 2026-08-21.** Every item below was verified against a running server and closed.
> See the "Verification" section at the bottom for the evidence.

## Missing Stats Fields in UI

The following fields are present in the Go structs and should appear in /api/stats and Settings page:

- `proxy_bind`
- `web_bind`
- `tls_interception`

~~Currently, they do not appear because the server fails to start.~~
**Fixed.** `StatsView` carries all three (`api_types.go`), `handleStats` populates them from the
`WithBindAddrs` / CA-cert state, and the Settings → Proxy section renders them as metrics
(Proxy listener / Web console / TLS interception On-Off). The `Stats` TS interface was extended to
match.

## Settings Page Sections

- Proxy Settings section — should display `proxy_bind`. **Done** — renders live from `/api/stats`.
- Scanner Settings section — should display `tls_interception` (and shipped scan configurations).
  **Done** — renders `/api/scanner/configs` (29 shipped by Burp, 6 implemented here, honest omission
  reason) plus the default config's concrete settings.

## Console Errors

None observed — page loads clean with both sections rendering.

## API Response Mismatch

Expected /api/stats to return:

```json
{
  "proxy_bind": ":18400",
  "web_bind": ":18401",
  "tls_interception": true
}
```

~~But endpoint is unreachable.~~
**Resolved.** The original failure was a zombie burpsy process holding the ports; it died with the
session that spawned it. Fresh instances bind and answer normally.

## Verification (2026-08-21)

Against freshly built binaries on test ports:

- `-proxy 127.0.0.1:28400 -web 127.0.0.1:28401` → `/api/stats` returns
  `"proxy_bind":"127.0.0.1:28400","web_bind":"127.0.0.1:28401","tls_interception":false`.
- Same plus `-intercept-tls` → `"tls_interception":true`.
- Browser check (agent-browser): Settings page shows Proxy listener / Web console /
  TLS interception = Off (first instance) and = On (TLS instance); Scanner section lists presets.
- Gates at close: `tsc --noEmit` + token checks green, `bun run build` green,
  `go vet ./internal/web/... ./cmd/...` clean, `gofmt -l` clean, `go test ./internal/web/...` ok.

---

# Parity push 2026-08-21 — five committed gaps closed, each verified live

| Gap | Commit | Evidence (agent-browser against a running server) |
|---|---|---|
| Scope page was a Settings delegate; no port/path arms in UI | 288889b | rule table renders full tuples; exact-tuple remove leaves same-host sibling intact |
| Menu bar: Project naming, no Tools menu, no layout reset | 6481352 | six triggers in Burp order; Tools navigates; Reset panel layout wipes burpsy.split.* |
| WS History showed frames but not the upgrade handshake | 5f468d3 | Handshake tab renders the real GET /ws … 101 pair from proxied traffic |
| Settings had no Hotkeys section | 926ba57 | all five groups render from the shared registry (lib/shortcuts.ts) |
| Organizer highlight picker was a text select | 6669247 | colour swatch radiogroup |
| Row context menu lacked scope/scan moves | 2b435d2 | "Add host to scope" lands a real Include rule; "Audit exchange" queues an active audit |
| Logger filters short of Burp's set | bbf8a0b | method + status-class selects filter live (2xx drops no-response rows correctly) |

## Deliberate gaps remaining (documented, not hidden)

- ~~TLS passthrough was CLI-only~~ — closed 2026-08-24: `/api/proxy/passthrough`
  (GET/POST/DELETE) lists, adds and removes host patterns on the proxy's live
  `TlsPolicy`; Settings → TLS passthrough renders it with add/remove; edits mirror
  to SQLite (`tls.passthrough` setting) and are re-applied over flag-configured
  rules on startup. Verified live: add/remove round trip, exact-match removal
  answering 404 for an absent pattern, and the list surviving a server restart.
- Scan-config creation wizard — the engine implements 6 of Burp's 29 shipped configurations and
  has no custom-config knobs; a wizard would offer controls that do nothing. The functional path
  exists: context-menu "Audit exchange", or Scanner → Targeted audit with the config selector.
- No protocol arm on scope rules — core.ScopeRule matches host/port/path (scope.go:22, matching at
  :80/:88); http-vs-https scoping is a six-layer change: a Protocol field + match extension in
  core/scope.go, caller-side scheme plumbing in sender/proxy/crawler (all three know the scheme at
  decision time), a scope_rules_v3 migration following the v2 precedent (SQLite cannot alter the
  rule shape; see persist.go:657-666), wire fields in ScopeRequest/scopeRuleView (api_capture.go —
  api_config.go's bundle would carry it automatically), and a protocol select + column on the Scope
  page mirroring the existing port/path arms. Assessed and scoped 2026-08-21; deferred so it lands
  as one complete RED→GREEN cycle per layer rather than half-migrated state.
- ~~No settings/rules import-export~~ — closed dd0781f: GET /api/config/export and POST
  /api/config/import carry scope + intercept rules + session handling rules as one atomic bundle;
  an invalid rule anywhere refuses the whole import (verified live: refused bundle left scope
  untouched). File menu → Export/Import configuration.
- No plugin/extension API — deliberate architecture decision (Phase 8 never shipped).
- No system tray — needs the Wails asset pipeline (docs/DESKTOP.md).
- "Show response in browser" — Burp loops responses through its own listener; burpsy has no
  loopback surface yet. Backend work required before the menu item can exist honestly.
- IP address column / delete-from-history — unchanged deliberate gaps (Exchange carries no ip
  field; TrafficStore is append-only by design).
