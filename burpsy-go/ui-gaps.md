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
