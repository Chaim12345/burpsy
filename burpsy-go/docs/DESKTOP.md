# Desktop shell (Wails v2)

> Added 2026-08-20. Phase 4 of the WebUI Burp-parity plan
> (`docs/plans/2026-08-19-webui-full-plan.md`) — the desktop bridge.

## What this is

`cmd/desktop` is a native desktop shell for burpsy, built with Wails v2 (Go backend,
WebKitGTK/WebView2/WKWebView native window). It is **not** a second UI implementation:
the window renders the exact same embedded React app the `burpsy` server binary already
ships (`internal/web/ui`, built to `internal/web/ui/dist/app.js` and served by
`internal/web/Server`).

## Hybrid mode — one server, two doors

On startup the desktop app builds the same engines `cmd/burpsy/main.go` does — one
`core.TrafficStore`, one `core.Scope`, one `core.FindingStore`, handed to both the proxy
and the web server, same as the CLI — and starts both listeners in the background:

- the intercepting proxy on `-proxy` (default `127.0.0.1:8080`)
- the JSON API + embedded UI on `-web` (default `127.0.0.1:8081`)

The Wails native window does not load its own bundled assets; its `AssetServer.Handler`
is a reverse proxy (`httputil.NewSingleHostReverseProxy`) onto the in-process web server.
That means:

- the desktop window and a browser pointed at `http://127.0.0.1:8081` render byte-identical
  UI and hit the same API — there is exactly one frontend build and one backend
  implementation to keep in parity, not two,
- an operator can run the desktop app locally *and* let a teammate reach the same
  engagement remotely over the web port, at the same time — the plan's stated "hybrid
  mode" requirement,
- any web-UI parity work (the page-by-page Burp parity pass) automatically applies to
  the desktop shell with no separate porting step.

## Deliberate duplication, and why

`cmd/desktop/main.go` builds its own `proxy.NewProxyConfig` / `web.NewServer` wiring
rather than importing a shared helper from `cmd/burpsy`. `cmd/burpsy` owns the full CLI
dispatcher, flag surface and store-verify / scan-config-list early-exit paths
(`cmd/AGENTS.md`); factoring that apart from its wiring is a larger refactor than this
shell needs. The duplication is bounded to the wiring block in `startup()` and is
deliberately not persistence-backed (`-db` is accepted but not yet wired — see Known gaps)
so this file stays small enough that the two entry points can be diffed by eye. A change
to the proxy or web wiring in `cmd/burpsy/main.go` must be mirrored here until a shared
wiring package exists.

## Native integration delivered

- **System tray / native menu bar** — `buildMenu` wires File (Export History, Quit), View
  (Toggle Theme, Command Palette), Tools (Repeater/Intruder/Decoder/Comparer, each with
  the same Alt+N accelerator the web shell's hotkeys use) and Help (Keyboard Shortcuts).
  Every item emits a `burpsy:menu` / `burpsy:navigate` Wails event; the React shell listens
  for these the same way it already listens for hotkeys, so a menu click and a keyboard
  shortcut drive the identical code path.
- **File dialogs** — `SaveFileDialog` / `OpenFileDialog` are bound Go methods
  (`window.go.main.App.*`) that open native OS dialogs. `src/lib/runtime.ts`'s
  `saveFileDialog` / `openFileDialog` call them when `isDesktop()` is true and return `null`
  in web mode, so a caller can `await saveFileDialog(...)` unconditionally and fall back to
  the browser download flow (`downloadText` in `lib/api.ts`) on `null`.
- **Notifications** — `Notify` emits a `burpsy:notify` frontend event rather than a native
  OS notification. Wails v2's classic runtime has no cross-platform native-notification API
  on Linux without per-OS extra wiring (see Known gaps); routing through a frontend event
  keeps behaviour identical to the existing `sonner` toast the web UI already uses, so a
  caller gets a working notification today rather than a half-implemented native one.
- **Runtime detection** — `src/lib/runtime.ts`'s `getRuntimeMode()` checks for
  `window.runtime` (Wails' injected global); `isDesktop()` wraps it. No other file needs to
  branch on desktop vs. web directly.

## Building and running

```bash
cd burpsy-go
go build -o desktop ./cmd/desktop   # plain go build works: the window loads over HTTP,
                                     # no wails-cli asset pipeline step is required
./desktop -proxy 127.0.0.1:8080 -web 127.0.0.1:8081
```

The `wails` CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0`) is only
needed for `wails build` (bundles a smaller production binary and platform installers) or
`wails dev` (hot reload against a `wails.json` project file, not present here since this
shell reverse-proxies rather than embedding its own frontend build). Neither is required
to build or run the binary above.

System requirements on Linux: `webkit2gtk-4.1`/`libgtk-3` dev packages (both present on
this machine — see below) and a C compiler (`gcc`) for cgo.

```bash
# verified present on this machine:
pkg-config --exists webkit2gtk-4.1 && echo ok
pkg-config --exists gtk+-3.0 && echo ok
```

## Known gaps (honest, not silently deferred)

- **`-db` is accepted but not wired.** The flag exists for CLI-compatible invocation but
  `startup()` does not open a `persist.Store` or restore from it — every desktop session
  starts with an empty `TrafficStore`/`Scope`/`FindingStore`, same as `cmd/burpsy` without
  `-db`. Wiring persistence is unfinished follow-up work, not a design decision.
- **No native OS notification**, only the in-app toast via the `burpsy:notify` event (see
  above) — this is a deliberate choice given the Linux native-notification wiring cost, not
  an oversight.
- **No system tray icon**, only the native menu bar. Wails v2's tray API
  (`menu.TrayMenu`) exists but needs a bundled icon asset and `wails build`'s asset
  pipeline to embed it; this shell currently ships with a plain `go build`, so the icon
  step was left for whoever wires the `wails build` production path.
- **`-tools` allowlist, `-bchecks`, TLS interception (`-intercept-tls`), scope flags,
  `-scan-config`** and the rest of `cmd/burpsy`'s flag surface are not exposed here. The
  desktop shell intentionally starts the minimum engine set the plan's Phase 4 asked for
  (proxy + web + intercept, passive scanning on); anything else an operator needs is
  reachable through the same web UI panels (Settings, Scope, Scanner config) once the
  window is open, because it is the same server.

## Files

| File | What |
|------|------|
| `cmd/desktop/main.go` | The Wails entry point: engine wiring, reverse-proxy AssetServer, native menu, bound dialog/notify methods |
| `internal/web/ui/src/lib/runtime.ts` | `getRuntimeMode()` / `isDesktop()` plus `saveFileDialog`/`openFileDialog`/`notifyDesktop` wrappers that fall back cleanly in web mode |