# altui — an alternative burpsy console (MVP)

An experiment in a workflow-centric console for burpsy, built against the
current Go backend's existing API. It does not replace the embedded console at
`internal/web/ui`; it is a separate, zero-build, zero-dependency SPA served by a
small Node proxy, so the whole lane is additive and touches no Go code.

The model is the engagement workflow, not the tool list:

- **Map** — what do we know: live site map tree + HTTP history with filters,
  exchange detail drawer, highlight/note annotations.
- **Probe** — poke it and see: request workbench (repeater). Dry run shows the
  exact bytes and the scope verdict *before* anything is sent; Send shows the
  response with timing and the recorded exchange id.
- **Attack** — held. Unbounded-traffic lanes (scanner, intruder, crawl) are
  project-held, so this MVP deliberately does not surface those controls.
- **Prove** — the evidence: consolidated findings with severity counts,
  advisory detail, occurrences that deep-link back into Map.

Live updates ride the backend's SSE stream (`/api/events`): new proxied traffic
and findings appear without a reload.

## Run

```
BURPSY_BACKEND=http://127.0.0.1:28081 ALTUI_PORT=3817 node altui/server.mjs
# open http://127.0.0.1:3817
```

## Security contract (do not relax casually)

- `server.mjs` binds **127.0.0.1 only** and adds **no CORS headers**. The
  backend has no authentication; the console is a local operator tool.
- The backend's cross-site gate (Origin == Host on mutations) is preserved, not
  bypassed: the proxy accepts a browser call only when its Origin is this
  console's own origin, and rewrites Origin to the backend authority so the
  pair matches there. Foreign origins get 403 from the proxy itself.
- The confirmation gate is a human-intent signal. On a 428 challenge the SPA
  shows the exact call and only a human click mints the one-time token
  (`POST <route>/confirm`, then retry with `X-Burpsy-Confirm`). The proxy never
  mints tokens. Destructive history deletion is intentionally not in the MVP.
- No new scanning or external targets: fixtures are a local demo app only.

## Layout

```
server.mjs        loopback static server + same-origin /api proxy
public/index.html shell with the workflow rail
public/app.js     router, health badge, SSE wiring
public/api.js     fetch wrapper with confirm-gate handling
public/components.js  modal confirm dialog, toasts, chips
public/views/     map.js, probe.js, prove.js
```
