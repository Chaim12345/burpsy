# burpsy-go — MCP server (reference)

> **Status: shipped** (burpsy-react-ui-q31t, commit `46bba66`). `cmd/burpsy-mcp` serves a running
> burpsy console over the Model Context Protocol on stdio, so any MCP client — Claude Desktop,
> Cursor, an SDK agent — can drive burpsy while burpsy keeps its own scope and approval enforcement.
> This page is the reference: the transport, how to launch it, the tool list it exposes, and how the
> confirmation gate maps onto the risk classes.

If you want agent control *without* MCP, the [JSON API](./JSON-API.md) is still the underlying
surface and is what the MCP layer calls.

## Launching it

```bash
burpsy-mcp -web http://127.0.0.1:8081
```

The console must already be running (`burpsy`, serving its JSON API on `-web`); this command speaks
MCP on **stdin/stdout** and does not start a second console.

| Flag | Default | Meaning |
|---|---|---|
| `-web` | `http://127.0.0.1:8081` | base URL of the running console. A bare `host:port` is accepted and assumed `http`. |
| `-timeout` | `10m` | how long one HTTP call to the console may take before the transport gives up. |
| `-sync-window` | `15s` | how long a call that started a console task (an audit, a crawl, an API scan) waits for it before answering with a task handle. |
| `-no-notifications` | off | do not push task completion and High/Critical issues as `notifications/message`. |
| `-surface` | `grouped` | which tool list to publish: `grouped` (capability-grouped tools, below) or `routes` (one tool per manifest route — the pre-cvzq surface, kept for debugging and for clients bound to its names). |
| `-list` | off | print the tool surface this binary would expose (surface, route count, tool names) and exit, without speaking stdio. The manifest is compiled in, so this works with no console running. |
| `-version` | off | print the version and exit. |

Everything diagnostic goes to **stderr**; stdout carries JSON-RPC and nothing else, because a stray
line on stdout corrupts the stream.

It is a separate binary rather than a `burpsy mcp` subcommand on purpose: every `cmd/burpsy`
subcommand is built through `newCLIContext`, which opens the traffic store, loads the bcheck corpus
and constructs the scanners *before* the command runs — a second engine wired against the same
database, built only to make HTTP calls to the first.

## The transport

Newline-delimited JSON-RPC 2.0, one message per line, which is what MCP's stdio transport specifies.
Implemented methods:

| Method | Behaviour |
|---|---|
| `initialize` | reports the protocol revision (echoing the client's when it is one this server knows: `2024-11-05`, `2025-03-26`, `2025-06-18`), `capabilities.tools`, and an `instructions` block that explains the risk classes and the confirmation flow before a client calls anything. |
| `notifications/initialized` | starts the console watcher (below). Like every notification it gets **no** reply — answering one makes a client that reuses ids mis-attribute the reply. |
| `notifications/cancelled` | cancels the named call in flight; a call waiting on a console task also cancels the task (`POST /api/tasks/{id}/cancel`). The cancelled call gets no answer. |
| `logging/setLevel` | sets the minimum level of pushed `notifications/message` (default `info`). |
| `prompts/list`, `prompts/get` | the console's skill library as MCP prompts (below). |
| `tools/list` | the grouped surface (62 tools, plus `burpsy_confirm` and `burpsy_task_status`) — or, with `-surface routes`, one tool per manifest route. |
| `tools/call` | forwards the call to the console and returns its answer. Dispatched concurrently (at most 8 at once), so a long call does not stop `ping`, `tools/list` or another call; every write goes through one serialised encoder. |
| `ping` | an empty result. |

## The tool list (default: capability-grouped)

> **Changed by burpsy-react-ui-cvzq.** The default `tools/list` is no longer one tool per route. A
> client pinned to the old names (`api_history`, `api_audit`, `api_pools_subtree`, …) runs
> `burpsy-mcp -surface routes`, which still publishes exactly that list; the section after this one
> describes it.

The grouped surface is a curated table (`internal/mcp/groups.go`) of capability tools — `history`,
`send`, `scope`, `sitemap`, `scan`, `issues`, `intruder`, `collaborator`, `organizer`, … — each
carrying one of Burp's own agent tool-group labels (*Requests & Responses*, *Scope & Sitemap*,
*Scanning & Auditing*, *Issues*, *Fuzzing*, *Collaborator*, *Datasets*, *Configuration*, *Scan Checks*,
*Utilities*, *Scripting*) and a one-line short description. A tool fronts a few **operations**, and an
operation is exactly one `(verb, route pattern)` of the manifest, spelled that way:

```json
{"name": "history", "arguments": {"op": "GET /api/message/", "id": "12"}}
{"name": "scan",    "arguments": {"op": "POST /api/audit/", "id": "3", "confirm": "<token>"}}
```

- `op` is required when the tool fronts more than one operation, and is an enum of exactly those.
- A subtree operation (pattern ending in `/`) takes `path` (`/api/message/12`) or the shortcut `id`
  (`12` → the pattern plus `12`). The path must resolve to the operation's own route, by the gate's
  own resolver — an op cannot be pointed at another route.
- `query`, `body` and `confirm` mean what they mean on the route surface.

Two rules are enforced by tests rather than by review:

1. **Coverage.** Every manifest route-verb is reachable from exactly one grouped tool, or sits on
   `notExposed` with a reason (`TestEveryRouteVerbIsReachableFromExactlyOneGroupedTool`). Not exposed:
   `GET /` and `GET /ca.crt` (assets), `GET /reissue/` (a one-shot URL for the operator's browser),
   `GET /api/events` (the never-ending SSE stream), and the legacy aliases `GET /api/exchanges/`,
   `GET /api/findings`, `POST /api/scanner/audit`.
2. **One risk class per tool** (`TestNoGroupedToolSpansTwoRiskClasses`), so the tool-level
   annotations — `riskClass`, `requiresConfirmation`, the four MCP hints — are true of every
   operation the tool reaches. The class is always read from the manifest; the table only says which
   operations sit together. `readOnlyHint` is additionally false for any tool that can PUT, PATCH or
   DELETE. The removal of history rows is its own `history_delete` tool fronting
   `DELETE /api/history/rows`, which the manifest classes `destructive` and the gate confirms; it was
   `DELETE /api/history` under that read route's `read` class until burpsy-react-ui-gf68.

Size, measured on this branch: the grouped surface is 64 tools and about 234 KB of `tools/list`
JSON with every body and query typed; the route surface is 168 tools and about 350 KB typed; before
this work the route surface was 148 tools and about 226 KB with untyped bodies. Grouping buys the tool
count, and typing spends roughly what grouping saved.

Each grouped descriptor's annotations carry `group`, `shortDescription` and `operations` beside the
risk keys. The server refuses to start if the table names a route or verb the manifest does not
have, rather than publishing a tool that can only fail.

## The route surface (`-surface routes`)

**One tool per manifest route.** The manifest (`internal/web/route_manifest.go`) is the single source:
the tool count, each tool's risk class and whether a call needs confirmation are read from the same
map the confirmation gate reads, so a tool descriptor cannot disagree with what the server will
enforce. `/api/audit/selected` and `/api/audit/` are two tools, not one — they are two routes.

Tool names normalise the pattern (`/api/crawl/start` → `api_crawl_start`). The manifest legitimately
holds both an exact route and the subtree under it (`/api/pools` and `/api/pools/`), and normalising
maps both onto one name, so the subtree half of a collision is named `api_pools_subtree`; a third
collision is numbered. Two descriptors with one name would be a tool a client cannot call
unambiguously.

Each descriptor carries:

- **description** — the manifest's own summary, the risk class and its plain-English safety string,
  the escalation tier, the hint set, whether a confirmation is required *and for which verbs*, and a
  concrete example path for a subtree pattern;
- **annotations** — MCP's four standard hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`) taken from the console's own derivation in `agent_tools.go` rather than re-judged
  here, plus `riskClass`, `escalationTier`, `requiresConfirmation` and the exact `route` pattern;
- **inputSchema** — `method` (an enum of the verbs that route declares), `path`, `query`, `body` and
  `confirm`, with `body`/`query` typed per verb (see *Typed input schemas* below). `path` is required for a subtree pattern (the pattern itself is not a requestable URL)
  and must be exactly the pattern for an exact route.

## Typed input schemas (burpsy-react-ui-3zw0)

Both surfaces publish each operation's `body` and `query` **typed**, and the type is the handler's
own — not a second, hand-written schema:

- `internal/web/route_schemas.go` names, per `"VERB /pattern"`, the Go type the handler decodes its
  body into (or `noBody`, or a `raw` description for a non-JSON upload), plus the query parameters
  it reads. `internal/web/route_schema.go` reflects JSON Schema from that type: field names from the
  `json` tags, types from the Go types, `desc:"…"` and `enum:"a|b"` tags where a field has them,
  `additionalProperties: false`. A type that decodes itself (a custom `UnmarshalJSON`) must have an
  explicit override — `intruder.PayloadSource`'s tagged union is published as one titled branch per
  `type` — or the sweep fails rather than publishing a guess.
- Every handler decodes through `requestJSON`. In an in-process probe (a context value no wire
  request can carry) it records the type it was handed and stops the handler before it acts.
  `TestEveryBodyTakingRouteDecodesItsDeclaredType` drives every declared route-verb through the
  real mux and asserts the handler decoded into **exactly** the declared type, that an example
  generated from the **published** schema decodes, and that an unknown field is refused.
  `TestEveryMutatingRouteVerbDeclaresItsInput` fails on a mutating route-verb with no declaration, so
  a new route cannot reach the MCP surface untyped.
- **Strict decoding for agents.** burpsy-mcp sends `X-Burpsy-Agent` on every call. A request carrying
  it is decoded with unknown fields refused: HTTP 400, and the decoder's own error — which names the
  field — rides the `X-Burpsy-Body-Error` response header, which the transport prints into the tool
  result as `body error: json: unknown field "…"`. The console's own UI does not send the header and
  keeps the lenient decoding it was written against (it round-trips several GET shapes into PUTs).
- Three settings patches decode a key→value map and check each key against a table of their own
  (`PUT /api/scanner/config`, `PUT /api/proxy/options`, `PUT /api/network/settings`). Their schemas
  are built from those tables, and `TestAKeyTablePatchRefusesAnUnknownKey` drives the handler's own
  refusal, which the probe cannot see.

On the grouped surface, `body` is the operation's schema when the tool has one body-taking
operation, and otherwise an `anyOf` with one branch per operation, titled with the operation
(`"POST /api/tools/hash"`). `query` lists every declared parameter with the operations that read it.

What is not proven: query parameters are declared, and `TestEveryDeclaredQueryParameterIsReadSomewhere`
only checks each name is spelled in a handler; and a declared `optional` body (the handler accepts an
empty one) is taken from the handler's `io.EOF` branch, not driven, because an empty-body probe would
let the handler act.

## The confirmation gate, mapped onto the risk classes

`needsConfirmation` (`internal/web/agent_tools.go`) is the set — `scope`, `attack`, `credential`,
`destructive` — and it is enforced **server-side** by `internal/web/confirm_gate.go`. Confirmation is
demanded of a **mutating** call only: a `GET` on a gated route is a read of the state the gate
protects, not the protected act, so it is not gated.

The MCP layer makes **no** authorisation decision of its own. It has no copy of the gate to drift
from it:

1. A mutating call to a confirmation-worthy route with no confirmation is refused by the console with
   **HTTP 428**, and the transport surfaces that refusal as an `isError` tool result with the gate's
   own body verbatim.
2. Recovering from it is an explicit, separate step: the client calls **`burpsy_confirm`** with
   `{"tool": "<the tool>", "arguments": {<the call's exact arguments, without confirm>}}` — the
   refusal prints this object for the refused call. The transport resolves those arguments with the
   same code `tools/call` uses (including the `{"async":true}` it adds to an audit), POSTs the resolved
   request to the console's own mint endpoint, and returns the console's **preview** of it — method,
   URL, body (secret-named JSON members withheld, still covered by the hash) and the body's canonical
   SHA-256 — with a one-time token bound to that request.
3. The original call is re-issued, unchanged, with `confirm` set to that token. The transport relays
   it as the `X-Burpsy-Confirm` header — it never mints a token, never retries without one, and never
   caches one.

The token is single-use, expires in **60 seconds**, and is bound to the **resolved call**, not the
route (burpsy-react-ui-e0yq): the gate recomputes method, path, canonical query and canonical body
hash from the request it is about to admit and refuses — and burns — a token presented with any
other request. A token minted for `POST /api/audit/41` does not authorise `POST /api/audit/42`; one
minted to export the CA certificate does not export its private key. JSON bodies and queries are
compared in canonical form (sorted keys/parameters, no insignificant whitespace), so a host that
re-serialises the arguments between the two calls is not refused; nothing that decodes differently
is ever equated.

`burpsy_confirm` is a separate tool precisely so the escalation is one visible, approvable call in
the host's transcript rather than a field a model fills in silently. Its description states the limit
the gate's own comment states: **an agent that can supply its own confirmation has learned nothing
from being asked**, so the enforcement point is the host and the operator, not this binary. An MCP
host that hands its model both halves of the ritual has made the checkpoint a formality; a host that
requires approval per tool, or an operator reading the transcript, sees the escalation as its own act.

## What the transport refuses locally, and why that is not a second gate

One refusal happens in the transport rather than at the server: a call whose `path` resolves to a
**different route** than the tool names. `/api/audit/` must not be reachable through the tool named
`api_audit` at `/api/audit/selected`, because a descriptor's published risk class would then describe
a route other than the one it reaches. It is decided by `web.MCPRouteForPath`, which is the gate's own
longest-prefix resolver, so the binding and the gate cannot disagree about which route a path names.

## Task handles, progress and pushed notifications (burpsy-react-ui-wdza)

- **Sync window.** An audit called through the transport (`scan` / `POST /api/audit/`) is started
  with `{"async": true}` — the console answers 202 with a `task_id` at once — and any 202 carrying a
  `task_id` (an audit, a crawl, an API scan, an audit of a selection) is awaited for the sync window
  (15 s, Burp's own). Finished in time: the call answers `HTTP 202 POST … -> task N finished …` with the
  task view, whose `result` is what a blocking audit returns. Not finished: the call answers
  `HTTP 202 task handle` with `{"task_id", "status": "running", "poll_interval_ms", "next"}`. The
  handle lives in the console's task registry, so it outlives the MCP process. `"async": false` in
  the body keeps the old blocking call.
- **`burpsy_task_status`** `{"task_id", "wait_seconds" (0–60)}` reads a handle — `GET /api/tasks/{id}`,
  long-polling until the task finishes.
- **Progress.** A `tools/call` carrying `_meta.progressToken` gets `notifications/progress` (done/total,
  and a message) while it waits on its task; a call without one gets none.
- **Cancellation.** `notifications/cancelled` for a call waiting on its task cancels the task.
- **Pushed notifications.** After `notifications/initialized` the transport holds the console's SSE
  stream (`/api/events`) and, on each dashboard or issues change, pushes `notifications/message`:
  `info` `{"event":"task.finished","task_id",…}` for each task that finished, and `warning`
  `{"event":"issue.found","issue_id","severity",…}` for each **High or Critical** issue that appeared
  since the session began (a baseline is taken first, so nothing older is announced). `initialize`
  advertises `capabilities.logging`.

## Skills as prompts (burpsy-react-ui-ulsy)

`burpsy -skills DIR` loads a skill library: one `<name>.json` manifest per skill —
`{"name", "description", "tools": [...], "arguments": [{"name","description","required"}],
"prompt": "… {{argument}} …"}` (or `"prompt_file"`, a file in the same directory). The transport
publishes them through MCP's prompts capability: `prompts/list` offers every skill that is available
and not disabled for the project, and `prompts/get` renders one with its arguments, prefixed by a
banner — `[burpsy skill NAME] description` / `Tools this skill calls: …` — flagging any tool the
current surface does not publish. A manifest that names a `"script"` loads but is **unavailable**
(script-bearing skills run through the scripting runtime, burpsy-react-ui-wiwh); a manifest that does
not parse is refused and listed with why (`GET /api/skills`). The console's **Settings › Skills** card
switches a skill off for the current project (`PUT /api/skills/disabled`, saved with `-db`). An
unreachable console is a JSON-RPC error, not an empty prompt list.

## Honest limits

- **stdio only.** No SSE/HTTP transport.
- A response over **1 MiB** is truncated, and the cut is stated in the result rather than left silent.
- A **streaming** route (`text/event-stream`) is refused with a reason, instead of being allowed to
  hang until the client timeout.
- Burp also publishes each tool's preview as an MCP resource (`burp://preview/<tool>{?args}`) with
  `previewUri` in the tool metadata. burpsy's server advertises `tools` only; the preview is the
  answer of `burpsy_confirm` rather than a separate resource read.
- On `-surface routes` only, `tools/list` returns every manifest route including static assets (`/`
  and the SPA catch-all). That is honest — they are routes — but a model calling them gets the
  console's own HTML. The default grouped surface does not publish them.

## Verifying a change here

```bash
cd burpsy-go
go build ./... && go vet ./internal/mcp/ && gofmt -l internal/mcp
go test ./internal/mcp/ -count=1
```

The tests mount a real `web.NewServer`'s **fully gated chain** on an `httptest` server and point the
transport at it, so the real `confirmStore` mints and spends the tokens: a fake store would pass
whether or not the production path exists. They cover tools/list against the real manifest, a read
call returning its route's result, the unconfirmed refusal, the mint-then-retry flow, the one-time
property of a token, every confirmation-worthy route's mint path, the tool/route binding, protocol
framing and result handling. A live pass is also worth running — build both binaries, start the
console, and drive a session with `initialize` → `tools/list` → a refused attack call → `burpsy_confirm`
→ the same call confirmed.
