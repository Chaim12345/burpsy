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
| `-timeout` | `10m` | how long one tool call may take before the transport gives up. Generous because an audit runs synchronously and a large one takes minutes. |
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
| `notifications/initialized` | ignored, like every notification. A notification gets **no** reply — answering one makes a client that reuses ids mis-attribute the reply. |
| `tools/list` | the grouped surface (59 tools, plus `burpsy_confirm`) — or, with `-surface routes`, one tool per manifest route. |
| `tools/call` | forwards the call to the console and returns its answer. |
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
   DELETE: that is why `DELETE /api/history`, which the manifest classes `read`
   (burpsy-react-ui-gf68), is its own `history_delete` tool rather than an op of `history`.

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
  `confirm`. `path` is required for a subtree pattern (the pattern itself is not a requestable URL)
  and must be exactly the pattern for an exact route.

The body schema is deliberately permissive: every route's wire shape is documented in the console's
own API docs rather than in the manifest, and inventing 122 schemas here would be a second source of
truth that nothing checks.

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
2. Recovering from it is an explicit, separate step: the client calls **`burpsy_confirm`** with the
   route pattern, which POSTs the console's own mint endpoint and returns a one-time token.
3. The original call is re-issued with `confirm` set to that token. The transport relays it as the
   `X-Burpsy-Confirm` header — it never mints a token, never retries without one, and never caches
   one.

The token is single-use, expires in **60 seconds**, and is bound to the route it was minted for.

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

## Honest limits

- **stdio only.** No SSE/HTTP transport.
- A response over **1 MiB** is truncated, and the cut is stated in the result rather than left silent.
- A **streaming** route (`text/event-stream`) is refused with a reason, instead of being allowed to
  hang until the client timeout.
- The gate's own 428 text prints the manifest pattern, so for a subtree route it reads
  `POST /api/audit//confirm` — one slash too many. The transport prints the path it will actually
  POST to (`/api/audit/confirm`) and says why the two differ; it does not edit the gate's message,
  which is evidence.
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
