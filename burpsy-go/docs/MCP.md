# burpsy-go — MCP server (status & plan)

> **Status: not yet shipped.** As of this writing there is **no MCP server** in
> the Go port (`burpsy-go/`) or in the Rust reference (`crates/`). An MCP surface
> is a planned item on the roadmap, not shipped behavior. This page documents
> that honestly and points at what drives burpsy *today*.

This page exists so that nobody reads the project blurb ("an MCP server so agents
can drive it") and expects an `mcp` command or endpoint that is not there. When
the MCP server lands, this page becomes its reference; until then it is the plan.

## What drives burpsy today

The **[JSON API](./JSON-API.md)** is the current agent-driving surface. It is a
complete, documented HTTP surface (served on the `-web` address, loopback by
default) that a script or an LLM-with-tools can already use to:

- read history, the site map, findings, coverage and dashboards;
- send Repeater requests and run Intruder / audits / crawls;
- manage scope, interception, sessions and the supporting tools.

Anything the eventual MCP server will expose, it will expose by wrapping these
same routes. If you want agent control now, target the JSON API.

## What the MCP server will be

From `ROADMAP.md`:

- burpsy will expose its existing JSON API as an MCP server, making it drivable
  by any MCP-capable agent with no vendor backend and no AI credits. The roadmap
  flags this as a high value-to-effort item precisely *because* the JSON API
  already exists — the MCP layer is a thin facade over it.

## The groundwork that already exists

The one piece of MCP-specific design already in the codebase is the **per-route
risk classification** in `internal/web/route_manifest_test.go`. Every route
declares a `riskClass` (`read`, `local-write`, `egress`, `attack`, `scope`,
`credential`, `destructive`, `asset`) — see the [JSON API reference](./JSON-API.md#risk-classes).

This is the field the planned confirmation gate (referred to as **MCP-02** in the
code) will use: when the API is driven by a model rather than by a human
clicking, the higher-risk classes — `scope` (removes the "no"), `attack`
(unbounded traffic / potential DoS), `credential` (reads secrets) and
`destructive` (discards evidence) — must require an explicit human confirmation
before the call proceeds. Classifying this next to each route, once, means every
future facade (MCP included) enforces the same policy instead of re-deciding it.

## When this changes

This doc is a defect the moment an MCP server ships without it being rewritten
into a real reference. If you land the MCP server, update this page (transport,
how to launch it, the tool list it exposes, and how the confirmation gate maps
to the risk classes) in the same change.
