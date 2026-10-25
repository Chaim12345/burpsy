# Design: plugin-provided Intruder payload generators and processors (0qwh)

Status: design accepted for implementation (integrator lane), 2026-10-25. Bead stays open until the gate below is green.

## Facts on the ground

- Host primitives already exist and are tested: `Host.GeneratePayload(ctx, name, registration, position) (payload, done, err)` and `Host.ProcessPayload(ctx, name, registration, payload, base) (out, skip, err)` (internal/extension/host.go:799, :826). Both validate the registration's kind (ErrWrongKind) and map plugin answers: done / payload+encoding / action=skip.
- The intruder engine materializes payloads eagerly: `PayloadSource.Resolve(maxCount) (*PayloadSet, error)` (internal/intruder/payload.go) returns a fully realized item list, capped at min(maxCount, MaxPayloads=200_000). The one caller that matters is the run-creation handler, internal/web/api_tools.go:1376.
- Processing rules are a compiled chain over the materialized set (`chain.Run(ps)`, api_tools.go:1383), with the static rule table in internal/intruder/process.go:185.
- internal/intruder must NOT import internal/extension (dependency direction: web composes both).

## Design

1. **Generator seam (intruder/payload.go).** New source type: `PayloadSource{Type: "plugin", Plugin: &PluginSource{Plugin, Registration string}}`. Resolve keeps its signature for every existing caller and delegates to `ResolveWith(cap int, bridge GeneratorBridge)`:
   ```go
   type GeneratorBridge interface {
       GeneratePayload(plugin, registration string, position int) (payload []byte, done bool, err error)
   }
   ```
   A "plugin" source resolved through Resolve (nil bridge) answers a PayloadError, never a substitute set. Materialization loops position 0..cap-1: done stops (exact=true, total=len(items)); hitting cap without done sets trunc=true, exact=false; any bridge error aborts the run config with a PayloadError naming the plugin and position; checkLen applies per item like every other kind.

2. **Processor seam (intruder/process.go).** New rule "plugin" carrying `{plugin, registration}`; the chain compiles it through an injected ProcessorBridge:
   ```go
   type ProcessorBridge interface {
       ProcessPayload(plugin, registration string, payload, base []byte) (out []byte, skip bool, err error)
   }
   ```
   Error policy matches the host contract: on error keep the original payload; skip drops it (same representation as skip_if_matches). The base value is the unprocessed payload, the Burp processPayload contract.

3. **Web wiring (web/api_tools.go).** The run-creation handler builds both bridges closing over the request context and the server's extension host. A plugin source or rule naming a plugin that is not loaded, or a registration of the wrong kind, fails run creation with 400 BEFORE any request is sent - the same bar as grep compilation. The web seam is a narrow interface over the host (GeneratePayload/ProcessPayload) so web tests stub it without a plugin process.

4. **UI.** The Intruder payload-type dropdown merges built-in kinds with registered payload-generator providers (from the extensions view, which already labels KindPayloadGenerator), submitting `{type:"plugin", plugin:{plugin, registration}}`. The processing-rule list gains "plugin" the same way. dist rebuilt by the integrator.

## Risks / called shots

- Eager materialization of a streaming generator is the honest fit: the engine's plan/radix arithmetic needs a realized set. A plugin generator is capped like every other kind (payloadCap); the doc comment must say a stateful generator pays one host call per position.
- Cancellation: bridge calls carry the run-creation request context; a hung plugin aborts the config, not a running attack, because materialization happens before the engine starts.
- No fence bypass: plugin code only answers bytes; the payloads enter the same engine, sender and scope path as built-in kinds.

## Gate

- intruder: plugin source tests with a fake bridge (stream-to-done, cap truncation, error mapping, nil bridge refuses); plugin rule tests (rewrite, skip, error-keeps-original). Negative controls per repo bar.
- web: run creation with a stubbed host bridge (success, unknown plugin 400, wrong-kind 400).
- Full intruder + web suites green, ui check + biome format if the dropdown changes, dist rebuilt.
- Close 0qwh with the evidence.
