<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# vulnapp

## Purpose

A deliberately vulnerable in-process HTTP application **and** a machine-readable declaration of what
it is vulnerable to. It exists so that "burpsy detects reflected XSS" (and every other row) is a fact
a test checks on every run rather than something somebody looked at once. It began as
`cmd/demo-target`; moving the handlers into a package let a test start the same app in-process and
assert the scanner finds what the app exposes, while the binary still exists for manual work.

The manifest is the point: `Vulnerabilities()` pairs each endpoint with the exact scanner-catalog row
name it should trigger, so coverage becomes checkable in both directions — a planted defect must be
found, and an endpoint marked `Safe` must *not* produce its row (a finding there is a named false
positive, the case a fires-on-vulnerable test alone can never catch).

## Key Files

| File | Description |
|------|-------------|
| `vulnapp.go` | The core: the `Endpoint` type (the manifest schema), `Vulnerabilities()`, `Handler()`, the `familyEndpoints`/`familyRegistrars` fan-out, and the core routes (search/login/download/ping/redirect/echo/CORS, DOM sinks, XML/XPath/LDAP/template, stored comment pair, SSI/code-injection) |
| `vulnapp_posture.go`, `vulnapp_analysis.go`, `vulnapp_headers.go`, `vulnapp_reflection.go`, `vulnapp_discovery.go`, `vulnapp_dom.go`, `vulnapp_remaining.go`, `vulnapp_final.go`, `vulnapp_stored.go`, `vulnapp_injection.go`, `vulnapp_sqli_dialects.go` | One file per check family; each exports `<family>Endpoints()` (manifest rows) and `register<Family>(mux)` (routes), the two halves that grow together |

## For AI Agents

- **Row names must match `internal/scanner`'s catalog exactly.** A typo silently exempts an endpoint
  from its own assertion, so the runtime test resolves every `Row` against the shipped catalog before
  running anything. When you add or rename a row, keep it in step with the scanner catalog.
- **Every family contributes in two mirrored lists.** `familyEndpoints` (manifest) and
  `familyRegistrars` (routes) are parallel and in fixed order. Add a family to *both*, or its
  endpoints are declared but unserved (or served but undeclared).
- **The `Endpoint` struct fields encode reachability, not decoration.** `Body`/`ContentType`,
  `RequestHeaders`, `TLS`, `DOM` and `Stored` all state what the *capture* must carry for the row to
  be reachable at all — e.g. an XML body point is unreachable without a body, the URL-override rows
  need `X-Original-URL`/`X-Rewrite-URL` on the seeded request, several transport rows need HTTPS, and
  `Stored` rows can only be confirmed in the scan's deferred re-fetch phase. `Safe` marks a
  no-defect twin; `SafeTwinNotApplicable` is a *written* reason (auditable) for a vulnerable endpoint
  that legitimately has no safe counterpart — empty keeps the pairing requirement, which is the norm.
- **No real damage, ever.** Nothing here executes a command, touches the filesystem, or opens a
  database. The SQL/traversal/OS-command/XXE endpoints pattern-match input and return a fixed
  artifact that *looks* like the real thing — all an evidence-based detector reads. Keep it that way;
  a genuinely exploitable target would be a liability in the repo. Note the JWT families do use real
  RSA (`crypto/rsa`) to mint/verify tokens and expose `jku`/`x5u`/JWKS trust variants — that is
  cryptographic behaviour under test, not a live exploit surface.
- Parameter names are deliberately *not* `xss`/`test`/`file` (the predecessor's hand-appended
  constants); those made a fixed check indistinguishable from a working one.

## Testing Requirements

This package carries no `_test.go` files of its own; it *is* the fixture. Its manifest and handlers
are exercised by the scanner's runtime-coverage suite, which starts `Handler()` in-process and
asserts each `Vulnerabilities()` row:

```bash
go test ./internal/scanner/...        # e.g. runtime_coverage_test.go drives this app
```

## Dependencies

No other `internal/` packages — the dependency runs the other way (`internal/scanner` tests import
this). Standard library only: `net/http`, `encoding/*`, `crypto/rsa`+`crypto/x509` (JWT/JWKS),
`regexp`, `sync`, etc. — plus `golang.org/x/net/http2` for the HTTP/2 side of the request-smuggling
listeners in `vulnapp_desync.go`, which are the one family served by listeners of their own
(`Endpoint.Listener`, `StartListener`) rather than routes on `Handler()`. There is no matching Rust crate under `crates/` — this package is Go-only.
