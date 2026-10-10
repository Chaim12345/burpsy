# Library adoption — 2026-10-10

Where adopting a library (or a library already in the binary) replaces hand-rolled code, removes a
recurring bug class, or adds a capability. Built from a sweep of the code, `.beads/issues.jsonl`,
`gaps.md` and the last 400 commits on master, plus online research. The owner's direction:
**adding dependencies is fine when it is better than hand-rolling.** This supersedes the
2026-08-25 "adopt nothing now" note in `docs/plans/2026-08-19-webui-parity-working-memory.md`
and updates `docs/go-ecosystem-research.md`.

Every item has a bead (label `library-adoption`). Priorities: P0 now, P1 next round, P2 the round
after, P3 later.

## 0. Security

| Bead | Item |
|---|---|
| vhxd (P0) | The root `package.json` and `bun.lock` declare `@cosmicstack/mercury-agent@1.2.2` (pulls AI SDKs, Slack/Discord/Telegram bot libraries, cron, dotenv) and `g`. Nothing uses them; they arrived in unrelated commit `92c8c263`. CI installs only from `burpsy-go/internal/web/ui`, so they never ran in CI — but `bun install` at the root would install them. Remove, and trace how they got in. |

## 1. Already in the binary, or the standard library

Several "would need a dependency" comments are stale: `go list -deps ./cmd/burpsy` shows these are
already linked transitively.

| Bead | Item | Evidence |
|---|---|---|
| mi8d (P1) | Brotli + zstd body decoding (`andybalholm/brotli`, `klauspost/compress/zstd`, linked via gitleaks) | `httputil.DecodeBody` gzip/deflate only; gaps.md of0z |
| cgim (P1) | HPACK Huffman decoding (`x/net/http2/hpack.HuffmanDecode`) | `internal/http2/hpack.go` returns "not implemented"; gaps.md 54–60 |
| iyew (P1) | Bounded TLS leaf cache (`golang-lru/v2`) + per-host singleflight key generation | unbounded `sync.Map`, one global lock in `proxy.TlsEngine` |
| z5l6 (P2) | One LRU for six hand-rolled evicting stores | h2sessions, dash tasks/events, audit_items, servercerts, netauth prompt |
| vnlh (P1) | Go 1.22 method/path route patterns; declare each route once and generate manifest, schemas and MCP groups | 218 manual method checks, 0 `PathValue`, routes declared in 4 places; beads 0gg5, u9t6, s9ma |
| elam (P1) | CodeMirror `lineSeparator` instead of the `editor-eol.ts` shadow text | root cause of ngao, eslt, oob3 |
| 6858 (P2) | One HTTP helper API: dechunk ×4, `headerValue` ×5, header-end search ×97 | `httputil/dechunk.go:15` admits the copies |
| 4lwb (P3) | Delete dead `tools/comparer.go`; one OpenAPI reader (consider libopenapi / kin-openapi) | 0 callers; `apidoc` and `crawler/apidoc` duplicate |
| r996 (P2) | AST taint analysis on `goja/parser` (linked since `950b6a4d`) | `scanner/dom.go` lexical pass, stale comment |
| j0s2 (P2) | Emit `[]` for nil slices now; encoding/json/v2 when it is the default (behind `GOEXPERIMENT=jsonv2` in Go 1.26) | security bug `9d479c52`; UI crashes 9n01, qmlk, 9pxd, 2qbi |

## 2. Testing and the API contract

| Bead | Item | Evidence |
|---|---|---|
| ibhs (P1) | Native `go test -fuzz` for the parsers, short runs nightly | 0 fuzz tests; ~6 framing, ~6 compression, ~4 CRLF fixes in 400 commits |
| ctdl (P1) | golangci-lint v2 (staticcheck, errcheck, gosec, bodyclose, ineffassign) + govulncheck in CI | CI is gofmt + vet only; large transitive tree via gitleaks |
| u5jf (P2) | `testing/synctest` (stdlib) for timeout/backoff tests; `go.uber.org/goleak` | ~9 timing flakes, ~8 race fixes |
| 13o5 (P2) | UI component tests (happy-dom + @testing-library/react) and Biome | 0 `.test.tsx`; 23 source-text pins |
| pg5a (P1) | OpenAPI 3.1 from the existing route schema reflection, extended to responses; generated TS client (openapi-typescript + openapi-react-query) | ~4,250 hand-mirrored lines of TS types, 118 raw `fetch`, unchecked `api<T>()` |

Huma was considered for the API layer: it only pays off if handler-level validation is wanted, and
the confirmation gate must keep seeing the raw body as middleware. Generating OpenAPI from the
manifest gets the contract without moving 178 handlers. Gin/Echo/Chi add nothing over Go 1.22
patterns; Testify/Ginkgo change assertion style, not what tests catch.

## 3. New capability

| Bead | Library | For |
|---|---|---|
| 0rrb (P1) | `google.golang.org/protobuf` (+ protocompile, dynamicpb, gRPC reflection client) | real descriptors instead of the hand .proto parser; beads 3x2g, 47id |
| 4xqt (P2) | `vektah/gqlparser` | GraphQL schema/query parsing and validation; 14 GraphQL beads, SDL import currently refused |
| khk9 (P2) | `pressly/goose` or a `user_version` migrator | no schema version; scope written to three table generations; bead 6db6 |
| 6j26 (P3) | `jcmturner/gokrb5` | Kerberos inside Negotiate (needs a KDC lab) |
| vlrh (P3) | `react-hook-form` + `zod` | `settings.tsx` 4,617 lines, 66 `useState`, 85 hand number parses |
| 63pf (P3) | `refraction-networking/utls` (pin after 1.8.1, GO-2026-4509) | browser-like TLS fingerprints toward WAF/bot-detection targets |
| 0hgx (P3) | `quic-go` (v0.62) | HTTP/3 in sender, then proxy; HTTP/3 smuggling (SCANNER-INFRA-ROADMAP.md:52) |
| 6ibj (P3) | `@codemirror/merge` | inline "compare with previous" in Repeater/Intruder |

Not needed: a hex editor (`ui/hex-editor.tsx` exists), a command palette (exists), a chart library
(uPlot only if Sequencer/Intruder plots grow), a UI router (hash routing works; revisit with
TanStack Router if shareable URL state becomes a goal). The script runtime stays on goja (bead
wiwh decision); `wazero` is already linked if multi-language plugins come up.

## 4. Hygiene

| Bead | Item |
|---|---|
| y6su (P3) | Run gitleaks as a subprocess: one file uses it, but it links viper, cobra, sprig, archives, wazero, go-re2 and zerolog |
| dyw9 (P3) | Drop unused `@codemirror/language`, `@lezer/highlight`; fix AGENTS.md package claims; consider building `dist/app.js` at release (27/400 commits are bundle rebuilds) |

## Suggested rounds

1. vhxd, mi8d, cgim, iyew, elam, ibhs, ctdl.
2. vnlh, pg5a, 0rrb, 13o5, j0s2, 6858.
3. 4xqt, khk9, u5jf, r996, z5l6, then the P3 items.

## Sources

[encoding/json go1.26](https://pkg.go.dev/encoding/json@go1.26.8) ·
[Go 1.26 without json v2](https://huizhou92.com/go-1-26-shipped-without-json-v2-heres-the-real-reason-why/) ·
[golangci-lint in 2026](https://dev.to/gabrielanhaia/golangci-lint-in-2026-a-config-that-catches-bugs-without-the-noise-o6m) ·
[testing/synctest](https://pkg.go.dev/testing/synctest) ·
[goleak](https://pkg.go.dev/go.uber.org/goleak) ·
[openapi-react-query](https://openapi-ts.dev/openapi-react-query/) ·
[gqlparser](https://pkg.go.dev/github.com/vektah/gqlparser/v2) ·
[goose](https://cdn.jsdelivr.net/gh/pressly/goose@main/README.md) ·
[GO-2026-4509](https://osv.dev/vulnerability/GO-2026-4509) ·
[quic-go](https://github.com/quic-go/quic-go) ·
[@codemirror/merge](https://npmjs.com/package/@codemirror/merge) ·
[chart benchmark](https://apexcharts.com/blog/javascript-chart-library-benchmark/) ·
[wazero](https://wazero.io/) ·
[Caido v0.58](https://www.caido.io/blog/2026-08-24-release-v0-58-0/)
