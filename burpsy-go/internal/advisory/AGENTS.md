<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# advisory

## Purpose

The issue-definition catalogue: the long-form description, remediation, references and vulnerability
classifications that turn a finding's one-line name into something an operator can act on and put in
a report. A finding carries a name and a severity; this package is what a consumer joins against to
show *why it matters and how to fix it*.

The bundled text is extracted from a local Burp Suite installation's own resource bundle
(`resources/KnowledgeBase/Issues`) and embedded with `go:embed`. That is PortSwigger's copyrighted
content, not open content — see the package doc in `advisory.go`. The whole package is written so
that if the embed ever has to be dropped (opening the repo, or shipping a binary, is redistribution),
`Load` becomes a one-line swap to read an operator-supplied directory with no caller affected.

## Key Files

| File | Description |
|------|-------------|
| `advisory.go` | The catalogue itself: `Definition`, `Severity`, `Classification`, `Reference`; `Load`/`loadFS` (embed → maps), `NormaliseName`, and the read-only `Catalogue` with `ByIndex`/`ByName`/`All`/`Len` lookups |
| `aliases.go` | The explicit burpsy-check-name → Burp-type-index map, the `unmapped()` table of checks that intentionally have no catalogue entry (with reasons), and `Catalogue.Resolve` |
| `sanitise.go` | `SanitisedHTML` (allow-list HTML renderer for Description/Remediation fragments) and `PlainParagraphs` (fragment → plain-text blocks), built on `golang.org/x/net/html` |
| `definitions/*.json` | The embedded catalogue — 183 issue definitions, one JSON file per Burp type index |
| `native/*.json` | burpsy's OWN definitions for rows Burp's catalogue lacks (`b5000100` Insecure direct object reference, CWE-639; `b5000200` Authentication attempts not rate limited, CWE-307; `b5000300` Username enumeration, CWE-204; `b5000400` Session fixation, CWE-384; `b5000500` Predictable session token, CWE-330; `b5000600` Session not invalidated after logout, CWE-613; `b5000800`-`b5000870` the password-reset rows; `b5001000` Host header injection, CWE-20; `b5001800` GraphQL query batching enabled, CWE-799; `b5001810` GraphQL query depth not limited, CWE-770; `b5001820` GraphQL debug information disclosed, CWE-209; `b5001400` Insecure deserialization, CWE-502; `b5002000` NoSQL injection, CWE-943; `b5002400` Cross-site WebSocket hijacking, CWE-1385; `b5002410` Access control bypass via spoofed client IP header, CWE-290; `b5002420` Rate limit bypass via spoofed client IP header, CWE-348; `b5002800` Cookie prefix requirements not met, CWE-693; `b5002810` Session cookie without SameSite protection, CWE-1275; `b5002820` Subdomain takeover, CWE-672; `b5002c00`-`b5002c20` the three server-side parameter pollution rows, query string CWE-235, REST path and structured data CWE-74; `b5003000` LLM prompt injection, CWE-1427). Authored here, not extracted from Burp; indices `0xb5000000`-`0xb5ffffff`; reachable by name/index and listed by `Native()`, never counted by `Len`/`All`/`IndexedLen`. A collision with a Burp index or name fails `Load`. The scanner side is `scanner.BurpsyNativeRows` |
| `advisory_load_test.go`, `aliases_test.go`, `sanitise_test.go` | Tests for load, alias/name resolution, and the sanitiser |

## For AI Agents

- **A missed lookup is a normal answer, not an error.** `ByIndex`/`ByName`/`Resolve` all return a
  miss cleanly; nothing else in burpsy requires the catalogue to be present. A malformed *file*,
  however, fails `Load` outright — a catalogue that silently loaded 182 of 183 would look
  indistinguishable from an unmapped check.
- **`Definition.Severity` describes the issue *class*, not a finding's own rating.** They are kept
  as distinct types on purpose; joining them would let a catalogue lookup silently rewrite a
  scanner's verdict.
- **Matching is deliberately conservative, not fuzzy.** `NormaliseName` folds case and collapses
  non-alphanumeric runs to single spaces — never word order or synonyms. `Resolve` tries the
  explicit alias table (keyed on the hex type index) *before* name, so a decision always beats a name
  coincidence, and `unmapped()` carries a written reason so the UI can say "no catalogue advisory
  because …" instead of showing a blank panel.
- **`SanitisedHTML` returns a plain `string`, not `template.HTML`.** That forces each caller to make
  the trust decision explicitly at its own boundary. Description/Remediation are HTML fragments
  carried verbatim (the paragraph markup is the point); the sanitiser keeps only structural/inline
  elements, drops *all* attributes (including `href`), keeps the text of dropped elements, and
  escapes unparseable input to visible-but-inert text.
- `Catalogue` is read-only after `Load` and therefore lock-free; do not add mutating methods.

## Testing Requirements

```bash
go test ./internal/advisory/...
```

## Dependencies

No other `internal/` packages. External: `golang.org/x/net/html` (+ `.../html/atom`) for the
sanitiser; standard library `embed`, `encoding/json`, `io/fs` otherwise. There is no matching Rust
crate under `crates/` — this package is Go-only.
