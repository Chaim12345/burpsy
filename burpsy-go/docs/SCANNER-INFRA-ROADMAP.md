# Scanner Infrastructure Roadmap

> **Status banner — 2026-08-18.** This roadmap's premise ("gaps that still block
> declined catalog rows") is now historical: the declined list is empty, and every
> row is runnable (`docs/SCANNER-COVERAGE.md`). It is retained as the record of the
> library-selection decisions, and its remaining "Planned" items have moved since:
> **`projectdiscovery/wappalyzergo` and `Masterminds/semver/v3` landed** (both used
> by `internal/scanner/infra_fingerprint.go` for real version-range fingerprinting),
> and **`golang.org/x/net/html` landed in the crawler** (`internal/crawler/discover.go`)
> though not yet for the scanner-side injection-context application this file
> describes — that specific row remains open.

Capability gaps that still block declined catalog rows, and the Go libraries that would close
them. This is a **plan, not a claim**: nothing here is implemented unless it also appears in
`docs/SCANNER-INFRA.md`, whose contents are asserted against the code by
`TestInfraPrimitiveMappingResolvesAgainstTheShippedCatalog`.

Ordering rule used throughout: a library already in the dependency tree beats a new
dependency, a pure-Go dependency beats one needing cgo or an external binary, and an
authoritative implementation beats a hand-rolled heuristic. Where our own shipped primitive
is *less correct* than an available library, that is called out as a defect rather than a
nice-to-have.

## Tier A — already in `go.mod`, not yet used

Zero new dependencies. Two of these fix real defects in primitives already shipped.

| Package | Why | Status |
|---|---|---|
| `golang.org/x/net/publicsuffix` | `CookieAttrs.ScopedToParentDomain` does naive RFC 6265 domain-matching and **cannot** distinguish `.co.uk` (a public suffix — browsers reject the cookie) from `.example.co.uk` (legitimate). `EffectiveTLDPlusOne` is the authoritative answer. | **Defect fix — applied** |
| `golang.org/x/text/encoding/htmlindex` | `CharsetIsRecognised` compares against a hand-written list. `htmlindex` is the WHATWG/IANA registry, so `HTML uses unrecognized charset` stops depending on how complete that list happened to be. | **Defect fix — applied** |
| `golang.org/x/net/html` | Replaces substring matching in `xss.go`, `linkAttributeReflection`, `CrossDomainScriptSrcs` and `DeclaredCharset`'s `<meta>` scan with a real HTML5 tokenizer. The material gain is **injection-context determination** — attribute value vs text node vs inside `<script>` vs inside a comment — which is exactly what separates exploitable reflection from harmlessly-encoded reflection, and which substring matching cannot see. `x/net v0.57.0` is well past the `v0.38.0` fix for CVE-2025-22872 (tokenizer mis-parse with XSS implications). | Planned |
| `github.com/dop251/goja/parser` | Arrived free with goja. JS AST without executing: lets a static pass find source→sink flows in extracted scripts and lets `internal/domexec` be reserved for cases that genuinely need a browser. | Planned |

## Tier B — new pure-Go dependency, recommended

| Package | Unblocks | Notes |
|---|---|---|
| `projectdiscovery/wappalyzergo` | **`React Server Components RCE (React2Shell)`** — the one row whose decline reason cites "version fingerprinting of React/Next.js dependency manifests", which nothing currently supplies. Also feeds `data/retirejs_repository.json`, already shipped but unused for active fingerprinting. | Pure Go, actively maintained, official fingerprint updates. Cleanest single win left. |
| `Masterminds/semver/v3` | Version-range matching for retirejs and wappalyzer output. `Vulnerable JavaScript dependency` is native today but does its own comparison. | Tiny. Already an indirect dep of several PD libraries. |
| `mvdan.cc/sh/v3/syntax` | `OS command injection`, `Expression Language injection`. Parse a candidate payload as shell and inspect the AST for command substitution, backticks and indirect expansion — so a probe is known to be *syntactically* an injection before it is sent, and a reflected payload can be confirmed to have kept its shell meaning rather than being escaped. | Pure Go, no cgo. |
| `github.com/vitessio/vitess` `sqlparser` (or `pganalyze/pg_query_go` for Postgres fidelity) | `SQL injection` confirmation quality. Today `sqli.go` classifies on error strings and response diffs. A parser lets us assert that a payload produces *valid altered SQL* rather than guessing from a 500. | Vitess is MySQL-dialect and large; `xwb1989/sqlparser` is the light fork. `pg_query_go` uses cgo — **excluded** on that basis. |
| `owenrumney/go-sarif` | Not a check capability — reporting. Would let findings feed GitHub Code Scanning / any SARIF consumer. | Complements `internal/report`. |
| `CycloneDX/cyclonedx-go` | SBOM output, and the natural home for wappalyzer/retirejs component data. | Pairs with the fingerprinting work. |

## Tier C — worth doing, bigger decision attached

| Package | Unblocks | The catch |
|---|---|---|
| `github.com/zmap/zcrypto` | `TLS certificate`, `Unencrypted communications`, `Strict transport security not enforced`, `Cacheable HTTPS response`, **and the TLS half of `Zut6`** that was explicitly left declined when robots.txt was ported. Gives older TLS versions, export ciphers and handshake logging that `crypto/tls` refuses to speak. | It forks stdlib crypto. That is a real posture change for this project and should be a deliberate decision, not incidental. `projectdiscovery/tlsx` is the lighter alternative if full research-grade coverage is not needed. |
| `projectdiscovery/katana` | Attack-surface discovery — feeds every per-URL and per-insertion-point check with endpoints the current crawler misses, especially SPA routes. | Overlaps `internal/crawler`; would need a clear boundary rather than a second crawler. Also pulls a large PD dependency tree, the same problem that ruled out importing `interactsh/pkg/client`. |
| `quic-go/quic-go` | HTTP/3 request smuggling and QUIC-transport race conditions. Recent research ("QUIC-er Races") shows HTTP/3 does not remove TOCTOU races, so the single-packet-attack surface moves rather than disappears. | Only worth it once HTTP/3 targets matter. `internal/sender`'s new `SendPipelined`/`TimedRead` already cover the HTTP/1.1 and HTTP/2 side. |
| Nuclei template corpus (data, not the engine) | A large free rule corpus alongside the 264-file BCheck corpus we already parse. | Importing `projectdiscovery/nuclei` as a library is heavy; ingesting templates as *data* into our own evaluator is the cheaper shape. Needs a YAML→evaluator mapping decision first. **Partly overtaken:** `internal/extscan` now runs the `nuclei` *binary* as a subprocess and folds its JSONL into `report.Row`s. That is a third option this table did not consider — neither library nor data — and it buys the corpus today at the cost of an external dependency at run time. Templates-as-data remains the better end state and is not closed by it. |
| `ffuf` content discovery | Directory, file and parameter fuzzing, which the tree had **nowhere** before. | **Landed as a subprocess** in `internal/extscan`, on the same allowlist and scope gate as the nuclei runner. A native Go reimplementation is still open; the hard part is not the fuzzing loop but response calibration (ffuf's `-ac`), which is what makes the results usable. |

## Rejected, with reasons

- **`BishopFox/jsluice`** — extracts URLs, paths and secrets from JavaScript; would genuinely feed both crawl surface and the disclosure bank. Rejected because it is **tree-sitter via cgo**, and a cgo dependency trips this project's stop condition on non-pure-Go dependencies. There is an open bounty to port it to pure-Go tree-sitter; revisit if that lands.
- **`trufflesecurity/trufflehog` / `gitleaks` as libraries** — their value is the detector corpus, but both are structured as applications, and trufflehog's verification step makes live network calls per candidate secret. Better shape: port the *rule patterns* into `infra_passive.go`'s existing disclosure bank, which already Luhn-validates cards and structurally validates JWKS.
- **`robertkrimen/otto`** — strictly dominated by goja: slower, ES5-only, largely dormant.
- **`zmap/zgrab2`** — a scanner application, not a library. `zcrypto` is the reusable part.
- **`esbuild`'s JS parser** — lives in `internal/`, no stable API, coupled to bundling.
- **`pganalyze/pg_query_go`** — cgo.

## Capability gaps with no library answer

These stay declined because no dependency solves them; they need design work.

- **Second-order / stored threading** — 18 `(stored …)` DOM rows plus the stored input-retrieval, open-redirection and suspicious-transformation rows. `core.PriorExchange` exists; what is missing is a producer that submits in one exchange and observes in a later one. This is the single largest remaining block by row count.
- **Form-field analysis** — `Cleartext submission of password`, `Password submitted using GET method`, `Password returned in URL query string`, `Password field with autocomplete enabled`, `Password value set in cookie`. Needs locating a password input and tracking its value; `x/net/html` (Tier A) is the enabler.
- **`Long redirection response`, `Cross-domain POST`, `Request URL override`, `Multiple content types specified`, `Content type is not specified`, `Cross-domain Referer leakage`** — small passive detectors that were in `infra_passive.go`'s brief but not implemented. No library needed; just unwritten.
- **Deserialization gadget chains** — `DetectSerializedObject` recognises the blob; exploiting it needs a ysoserial-equivalent gadget corpus, which has no Go implementation.
- **WAF detection** — no maintained Go library.
