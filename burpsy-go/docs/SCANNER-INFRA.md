# Scanner Infrastructure Primitives

The capability layer behind the catalog checks, and the wiring that now sits on it. This
document began life describing **infrastructure only** — machinery built, nothing wired, the
partition unchanged at 29 runnable / 154 declined. That is no longer the state: every one of
the **183 catalog rows is runnable**, and the declined list is empty.

The distinction the document was built around still governs it. "We now have the machinery"
and "we now detect this" are different claims, and the mapping in
`internal/scanner/infra_coverage.go` keeps them in separate fields (`UnblockedIssues` vs
`WiredIssues`) so the two can never be collapsed. What changed is that `UnblockedIssues` is
now empty: there is no longer a row whose blocker is resolved but whose evaluator is missing.

## Totals

| Bucket | Count |
|---|---:|
| Catalog issues (total) | 183 |
| **Runnable checks** | **183** |
| Declined checks | 0 |
| Primitives built | 24 |
| Rows unblocked but *not* wired (`UnblockedIssues`) | 0 |
| **Rows a primitive now actually detects** (`WiredIssues`) | **139** |

`WiredIssues` counts 139, not 183, because it maps only the rows attributable to one of the
24 primitives in this document. The other 44 are runnable too, and split into two groups:
40 checks that already existed before this layer and never needed a primitive from it (`SQL
injection`, `Cross-site scripting (reflected)`, the CORS and cache families, the discovery
checks, and so on), plus the 4 provenance rows described at the end of this document. The
split is verifiable rather than asserted: a row is in `WiredIssues` only if a primitive here
is what makes it work.

The 0 unblocked is asserted by `TestInfraUnblockedIssueCountIsReportedNotInferred` and the 139
wired rows by `TestInfraWiredIssueCountIsReportedNotInferred`; the mapping it
counts is `InfraPrimitives` in `internal/scanner/infra_coverage.go`, and every issue name
in it is resolved against the shipped catalog by
`TestInfraPrimitiveMappingResolvesAgainstTheShippedCatalog`. The doc cannot drift from the
code because the code is the source and the tests fail if they disagree.

## The honest-counting gate

`TestNoDeclineReasonCitesAnAvailablePrimitive` walks all 183 registry rows and fails if any
declined row's `DeclineReason` still claims a capability that now exists. It caught 43 such
reasons when first run; all were rewritten, and the list they policed is now empty. The test
stays because it is what stops a future decline from citing a capability the tree already has.

This matters more than it looks. A reason reading *"burpsy has no native CSP evaluator"*
tells an operator the gap is architectural. Once `infra_csp.go` exists, that sentence is
false, and a false reason is worse than a missing check — it misdirects whoever would
otherwise wire the check up. The test makes the lie impossible to leave in the tree.

## Primitives

| Primitive | File | Declined issues whose blocker it resolves |
|---|---|---:|
| `csp-parser` | `internal/scanner/infra_csp.go` | 5 |
| `crossdomain-policy-parser` | `internal/scanner/infra_crossdomain.go` | 2 |
| `viewstate-decoder` | `internal/scanner/infra_viewstate.go` | 1 |
| `serialized-object-recogniser` | `internal/scanner/infra_viewstate.go` | 1 |
| `cookie-security-analyser` | `internal/scanner/infra_passive.go` | 4 |
| `header-attribute-analyser` | `internal/scanner/infra_passive.go` | 8 |
| `disclosure-pattern-bank` | `internal/scanner/infra_passive.go` | 9 |
| `smtp-mail-header-evaluator` | `internal/scanner/infra_smtp.go` | 1 |
| `jwt-forgery` | `internal/scanner/infra_jwt.go` | 6 |
| `graphql-engine` | `internal/scanner/infra_graphql.go` | 4 |
| `xml-xxe-payloads` | `internal/scanner/infra_xml.go` | 2 |
| `http-pipelining` | `internal/sender/pipeline.go` | 2 |
| `auth-differential` | `internal/scanner/infra_authdiff.go` | 2 |
| `oob-interaction-channel` | `internal/oob/client.go` | 4 |
| `dom-execution-harness` | `internal/domexec/browser.go` | 32 |
| `js-execution-tier` | `internal/jsexec/jsexec.go` | 1 |
| `stored-canary-ledger` | `internal/scanner/infra_stored.go` | 26 |
| `tlsx-probe` | `internal/tlsprobe/tlsprobe.go` | 1 |
| `form-field-analyser` | `internal/scanner/infra_forms.go` | 6 |
| `shell-breakout-classifier` | `internal/scanner/infra_cmdinject.go` | 1 |
| `technology-fingerprint` | `internal/scanner/infra_fingerprint.go` | 1 |
| `response-shape-analyser` | `internal/scanner/infra_response.go` | 5 |
| `transport-posture-analyser` | `internal/scanner/infra_transport.go` | 4 |
| `injection-evaluator-logic` | `internal/scanner/infra_injection_payloads.go` + `infra_injection_evidence.go` | 11 |

See `InfraPrimitives` for the exact issue names and the stale-reason phrases each primitive
retires. Counts in the table above are `UnblockedIssues` + `WiredIssues` per primitive.

## Wiring: `UnblockedIssues` vs `WiredIssues`

Every row in this document used to be declined. Fifteen no longer are, and the mapping keeps
the two states in separate fields because collapsing them is exactly the dishonest counting
the project forbids:

- **`UnblockedIssues`** — the machinery exists, nothing calls it. The row is still declined
  and still absent from every scan result. `TestEveryIssueAnInfraPrimitiveUnblocksIsStillDeclined`
  fails if one of these has quietly become runnable.
- **`WiredIssues`** — a native evaluator exists and the row is runnable.
  `TestEveryWiredIssueIsActuallyRunnable` fails if one of these is still declined, which is
  the dishonest direction: claiming detection the scanner does not perform.

`InfraWiredIssueCount()` is the only number in this document that means coverage.
`InfraUnblockedIssueCount()` deliberately does not.

The first fifteen wired rows are the network-free ones — `checks_passive_posture.go`, gated
behind `ScanConfig.CheckPassivePosture`, off by default like every other family switch. They
send nothing, so they are admissible in a passive-only scan. Each runner reads the captured
exchange and calls a pure analyser; the analysers were already tested, so the tests added
with the wiring cover the wiring itself — that the runner reads the right part of the
exchange, gates on TLS where the row's name depends on it, and passes the catalog's
remediation through unchanged (including where the catalog has none, as with
`Cross-domain POST`).

The second tranche is another 28, also network-free — `checks_passive_analysis.go`, gated
behind `ScanConfig.CheckPassiveAnalysis`: cookie security (4), response/header attributes (8),
the nine information-disclosure families, ASP.NET ViewState, serialized-object recognition,
and the five CSP directive rows. Row boundaries the runners have to get right, and which the
tests pin:

- The five CSP runners read the **enforcing** header only. `Content-Security-Policy-Report-Only`
  enforces nothing, so evaluating it would report weaknesses in a policy that was never in
  effect.
- `Content type incorrectly stated` requires a *present* Content-Type. Absence is
  `Content type is not specified`, a different row — and `ContentTypeMatchesBody` returns true
  for absence, which is the opposite of detecting it.
- `HTML does not specify charset` and `HTML uses unrecognized charset` are mutually exclusive
  by construction, and neither fires on a non-HTML response.
- The ViewState finding is `tentative` and says "heuristic" in its own detail text, because
  `MACEnabled` is a byte-diversity discriminator rather than a proof. A ViewState the
  heuristic reads as protected, or one that is encrypted, stays quiet: reporting a protected
  ViewState as unprotected is the expensive direction of that error.
- Each disclosure family is its own dispatch unit, so a private key found in a body must not
  surface under `Credit card numbers disclosed`.

The third tranche is the twelve **active** injection rows — `checks_injection.go`, gated behind
`ScanConfig.CheckActiveInjection`. Unlike the first two tranches these *send*, so they are not
admissible in a passive-only scan.

They run on `ProbeHarness` (`probe_harness.go`), which captures a baseline once, enumerates
insertion points through `bcheck.Enumerate`, applies payloads with `InsertionPoint.Apply`, and
sends through the same `probeGate` chokepoint as every other probe. Four decisions worth
naming:

- **A missing capability is an error, not an empty result.** No sender or no baseline makes
  every classifier unusable, so the check returns the harness's error and the audit engine
  counts a refusal. Returning nil findings would turn an unusable scan into a clean report.
- **The point set is capped** at `MaxInjectionPointsPerCheck`, and the untested remainder is
  reported through `ProbeCoverage.PointsTested` / `PointsDeclined`, which are folded into every
  finding's description. The bound shows up as reduced coverage, never as a silently short scan.
- **Confidence follows the evidence class**: `certain` for an evaluated payload, `firm` for an
  introduced error signature or an observed delay, `tentative` for a boolean differential.
- **Each family stops at its first confirmation.** Further payloads cost requests and add
  nothing to a finding already proven.

The tests pair every family with a deliberately vulnerable local server *and* a plain echo
server that reflects input without acting on it. The echo case is the one that matters:
reflection is what most endpoints do, and an evaluator that fires on it is a false-positive
generator. `File path manipulation` is the sharpest example — it is confirmed by
`TraversalFileSignatures` (real `/etc/passwd` content), never by the traversal string coming
back, and a mutation that swapped those two is caught.

## How the last 47 declined rows were closed

This section used to list 47 rows that could not be wired, each with its missing piece. All
47 now run. What each needed, and what it got:

**15 — DOM families with no instrumented sink.** These were declined because wiring an
evaluator to a sink `internal/domexec` does not wrap creates a check that can never fire, and
a permanently silent check is worse than an honest decline: every report counting runnable
checks scores it as coverage. The fix was in the harness, not the evaluators — seven sinks
were added to `instrumentationJS` (`SinkWebSQL`, `SinkXPathEvaluate`, `SinkJSONParse`,
`SinkAnchorHref`, `SinkRegExpCtor`, `SinkFileRead`, `SinkPrototypePollution`), each proven to
fire against a live page and to stay quiet on a negative one, with call-through preserved.

**14 — stored rows with no planting driver.** `StoredLedger` supplied correlation and
`ObserveStoredCanaries` the observation half; what was missing was something to plant. That is
now `PlantStoredCanaries` in `checks_stored.go`. Planting deliberately lives *inside* the
stored checks rather than in a pseudo-check of its own, because planting is not a detection
and must not claim a catalog row. `StoredLedger.ClaimPlanting` makes exactly one caller per
exchange the planter: without it every stored check would replant and overwrite the values an
earlier one was waiting to observe.

**14 — miscellaneous, each with a named missing piece.** All built:

| Rows | What it needed | Where it landed |
|---|---|---|
| `Broken access control`, `Cross-site request forgery` | a `session.Coordinator` handle on `CheckContext` | `scanner.go` field + `checks_final.go` |
| `JWT arbitrary jku header supported`, `...x5u...` | a server we control that the target will fetch chosen content from | `jwks_host.go` — a local one-shot JWKS/x5u host |
| `HTTP request smuggling`, `Client-side desync` | a driver over `internal/sender/pipeline.go` | `pipeliningCheck` in `checks_final.go`, CL.TE and TE.CL probes |
| `Hidden HTTP 2` | a paired probe: `h2` absent from the ALPN offer, then a prior-knowledge attempt | `checkHiddenHTTP2` over `internal/alpn` |
| `External service interaction (SMTP)` | an SMTP collaborator | the interactsh channel already observes SMTP; what was missing was payload *shape*. `oobPayloadsFor` gives the SMTP row address-shaped payloads (`burpsy@<host>`), because a URL never asks an application to send mail — the row would otherwise be wired but unable to fire |
| the reflection-differential rows | a producer that compares a probe against its baseline in context | `reflectedContextCheck` in `checks_final.go` |

**4 — not detections at all.** `Extension generated issue`, `Manually generated issue`,
`BCheck generated issue`, `Bambda generated issue` are issue-*source* provenance labels Burp
applies when a human or an extension files a finding. There is nothing to *detect*, and
inventing a probe for them would be fabrication. They are runnable in the honest sense
available to them: `provenanceCheck` reports findings that were filed through those routes,
reading the `ProvenanceLedger` rather than sending traffic. With an empty ledger they report
nothing, which is the correct answer to "what did an extension file?" when none did.

## A gate change worth knowing about

`CheckSSRF` and `CheckXXE` used to admit one declined row each. Once those rows had real
evaluators the switches became live, and `CheckSSRF` is on by default in the web layer's
live-audit config — so a default scan began erroring every sweep on any machine without
`interactsh-client` installed, because the OOB check correctly reports a missing channel as an
error rather than as zero interactions.

Both rows are now additionally gated behind `CheckExtendedActive`. That restores "a default scan
sends nothing it was not asked to send" while keeping the honest error semantics: when an
operator opts in and the channel is absent, the check refuses rather than reporting clean.

## Active injection: banks recovered, evidence earned

Twelve rows declined with one sentence — *"burpsy has no native evaluator for this injection
class"* — and that sentence hid two separate gaps: no payloads, and no way to judge a
response. Both are now closed.

### What the Java actually gave up

| Class | Recovered |
|---|---|
| `burp.Ze2s` | 66 literals: ~42 SQL error signatures, 7 XPath error signatures, and 17 SQL payload fragments — one mixed bank, because `burp.Zg_c` (`APIP_SqlAndXPathInjection`) drives both families from a single check |
| `burp.Zxpy` | PostgreSQL delays: `pg_sleep(%%)--`, `+nullif(0,pg_typeof(pg_sleep(%%)))`, `'||pg_sleep(%%)||'` |
| `burp.Zuyg` | MS SQL delay: `waitfor delay'0:0:%%'--` |
| `burp.Zsna` | LDAP: `objectClass=*`, `%s)(%s`, `!(%s)` |
| `burp.Zx8l` | Six OS command breakouts echoing a marker, plus the marker fragment `xzwx` |
| `burp.Zxvd` | SSI `#echo` / `#set` / `#exec cmd="nslookup -q=cname` and the triple-close breakout prefix (double-quote, single-quote and backtick each followed by `-->`) |
| `burp.Zp3p` | Out-of-band FreeMarker, Velocity, Thymeleaf, Java EL, Spring and Struts OGNL payloads |
| `burp.Zwv2` | 17 template engine names |
| `burp.Zxvv` | PHP: `".(7*6)."` arithmetic proof, `gethostbyname`, `fsockopen` |
| `burp.Zwvr`, `Zwug`, `Zwuj` | the three quoting contexts every code-injection check reports: *an unquoted*, *a single-quoted*, *a double-quoted* |

The three-context vocabulary is the structural find. It is not prose — it is the loop shape:
the same payload is tried unquoted, single-quoted and double-quoted, and the finding names
which context worked. `CodeInjectionProbeSet` walks that matrix.

### What was *not* recovered, and is labelled so

Burp's Perl, Ruby, Python and server-side-JavaScript payload text is not in the evidence —
those classes carry only issue prose and the `%%`/`$$` placeholders. The emitters in
`CodeInjectionEmitters` are therefore documented standard forms for each language, carrying
`Recovered: false`, and `TestOnlyPHPEmittersClaimRecovery` fails if any of them ever claims
otherwise. The arithmetic operands they emit *are* recovered (`7*6`, `burp.Zxvv`).

`PathTraversalPayloads` comes from `burp.Zr8k`, which is Burp's manual-testing traffic
simulator rather than its traversal scan check. The literals are genuine; their source class
is a generator, and the file says so instead of implying they are the check's own bank.

### Why the classifier is the actual evaluator

A payload bank proves nothing. `infra_injection_evidence.go` takes the baseline response as
a mandatory argument to every classifier, because:

- An error signature already in the baseline means the endpoint always errors. It is
  recorded in `ErrorEvidence.Preexisting` and yields `InjectionEvidenceInconclusive`, never a
  finding. Several recovered signatures are broad enough — `PostgreSQL`, `SQLException` — to
  match a page that merely discusses a database, which is exactly why this is mandatory.
- A response containing `42` that always contained it proves nothing, and a response echoing
  `;echo MARK1;` back contains the marker without any command having run. `ClassifyEvaluation`
  rejects both.
- A boolean differential needs *both* halves: true-condition matching baseline and
  false-condition diverging. If both diverge the input was sanitised, not interpreted.
- Timing needs the baseline to be faster than half the requested delay, or the delay is
  indistinguishable from the endpoint's own latency.

`InjectionEvidenceInconclusive` outranks `InjectionEvidenceNone` in `BestEvidence`, so a
probe set where nothing confirmed but something was unmeasurable can never be reported as
clean.

## Second-order threading: the correlation half

`TrafficStore.PriorExchange` already answered "what did this same endpoint look like last
time", and the audit engine already threaded it into `CheckContext.StoredExchange`. That is
not what a stored-input check needs: the submission and the observation are *different*
endpoints, so same-endpoint history cannot express the relationship at all.

`StoredLedger` closes that gap. `Plant` mints an alphanumeric canary — alphanumeric because
every other byte class is re-encoded by HTML, JSON or URL encoders, and a mangled token is a
false negative. `Observe` records a sighting but promotes it to `StoredCanaryStored` only
when it surfaces in an exchange other than the one that planted it; an echo from the
submitting response is `StoredCanaryReflectedOnly`, which is reflection and belongs to the
reflected checks.

The state that matters for honest counting is `StoredCanaryOutstanding`: planted, never seen
anywhere. A stored check that plants a payload, re-requests one page, sees nothing and
reports "not vulnerable" is lying — the payload may be awaiting moderation, may surface only
to another role, may sit on a page the crawl never reached. `Outstanding()` and
`Summarise()` expose that set so a report can state how much planted input is still
unaccounted for rather than folding it into "no issues found".

## Why `zcrypto` was rejected in favour of the `tlsx` binary

`zmap/zcrypto` was the obvious candidate for TLS analysis and was evaluated directly. It
builds cleanly under Go 1.26.2 and costs only three modules, so the usual objections do not
apply — but its current release has been re-synced with upstream stdlib and has *dropped*
the legacy capabilities that were the only reason to prefer it over `crypto/tls`:

- `MinVersion: VersionSSL30` fails client-side with `tls: no supported versions satisfy
  MinVersion and MaxVersion`; the constant survives, the support does not.
- RC4 and export-grade DH handshakes (`rc4.badssl.com`, `dh512.badssl.com`) fail.

A fork of stdlib crypto that can no longer negotiate what stdlib refuses buys nothing. The
`tlsx` CLI reaches the legacy cases through its `-scan-mode openssl` backend, and adds
cipher-strength classification (`-cipher-enum -cipher-type weak,insecure`) plus the five
certificate misconfiguration probes that map one-to-one onto the `TLS certificate` row's
discriminators. Subprocessing it follows the precedent already set by `interactsh-client`
and keeps the module graph unchanged.

`internal/tlsprobe` keeps `OutcomeNotInvoked`, `OutcomeUnavailable` and `OutcomeFailed`
distinct from `OutcomeCompleted` for the same reason the ledger tracks outstanding canaries:
a missing binary or a timeout must never read as a clean TLS result.

## Evidence provenance

Every primitive was grounded in the recovered Burp evidence where it existed, and labelled
as standard where it did not. This is the same rule the ported checks follow: never present
an invented payload as recovered.

**Genuinely recovered from the deobfuscated tree:**

- `crossdomain-policy-parser` — found the real backing helpers `Zudv`/`Zebv` behind
  `Zm24`/`Zbtu`, recovering `/crossdomain.xml`, `/clientaccesspolicy.xml`, the
  `allow-access-from`/`domain`/`uri` element and attribute names, and porting the wildcard
  comparison **verbatim**: Flash tests `domain.equals("*")` with no scheme handling, while
  Silverlight strips a leading `http://`/`https://` case-insensitively *before* the same
  test, so `*`, `http://*` and `https://*` are all wildcards there but only `*` is in Flash.
- `xml-xxe-payloads` — five classes yielded real literals: `Zge7` (`/etc/passwd`,
  `win.ini`), `Zeix` (parameter-entity OOB), `Zcli` (PUBLIC-doctype OOB), `Zch5`
  (`xml-stylesheet` PI OOB), `Zgij` (the actual billion-laughs nested-doubling construction,
  including its `xee` entity prefix), `Zbiw` (XInclude).
- `graphql-engine` — `Zbop` gave the real suggestions probe `query{__type}` and the real
  confirmation substring `must have a selection of subfields. Did you mean`. `Zmzj` gave
  `query{__typename}` and `application/json; charset=utf-8`.
- `auth-differential` — `Zcxn`'s architecture recovered in full: it sends one request
  through two identity lambdas (with-session, without-session) and diffs them on
  `STATUS_CODE` plus `PAGE_TITLE`/`LINE_COUNT`/`JSON_NODE_COUNT`; identical responses mean
  broken access control. `Zg8u` confirmed as a pure Referer-validation probe.
- `cookie-security-analyser` — session-cookie families from `Zmac`.
  `header-attribute-analyser` — spoofable-client-IP header names from
  `Zcg4`/`Zgl4`/`Zwv9`/`Zb8r`. `disclosure-pattern-bank` — source-code markers from
  `Zxvv`/`Zu86`, directory-listing text verbatim from `Zewc`, PEM/JWKS vocabulary from `Zi8s`.
- `csp-parser` — directive vocabulary and finding prose cross-checked against `Zupz`/`Zifp`.
- `jwt-forgery` — header names from `Zs83` (`jku`, `x5u`) and `Zi8s` (`alg`, `jwk`, `kid`);
  all six `TypeIndex` values independently cross-checked against `catalog_data.go` via `Zc84`.

**Standard, not recovered — and labelled as such in each file header:**

- `smtp-mail-header-evaluator` — `Zgcg` delegates payload generation to a shared engine whose
  arrays are ZKM ciphertext residue. The 3×3 separator/encoding matrix is documented
  technique.
- `viewstate-decoder` / `serialized-object-recogniser` — Burp's own signature tables decode to
  residue; the magic bytes used are public platform behaviour, verified numerically rather
  than assumed.
- `jwt-forgery` — no static payload exists to recover: a forged token's material is a
  runtime-generated keypair, not a class literal.
- `xml-xxe-payloads` quadratic-blowup variant, and the `XMLInjectionPayloads` structural
  probes (`Zp7s`/`Zf5e` carry no recoverable literals).

## Deliberate omissions

Rows are **not** claimed as unblocked when no exported function supplies their
discriminator, even where a sibling row in the same family is covered. Claiming them would
force a reason rewrite that would itself be false:

- `Long redirection response`, `Cross-domain POST`, `Request URL override` — in
  `infra_passive.go`'s target list, but no detector shipped.
- `Multiple content types specified`, `Content type is not specified` —
  `ContentTypeMatchesBody` answers "incorrectly stated" only, and returns `true` for an
  absent `Content-Type`, which is the opposite of detecting absence.
- `Cleartext submission of password`, `Password submitted using GET method`,
  `Password returned in URL query string`, `Password field with autocomplete enabled`,
  `Password value set in cookie` — all need form-field analysis to locate a password input.
- `Cross-domain Referer leakage` — needs outbound-Referer analysis; only inbound Referer
  probing shipped.

## Browser and JS execution — built, with an honest split

`internal/domexec` drives real Chrome via `chromedp` (human-approved dependency; 7 modules).
It injects instrumentation before any page script runs, hooking 15 sinks against 5
controllable sources, and reports which sink received a planted canary. `RenderedDOM` also
exposes post-script markup the HTTP-only scanner cannot see at all.

Two findings from building it are worth recording because both were false-positive sources:

- **`location` cannot be hooked from JavaScript in Chromium.** `Object.defineProperty` on
  `Location.prototype` succeeds but is dead code: `href`/`assign`/`replace` are
  non-configurable *own* accessors on the `Location` instance, so property lookup finds them
  before the prototype. Verified empirically, not assumed. DOM-based open redirection is
  therefore detected from CDP frame-navigation events instead.
- **Our own probe navigation looked like a finding.** CDP normalises `http://host` to
  `http://host/`, so comparing the reported navigation against the planted URL as raw strings
  never matched, and every hash-probed page reported a DOM open redirection — the probe URL
  contains the canary by construction. Fixed with URL-canonical comparison (`sameNavigation`).

`internal/jsexec` (goja, pure Go) is a deliberately *weaker* second tier, and is documented as
such in its package comment. It has no DOM and cannot replace the browser. It exists for two
jobs a browser is the wrong tool for: prototype-pollution testing by before/after inspection of
`Object.prototype`, and graceful degradation on a host with no Chrome, where an extracted
snippet can still be evaluated for a source-to-sink flow. A clean result from that tier must be
reported as "no flow observed by the DOM-less tier", never as "no DOM vulnerability".

### The stored-variant split

Of the 51 rows citing the browser blocker, only **33** are claimed. The 18 `(stored …)`
variants need a browser **and** a second-order producer that submits in one exchange and
observes in a later one, which does not exist. Their reasons were rewritten to say the browser
half is resolved and the stored half is not, rather than claiming them outright.

## Verification

```bash
cd burpsy-go
go build ./...
go vet ./...
go test ./... -count=1                      # internal/bcheck has 8 pre-existing failures (see below)
go test ./internal/scanner/... ./internal/oob/... ./internal/sender/... -count=1
go test -tags oob_live ./internal/oob/... -count=1   # real Interactsh pingback; excluded from the default gate
```

`internal/bcheck`'s 8 failures predate this batch — they come from uncommitted third-party
work in `insertion.go`/`insertion_test.go`, confirmed by `git stash` showing the package
green without those changes. They were surfaced rather than "fixed", because silently
repairing someone else's in-flight edit is how you lose their work.

The live OOB test is behind `//go:build oob_live` deliberately: a suite whose result depends
on a third-party service being reachable is a flaky suite, and a flaky gate trains people to
ignore red.
