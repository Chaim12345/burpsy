<!-- PROVENANCE — read this before citing anything below. -->

> **This file was restored on 2026-08-26.** Until then, `docs/parity/W1-broken-behaviour.md`
> held a 72-line *reconstruction* written after the original was destroyed with a reaped
> `.orchestry` workspace. That reconstruction opened with:
>
> > "**1 confirmed STATE 5 in scope.** All other accepted-vs-handled tables across
> > `intercept`, `netauth`, `session`, `upstream`, proxy-options and toolkit came back
> > **clean** at `a619c9a`."
>
> **The clause naming `session` as clean was false**, and it was the git-canonical evidence
> file for the whole analysis while it said so. The full original below records the
> `session.ValidityRule.Evaluate` first-stated-field-wins defect — the worst finding in the
> master report (§3.1a), whose blast radius is every finding of an authenticated scan. A
> reader who followed the report's own citation trail to this file would have been told the
> defect did not exist.
>
> Two lessons, both already in §10 and both re-earned here:
> 1. **A reconstruction is not evidence.** Summarising from memory after losing the artefact
>    silently inverted a finding. It should have been labelled unrecoverable, not rewritten.
> 2. **Check that the evidence file says what the report says it says.** This contradiction
>    survived three commits and a merge because nobody re-read the cited file after citing it.
>
> The 72-line reconstruction is preserved in git history (see `6e83ced`) and is superseded.
> The proof harness for the session defect is `docs/parity/W3a-session-validity-proof_test.go.txt`.

---

# W1 — behavioural hunt for STATE 5 (reachable but silently wrong)

Baseline: `a619c9a9423dbb72b14a0a27119e89b15b3741e6`. `git status --short --branch` at the start of
this pass reported a clean tree (`## ui-react-comparison...origin/ui-react-comparison [ahead 37]`,
no modified files). No file under `burpsy-go/internal` was modified; all execution was done against
copies under `/tmp/burpsy-scratch`.

Bug class hunted: an API-layer vocabulary (string→enum parser, switch on a type field, accepted
config key, accepted config *shape*) that admits more values than the engine-layer switch
implements, where the engine's default branch is neither an error nor a no-op but a
plausible-looking wrong action.

**Result: 4 confirmed STATE 5 findings**, all with executed behavioural proof. Two are
high-damage (a live-traffic surface silently does the wrong thing for input the shipped UI itself
produces or documents); two are lower-damage tolerant-parser coercions that only fire for
out-of-vocabulary input, which the shipped UI does not currently send.

The negative-result tables (§Accepted-vs-handled) cover every parser/switch pair examined,
including the ones with no defect.

---

## Findings, worst first

### Session-handling rule validity check — multi-field validity block — STATE 5

Burp side: not compared to the Burp reference (`/root/burp-re` is a compressed teardown at this
SHA and I did not unpack it). The focus here is burpsy's own contract violation, and the contract is
stated in burpsy's own UI, in words, to the operator.

burpsy side:
- Contract, rendered next to the form: `burpsy-go/internal/web/ui/src/pages/session.tsx:828` —
  *"Every stated field has to hold for the probe response to count as a valid session."*
- The form that lets an operator state several fields at once:
  `burpsy-go/internal/web/ui/src/pages/session.tsx:830-869` (a `status_is` `Field` plus the four
  `VALIDITY_FIELDS` declared at `session.tsx:56-62`: `body_contains`, `body_not_contains`,
  `header_present`, `header_absent`). The default draft ships with `status_is: 200` already filled in
  (`session.tsx:157`), so *every* extra field an operator adds is a second stated field.
- The engine: `burpsy-go/internal/session/session.go:38-118`, `func (vr *ValidityRule) Evaluate`.
  It is a chain of `if` statements, each of which **returns**: `StatusIs` (line 42), then
  `BodyContains` (51), `BodyNotContains` (57), `HeaderPresent` (63), `HeaderAbsent` (70), then
  `All`/`Any`/`Not`. The first stated field decides the answer and every later stated field is never
  read. There is no AND anywhere on this path.
- Nothing refuses the shape: `dtoToRule` (`burpsy-go/internal/web/api_session.go:337-341`) unmarshals
  the validity block verbatim, and `internal/session/validate.go` has no validity-field check at all
  (`grep -rn 'BodyContains\|StatusIs\|HeaderPresent' internal --include='*.go' | grep -v _test.go`
  returns only `session/session.go:28,29,31,42,51,63` — i.e. the struct declaration and `Evaluate`
  itself, and nothing in `validate.go` or the web layer).
- The result is consumed on the live path: `internal/session/session.go:894`,
  `internal/session/session.go:1022`, `internal/session/recovery.go:198`,
  `internal/session/recovery.go:325`, `internal/session/recovery.go:375`.
- Reachability: route `POST/GET /api/session/rules` registered at
  `burpsy-go/internal/web/server.go:728`; UI callers at
  `burpsy-go/internal/web/ui/src/lib/data.ts:312-313` and `lib/data.policy.ts:44`.

What actually happens: an operator writes the natural session check — "the session is valid when the
probe returns 200 **and** the body does not contain *Please log in*". The app, like most apps,
answers **200 with the login page** when the session has expired. `Evaluate` returns on `StatusIs`,
answers `Valid`, and the coordinator concludes the session is fine. No re-login is attempted, no
error is raised, and the whole authenticated scan/crawl proceeds logged out. This is the exact
failure the session-handling feature exists to prevent, and the UI told the operator it would not
happen.

Proof (run against a copy of the whole module in `/tmp/burpsy-scratch/burpsy-go`, exercising the
real HTTP handler and the real coordinator):

```
$ cd /tmp/burpsy-scratch/burpsy-go && go test ./internal/web/ \
    -run TestSessionValidityMultiFieldAcceptedThenIgnored -v
=== RUN   TestSessionValidityMultiFieldAcceptedThenIgnored
POST /api/session/rules -> 200
{"rule":{"id":1,"name":"login","enabled":true,"steps":[{"method":"POST","url":"http://app.example.com/login","headers":null,"body":"u=a&p=b"}],"validity":{"status_is":200,"body_not_contains":"Please log in"},"max_attempts":3}}

stored validity evaluated against HTTP 200 + body "Please log in" => Valid
UI text at internal/web/ui/src/pages/session.tsx:828: "Every stated field has to hold for the probe response to count as a valid session."
--- PASS
```

Unit-level proof isolating the engine, with both single-field controls (copy of
`internal/session` only, `/tmp/burpsy-scratch/session`):

```
$ cd /tmp/burpsy-scratch/session && go test -run TestValidityFirstStatedFieldWins -v ./...
=== RUN   TestValidityFirstStatedFieldWins
validity JSON:      {"status_is":200,"body_not_contains":"Please log in"}
UI contract:        "Every stated field has to hold" -> expect Invalid
Evaluate(200, body containing "Please log in") = Valid
control {"body_not_contains":"Please log in"} = Invalid
control {"status_is":200} = Valid  (identical to the combined rule => body_not_contains was never read)
--- PASS
```

The two controls are the positive control for the claim: the second field *does* work when it is the
only field stated (`Invalid`), and the combined rule's answer is byte-identical to the
`status_is`-only rule's answer, so the second field was demonstrably not consulted.

Denominator: 1 of 1 validity-evaluation path in the codebase is affected — I counted the callers
myself with `grep -rn 'Validity.Evaluate' internal --include='*.go' | grep -v _test.go`, which
returns 5 call sites (`recovery.go:198,325,375,381`, `session.go:894,1022` — 6 lines, 5 distinct
guards) and all of them go through this one `Evaluate`. Of the 5 validity fields the UI form offers
(1 `status_is` + 4 `VALIDITY_FIELDS`, counted by reading `session.tsx:55-62` and `session.tsx:830`),
**at most 1 is ever honoured per evaluation**; the other 4 are silently inert whenever an
earlier-listed field is also set. The UI's own default draft pre-fills the earliest-listed field
(`status_is: 200`, `session.tsx:157`), so the default path is the broken path.

Not determined:
- Whether Burp's own "session is valid" definition ANDs its conditions. Not checked against
  `/root/burp-re` — the teardown is a `.tar.zst` I did not unpack.
- Whether any Playwright e2e test covers a multi-field validity rule. Per TAXONOMY rule 5, the e2e
  suite is not in CI, so a green run there would be an ungated manual observation anyway.
- What the *intended* semantics are. Two readings are defensible (AND the stated fields, as the UI
  says; or refuse a multi-field flat block and force `all: [...]`). Either would be a fix; the
  current behaviour matches neither.

---

### `/api/proxy/matchreplace` — `request_param_name` / `request_param_value` — STATE 5 (confirmed baseline, pre-proven)

Burp side: not compared to the Burp reference in this pass; the contract violated is burpsy's own —
the endpoint names two parameter-scoped targets and applies a body-wide rewrite instead.

burpsy side at `a619c9a` — line numbers and content re-verified by reading, and they still match:
- `burpsy-go/internal/web/api_toolkit.go:563-572` — `matchReplaceTargetNames` lists seven accepted
  `rule_type` values including `"request_param_name"` (line 567) and `"request_param_value"` (568).
- `burpsy-go/internal/web/api_toolkit.go:587-608` — `targetToCategory` returns
  `matchreplace.TargetRequestParamName` (line 596) and `TargetRequestParamValue` (line 598) with a
  nil error. Its `default` (605-606) *is* a 400, so the parser is otherwise hardened; these two are
  admitted, not defaulted.
- `burpsy-go/internal/web/api_toolkit.go:645-676` — `matchReplacePut` builds the rule and calls
  `s.matchReplace.SetRules(rules)` (line 674), answering `200` with `{"compiled":N}` (line 678).
- `burpsy-go/internal/matchreplace/matchreplace.go:242-253` — `applyOne` has cases for
  `TargetRequestBody/TargetResponseBody` (244), `TargetRequestHeader/TargetResponseHeader` (246) and
  `TargetRequestFirstLine` (248). There is **no case for `TargetRequestParamName` or
  `TargetRequestParamValue`**; both hit `default: return applyBody(r, raw)` (250-251) — a body-wide
  substring/regex rewrite that will corrupt unrelated parameters, header-adjacent text and any other
  occurrence of the same substring anywhere in the message.
- `matchreplace.go:236-237` (`targetsDir`) and `matchreplace.go:129` both explicitly *include* the
  two param targets in the request direction, so the rules are selected and dispatched on live
  traffic; only the application is wrong.
- The enum constants themselves: `matchreplace.go:21-22`.

Proof: not re-run — this finding was proven behaviourally in a prior pass and the task scoped it as
a read-only sanity check. The read-only confirmation is that all six cited sites are unchanged at
`a619c9a` and the description above is exact. (Note the file's own comments at `api_toolkit.go:585`
and `684-694` describe two *previously fixed* variants of this bug on the same endpoint — the
`0, nil` default and the `matchReplaceTargetName` fallback — which is why the surviving engine-side
gap is easy to miss: the web layer looks fully hardened.)

Denominator: 2 of the 7 accepted `rule_type` values are unimplemented in the engine. I counted the 7
myself from `matchReplaceTargetNames` (`api_toolkit.go:565-572`, seven string literals) and
cross-checked against the seven `case` arms of `targetToCategory` (`api_toolkit.go:589-602`) and the
seven arms of its inverse `matchReplaceTargetName` (`api_toolkit.go:695-710`). The engine's
`applyOne` implements 5 of those 7 (3 case arms covering 5 enum values: `matchreplace.go:244-249`).
So: **5/7 implemented, 2/7 silently mis-applied**.

Not determined: whether any live UI flow selects the two param targets. `matchreplace.tsx` was not
audited for its rule-type dropdown contents in this pass; the endpoint accepts them regardless, and
the round-trip test at `internal/web/matchreplace_target_test.go:139-140,179,217` asserts they are
storable and readable, so a config restored from disk or written by any API client reaches the bug.

---

### `PUT /api/intercept/rules/{requests|responses}` — rule `category` coercion — STATE 5

Burp side: not compared to the Burp reference; Burp's equivalent field is a two-value choice
("Regex"/"Simple string") and the contract violated here is burpsy's own two-value wire vocabulary.

burpsy side: `burpsy-go/internal/web/api_intercept.go:159-179`, `specToRules`:

```go
cat := intercept.CategoryRegex
if sp.Category == "literal" {
    cat = intercept.CategoryLiteral
}
```

The wire vocabulary is `{"regex","literal"}` (its inverse `rulesToSpecs` at `api_intercept.go:181-197`
emits exactly those two, and the UI's dropdown at `ui/src/pages/intercept.tsx:49-50` offers exactly
those two). Anything else — a different case, a Burp-style spelling, a typo, an omitted field — is
neither refused nor treated as literal: it is silently installed as a **regex**. `intercept.ParseField`
right above it (line 164) *does* return an error for an unknown field and the handler 400s on it
(`api_intercept.go:218`), so the asymmetry is inside a single loop.

Damage: a literal match string containing regex metacharacters becomes a pattern. `.` matches every
character, `*`/`+`/`(` become a compile error (400, visible), and — worse — a string like
`api.example.com` or `/admin?x=1` silently over-matches, so the intercept list holds traffic the
operator did not ask to hold, or (for a response-side rule) holds nothing they expected. It is
"plausible-looking wrong action", not an error.

Proof (real handler, real engine, `/tmp/burpsy-scratch/burpsy-go`; the rule is `path` contains
`a.c`, and the probe path is `abc`, which only a regex can match):

```
$ cd /tmp/burpsy-scratch/burpsy-go && go test ./internal/web/ -run TestInterceptCategoryCoercion -v
=== RUN   TestInterceptCategoryCoercion
sent category="literal"       status=200 readback="literal" matches path "abc" (regex-only) = false
sent category="Literal"       status=200 readback="regex"   matches path "abc" (regex-only) = true
sent category="simple_string" status=200 readback="regex"   matches path "abc" (regex-only) = true
sent category=""              status=200 readback="regex"   matches path "abc" (regex-only) = true
sent category="regex"         status=200 readback="regex"   matches path "abc" (regex-only) = true
--- PASS
```

Row 1 is the positive control: the in-vocabulary value `"literal"` behaves correctly (no regex
match). Rows 2-4 are out-of-vocabulary values accepted with `200` and silently promoted to regex
semantics, and the GET read-back lies about what the operator sent.

Denominator: 2 of 2 accepted category spellings are handled correctly; **every one of the infinitely
many other strings is coerced to regex rather than refused** — accepted-minus-handled is unbounded
here rather than a finite miss. I counted the vocabulary myself: two `case`-equivalent branches in
`specToRules`/`rulesToSpecs` (`api_intercept.go:166-169` and `186-189`) and two `<option>` values in
`ui/src/pages/intercept.tsx:49-50`.

Not determined: whether any shipped client sends a value outside `{"regex","literal"}`. The React UI
does not (`intercept.tsx:49-50,60`). Intercept rules are **not persisted** (`grep -rn 'intercept\.'
internal/persist/*.go | grep -v _test.go` returns nothing, positive control: the same grep for
`matchreplace` returns `persist.go:959,985`), so a restored-config path cannot reach it either. The
realistic trigger is a third-party API client, a script, or a future UI change — the defect is that
the endpoint accepts it with `200` and does the wrong thing rather than answering 400 the way
`targetToCategory` on the sibling endpoint now does.

---

### `PUT /api/proxy/matchreplace` — rule `category` coercion — STATE 5

Burp side: as above, burpsy's own two-value vocabulary.

burpsy side: `burpsy-go/internal/web/api_toolkit.go:662-665` (the live PUT) and
`burpsy-go/internal/web/api_toolkit.go:748-751` (the `/api/proxy/matchreplace/test` dry run), both:

```go
cat := matchreplace.CategoryLiteral
if spec.Category == "regex" {
    cat = matchreplace.CategoryRegex
}
```

This is the **mirror image** of the intercept bug on the same wire field name: here anything that is
not exactly `"regex"` becomes **literal**. So the same out-of-vocabulary `category` value produces
opposite semantics on the two endpoints. Sitting two lines below `targetToCategory`, whose whole
documented purpose (`api_toolkit.go:576-586`) is that a value the engine cannot express must be a
400 rather than a coercion, this is the one coercion the file did not remove.

Damage: an operator's regex rewrite is installed as a literal substring rewrite and silently never
fires (or fires on the literal text of the pattern), against live proxy traffic, with `200` and
`{"compiled":1}`.

Proof (real handler, real ruleset):

```
$ cd /tmp/burpsy-scratch/burpsy-go && go test ./internal/web/ -run TestMatchReplaceCategoryCoercion -v
=== RUN   TestMatchReplaceCategoryCoercion
sent category="regex"    status=200 installed engine category = regex
sent category="Regex"    status=200 installed engine category = literal
sent category="regexp"   status=200 installed engine category = literal
sent category=""         status=200 installed engine category = literal
sent category="literal"  status=200 installed engine category = literal
--- PASS
```

Rows 1 and 5 are the positive controls (both in-vocabulary values install correctly); rows 2-4 are
out-of-vocabulary values silently demoted to literal.

Denominator: 2 of 2 accepted category spellings handled correctly, unbounded accepted-minus-handled,
counted the same way — `matchReplaceCategoryName` (`api_toolkit.go:715-720`) emits exactly two
strings, and `ui/src/pages/matchreplace.tsx:27-28` offers exactly two options. Two code sites carry
the coercion (`api_toolkit.go:662` live, `752` dry-run) out of 2 places that build a
`matchreplace.Rule` from a wire spec — **2/2 affected**, so the dry-run preview agrees with the live
path here (it is wrong in both, consistently).

Not determined: same as the intercept case — the shipped UI stays in vocabulary
(`matchreplace.tsx:43` clamps to `value === "regex" ? "regex" : "literal"`), and persistence stores
the category as an `int` (`internal/persist/persist.go:959,985`), so no restore path reaches it. The
trigger is any non-UI client.

---

## Adjacent findings that are NOT state 5 (recorded separately, as instructed)

### Nested validity combinators `all` / `any` / `not` — STATE 3 (unreachable from the UI)

`internal/session/session.go:79-117` fully implements `All`, `Any` and `Not`, including three-valued
logic with `Indeterminate` propagation. `dtoToRule` accepts them (it unmarshals the whole
`ValidityRule`, `api_session.go:337-341`), and `ruleToDto` round-trips them
(`api_session.go:282-286`). But the UI can only *preserve* them, never author them: `session.tsx:169`
`hasNestedValidity` detects them and `session.tsx:874-881` renders a read-only warning — *"This rule
combines conditions with all / any / not. Those nested branches are kept exactly as saved — the
fields above edit the flat conditions only."* There is no control anywhere in `session.tsx` that
constructs an `all`/`any`/`not` node (positive control: `grep -n '"all"\|all:' session.tsx` finds
only the `hasNestedValidity` read at line 170).

This is the direct cause of finding #1's severity: the one construct that *would* express "every
stated field has to hold" is the one an operator cannot create from the UI, so they use the flat
form the UI offers and get first-match-wins.

Denominator: 3 of the 8 `ValidityRule` fields (`session.go:28-35`: `status_is`, `body_contains`,
`body_not_contains`, `header_present`, `header_absent`, `all`, `any`, `not` — I counted the struct
fields myself) are engine-complete and UI-unauthorable.

### Intercept rule lists are not persisted — STATE 2-adjacent

`grep -rn 'intercept\.' internal/persist/*.go | grep -v _test.go` returns nothing. Positive control:
the same grep shape for `matchreplace` returns `internal/persist/persist.go:959` and `:985`, and for
`session` returns `persist.go:1129`. So match/replace rules and session rules survive a restart and
intercept match rules do not. Not proven behaviourally (no restart harness built), hence recorded as
a candidate rather than a finding.

---

## Accepted-vs-handled tables (required negative-result deliverable)

Every parser/switch pair examined in this pass, including the clean ones. "Non-error default"
answers the question the hunt turns on: does the default branch refuse, or does it silently act?

### Scope of the sweep, self-counted

| Denominator | Value | How I counted it |
|---|---|---|
| `case "` string-vocabulary sites in the six packages | **30** | `grep -rn 'case "' proxy matchreplace intercept session netauth upstream --include='*.go' \| grep -v _test.go \| wc -l` run from `burpsy-go/internal` |
| non-test `api_*.go` files in `internal/web` | **33** | `ls api_*.go \| grep -v _test.go \| wc -l` (49 including `_test.go`) |
| of those, files importing one of the six packages | **7** | `grep -ln 'internal/\(proxy\|matchreplace\|intercept\|session\|netauth\|upstream\)"' api_*.go \| grep -v _test.go` → `api_toolkit.go`, `api_config.go`, `api_intercept.go`, `api_netauth.go`, `api_network_proxy.go`, `api_proxyoptions.go`, `api_session.go` (plus `server.go`, which is not an `api_*.go` file) |
| parser/switch pairs in the table below | **24** | counted by reading each site listed; rows below |
| of those, defective | **4** | findings above |

### The table

| # | Parser / switch pair | Accepted by the API/parser side | Handled by the engine side | Non-error default? | Verdict |
|---|---|---|---|---|---|
| 1 | `web.targetToCategory` (`api_toolkit.go:587`) → `matchreplace.applyOne` (`matchreplace.go:242`) | 7: `request_header`, `request_body`, `request_first_line`, `request_param_name`, `request_param_value`, `response_header`, `response_body` | 5 (3 case arms: body×2, header×2, first-line) | **yes** — `default: return applyBody(raw)` | **STATE 5** (finding #2) |
| 2 | `session.ValidityRule` JSON shape (`api_session.go:337`) → `ValidityRule.Evaluate` (`session.go:38`) | any combination of 8 fields | 1 field per evaluation (first stated wins) | **yes** — silently returns on the first field | **STATE 5** (finding #1) |
| 3 | intercept `category` (`api_intercept.go:166`) → `intercept.Category` | 2 documented (`regex`, `literal`); in practice any string | 2 | **yes** — `!= "literal"` ⇒ regex | **STATE 5** (finding #3) |
| 4 | matchreplace `category` (`api_toolkit.go:662`, `:752`) → `matchreplace.Category` | 2 documented (`regex`, `literal`); in practice any string | 2 | **yes** — `!= "regex"` ⇒ literal | **STATE 5** (finding #4) |
| 5 | `intercept.ParseField` (`intercept.go:71`) → `Message.FieldValue` (`intercept.go:191`) | 7: `host`, `path`, `extension`, `method`, `url`, `status_code`, `content_type` | 7 | no — `ParseField` default is an error (`intercept.go:87`); `FieldValue` default returns `""` but is total over the enum | clean |
| 6 | `intercept.Field.String` (`intercept.go:52`) | 7 enum values | 6 named + `default: "content_type"` | yes, but total over the declared enum today | clean; brittle if an 8th field is added |
| 7 | `web.directionFor` (`api_intercept.go:148`) | 2: `requests`, `responses` | 2 | no — returns `ok=false`, handler 404s (`api_intercept.go:203`) | clean |
| 8 | intercept held-message action (`api_intercept.go:260-288`) | 2: `forward`, `drop` | 2 | no — `default:` 404 "Unknown action" | clean |
| 9 | `web.matchReplaceTargetName` (`api_toolkit.go:695`) | 7 enum values | 7 | no — default emits a poison string `unrecognised_target_%d` | clean |
| 10 | `matchreplace.targetsDir` (`matchreplace.go:236`) | 7 enum values | 7 (5 request + 2 response) | n/a (boolean) | clean |
| 11 | `sessionExtractDto.extractFrom` (`api_session.go:56`) → `Extraction.RunResult` (`session.go:356`) | 2: `"body"`, `{"header": name}` | 2 | engine default is `ExtractInert` (a *reported* inert outcome, not a wrong action) and the wire parser errors first | clean |
| 12 | `sessionExtractDto.extractHow` (`api_session.go:97`) | 3: `"whole"`, `{regex:…}`, `{json_path:…}` | 3 (`whole` compiled to `(?s)^.*$`, `api_session.go:52`) | no — every other shape errors, incl. both-arms-stated | clean |
| 13 | `session.ValidateRule` extraction `from` (`validate.go:154`) | 2: `body`, `header` | 2 | no — `default:` refuses at save time | clean |
| 14 | `session/jsonpath.go` grammar (`jsonpath.go:146`, `:209`, `:293`, `:311`) | dotted keys + array indices | same | unsupported constructs refused at save time (`validate.go:172-186`) rather than compiled as a regex | clean |
| 15 | `session.ExtractOutcome.String` / `.Explanation` (`session.go:279`, `:300`) | 7 outcomes | 7 + `"unknown"` tail | display only | clean |
| 16 | `session.Extraction.runJSONPath` source switch (`session.go:404`) | 2: `body`, `header` | 2 | default is `ExtractInert` with a named detail | clean |
| 17 | `session.Coordinator.recover` (`recovery.go:369`) | 3 `LoginOutcomeKind` values | 3 | tail `return RecoveryGaveUp` — unreachable, total | clean |
| 18 | `web.loginOutcomeResponse` (`api_session.go:649`) | 7 `RecoveryOutcomeKind` values | 7 | no — unmapped kinds answer 500 `unmapped_outcome` | clean |
| 19 | `web.validityName` (`api_session.go:703`) | 3 `ValidityState` values | 2 named + `default: "indeterminate"` | total over the enum | clean |
| 20 | `netauth.ParseScheme` (`netauth.go:122`) → `Credentials.AuthorizationFor` (`digest.go:430`) | 2: `basic`, `digest` (NTLM/Negotiate/Kerberos get a *named* refusal, `netauth.go:129`) | 2 | no — `default: return "", false`, and `SupportedSchemes()`/`UnsupportedSchemes()` are served to the UI (`api_netauth.go:119-127`) so the panel cannot offer an unimplemented scheme | clean — best-in-repo example of this class done right |
| 21 | `netauth.newHash` (`digest.go:88`) | 4: `MD5` (incl. empty), `MD5-sess`, `SHA-256`, `SHA-256-sess` | 4 | no — `default:` errors rather than defaulting to MD5 | clean |
| 22 | `netauth` digest challenge param parse (`digest.go:176`, `:218`, `:262`) | server-supplied params | known params consumed, unknown ignored | ignoring unknown challenge params is RFC-correct, not a vocabulary miss | clean |
| 23 | `upstream.Parse` scheme (`upstream.go:112`) → `Proxy.DialContext` (`upstream.go:272`) | 6 spellings → 4 kinds (+ `""`/`direct`) — and `upstream.Schemes()` (`upstream.go:167`) returns exactly those 6, serving the UI's dropdown from the parser's own set (`api_network_proxy.go:119-120`) | 4 kinds + direct | no — `Parse` default errors naming the accepted schemes; `DialContext` default errors rather than falling back to a direct dial | clean |
| 24 | `proxy.OptionKey` / `KnownOption` (`options.go:68`, `:80`) → `Options.ApplyRequest`/`ApplyResponse` (`options.go:287`, `:322`) | 6 keys | 6 (5 response rules at `options.go:98-104` + `strip_accept_encoding` on the request side) | no — `PUT /api/proxy/options` validates **every** key before applying **any** (`api_proxyoptions.go:69-74`), and both apply paths are live (`proxy/proxy.go:1301,1317,1338`) | clean |

Not covered in the table: `upstream/upstreamtest/upstreamtest.go:266-289` (a SOCKS test server's
command switch — test-only fixture, not an API-reachable vocabulary); `upstream.socks4Reason`
(`upstream.go:494`, display-string only, default names the unrecognised code); `proxy/proxy.go:623`
(a `select` default, not a vocabulary switch).

## Provenance / honesty notes

- Prior docs were not used as sources. `BURP_FEATURE_INVENTORY_VS_BURPSY.md`, `gaps.md`,
  `ui-gaps.md` and `PORT_STATUS.md` were not consulted for any claim in this file; every denominator
  above was recounted from the source with the command shown.
- Every STATE 5 claim above except finding #2 was executed, not read. Finding #2 was verified by
  reading only, as scoped by the task (it was proven behaviourally in a prior pass); its six cited
  sites were re-read at `a619c9a` and match the description exactly.
- Scratch copies used: `/tmp/burpsy-scratch/session` (package copy, for the isolated unit proof) and
  `/tmp/burpsy-scratch/burpsy-go` (whole-module copy with `internal/web/ui/node_modules` excluded,
  for the handler-level proofs). Proof files: `zz_proof_test.go`, `zz_proof2_test.go`. Nothing under
  `burpsy-go/internal` was written.
- The six named packages are, on the whole, *unusually* well hardened against this bug class — most
  of them carry doc comments naming the exact failure mode and explaining why the default refuses.
  Findings #1, #3 and #4 are the places that hardening did not reach; #1 is a different shape from
  the rest (a config *shape* that admits more combinations than the evaluator implements, rather
  than a string→enum parser), which is likely why the parser-focused hardening pass missed it.
