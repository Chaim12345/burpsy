# BCheck DSL — grammar, corpus statistics, implementation order

Researched 2026-07-26. Everything below is **observed**, not inferred, unless tagged `INFERRED`.

**Sources**
1. `github.com/PortSwigger/BChecks` @ HEAD — **264 `.bcheck` files**.
2. `BCheckChecker-1.9.jar` (2024-04-25), shipped in that repo. It contains PortSwigger's **actual
   parser**, CongoCC/JavaCC-21-generated, with separate `v1beta` and `v2beta` packages — one class per
   grammar token and production. Decompiled with Vineflower; enums read with `javap`.
3. The same jar used as a **grammar oracle**: ~45 probe files run through the real validator to settle
   every construct the corpus doesn't exercise. Marked `PROBED`.

The parser references its own grammar source as `v2beta/BCheckAstParser.javacc` — not shipped, but
production names and token sets are recoverable in full.

---

## 0. Findings that change the plan

1. **The corpus is 78% v1-beta, not v2-beta.** 205 × `v1-beta`, 59 × `v2-beta`.
2. **v2-beta is a strict superset of v1-beta.** Token-set diff between the two parser packages is
   exactly 4 tokens, all additions: `AND_CONTINUE`, `ISSUE_NAME_HEADER`, `PATH_FREQ`, `QUERY_STRING`.
   Zero tokens are v1-only. **Implement the v2-beta grammar and you parse 100% of the corpus** —
   `language:` is a declaration, not a parser selector.
3. **Indentation and newlines are completely insignificant.** `PROBED`: a check with everything at
   column 0 parses; so does one with random indentation; so does the entire body on a single line.
   `end if` is the only block terminator. No offside rule — do not build one.
4. **`{{1337*1337}}` is not BCheck arithmetic.** It appears in 2 files, inside a *literal*
   (non-interpolating) `"…"` string. It is a Jinja/Twig SSTI **payload** sent verbatim; `answer =
   "1787569"` is the author's hand-computed expected output. `template-injection.bcheck` even carries
   the comment *"(The variables 'sum' and 'calc' need to be synchronized.)"*. **BCheck has no arithmetic
   operators at all.**
5. **Two string types, and this is the single most important lexical fact:** `"…"` is a **literal**
   string (no interpolation), `` `…` `` is an **interpolatable** string. Separate lexical states
   (`WithinLiteralString` / `WithinInterpolatableString`). 132/264 files use backticks.
6. **`inserting:` does not exist** (`PROBED`, rejected). Payload modifiers are `appending:` and
   `replacing:` only.

---

## 1. Grammar (v2-beta, EBNF)

Terminals in `UPPER`, literal spellings in `'quotes'`. Whitespace/newlines are insignificant
everywhere; `#` to end-of-line is a comment.

```ebnf
Start        ::= Metadata DefineBlock? RunForEachBlock? GivenBlock

Metadata     ::= 'metadata' ':' LanguageLevelField NameField MetadataField*
LanguageLevelField ::= 'language' ':' ( 'v1-beta' | 'v2-beta' )
NameField    ::= 'name' ':' StringLit
MetadataField::= 'description' ':' StringLit
               | 'author'      ':' StringLit
               | 'tags'        ':' StringLit ( ',' StringLit )*

DefineBlock  ::= 'define' ':' NonIterableVarDecl+
NonIterableVarDecl ::= VARIABLE_NAME '=' Value

RunForEachBlock ::= 'run for each' ':' IterableVarDecl+
IterableVarDecl ::= VARIABLE_NAME '=' Value ( ',' Value )*     (* check runs once per value *)

GivenBlock   ::= 'given' Frequency 'then' Statement+
Frequency    ::= 'host' | 'path' | 'request' | 'response'
               | InsertionPointTypes? 'insertion point'
InsertionPointTypes ::= IPType ( 'or' IPType )*
IPType       ::= 'any' | 'query' | 'header' | 'body' | 'cookie'

Statement    ::= IfBlock | SendRequest | SendPayload | ReportIssue

IfBlock      ::= 'if' BoolExpr 'then' Statement+ ElseBlock? 'end if'
ElseBlock    ::= 'else' ( IfBlock                       (* else if … then … ; no own 'end if' *)
                        | 'then' Statement+ )           (* bare else REQUIRES 'then' *)

SendRequest  ::= 'send request' ( 'called' REQUEST_NAME )? ':'
                 ( RequestModifier+ | INTERPOLATABLE_STRING )   (* raw request as backtick string *)
RequestModifier ::= 'removing'  RemovePart
                  | 'appending' PartAssignment
                  | 'replacing'? PartAssignment                 (* 'replacing' is OPTIONAL *)
RemovePart   ::= ( 'body' | 'method' | 'path' | 'query_string' )        (* whole part, no value *)
               | ( 'headers' | 'queries' ) ':' StringLit ( ',' StringLit )*   (* by key *)
PartAssignment ::= ( 'method' | 'path' | 'body' | 'query_string' ) ':' Value
                 | ( 'headers' | 'queries' ) ':' KeyValue ( ',' KeyValue )*
KeyValue     ::= Value ':' Value

SendPayload  ::= 'send payload' ( 'called' REQUEST_NAME )? ':'
                 ( 'appending' | 'replacing' ) ':' Value

ReportIssue  ::= 'report issue' 'and continue'? ':'
                 IssueNameField?                                  (* spelled 'name:', must be 1st *)
                 ( SeverityField ConfidenceField                  (* both required, either order *)
                 | ConfidenceField SeverityField )
                 DetailField? RemediationField?                   (* both optional *)
IssueNameField ::= 'name' ':' Value
SeverityField  ::= 'severity'   ':' ( 'high' | 'medium' | 'low' | 'info' )
ConfidenceField::= 'confidence' ':' ( 'certain' | 'firm' | 'tentative' )
DetailField    ::= 'detail'      ':' Value
RemediationField ::= 'remediation' ':' Value

BoolExpr     ::= BoolTerm ( ( 'and' | 'or' ) BoolTerm )*
BoolTerm     ::= 'not' '(' BoolExpr ')' | '(' BoolExpr ')' | BoolAtom
BoolAtom     ::= Value 'matches' StringLit          (* regex; RHS is a literal string *)
               | Value ( 'in' | 'is' | 'differs from' ) Value
               | InteractionType 'interactions'     (* Collaborator poll *)
InteractionType ::= 'any' | 'dns' | 'http' | 'smtp'

Value        ::= VariableRef | StringLit
StringLit    ::= '"' … '"'        (* literal, NO interpolation *)
               | '`' … '`'        (* interpolatable: {…} expanded, \{ escapes a brace *)
VariableRef  ::= '{' ( VARIABLE_NAME | ObjectPath | FunctionCall ) '}'
```

`PROBED` details behind the above:
- `else` alone is rejected; `else then` and `else if … then` both parse. `else if` does **not** take
  its own `end if`.
- `report issue` fields are order-independent apart from `name:`; `detail:`/`remediation:` are
  optional; severity **and** confidence are both mandatory.
- The issue-name field's token is internally `ISSUE_NAME_HEADER` but is spelled **`name:`** —
  `issue name:` / `issue_name:` / `issuename:` are all rejected.
- The modifiable part is spelled **`query_string`** (underscore); `query string`, `query-string`,
  `querystring` are all rejected.
- `headers:` takes **key/value pairs** (`headers: "X-A": "1", "X-B": "2"`); a bare
  `headers: "X-A: 1"` is rejected. `queries:` accepts a plain list.

### v1-beta vs v2-beta

Token-set diff of the two parser packages (v1 = 102 tokens, v2 = 106):

| v2-only token | Surface syntax | Corpus |
|---|---|---|
| `PATH_FREQ` | `given path then` | 11 files, all v2 |
| `AND_CONTINUE` | `report issue and continue:` | 11 files, all v2 |
| `ISSUE_NAME_HEADER` | `name:` inside `report issue` | **0 files** |
| `QUERY_STRING` | `query_string` request part | **0 files** |

Nothing is v1-only; v1's `Frequency` enum is simply `PER_HOST, PER_REQUEST, PER_RESPONSE,
PER_INSERTION_POINT` (no `PER_PATH`). `PROBED`: `given path then` and `report issue and continue:`
under `language: v1-beta` are both rejected by the validator, so if you want to be strict, gate those
two productions on the declared version. Otherwise parse everything as v2.

---

## 2. `given` inventory and scope mapping

Authoritative enum `GivenBlock$Frequency` = `PER_HOST, PER_REQUEST, PER_RESPONSE,
PER_INSERTION_POINT, PER_PATH`. That is the complete set — `PROBED`: `given url then`,
`given query then`, `given header then` are all **rejected**. There is no `given query`/`given header`
form; those words only exist as *insertion-point type* qualifiers.

| BCheck form | Frequency enum | Your dispatch scope | Files | % |
|---|---|---|---|---|
| `given response then` | `PER_RESPONSE` | **passive scanner** (per response) — not one of the 7 | 105 | 39.8% |
| `given host then` | `PER_HOST` | `perHost` | 99 | 37.5% |
| `given request then` | `PER_REQUEST` | `perRequest` | 40 | 15.2% |
| `given path then` | `PER_PATH` | `perPath` | 11 | 4.2% |
| `given [T or T…] insertion point then` | `PER_INSERTION_POINT` | `perInsertionPoint` | 9 | 3.4% |

Insertion-point qualifiers (`GivenBlock$InsertionPointType` = `ANY, QUERY, HEADER, BODY, COOKIE`).
All `PROBED` as accepted, singly and `or`-chained:
`given insertion point`, `given any insertion point`, `given query insertion point`,
`given header insertion point`, `given body insertion point`, `given cookie insertion point`,
`given query or body insertion point`, `given query or header or cookie insertion point`.
Bare `given insertion point` ≡ `any`.

**Three of your seven scopes have no BCheck syntax**: `perUrl`, `inSessionPerRequest`,
`storedPerInsertionPoint`. Those are Burp-internal dispatch modes; nothing in the DSL can target them,
so they are dead weight for the interpreter (keep them for your own native checks).

Exactly one `given` block per file across all 264 files — the grammar allows only one.

---

## 3. Statement / expression reference

### `send request`
```
send request called check:          # 'called <name>' optional; name binds {check.request}/{check.response}
    method: "GET"                   #   bare part: == 'replacing'
    path: "/admin"
    replacing path: "/admin"        #   explicit form, identical
    appending queries: "a": "1"
    removing headers: "Referer"
    removing body                   #   whole-part removal, no colon/value
    body: "hello"
    query_string: "a=1&b=2"
send request:                       # raw-request form: one interpolatable string
    `GET /admin HTTP/1.1
Host: {base.request.url.host}

`
```
Both forms `PROBED` OK. Parts: `method`, `path`, `body`, `query_string` (scalar) /
`headers`, `queries` (key-value lists).

### `send payload`
```
send payload:                       # 'called <name>' also allowed (PROBED)
    appending: {calculation}
    replacing: {injections}
```
Only valid under a `given … insertion point` block. `inserting:` and `removing:` are **not** payload
modifiers (`PROBED`, both rejected).

### `report issue`
```
report issue and continue:          # 'and continue' = keep scanning after reporting (v2)
    name: "Custom title"            # v2, optional, must be first (spelled 'name', not 'issue name')
    severity: high|medium|low|info
    confidence: certain|firm|tentative
    detail: "…" | `…` | {var}
    remediation: "…"
```
Severity/confidence values from `IssueSeverityField$Severity` and `IssueConfidenceField$Confidence`.
Corpus usage (by file): severity `info` 118, `high` 111, `low` 67, `medium` (mostly one giant file);
confidence `certain`, `tentative`, `firm` all common.

### Operators

| Operator | Semantics | Files | % |
|---|---|---|---|
| `matches` | regex, RHS is a **literal** string | 140 | 53.0% |
| `in` | substring / containment | 131 | 49.6% |
| `is` | exact equality | 101 | 38.3% |
| `differs from` | **object** inequality — compares whole named request/response pairs, e.g. `{garbage} differs from {check}` | 2 | 0.8% |
| `and` / `or` / `not(…)` | boolean; `(…)` groups | 145 | 54.9% |
| `<type> interactions` | Collaborator poll: `any`/`dns`/`http`/`smtp` | 26 | 9.8% |

No `!=`, no `>`/`<`, no arithmetic. Regex flavour is Java's (`\w`, `\s`, `\d`, backreference `$1` in
`regex_replace`) — `INFERRED` from the payload strings; the DSL just hands the pattern to Java.

---

## 4. Variables, interpolation, functions

`{…}` is a variable reference. Inside `` `…` `` it interpolates; inside `"…"` it is literal text.

**Object namespace** — `{<obj>.<part>[.<prop>]}`:

| Object | Meaning |
|---|---|
| `base` | the request/response the check was dispatched on |
| `latest` | the most recent request/response the check issued |
| `<name>` | a request named via `send request called <name>` / `send payload called <name>` |

| Path | Corpus hits |
|---|---|
| `{latest.response}` | 1712 |
| `.response.body` | 335 |
| `.response.headers` | 155 |
| `.response.status_code` | 147 |
| `.request.url` / `.response.url` | 30 |
| `.url.host` / `.url.path` / `.url.file` / `.url.port` / `.url.query` | 22 / 12 / 3 / 2 / 1 |
| `.request.method` | 9 |

A bare `{latest.response}` or `{base.response}` (no property) is the whole message — that is the
common form for `matches`/`in`. 330 distinct `{…}` names across the corpus.

**Built-in functions** (token list is exhaustive — these 9 are all that exist):

| Function | Files | Notes |
|---|---|---|
| `generate_collaborator_address()` | 27 | needs an interaction server |
| `random_str(n)` | 19 | |
| `regex_replace(subject, pattern, replacement)` | 17 | 3-arg; `$1` backrefs |
| `to_lower(s)` / `to_upper(s)` | 4 | |
| `base64_encode(s)` / `base64_decode(s)` | 2 | |
| `md5(s)` / `sha1(s)` / `sha256(s)` | **0** | in grammar, unused by corpus |

There is **no `urlencode`** — 0 occurrences, and no such token exists. Calls nest inside interpolation:
`` `{prefix}{regex_replace({payload}, "__calc__", {calc})}{suffix}` ``.

**Typing.** `define:` values are untyped strings (a `Value`: literal string, interpolatable string, or
variable ref). `run for each:` declares an *iterable* — the whole check body re-runs once per element:
```
run for each:
    extension = ".bak", ".back", ".backup", ".old"
```
This is used by **30.7% of files** and is the single most under-appreciated construct: skip it and you
lose a third of the corpus. `INFERRED`: multiple iterables in one block are a cartesian product — the
grammar allows several `IterableVarDecl`s but no corpus file uses more than one.

**Escaping.** In backtick strings, `\{` escapes a brace; `\"`, `\\`, `\/` also observed.

---

## 5. Corpus statistics

264 files. **Use the file-count column, not occurrence counts** — two secret-scanning files
(`other/tokens/Certain-leaks-checker.bcheck` with 881 `report issue` blocks and
`Tentative-leaks-checker.bcheck` with 726) distort every raw total by ~10×.

| Feature | Files | % |
|---|---|---|
| `metadata:` | 264 | 100.0% |
| `report issue` | 263 | 99.6% |
| `if … then / end if` | 214 | 81.1% |
| `send request` | 149 | 56.4% |
| `bool and/or/not` | 145 | 54.9% |
| `matches` (regex) | 140 | 53.0% |
| interpolatable `` `…` `` | 132 | 50.0% |
| `in` | 131 | 49.6% |
| `is` | 101 | 38.3% |
| `define:` | 87 | 33.0% |
| **`run for each:`** | **81** | **30.7%** |
| `# comments` | 61 | 23.1% |
| `generate_collaborator_address` / `interactions` | 27 | 10.2% |
| `random_str` | 19 | 7.2% |
| `regex_replace` | 17 | 6.4% |
| `else if` / `else` | 13 | 4.9% |
| `report issue and continue` | 11 | 4.2% |
| `send payload` | 9 | 3.4% |
| `to_lower`/`to_upper` | 4 | 1.5% |
| `base64_*` | 2 | 0.8% |
| `differs from` | 2 | 0.8% |
| `md5`/`sha1`/`sha256` | 0 | 0.0% |
| `name:` in report issue | 0 | 0.0% |
| `query_string` part | 0 | 0.0% |

---

## 6. Collaborator dependency

**27 / 264 files = 10.2%** need out-of-band interaction — either `generate_collaborator_address()`
(27 files) or an `<x> interactions` condition (26 files); the two nearly always co-occur.

**Excluding them caps a no-Collaborator milestone at 89.8% of the corpus.** That is a cheap 90%.
Interaction types to support later: `any`, `dns`, `http`, `smtp`.

---

## 7. Ranked implementation order

Cumulative "% of corpus files where *every* construct used is implemented". Each row adds one feature.

| # | Add | Files runnable | Cum % |
|---|---|---|---|
| 1–7 | `metadata` + `given response` + `if/end if` + `report issue` + `in` + `is` + `and/or/not` | 5 | 1.9% |
| **8** | **`matches` (regex)** | **88** | **33.3%** |
| 9 | interpolatable `` `…` `` strings | 90 | 34.1% |
| 10 | `define:` | 97 | 36.7% |
| 11 | `send request` (+ named requests) | 97 | 36.7% |
| **12** | **`given host`** | **128** | **48.5%** |
| 13 | `given request` | 137 | 51.9% |
| **14** | **`run for each:`** | **192** | **72.7%** |
| 15 | `random_str()` | 195 | 73.9% |
| 16 | `and continue` | 202 | 76.5% |
| 17 | `given path` | 207 | 78.4% |
| 18 | `else if` / `else then` | 213 | 80.7% |
| 19 | `send payload` | 213 | 80.7% |
| 20 | `given … insertion point` | 216 | 81.8% |
| 21 | `regex_replace()` | 231 | 87.5% |
| 22 | `differs from` | 232 | 87.9% |
| 23 | `base64_encode/decode()` | 233 | 88.3% |
| 24 | `to_lower/to_upper()` | 237 | **89.8%** ← no-Collaborator ceiling |
| 25 | `md5/sha1/sha256()` | 237 | 89.8% (0 corpus users) |
| 26 | Collaborator + `interactions` | 264 | 100.0% |

Read it as three milestones:

- **M1 — passive engine, 33% of corpus.** `metadata` + `given response` + `if/end if` +
  `report issue` + `in`/`is`/`matches` + booleans. No HTTP sending at all. Note the discontinuity at
  row 8: `matches` alone takes you from 1.9% → 33.3%, because the 80-file `other/tokens` secret-scanner
  set is pure passive regex. **Implement the regex operator early.**
- **M2 — active engine, 81%.** Add backtick interpolation, `define:`, `send request` with named
  requests, `given host`/`request`/`path`, **`run for each:`** (+13 points on its own, the biggest
  single jump after `matches`), `random_str`, `and continue`, `else`.
- **M3 — 89.8%.** Insertion points + `send payload` + `regex_replace` + `differs from` + base64 +
  case functions. Everything left is Collaborator.

Parser notes that fall out of this:
- No offside rule, no significant newlines — a flat token-stream recursive-descent parser is correct
  and simple.
- `"…"` vs `` `…` `` must be distinct token types from the lexer, with interpolation only scanned
  inside the latter.
- `differs from` compares *objects* (`{garbage} differs from {check}`), so your value model needs a
  request/response handle type, not just strings — but at 0.8% of the corpus, defer it.
- Skip `perUrl`, `inSessionPerRequest`, `storedPerInsertionPoint` in the BCheck dispatcher; no DSL
  syntax reaches them.

---

## 8. Parser test fixtures

### F1 — minimal passive (`other/tokens/nuget-api-key.bcheck`, v1-beta)
```
metadata:
  language: v1-beta
  name: "NuGet API Key"
  description: "Looks for NuGet API keys in page source."
  author: "@puzzlepeaches"
  tags: "nuget", "token", "exposure" 

given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
          remediation: "Review and remove unnecessary exposure of keys and/or sensitive data from page source."
  end if
```
Exercises: metadata w/ tags list, `given response`, `matches`, whole-message `{latest.response}`,
`report issue`, 2-space indent. Note the regex contains `{43}` — **braces inside a literal string must
not be treated as interpolation.** Good negative test.

### F2 — active, named request, `define`, boolean chain (`CVE_2022_0150…`, v1-beta)
```
metadata:
	language: v1-beta
	name: "CVE-2022-0150 WordPress Accessibility Helper <0.6.0.7 - Cross-Site Scripting"
	author: "Parimal Shaw"
	description: "Check for CVE-2022-0150."
	tags: "CVE-2022-0150"

define:
    potential_path = "/?wahi=JzthbGVydChkb2N1bWVudC5kb21haW4pOy8v"

given host then
    send request called check:
		method: "GET"
		path: {potential_path}

			if {check.response.status_code} is "200" and "var wah_target_src = '';alert(document.domain);//';" in {check.response.body} and "text/html" in {check.response.headers} then
					report issue:
						severity: medium
						confidence: certain
						detail: "WordPress Accessibility Helper plugin before 0.6.0.7 contains a cross-site scripting vulnerability."
						remediation: "Upgrade to Latest Version."
			end if
```
Exercises: `define:`, `given host`, `send request called`, bare-`replacing` parts, `{name.response.*}`,
3-way `and`, **tabs + wildly inconsistent indentation that must still parse**.

### F3 — `run for each`, v2 features, functions, object comparison (`examples/exposed-backup-file.bcheck`, v2-beta)
```
metadata:
    language: v2-beta
    name: "Path-level"
    description: "Tests for exposed backup files"
    author: "Carlos Montoya"

run for each:
    # you could add more values to this list to make the check repeat
    extension = ".bak", ".back", ".backup", ".old"

given path then
    if not({base.response.status_code} is "404") then
        send request called check:
            replacing path: {regex_replace({base.response.url.path}, "(.)/?$", `$1{extension}`)}

        if {check.response.status_code} is {base.response.status_code} then
            send request called garbage:
                replacing path: {regex_replace({base.response.url.path}, "(.)/?$", `$1.{random_str(10)}`)}

            if {garbage} differs from {check} then
                report issue and continue:
                    severity: info
                    confidence: firm
                    detail: `Backup file found at {check.request.url}`
                    remediation: "Ensure your backup files are not exposed."
            end if
        end if
    end if
```
Exercises: `run for each` + comment inside it, `given path` (v2), `not(…)`, nested `if`, explicit
`replacing path:`, nested function calls, backtick interpolation as a function argument,
`differs from` on whole objects, `report issue and continue` (v2), `{name.request.url}`.

### F4 — insertion points, payloads, Collaborator (`SSRFInjection.bcheck`, v1-beta)
```
metadata:
    language: v1-beta
    name: "SSRF in each insetpoint"
    description: "Insert an Collaborator address into each parameter to detect SSRF"
    author: "xelkomy"

define:
    ssrfaddress=`{generate_collaborator_address()}`

# we will automatically insert into nested insertion points
given insertion point then
    send payload:
        appending: {ssrfaddress}
		
	if http interactions then
        report issue:
            severity: high
            confidence: firm
            detail: "SSRF Discovery by BCheck"
            remediation: "Implement SSRF remediation measures."
    end if
```
Exercises: `define` with no spaces around `=`, `given insertion point`, `send payload: appending:`,
`http interactions`, and again mixed tab/space indentation.

### F5 — negative fixtures (all `PROBED` as **rejected** by the official validator)
```
else                       # bare else without 'then'
issue name: "N"            # correct spelling is  name:
query string: "a=1"        # correct spelling is  query_string:
inserting: "x"             # not a payload modifier
removing: "x"              # under send payload
headers: "X-A: 1"          # headers need key:value pairs
given url then             # no such frequency
given query then           # 'query' is only an insertion-point qualifier
given path then            # under language: v1-beta
report issue and continue: # under language: v1-beta
```

---

## 9. Reproduce

```bash
git clone --depth 1 https://github.com/PortSwigger/BChecks /tmp/BChecks
cd /tmp/BChecks && java -jar BCheckChecker-1.9.jar     # validates every .bcheck under cwd
```
Drop probe files into a directory and run the jar there — it recurses and reports
`BCheckParseException{encounteredString=…, lineNo=…, colNo=…}`. That is the cheapest possible
conformance oracle for our parser: run both over the corpus and diff accept/reject.
