# W2 — Can burpsy's scanner actually fire?

## BASELINE

Measured against burpsy commit:

```
$ git rev-parse HEAD
638c48005c9b4998ead63de2822bb176aa591147   (short: 638c480)
$ git log --oneline -1
638c480 logger: two-axis tool filters, and the matchreplace refusal they surfaced
$ git status --short --branch
## orchestry/tsk_KBUxW7m/auto-cto-burp-parity-gap-analysis-measur
(clean — no modified/staged files in this worktree)
```

The shared checkout at `/root/burpsy-react-ui` is at the same SHA (`638c480`) but has an
untracked file `?? burpsy-go/internal/web/ui/design/css-patterns.css` from another agent.
All citations below are read via `git show 638c480:<path>` or from this clean worktree.

Reference corpus: `/root/burp-re` (Burp Suite 2026.7.1 teardown).

Status: COMPLETE.

---

## 1. The active-check inventory

### 1.1 burpsy's numerator: 183 registered descriptors, 58 admitted by default

burpsy's check registry is `NativeCheckRegistry()`
(`burpsy-go/internal/scanner/check_registry.go:13-46`). It is **not** the advisory catalogue —
it is a separate list of `CheckDescriptor` rows, each of which carries a `Run CheckRunner`
(`check_contract.go:71-81`) and an `Enabled func(*ScanConfig) bool` gate.

The registry has a purpose-built honesty mechanism: `ImplementationDeclined`
(`check_contract.go:20`) exists so a catalogue row with no evaluator is *declared* rather than
silently absent, and `CheckDescriptor.Runnable()` (`check_contract.go:83-85`) returns false for
those rows. **At `638c480` that list is empty** — `DeclinedCatalogDescriptors()` returns
`[]CheckDescriptor{}` (`check_registry_declined.go:26-28`), with the file comment stating
"all 183 catalog rows have evaluators."

Recounted by executing the registry (see DENOMINATORS §D1):

```
W2:TOTAL_DESCRIPTORS=183
W2:RUNNABLE=183
W2:DECLINED=0
W2:IMPL native=183
W2:RUNNABLE_PHASE active=183
W2:CATALOG=183
```

So the claim "183 advisories bundled" and "183 checks registered" happen to be the same
number here — but they are different facts and both were measured separately. Every one of
the 183 registry rows has a non-nil `Run`. **That is a real numerator, not the advisory
count.**

### 1.2 The number a user actually gets is 58, not 183

Every descriptor is gated by an `Enabled(*ScanConfig)` predicate, and `ScanConfig` carries
**21 family switches**, most documented in-source as "Off by default like every other
per-family switch" (e.g. `scanner.go:153,157,161,167,172,178,182,187`).

The default config the server's scanner is constructed with is the literal in
`NewActiveScanner` (`scanner.go:230-246`): **8 of the 21 switches are on**
(`CheckSqli`, `CheckXss`, `CheckPathTraversal`, `CheckSSRF`, `CheckHeaders`,
`CheckPassivePosture`, `CheckPassiveAnalysis`, `CheckHostDiscovery`). `CheckXXE` is
explicitly `false`; the other 12 are zero-valued.

Evaluating each descriptor's `Enabled` predicate against that exact literal:

```
W2E:REGISTRY=183
W2E:ENABLED_DEFAULT=58
W2E:ENABLED_ALLON=183
W2E:NIL_PREDICATE=0
```

**58/183 checks are admitted by a burpsy scan at shipped defaults.** The other 125 require
the operator to flip a family switch through `PUT /api/scanner/config`
(`internal/web/api_scanner_config.go:79-104` lists the 21 writable bool keys).

This is a *documented, deliberate* default, not a defect — TAXONOMY rule 7. But any statement
of the form "burpsy implements 183 checks" is describing the registry, not a scan.

### 1.3 The honest Burp-side denominator

**NOT DETERMINED as a check count.** What *is* determined:

- Burp's own scan-config vocabulary exposes check selection as `scanner.issues_reported`
  (12 keys) — a family-group selector, not one key per check. It is not a check inventory.
- burpsy's 183 TypeIndex values are recovered *from Burp's own advisory catalogue*, so the
  183 is Burp's issue-type cardinality, not burpsy's invention.

Burp does not publish a per-check count in its shipped resources in a form I could recount,
so **I refuse to state an "N of M checks" ratio for the check inventory.** The defensible
statement is the TypeIndex one: burpsy declares an evaluator for 183/183 catalogue TypeIndex
values, and admits 58/183 of them at shipped defaults.

---

## 2. Insertion points — WHERE burpsy actually injects

### 2.1 The Burp denominator, recounted

`scanner.insertion_point_types` carries exactly **8** leaf keys. Recounted from Burp's own
shipped configs (see DENOMINATORS §D2):

```
scanner/insertion_point_types/insert_body_params
scanner/insertion_point_types/insert_cookies
scanner/insertion_point_types/insert_entire_body
scanner/insertion_point_types/insert_http_headers
scanner/insertion_point_types/insert_param_name
scanner/insertion_point_types/insert_url_params
scanner/insertion_point_types/insert_url_path_filename
scanner/insertion_point_types/insert_url_path_folders
```

Burp additionally carries `scanner.modifying_parameter_locations` with **6** keys
(`body_to_cookie`, `body_to_url`, `cookie_to_body`, `cookie_to_url`, `url_to_body`,
`url_to_cookie`) — a second axis of the same surface. There is no separate JSON or XML key:
Burp handles those as *nested* points inside an already-enumerated parameter.

### 2.2 burpsy's enumerator implements 15 kinds — the scanner requests 4

`internal/bcheck/insertion.go:73-105` defines **15** `IpKind` constants covering all 8
Burp insertion-point types plus all 6 relocations plus `synthetic_header`. `EnumerateWithLimit`
(`insertion.go:299-579`) has a real construction branch for every one of them, and
`expandNested` gives nested JSON/base64/XML expansion (`insertion.go:566`). The library is
genuinely complete.

**The scanner never asks for 11 of them.**

`DefaultProbeInsertionKinds = []string{"query", "body", "cookie", "header"}`
(`internal/scanner/probe_harness.go:40`). That value is what 18 of the 21 non-test
`NewProbeHarness`/`runInjection` call sites pass, and it is also what the audit-item ledger
enumerates with (`internal/scanner/audit_engine.go:849`). The three exceptions:

| Call site | kinds requested | gate |
|---|---|---|
| `checks_core_injection.go:52` `coreInjectionKinds` | `query, body, cookie` | SQLi / XSS / traversal (**default ON**) |
| `checks_remaining.go:399` `checkXXE` | `entire_body, body, query` | `CheckExtendedActive` (**default OFF**, `checks_remaining.go:45`) |
| `checks_remaining.go:424` `checkXMLEntityExpansion` | `entire_body, body` | `CheckExtendedActive` (**default OFF**) |
| `checks_remaining.go:190`, `checks_final.go:114,181` | `header` / `header, cookie` | `CheckExtendedActive` |
| `checks_reflection2.go:178,357` | `query, body` | `CheckReflectionProbes` (default OFF) |

BCheck-corpus checks are narrower still: `given insertion point any` resolves through
`dslAddressable` (`insertion.go:594-600`) to exactly `query, body, cookie, header`.

### 2.3 Mapping to Burp's 8 keys

| Burp key | burpsy `IpKind` exists? | scanner requests it? |
|---|---|---|
| `insert_url_params` | yes (`IpQuery`) | **YES** — default |
| `insert_body_params` | yes (`IpBody`) | **YES** — default |
| `insert_cookies` | yes (`IpCookie`) | **YES** — default |
| `insert_http_headers` (existing headers) | yes (`IpHeader`) | **YES** — default |
| `insert_http_headers` (synthesised Referer/User-Agent) | yes (`IpSyntheticHeader`) | **NO** — zero production callers |
| `insert_entire_body` | yes (`IpEntireBody`) | only behind `CheckExtendedActive` (default OFF) |
| `insert_param_name` | yes (`IpParamNameURL`, `IpParamNameBody`) | **NO** — zero production callers |
| `insert_url_path_filename` | yes (`IpURLPathFilename`) | **NO** — zero production callers |
| `insert_url_path_folders` | yes (`IpURLPathFolder`) | **NO** — zero production callers |
| all 6 `modifying_parameter_locations` | yes (6 `IpRelocate*`) | **NO** — zero production callers |

**Two different numbers, and the difference is §5.3's defect:**

- **Kinds the audit ledger *enumerates* at defaults: 4** — `query, body, cookie, header`
  (`audit_engine.go:849`).
- **Kinds a payload is actually *placed* in at defaults: 3** — `query, body, cookie`, because
  the only insertion-point checks admitted at defaults walk `coreInjectionKinds`
  (`checks_core_injection.go:52`). Behaviourally proven in §5.3: across five audits, not one
  probe modified a header.
- **With all 21 switches on: 5** — the above plus `header` and `entire_body`.

So: **3 of Burp's 8 insertion-point types at shipped defaults, 5 of 8 with everything enabled,
and 0 of 6 parameter-relocation types, ever.**

Grep evidence, with the positive control TAXONOMY rule 3 demands (see DENOMINATORS §D3): a
literal-string count over `internal/scanner internal/web internal/extscan cmd` excluding
`_test.go` returns `query:13 body:16 cookie:10 header:15 entire_body:2` and **0 for all
eleven** of `param_name_url, param_name_body, url_path_filename, url_path_folder,
synthetic_header, relocate_*` (six). The positive control: the same grep widened to the whole
tree *does* find every one of those eleven strings — in `internal/bcheck/insertion.go`
(the definitions), `internal/bcheck/insertion_test.go` (tests that exercise them), and
`internal/intruder/points.go`. So the zeros are real absences of a scanner caller, not a
mistyped pattern.

### 2.4 Behavioural proof (STATE 2 for the 11 unused kinds)

A live scan's own audit-item ledger reports the kinds it enumerated. From the run in §4:

```
$ curl -s http://127.0.0.1:18481/api/scanner/audit-items
  "point_kinds": ["query","body","cookie","header"],
  "points": [
     {"kind":"query","name":"q","status":"Audited"},
     {"kind":"query","name":"id","status":"Audited"},
     {"kind":"header","name":"User-Agent","status":"Audited"},
     {"kind":"header","name":"Accept","status":"Audited"},
     {"kind":"header","name":"Proxy-Connection","status":"Audited"}
  ],
  "max_insertion_points_per_request": 30
```

The request was `GET /search?q=hello&id=1`. `/search` is a URL-path filename and `search` a
folder segment; neither appears as a point. That is `IpURLPathFilename` / `IpURLPathFolder`
in **STATE 2 — real implementation, zero non-test callers.**

### 2.5 The contrast worth recording

`internal/intruder/points.go:21-33` defines its own 9-kind `PointKind` enum whose comment
says it "Maps 1:1 onto Burp's insertion_point_types" — and it *does* include
`url_path_folder`, `url_path_filename`, `url_param_name`, `body_param_name` and
`entire_body`. **burpsy's Intruder covers Burp's insertion-point surface; burpsy's Scanner
does not**, despite the Scanner's own `bcheck` library implementing every kind. Two
enumerators, one wired wide and one wired narrow.

---

## 3. Passive vs active — what actually fires, and from where

burpsy has **three separate finding sources**, and they behave differently. This matters more
than the check count.

### 3.1 Source A — the legacy `PassiveScanner`, 5 hardcoded checks, auto-fires on proxy traffic

`internal/scanner/scanner.go:669-691` `PassiveScanner.Scan` runs three hardcoded analysers —
`checkSecurityHeaders` (`:693`), `checkInfoDisclosure` (`:755`), `checkCookieSecurity` (`:789`).
Its only production caller is `internal/scanner/capture.go:298`, on the proxy capture path, so
it fires on **every proxied response with no user action.**

It raises 5 issue names that are **not catalogue rows**:
`Missing X-Frame-Options Header`, `Missing X-Content-Type-Options Header`,
`Missing Content-Security-Policy Header`, `Cookie Missing HttpOnly Flag`,
`Cookie Missing SameSite Flag`.

**Mutual exclusion worth knowing:** `Scan` opens with
`if s.coverage != nil { return s.scanBChecks(exchange) }` (`scanner.go:670-672`). Loading a
BCheck corpus with `-bchecks` therefore **silently switches these 5 built-in checks off** — it
is an either/or, not an addition.

### 3.2 Source B — the BCheck corpus (only with `-bchecks`)

`internal/scanner/passive.go:172` `scanBChecks`. Not exercised in my run (no corpus flag), so
NOT DETERMINED here beyond the branch structure above.

### 3.3 Source C — the catalogue registry, which fires only on an explicit audit

The 183-row registry runs through the audit engine, reached by `POST /api/audit/{id}` or
`POST /api/scanner/live`. **Nothing dispatches it from the proxy capture path.**

Decomposing the 58 default-admitted checks by which switch admits them (see DENOMINATORS §D4):

```
W2F:CheckSqli=1              W2F:CheckPassivePosture=15
W2F:CheckXss=1               W2F:CheckPassiveAnalysis=29
W2F:CheckPathTraversal=1     W2F:CheckHostDiscovery=5
W2F:CheckSSRF=0              W2F:CheckHeaders=6
W2F:UNION_DEFAULT_ON=58
```

So of the 58:

| Kind | Count | Names / behaviour |
|---|---|---|
| **Genuine active injection** (sends crafted payloads, differential classifier) | **3** | `SQL injection`, `Cross-site scripting (reflected)`, `File path traversal` |
| **Active fetch / discovery** (sends requests to *other* URLs, no payload placement) | **5** | `OpenAPI definition found`, `Robots.txt file`, `GraphQL endpoint discovered`, `HTTP PUT method is enabled`, `HTTP TRACE method is enabled` |
| **Network-free response analysis** (no request sent; "passive" work done during an active audit) | **50** | 6 `CheckHeaders` (CORS ×3, CSP ×2, duplicate cookies) + 15 `CheckPassivePosture` + 29 `CheckPassiveAnalysis` |

`CheckSSRF` admits **zero** checks on its own — its single row is additionally gated behind
`CheckExtendedActive`, documented at `scanner.go:120-125`. A user who turns SSRF on and nothing
else gets nothing. That is *documented*, so a capability gap under TAXONOMY rule 7, but it is a
default-ON switch that admits nothing, which is worth a UI note it does not have.

### 3.4 The consequence: burpsy's "passive scanning" is not passive

**50 of the 58 default-admitted checks are network-free response analysis that Burp would run
automatically on proxied traffic — and burpsy only runs them when the user launches an audit
on that specific exchange.** Proven in §4 below: proxying one request yields 5 findings
(source A only); the same exchange after `POST /api/audit/0` yields 15.

This is the single largest behavioural divergence I found. It is not a broken check; it is a
dispatch-model difference that means a burpsy user browsing a site through the proxy sees 5
issue types where a Burp user sees the full passive set.

---

## 4. End-to-end: does a scan launched the way a user launches it emit findings?

### Setup (all commands reproducible)

Read-only per TAXONOMY rule 8: the tree was copied to `/tmp/w2-burpsy-go` and the binary built
there. **No production file was modified.**

```
cp -a <worktree>/burpsy-go /tmp/w2-burpsy-go
cd /tmp/w2-burpsy-go && go build -o /tmp/w2-burpsy ./cmd/burpsy    # go1.26.2, clean build
python3 /tmp/w2run/target2.py 18470        # deliberately vulnerable origin, logs every request
/tmp/w2-burpsy --proxy 127.0.0.1:18480 --web 127.0.0.1:18481
```

The target reflects `q` unescaped (XSS), emits a MySQL error string when `id` contains a quote
(SQLi), sets `Set-Cookie: sessid=abc123; Path=/` with no flags, and serves a password form.

### 4.1 Path A — proxy only, no scan launched — **STATE 4**

```
$ curl -x http://127.0.0.1:18480 "http://127.0.0.1:18470/search?q=hello&id=1"
$ curl -s http://127.0.0.1:18481/api/issues | jq '.counted'
5
 - Low           | Missing X-Frame-Options Header
 - Low           | Missing X-Content-Type-Options Header
 - Informational | Missing Content-Security-Policy Header
 - Low           | Cookie Missing HttpOnly Flag
 - Low           | Cookie Missing SameSite Flag
```

Five findings, all from the legacy `PassiveScanner` (§3.1). **Zero catalogue checks fired.**

### 4.2 Path B — `POST /api/audit/{id}` (UI: right-click an exchange → "Audit exchange #N") — **STATE 4**

UI path confirmed: `lib/actions.ts:403` registers
`{ id: "audit", label: "Audit exchange #${exchange.id}", onSelect: () => void auditExchange(exchange) }`
in the `scope-scan` action group; `auditExchange` (`lib/actions.ts:245-252`) POSTs
`/api/audit/${exchange.id}`. The action group is consumed by `pages/history.tsx:325`,
`pages/sitemap.tsx:202` and `pages/wshistory.tsx:107` via `useExchangeActions`.

Server response, real output:

```
$ curl -X POST -d '{}' http://127.0.0.1:18481/api/audit/0
{"active_checks": 58,
 "breakdown": {"breakdown": {"found": 10, "skipped": 0, "errored": 0, "gated": 0,
                             "complete": true,
                             "summary": "10 found, and nothing was skipped, errored or gated"}},
 "dispositions": [{"disposition":"ran","count":58}, ...]}
```

`active_checks: 58` is the server independently confirming the 58 of §1.2.

Issue list afterwards — 15 findings, including two **genuine active-probe** results:

```
 - High | SQL injection                    | query "id": introduced You have an error in your SQL syntax (error signature abs…
 - High | Cross-site scripting (reflected) | Reflected XSS evidence: query "q": HTML/attribute breakout: injected tag reflect…
 - High | Cleartext submission of password
 - Informational | Frameable response (potential Clickjacking)
 - Informational | Content security policy: not enforced
 - Informational | Content security policy: allows clickjacking
 - Informational | HTML does not specify charset
 - Low  | Cookie without HttpOnly flag set
 - Low  | Password field with autocomplete enabled
 - Low  | Unencrypted communications
```

Independent proof the probes were really sent — the target's own request log during the audit
of one `GET /app/search.php?q=hello&id=1`:

```
target received 64 HTTP requests; 14 to /app/search.php, e.g.
  GET /app/search.php?q='&id=1
  GET /app/search.php?q=hello&id='
  GET /app/search.php?q=zxss172496e1d464&id=1
  GET /app/search.php?q="><svg%20id%3Dzxss31b69e6f344a%20onload%3Dalert(1)>&id=1
  GET /app/search.php?q=../../../../../../../../etc/passwd&id=1
  ... cookie: sessid=../../../../../../../../etc/passwd; theme=dark
plus discovery fetches: /robots.txt /openapi.json /swagger.json /graphql /api/v2/api-docs ...
```

On a POST exchange the same audit probed body parameters:

```
  POST /app/login.php  body: user='&pw=secret
  POST /app/login.php  body: user=bob&pw="><svg id=zxss… onload=alert(1)>
  POST /app/login.php  cookie: sessid='
→ High | SQL injection | body "user": introduced You have an error in your SQL syntax
```

**Verdict: STATE 4 — WIRED.** Query, body and cookie insertion points are genuinely probed;
findings reach `/api/issues`.

### 4.3 Path C — the "Live active audit" toggle — **STATE 4**

`pages/scanner.tsx:97-163` `LiveAuditCard` renders a `Switch` bound to `useSetScannerLive`
(`lib/data.attack.ts:113-118` → `POST /api/scanner/live`). The Issues view itself is the
`scanner` nav leaf, labelled **"Issues"** (`src/nav.ts:89`), and reads `/api/issues` via
`useIssuesDetailed()` (`pages/scanner.tsx:271`, `lib/data.attack.ts:90`).

```
$ curl http://127.0.0.1:18481/api/scanner/live
{"wired":true,"enabled":false,"behind":0,"collapsed":0,"ledger_resets":0}
$ curl -X POST -d '{"enabled":true}' http://127.0.0.1:18481/api/scanner/live
{"wired":true,"enabled":true,...}

issues before: 26
$ curl -x http://127.0.0.1:18480 "http://127.0.0.1:18470/live/page.php?name=world&uid=7"
issues after:  38          # +12, with no further user action
$ curl http://127.0.0.1:18481/api/scanner/live
{"wired":true,"enabled":true,"swept":3,"findings":23,"behind":0,"collapsed":16,"ledger_resets":0}
target saw 49 requests
```

**Verdict: STATE 4 — WIRED.** Toggle on → proxied traffic is actively audited automatically →
12 new findings for the new URL appear in `/api/issues`.

### 4.4 Summary of the end-to-end answer

**Yes — burpsy's scanner fires, and the fired findings reach the Issues view.** This is a real,
working scanner, not a shell. The gaps are in *breadth* (58/183 checks, 3/8 insertion-point
types) and in *dispatch model* (§3.4), not in wiring.

---

## 5. STATE 5 — reachable but wrong (behavioural proof for each)

### 5.1 Host-discovery probes reuse the base exchange's HTTP method — STATE 5

**Claim under test:** `Robots.txt file` and `OpenAPI definition found` are default-ON checks
(`CheckHostDiscovery`, `scanner.go:230-246`) that "fetch /robots.txt … and confirm on a 200
response" (`checks_discovery.go:83-88`).

**Evidence:** `checkRobotsTxtFile` calls `cc.Scanner.sendTestRequestFull(ctx, exchange,
"/robots.txt", nil)` (`checks_discovery.go:88`). `sendTestRequestFull`
(`scanner.go:507-539`) builds its request with `Method: exchange.Method`
(`scanner.go:515`) — **the method of whatever exchange happened to be the audit's base
request.** The package already has the correct primitive: `sendTestRequestBody`
(`scanner.go:546`) takes an explicit method and its own comment says it exists "for probes
that need a specific method … rather than the exchange's own method"
(`scanner.go:541-545`). The discovery checks do not use it.

Same defect, same primitive, at five more default-reachable or gated call sites:
`checks_discovery.go:62` (OpenAPI, default ON), `checks_discovery.go:185` (the *verification
GET* of the HTTP-PUT check — its own finding text says "a subsequent GET of the same path"),
`checks_reflection3.go:61,84` (backup-file discovery), `checks_reflection3.go:227`
(`/trace.axd`), `checks_reflection3.go:200` (`/Default.aspx`).

**Proof — run it, real output.** Two identical origins, both serving
`GET /robots.txt → 200 "User-agent: *\nDisallow: /admin"` and `POST /robots.txt → 405`
(a normal web server does not serve static files over POST):

```
$ curl -o /dev/null -w '%{http_code}' http://127.0.0.1:18471/robots.txt        # GET
200
$ curl -o /dev/null -w '%{http_code}' -d '' http://127.0.0.1:18472/robots.txt  # POST
405

# proxy one GET base exchange to :18471 and one POST base exchange to :18472
$ curl -x http://127.0.0.1:18480  http://127.0.0.1:18471/index.html
$ curl -x http://127.0.0.1:18480 -d a=1 http://127.0.0.1:18472/submit
# live active audit is on, so both are audited automatically

--- what each origin actually received from the scanner ---
port 18471:   GET  /robots.txt
              GET  /robots.txt
port 18472:   POST /robots.txt
              POST /robots.txt

--- findings ---
Robots.txt file  ->  [{'exchange_id': 3, 'path': '/index.html'}]      # the GET base only
                     (nothing for /submit)

--- the POST item's own audit outcome ---
exchange 4 POST /submit  state=audited
   ran=58 findings=5 skipped=0 not_run=0 send_failures=0 requests_sent=50 unmeasurable=0
   note: None
```

**Impact.** The same robots.txt, on the same host, is found or missed depending on the HTTP
method of an unrelated captured request. The miss is reported as a **clean, complete audit**:
`state=audited`, `skipped=0`, `send_failures=0`, no note. This is exactly the failure mode
this package's own comments say it exists to prevent — `checks_injection.go:6-11`: *"'we could
not look' is not 'we looked and found nothing'."* Here it is, silently, in a default-ON family.

A user who browses an API through the proxy (mostly POSTs) gets a discovery sweep that
POSTs to `/robots.txt`, `/openapi.json`, `/swagger.json` and 20 other static paths, and
reports clean on every one.

### 5.2 The same advisory is reported twice, under two names, at two severities — STATE 5

**Claim under test:** `/api/issues` is the Issues view's finding list, and its `counted` field
is what the UI shows as the issue count.

**Evidence:** two independent finding producers write into the same list.
`PassiveScanner.Scan` (`scanner.go:669`, called from `capture.go:298` on every proxied
response) raises 5 hardcoded names; the catalogue registry raises the corresponding catalogue
rows during an audit. `internal/advisory/aliases.go:7` deliberately maps burpsy's
condition-shaped names onto the catalogue advisories — so **both findings resolve to the same
advisory `type_index`.**

**Proof — run it, real output.** Grouping `/api/issues` by `(url, advisory.type_index)`:

```
path ('/live/page.php?name=world&uid=7',) type_index 005009a0 = Frameable response (potential Clickjacking)
       Low             Missing X-Frame-Options Header
       Informational   Frameable response (potential Clickjacking)
path ('/live/page.php?name=world&uid=7',) type_index 00500600 = Cookie without HttpOnly flag set
       Low             Cookie Missing HttpOnly Flag
       Low             Cookie without HttpOnly flag set
path ('/index.html',) type_index 005009a0 = Frameable response (potential Clickjacking)
       Low             Missing X-Frame-Options Header
       Informational   Frameable response (potential Clickjacking)
path ('/submit',) type_index 005009a0 = Frameable response (potential Clickjacking)
       Low             Missing X-Frame-Options Header
       Informational   Frameable response (potential Clickjacking)
```

**Impact.** Two things are wrong, not one:
1. **The issue count is inflated.** One audited URL with no cookies double-counts by 1; with a
   flagless cookie, by 2. `counted` went 5 → 15 for a single exchange in §4.2, of which 3 were
   the same conditions counted twice.
2. **The same condition carries two different severities** — `Low` from the legacy check and
   `Informational` from the catalogue row, for advisory `005009a0`. A triage sorted by severity
   puts the same finding in two buckets.

This is the same class as the already-recorded "issue counts summing to 15 of 21" defect in
the master report §6.4, in a different surface.

### 5.3 Header insertion points are enumerated and labelled "Audited" while nothing probes them — STATE 5

**Claim under test:** `AuditItem.PointKinds`' own doc says the point count "is a claim about
the four kinds the native injection evaluators walk" (`audit_items.go:357-360`), and
`AuditItemPointCovered` means "an admitted insertion-point check walked this request's point
set" (`audit_items.go:186-187`), rendered to the operator as **"Audited"**
(`audit_items.go:216`).

**Evidence:** the ledger enumerates with `DefaultProbeInsertionKinds`
(`audit_engine.go:849`) = `query, body, cookie, header`. But the only insertion-point checks
admitted at shipped defaults are SQLi / XSS / path-traversal, which walk `coreInjectionKinds`
= `query, body, cookie` (`checks_core_injection.go:52`) — **three kinds, not four.** Every
other harness caller that includes `header` is gated behind `CheckActiveInjection`,
`CheckReflectionProbes` or `CheckExtendedActive`, all default OFF.

**Proof — run it, real output.** The ledger for a default-config audit:

```
points [('query','q','Audited'), ('query','id','Audited'),
        ('header','User-Agent','Audited'), ('header','Accept','Audited'),
        ('header','Proxy-Connection','Audited'),
        ('cookie','sessid','Audited'), ('cookie','theme','Audited')]
point_kinds ['query','body','cookie','header']
```

and the *complete* set of probes the origin received for that request — every payload landed
in a query parameter or a cookie, **not one in any header**:

```
GET /app/search.php?q='&id=1                       ... (6 SQLi payloads on q)
GET /app/search.php?q=hello&id='                   ... (6 SQLi payloads on id)
GET /app/search.php?q=zxss172496e1d464&id=1        ... (XSS probes on q)
GET /app/search.php?q=../../../../../../../../etc/passwd&id=1
GET /app/search.php?q=hello&id=1  cookie: sessid=../../../../../../../../etc/passwd; theme=dark
GET /app/search.php?q=hello&id=1  cookie: sessid=abc123; theme=..\..\..\..\..\..\..\..\boot.ini
   -- User-Agent, Accept and Proxy-Connection are byte-identical in all 14 probes --
```

Reproduced identically on a second exchange (`POST /app/login.php`): 4 header points listed
`Audited`, zero header probes among 36 sends.

**Impact.** The audit-queue view tells the operator that User-Agent, Accept, Content-Type and
Proxy-Connection were audited on every request. At shipped defaults, no check can look at
them. The status vocabulary already contains the right answer —
`AuditItemPointNoChecks` / "No insertion point checks" (`audit_items.go:188-190`) — and it is
not used here.

Grading note: the package documents the *unit-vs-point granularity* limitation honestly at
`audit_items.go:164-176`. That is not what is wrong here. What is wrong is the **kind
mismatch**: the ledger enumerates a kind no admitted check requested, and the doc's own
sentence — "the four kinds the native injection evaluators walk" — is false at defaults, where
they walk three.

---

## 6. Two further gaps, graded and evidenced

### 6.1 `CheckPhase` is a six-value taxonomy with one value ever assigned — STATE 2

`check_contract.go:24-33` defines `PhasePassive, PhaseLightActive, PhaseActive, PhaseStored,
PhaseCollaborator, PhaseJavaScript`. The only two places a `Phase` is ever set are
`nativeDescriptor` (`check_registry.go:57`) and `declinedDescriptor`
(`check_registry.go:73`), both hard-coding `Phase: PhaseActive`.

```
$ git grep -n "Phase:\s*Phase" 638c480 -- 'burpsy-go/internal/scanner/*.go' | grep -v _test
638c480:burpsy-go/internal/scanner/check_registry.go:57:  Phase:  PhaseActive,
638c480:burpsy-go/internal/scanner/check_registry.go:73:  Phase:  PhaseActive,
```

Positive control: the other five constants *are* referenced — at their own definition site
(`check_contract.go:27,28,32`) and nowhere else in `internal/`. Confirmed by executing the
registry: `W2:RUNNABLE_PHASE active=183`, no other phase present.

**Why it matters for parity:** Burp's own scan-config vocabulary selects checks by exactly
this axis — `scanner/issues_reported/scan_type_passive`, `scan_type_light_active`,
`scan_type_medium_active`, `scan_type_intrusive_active`, `scan_type_javascript_analysis`
(recounted, §D5). burpsy has the field to express it and never populates it, so a
"passive-only scan" or a "light active scan" is **not representable** — the operator's only
axis is the 21 family switches.

### 6.2 `NativeCheckCoverage()` — the per-check operator report — has zero non-test callers — STATE 2

`check_coverage.go:17-19`: *"NativeCheckCoverage returns stable rows for the current registry.
It is a registry report, not a claim that any row ran."* Exactly the artefact an operator needs
to see which of the 183 are admitted.

```
$ git grep -n "NativeCheckCoverage" 638c480
burpsy-go/internal/scanner/check_coverage.go:17:  // NativeCheckCoverage returns ...
burpsy-go/internal/scanner/check_coverage.go:19:  func NativeCheckCoverage() []CheckCoverageRow {
burpsy-go/internal/scanner/check_coverage_test.go:5: func TestNativeCheckCoverageSeparatesRunnableAndDeclined(t *testing.T) {
burpsy-go/internal/scanner/check_coverage_test.go:6:   rows := NativeCheckCoverage()
```

Positive control (TAXONOMY rule 3): the same grep for the sibling `NativeCheckRegistry` finds
12 production references across 9 files. So the zero is a real absence of a caller.

`/api/scanner/coverage` does **not** serve it — it serves the BCheck corpus coverage
(`api_scanner_coverage.go:39` → `s.passiveScanner.Coverage()`). With no `-bchecks` corpus,
which is the default:

```
$ curl http://127.0.0.1:18481/api/scanner/coverage
{"checks":[],"enabled":false,"loaded":0,
 "partition":[{"state":"never dispatched","count":0},{"state":"ran clean","count":0},
              {"state":"ran and found","count":0},{"state":"errored","count":0}],
 "summary":"no passive checks loaded"}
```

**Impact.** A default burpsy tells the operator "no passive checks loaded" and shows an empty
coverage table, while 58 native checks are in fact admitted and running. The correct answer
exists in-tree, one function call away, and nothing calls it.

### 6.3 Per-issue detection-method selection — a Burp axis burpsy has no representation for

Burp's `selected_issues` entries carry a `detection_methods` list per issue. Recounted union
across every shipped config (§D6): **12** distinct method names —
`Error messages`, `Time delays`, `Boolean conditions`, `Oracle specific`, `MySQL specific`,
`SQL Server specific`, `Burp Collaborator`, `Burp Infiltrator`, `String echo`,
`Back-end socket poisoning`, `Passive checks`, `Active checks`.

burpsy's `ScanConfig` has no per-issue structure at all — 21 booleans, and the SQLi check's
detection methods are fixed in code. **0 of 12 representable.** This is a *config-model* gap,
the same shape as the master report's 4/77 scanner-config finding, and reinforces it from an
independent direction.

---

## 7. Findings table (TAXONOMY format)

### burpsy scanner end-to-end — STATE 4
Claim under test: a scan launched from the UI produces issues in the Issues view.
Evidence: `lib/actions.ts:245-252,403`; `pages/scanner.tsx:97-163,271`; `src/nav.ts:89`;
`internal/web/server.go:680,697,708`.
Proof: §4.2/§4.3 — `POST /api/audit/0` → `{"active_checks":58, "summary":"10 found…"}`,
`/api/issues` `counted` 5→15; live toggle on → proxying one URL → `counted` 26→38, with the
origin's own log showing 49 probe requests.
Impact: none — this works.

### Active check breadth — STATE 4, but 58/183 admitted
Claim under test: "burpsy implements 183 checks."
Evidence: `check_registry.go:13-46`; `check_registry_declined.go:26-28`; `scanner.go:230-246`.
Proof: registry executed → 183 descriptors, 183 runnable, 0 declined; `Enabled` evaluated
against the shipped default literal → 58. Server independently reports `"active_checks": 58`.
Impact: an operator who never opens scanner settings gets 3 injection checks, 5 discovery
checks and 50 network-free analysers — not 183.

### Insertion points — STATE 2 for 11 of 15 kinds
Claim under test: burpsy injects where Burp injects.
Evidence: `bcheck/insertion.go:73-105,299-579` (15 kinds implemented);
`scanner/probe_harness.go:40` and `checks_core_injection.go:52` (4 and 3 requested);
zero production callers for the other 11, positive control in §2.3.
Proof: §2.4 — live ledger `point_kinds ["query","body","cookie","header"]`; `/search` produced
no path-filename or path-folder point.
Impact: URL path segments, parameter names, the entire body and all six parameter relocations
are never probed by the scanner. **3** of Burp's 8 insertion-point types actually receive a
payload at defaults, **5** of 8 with every switch on, **0** of 6 relocation types ever.

### Host-discovery method reuse — STATE 5
See §5.1. Behavioural proof included.

### Duplicate advisory reporting — STATE 5
See §5.2. Behavioural proof included.

### Header insertion points labelled "Audited" — STATE 5
See §5.3. Behavioural proof included.

### `CheckPhase` taxonomy — STATE 2
See §6.1.

### `NativeCheckCoverage()` — STATE 2
See §6.2.

---

## NOT DETERMINED

1. **The Burp-side check-count denominator.** Burp does not publish a per-check inventory in
   its shipped resources in a form I could recount. `scanner/issues_reported/selected_issues`
   only enumerates issues *selected by a given preset* (15 distinct `type_index` across all
   shipped configs — not a total). I refuse to state an "N of M checks" ratio. The defensible
   substitutes are stated instead: 183/183 catalogue TypeIndex values have an evaluator;
   58/183 admitted at defaults; 3/8 insertion-point types injected at defaults (5/8 all-on); 0/12 detection methods; 0/5 scan
   types.
2. **Whether the 183 evaluators are individually *correct*.** I proved 8 distinct checks fire
   against a target built to trigger them (SQLi ×2 positions, reflected XSS, cleartext
   password, autocomplete, frameable, CSP ×2, charset, cookie HttpOnly, unencrypted comms,
   robots.txt). The other ~170 were not individually driven. **This is the largest open gap in
   my report.** A check that is registered, admitted and dispatched can still be a check that
   can never return a finding, and I did not test for that.
3. **BCheck-corpus mode.** Every measurement here was taken without `-bchecks`. The
   `Scan` early-return at `scanner.go:670-672` means corpus mode is a different code path with
   a different check set; I did not measure it. `e2e-scan.sh` covers it but drives
   `./target/debug/burpsy` — the **Rust** binary — not `burpsy-go`, so it is not evidence about
   the Go scanner.
4. **`internal/scanner/tools` and `bcheck_runner.go`** (`ImplementationTool` / `ImplementationBCheck`)
   were not exercised. Zero descriptors carry those implementations at HEAD
   (`W2:IMPL native=183`), but the sqlmap/nuclei tool-runner path exists and I did not drive it.
5. **Whether the Issues page *renders* the findings.** I proved `/api/issues` returns them and
   that `pages/scanner.tsx:271` reads that endpoint through `useIssuesDetailed()`. I did not
   drive a browser, so the render step is inferred from code, not observed. Per TAXONOMY that
   makes the *page* unproven even though the *pipeline* is proven.
6. **Field incidence of §5.1.** How often a real user's base exchange is a non-GET when a
   host-scoped discovery check runs. `DispatchScopePerHost` means one run per host, and which
   exchange wins that race is not something I measured.
7. **`crawlFrom` ("Actively scan this branch/host")** — `lib/actions.ts:404-405` offers two
   more scan-launch entry points through `/api/crawl`. Not measured.

---

## DENOMINATORS I RECOUNTED

**D1 — burpsy check registry: 183 descriptors, 183 runnable, 0 declined, 58 admitted at
shipped defaults.**
Corpus: the executed `NativeCheckRegistry()` at `638c480`, in a scratch copy at
`/tmp/w2-burpsy-go` (no production file touched).
```
cp -a burpsy-go /tmp/w2-burpsy-go
# add /tmp/w2-burpsy-go/internal/scanner/zz_w2_dump_test.go: iterate NativeCheckRegistry(),
#   tally Implementation / Runnable() / Phase / Scope
go test ./internal/scanner/ -run TestW2DumpRegistry -count=1 -v | grep '^W2:'
  W2:TOTAL_DESCRIPTORS=183   W2:RUNNABLE=183   W2:DECLINED=0   W2:IMPL native=183
  W2:RUNNABLE_PHASE active=183
  W2:RUNNABLE_SCOPE per_host=21  per_url=118  per_request=18  stored_per_insertion_point=26
  (the other 3 of the 7 scopes — per_path, in_session_per_request and
   per_insertion_point — carry ZERO descriptors; note that
   DispatchScopePerInsertionPoint, Burp's own cost centre, is one of them)
  W2:CATALOG=183
# zz_w2_enabled_test.go: replicate the NewActiveScanner literal (scanner.go:230-246),
#   evaluate every descriptor's Enabled predicate against it
go test ./internal/scanner/ -run TestW2EnabledUnderConfigs -count=1 -v | grep '^W2E:'
  W2E:REGISTRY=183  W2E:ENABLED_DEFAULT=58  W2E:ENABLED_ALLON=183  W2E:NIL_PREDICATE=0
```
Independent confirmation from the running server, not the same code path:
`POST /api/audit/0` → `"active_checks": 58`.
What each counts: descriptors registered / descriptors with a non-nil `Run` and no
`DeclineReason` / descriptors whose `Enabled(cfg)` is true for the shipped default config.

**D2 — Burp `scanner.insertion_point_types`: 8 keys. `scanner.modifying_parameter_locations`: 6.**
Corpus: `/root/burp-re/in/extract/resources/BuiltInConfigs/*.json` — Burp 2026.7.1's own
shipped configs (29 files).
```
python3 -c "
import json,glob
ks=set()
for f in glob.glob('/root/burp-re/in/extract/resources/BuiltInConfigs/*.json'):
    d=json.load(open(f))
    def walk(o,p=''):
        if isinstance(o,dict):
            for k,v in o.items(): walk(v,p+'/'+k if p else k)
        else: ks.add(p)
    walk(d)
print([k for k in sorted(ks) if 'insertion_point' in k or 'modifying' in k])"
```
Result: 8 `insertion_point_types` leaves, 6 `modifying_parameter_locations` leaves. Full list
in §2.1. Counts leaf config keys, not checks.

**D3 — insertion kinds requested by burpsy's scanner: 5 of 15 appear at all in production
code; 4 at defaults.**
Corpus: `internal/scanner internal/web internal/extscan cmd`, `--include=*.go`, `_test.go`
excluded.
```
for k in query body cookie header param_name_url param_name_body entire_body \
         url_path_filename url_path_folder synthetic_header \
         relocate_body_to_query relocate_query_to_body relocate_query_to_cookie \
         relocate_cookie_to_query relocate_body_to_cookie relocate_cookie_to_body; do
  echo "$k : $(grep -rn "\"$k\"" --include=*.go internal/scanner internal/web internal/extscan cmd \
                | grep -v _test | wc -l)"
done
```
Result: `query 13, body 16, cookie 10, header 15, entire_body 2`, and **0 for the other 11**.
**Positive control (TAXONOMY rule 3):** the identical grep widened to the whole tree finds
every one of the eleven zero-count strings — in `internal/bcheck/insertion.go` (definitions),
`internal/bcheck/insertion_test.go` (tests), `internal/intruder/points.go`. So the pattern is
correct and the zeros are real. Counts source-literal occurrences, i.e. request sites.

**D4 — the 58 default-admitted checks, by admitting switch.**
Same scratch-copy method as D1; each family switch set alone on an otherwise-zero `ScanConfig`.
```
go test ./internal/scanner/ -run TestW2Families -count=1 -v | grep '^W2F:'
  CheckSqli=1  CheckXss=1  CheckPathTraversal=1  CheckSSRF=0  CheckHeaders=6
  CheckPassivePosture=15  CheckPassiveAnalysis=29  CheckHostDiscovery=5
  UNION_DEFAULT_ON=58
```
The eight sum to 58 with no overlap. Counts descriptors admitted by each single switch.

**D5 — burpsy `ScanConfig` family switches: 21. Writable keys on `/api/scanner/config`: 21.**
```
git show 638c480:burpsy-go/internal/scanner/scanner.go \
  | sed -n '/^type ScanConfig struct/,/^}/p' | grep -cE '^\s+Check[A-Za-z]+ +bool$'      # 21
git show 638c480:burpsy-go/internal/web/api_scanner_config.go \
  | sed -n '/^var scannerConfigBoolKeys/,/^}/p' | grep -c '"check_'                      # 21
```
They match — no accepted-but-unhandled gap in this vocabulary. Counts bool struct fields /
wire keys.

**D6 — Burp scan types: 5. Burp per-issue detection methods: 12.**
Corpus: `BuiltInConfigs/*.json` + `Preferences/*.json`, same walk as D2.
Scan types (`scanner/issues_reported/scan_type_*`): `passive`, `light_active`,
`medium_active`, `intrusive_active`, `javascript_analysis`.
Detection methods (union of every `selected_issues[].detection_methods[].name`): 12, listed in
§6.3. Also recorded: only **15** distinct `type_index` values appear anywhere in
`selected_issues` across all shipped configs, so that field is **not** a full Burp check
inventory and must not be used as one.

**D7 — burpsy catalogue: 183 rows, 183 unique TypeIndex; Burp ships 183 issue JSON files.**
```
git show 638c480:burpsy-go/internal/scanner/catalog_data.go | grep -cE '^\t\tTypeIndex:'      # 183
git show 638c480:burpsy-go/internal/scanner/catalog_data.go | grep -E '^\t\tTypeIndex:' | sort -u | wc -l  # 183
ls /root/burp-re/out/scanner_spec/issues/*.json | wc -l                                       # 183
```
Confirms the master report's "183 bundled". **This is an advisory count, not a check count** —
§1 keeps them separate deliberately.

---

## Closing note on method

Every number above was produced by executing code or by driving the running binary, not by
reading it. The three STATE 5 findings each carry a command and its real output. The one place
I stopped short is named in NOT DETERMINED §2: I did not individually drive ~170 of the 183
evaluators, so "the registry has 183 runnable descriptors" must not be restated as "183 checks
work."
