# BCheck M2 — runtime/evaluation semantics

Researched 2026-07-26. Three independent evidence sources, and where they agree I say so explicitly:

- **CORPUS** — 264 `.bcheck` files at `/tmp/BChecks` (139 active: host/request/path).
- **DOCS** — PortSwigger's BCheck reference, worked examples, v2-beta wiki, scanner error reference.
- **BURP** — the actual interpreter, decompiled, at `/root/burp-re/out/deobf_merged/burp/`. The BCheck
  execution context is `Zpa0` (abstract base) / `Zpao` (concrete). Several **original method names
  survived as lambda synthetics** (`lambda$getRequestToDiffAgainst$0`,
  `lambda$clearRepeatedDiffRequestResponses$2`, `lambda$addResult$1`), which is what let me identify
  these classes. Recovered ZKM string literals give the reserved names verbatim.

Tags: **OBSERVED** (seen in corpus/docs/decompiled code, cited) · **INFERRED** (reasoned, with the
reasoning shown) · **UNVERIFIED** (no evidence; do not trust) · **AMBIGUOUS** (evidence conflicts —
safer reading proposed).

---

## Q1 — `base` vs `latest`

### `latest` is initialised to `base`; it is never undefined. **OBSERVED**

`other/bypass/path-bypass.bcheck:30-37` reads `{latest.response}` **before any send has occurred**,
and the whole check depends on it:
```
    30	given request then
    31	    #Check if we triggered a 403/401 path that isen't a response from a firewall (…)
    32	    if {latest.response.status_code} matches "40(3|1)" and not( ("What happened?" in {latest.response.body} …
    33	
    34	        if {payload} is "/" then
    35	            send request:
    36	            method: "GET"
    37	            path: {latest.request.url.path}
```
Line 32 gates the entire check on the *scanned* response's status; line 37 builds the outgoing request
from the *scanned* request's path. The file is marked `#Verified: Yes` (line 1). The only reading under
which this check functions is **`latest` ≡ `base` until the first send**.

Corroboration from BURP: `Zpao.Zq(String name, Zx4o requestResponse)` — the sole registration path —
writes `latest` *unconditionally*:
```java
public void Zq(String string, Zx4o zx4o) {
    this.ZN().put(Zpao."latest", zx4o);        // ALWAYS, before anything else
    if (string == null) break block10;          // unnamed send: done
    ...
    this.ZN().put(string, zx4o);                // named send: also bind the name
}
```
(`/root/burp-re/out/deobf_merged/burp/Zpao.java:151-190`; `"latest"` is a recovered ZKM string.)

### Every send updates `latest`, including unnamed sends and `send payload`. **OBSERVED**

From the code above, `put("latest", …)` precedes the `name == null` early exit. Corpus confirms for
`send payload` — `other/tokens/jwt-none-algorithm.bcheck:12-26`:
```
    12	        send payload:
    …
    18	        if {latest.response.status_code} is {base.response.status_code} then
    20	            # Send request with no signature without changing 'alg' value to check for false positives
    21	            send payload:
    …
    26	            if not ({latest.response.status_code} is {base.response.status_code}) then
```
Two `send payload`s; each `{latest.…}` reads the one immediately above it.

### After two sends, `latest` is the second. **OBSERVED**

`examples/server-side-prototype-pollution.bcheck:18-27` — two unconditional, sequential sends:
```
    18	        send request called inject_sspp:
    22	        send request called check_sspp:
    26	        if {latest.response.body} matches "\"statusCode\":510" or
```
The injection response is not the one being tested; `latest` must be `check_sspp`.

`other/files/ds-store-exposed.bcheck:14-26` — `check` is conditional, `check1` is unconditional and
follows it, so on the common path two sends occur and `latest` is the later one:
```
    14	    if not({base.request.url.path} is "/") then
    15	        send request called check:
    19	    end if
    22	    send request called check1:
    26	    if {latest.response.status_code} is "200" and
```

`vulnerabilities-CVEd/CVE-2023-25690 Apache mod_proxy CRLF Smuggling.bcheck:13-22` is the sharpest case
— it reads an **earlier** send by name and the **later** send via `latest`, in one expression:
```
    13	        send request called split:
    17	        send request called oob:
    21	        if {split.response.body} matches "\"statusCode\":200" or
    22	            {latest.response.status_code} is "200" then
```

### `latest` also tracks across mutually-exclusive branches. **OBSERVED**
`other/files/svn-exposed.bcheck:11-25` sends from either arm of an if/else and then tests `latest`,
which resolves to whichever arm ran:
```
    11	given path then
    12	    if {base.request.url.path} is "/" then
    14	        send request called check:
    17	    else then
    20	        send request called check1:
    23	    end if
    25	    if {latest.response.status_code} is "200" then
```
So `latest` is genuinely dynamic execution state, not a lexical "last send in the file".

### `base` is pinned for the whole check. **OBSERVED**

`other/tokens/jwt-none-algorithm.bcheck:18` and `:26` compare against `{base.response.status_code}`
*after* one and two `send payload`s respectively, and the comparison is only meaningful if `base` still
means the original. Likewise `other/bypass/PathSuffix_WAF_Proxy.bcheck:47,51` reads
`{base.response.status_code}` after `send request called check`.

In BURP, `base` is a **reserved name** (`Zpa0.java:480`: `Zpa0.Zh = Set.of(Zpa0."base", Zpa0."latest")`)
and is never a target of `Zq()`, so nothing can rebind it.

### Both `latest.request` and `latest.response` exist
`path-bypass.bcheck:37` `{latest.request.url.path}`, `:46` `{latest.response.url.path}` — note a
`.url` is reachable from a **response** object as well as a request. **OBSERVED**

---

## Q2 — Named requests

### `{NAME.request}` and `{NAME.response}` are both in scope. **OBSERVED**
`examples/exposed-backup-file.bcheck`:
```
    13	        send request called check:
    16	        if {check.response.status_code} is {base.response.status_code} then
    24	                    detail: `Backup file found at {check.request.url}`
```

### A named response stays reachable after later sends. **OBSERVED**
`other/bypass/PathSuffix_WAF_Proxy.bcheck:44-51`:
```
    44	        send request called check:
    47	        if not({check.response.status_code} is {base.response.status_code}) then
    48	            send request called garbage:
    50	            if {garbage} differs from {check} then
    51	                if {base.response.status_code} matches "40(1|3)" and {check.response.status_code} is "200" then
```
`check` is read at line 51, two sends later. Bindings accumulate; they are not consumed.

### Names are **check-scoped**, flat, and cannot be shadowed — reuse is a hard error. **OBSERVED (BURP)**
`Zpao.java:151-190` — after writing `latest`:
```java
if (!Zh.contains(string)) break block11;
throw new Zxif(string);                       // (1) reserved name  -> throw
...
if (!string.startsWith("repeat:") && this.ZN().containsKey(string)) break block12;
if (!this.ZD().containsKey(string)) break block13;
throw new Zxij(string);                       // (2) duplicate name -> throw
```
Three rules fall out:
1. **`base` and `latest` are reserved** (`Zpa0.java:480`). `send request called base:` throws.
2. **Duplicate request name → throw.** No shadowing, no last-write-wins.
3. **A request name may not collide with a variable name either** — the check tests `ZD()`, the
   variable map (the same map that holds `insertion_point_base_value`, `Zpao.java:69`). So
   `define: check = "x"` + `send request called check:` is an error.

The `repeat:` prefix is exempt from the duplicate check — that is Burp's internal namespace (see Q7).

There is a single flat `Map<String, Zx4o> ZN()` per execution context (`Zpa0.java:110`), so scoping is
per-check-execution, not per-block. `Zpa0.ZI(String)` (line 112) throws `Zxie(name)` on an unknown name
— referencing an undefined request is an error, not an empty value.

### `send payload called NAME:` is legal
Accepted by `BCheckChecker-1.9.jar`. **Zero corpus users** — all 9 insertion-point checks use unnamed
payload sends. **OBSERVED (grammar), UNVERIFIED (semantics)** — presumably binds the same way.

### Corpus shape of named requests
124 files, **158 named-send statements**. How the name is subsequently used:

| usage | count |
|---|---|
| `{NAME.response…}` only | 137 |
| both `.response` and `.request` | 4 |
| `.request` only | 0 |
| never referenced by name (result read via `{latest…}`, or compared bare) | 17 |

**Zero files reuse a name** — consistent with reuse being a hard error (rule 4 below). Only
`{NAME.request.url}` and bare `{NAME.request}` are ever read off a named request; deeper request paths
(`.request.headers`, `.request.body`) are only ever read off `base`/`latest`.

---

## Q3 — The implicit base request per `given` type

**Every scan point has a base request/response pair, and `send request` modifiers layer onto a copy of
it.** The strongest single piece of evidence is a `given path` check that specifies *only* a header
replacement — `other/supportForOtherContentTypesThanJson.bcheck:20-24`:
```
    20	given path then
    21	    if {base.request.headers} matches "(?i)Content-Type:\s+application\/json" then
    22	        send request called checkSupport:
    23	            replacing headers:
    24	                "Content-Type": `{content_type}`
```
Method, path, body and every other header are inherited from `base.request`. **OBSERVED**

Per-type behaviour measured across the corpus (files with ≥1 `send request`):

| `given` | files | with send | sets `method:` | sets `path:` | raw-string form |
|---|---|---|---|---|---|
| `host` | 99 | 99 | 90 | 90 | 6 |
| `path` | 11 | 11 | 7 | 4 | 0 |
| `request` | 40 | 39 | 17 | 11 | 0 |
| `response` | 105 | **0** | 0 | 0 | 0 |

Readings:

- **`given response` — passive, no base *request* needed.** 105/105 files issue no request at all.
  **OBSERVED**
- **`given request` — base is the crawled request.** Only 17/39 set a method and 11/39 a path; the rest
  mutate the scanned request. **OBSERVED**
- **`given path` — base is the crawled request for that path.** DOCS: *"a per-path check (that is, a
  check that runs once for each path scanned)"*, base being *"the original HTTP response for each
  individual path"*. Corpus agrees (4/11 set a path). **OBSERVED**
- **`given host` — a base request to that host exists, but almost nobody relies on it.** 90/99 set both
  method and path; 6 send a raw request. The 9 that set neither still layer onto something —
  `other/php-8.1.0-dev-backdoor.bcheck:12-14`:
  ```
      12	given host then
      13	    send request:
      14	        appending headers:
      15	            "User-Agentt": `{payload};`
  ```
  Appending a header presupposes a request to append it to. DOCS: *"runs once for each host scanned…
  When you specify only a path without a base URL, the request targets each discovered host using that
  path appended to it."* **OBSERVED that a base exists; AMBIGUOUS what it is.**

  **Safer reading for burpsy:** for `given host`, synthesise the base request as `GET /` on the host
  using the crawl's representative request headers (so `appending headers:` works), and treat
  `{base.response}` as that request's response. Do **not** invent a body or a non-GET method. This
  matches all 99 corpus files: the 90 that set method+path overwrite it anyway, the raw-form 6 bypass
  it, and the 9 header-appenders get a sane target.

---

## Q4 — Request modifier composition

### Modifiers form an accumulator, applied in source order. **OBSERVED — this is settled**

`other/Perl Jam 2 - RCE.bcheck:20-25` is decisive, and the author left a comment explaining it:
```
    20	    send request called RCE:
    21	        method: "POST"
    22	        replacing query_string: {rce_payload}
    23	        #our payload needs to be at the beginning of the POST body; followed by the original body
    24	        replacing body: `--{boundary}\r\nContent-Disposition: form-data; name="file"\r\n\r\nARGV\r\n`
    25	        appending body:`{request_original_body}`
```
`appending body` on line 25 appends to the value produced by `replacing body` on line 24 — *not* to
`base.request.body`. Confirmed twice over: the check has to stash the original body in a variable first,
because after line 24 it is gone (`:15  request_original_body = \`{base.request.body}\``).

So: **build a mutable request seeded from `base.request`, apply modifiers strictly in source order, each
one reading and writing the accumulator.** That is the real model, not a diff against base.

Repeated same-part modifiers **accumulate rather than overwrite** for keyed parts —
`vulnerabilities-CVEd/CVE-2011-3192-Apache DoS.bcheck:21-25` sets three headers with three separate
`headers:` lines (and note the ragged indentation, which parses fine):
```
    21	        send request called DoS:
    22	            method: "GET"
    23	                headers: "Range": {DoS_payload}
    24	                headers: "Request-Range": {DoS_payload}
    25	                headers: "Content-Range": {DoS_payload}
```
Only 2 of 149 multi-modifier send blocks touch the same part twice, but both are unambiguous.

Other settled points:

- **Modifiers apply to a copy of `base.request`, not to each other's absence.** Same evidence as Q3.
  **OBSERVED**
- **`appending X` appends to the base value of X; `replacing X` overwrites it.**
  `PathSuffix_WAF_Proxy.bcheck:44-45`:
  ```
      44	        send request called check:
      45	            appending path: {suffix}
  ```
  A path-suffix bypass is only meaningful appended to the real path. Contrast
  `exposed-backup-file.bcheck:13-14`, which computes the whole new path and uses `replacing path:`.
  **OBSERVED**
- **Multiple modifiers on *different* parts compose, in source order.** Common, e.g. the host template
  sets `method:` then `path:`. **OBSERVED**

Modifier co-occurrence across 149 multi-modifier send blocks — `method`+`path` dominates:
`method+path` 74 · `method+replacing path` 10 · `headers+method+path` 7 · `appending path+method` 7 ·
`method+path+replacing headers` 5 · `body+method` 4 · `body+headers+method+path` 4 · tail of ~15 more.

**Still not settled by the corpus:**
- **`removing` never appears in any of the 264 files.** Zero uses, so `removing body` followed by
  `appending body:` is unexercised. The accumulator model above answers it consistently
  (result = `"x"`), and that is what I'd implement, but flag it as unvalidated.
- Two `replacing path:` in one block (repeated *scalar* parts). The keyed-part case is settled by
  CVE-2011-3192; the scalar case is not. Accumulator model says last-write-wins.

Emit a warning when two modifiers target the same scalar part so divergence shows up in testing.

---

## Q5 — Control flow after a send, and after `report issue`

### `report issue` (without `and continue`) terminates the check. **OBSERVED (DOCS)**
Verbatim: *"The standard 'report issue' action causes Burp Scanner to report an issue and **terminates
the BCheck**, even if there are parts of the check that have not yet run."* The v2-beta wiki:
*"`report issue and continue` enables raising issues without terminating check execution. This works
well with the `run for each` construct, allowing multiple issues to be reported from a single BCheck."*

### Does it stop the current `run for each` iteration, or all of them? **AMBIGUOUS**

The two sources point opposite ways:
- DOCS (path example): *"will iterate through this list, performing **one full check for each entry**
  before moving on to the next one"* → suggests iterations are independent, so termination is
  per-iteration.
- v2 wiki: `and continue` exists so that `run for each` can raise *multiple* issues → only makes sense
  if plain `report issue` suppresses the later iterations' issues.

BURP leans toward independence. `Zpa0.ZI()` (`Zpa0.java:127-149`) expands iterables into a **list of
fully independent context objects** — a cartesian product, one context per combination:
```java
LinkedList<Zpa0> linkedList = new LinkedList<>();
linkedList.add(this.ZF());                                  // ZF() = deep copy of the context
for (Map.Entry<String, List<Zpe3>> entry : this.Zd().entrySet()) {   // each iterable variable
    LinkedList<Zpa0> linkedList2 = new LinkedList<>();
    for (Zpe3 zpe3 : entry.getValue()) {                    // each value
        for (Zpa0 zpa0 : linkedList) {
            Zpa0 zpa02 = zpa0.ZF();
            zpa02.Zm(entry.getKey(), zpe3.ZR(zpa0), true);   // bind value, outer scope = true
            linkedList2.add(zpa02);
        }
    }
    linkedList = linkedList2;
}
```
Two side facts fall out of this, both **OBSERVED**:
- **Multiple `run for each` variables produce a cartesian product** (my previous report flagged this as
  INFERRED — it is now confirmed in the implementation).
- Each iteration gets a **copied context**, so named requests and `latest` do **not** leak between
  iterations.

Corpus usage does **not** break the tie, and is worth knowing before you pick: among files that use
`run for each`, **77 use plain `report issue:` and only 5 use `report issue and continue:`**. So plain
reporting inside a loop is overwhelmingly the norm — authors are evidently content with "first hit
wins" for things like the 13 Springboot-actuator path lists. The 5 that opt into `and continue` are
exactly the ones that want a finding per iteration value (`exposed-backup-file` per extension,
`PathSuffix_WAF_Proxy` per suffix, `CONNECT_port_scan` per port).

`other/HTTP Methods/CONNECT_port_scan.bcheck` is the most suggestive: it iterates
`new_port = "80", "443"` and uses `and continue` for its first two reports (lines 35, 43) but plain
`report issue` for the last (line 51) — i.e. the author deliberately kept the check alive between
reports and let the final one end it.

**Safer reading:** treat plain `report issue` as terminating **the entire BCheck, all remaining
iterations included**. Rationale: it is the reading the wiki's justification for `and continue`
requires, and over-suppressing produces one issue where Burp produces one issue, whereas
under-suppressing produces N duplicates that then have to be deduped. This is the single semantic I'd
most want to A/B against real Burp before shipping — 77 files change behaviour depending on the answer.

### Send failure: no corpus construct, no documented error. **INFERRED**
The corpus has no error-handling syntax whatsoever — no try, no timeout, no status test for "did the
send work". The scanner error reference documents exactly one BCheck-related error, and it is a
*graceful degradation*: *"The X BCheck didn't run Collaborator checks, as Collaborator has been
disabled."* → *"When running the BCheck, Burp Scanner used a random string instead"* of the Collaborator
payload and didn't poll. **OBSERVED**

That is a strong precedent: Burp's model is *substitute something harmless and keep going*, not abort.

**Safer reading:** a failed send (connection refused, timeout, TLS failure) should **not** abort the
check. Bind an empty response (status 0, empty headers, empty body), update `latest` to it, and
continue. Every corpus comparison against an empty response is falsy (`in`/`is`/`matches` on empty), so
checks naturally fall through without reporting. Aborting would be equally safe from a false-positive
standpoint but diverges from Burp on multi-send checks where the first send is expected to fail (e.g.
`svn-exposed` probes two paths and only tests `latest`).

**UNVERIFIED:** whether Burp raises a scan error entry for a failed BCheck send. Log it; don't report an
issue.

---

## Q6 — The nine built-in functions

Signatures are **OBSERVED (DOCS)**; behavioural detail as tagged.

| Function | Signature | Semantics |
|---|---|---|
| `random_str(n)` | 1 int arg | DOCS: length **0–9,999,999**. Charset not documented. **INFERRED: alphanumeric** — corpus embeds it directly in URL paths (`exposed-backup-file.bcheck:18` `` `$1.{random_str(10)}` ``, `PathSuffix:49` `` `{random_str(10)}{suffix}` ``), which would break with punctuation. Montoya's `RandomUtils.randomString(int)` has sibling overloads taking `CharacterSet{ASCII_LOWERCASE, ASCII_UPPERCASE, ASCII_LETTERS, DIGITS, PUNCTUATION, WHITESPACE, PRINTABLE}`, implying a conservative default. |
| `regex_replace(subject, pattern, replacement)` | 3 args | **`$1` is the backreference, not `\1`. OBSERVED** — `exposed-backup-file.bcheck:14`: `regex_replace({base.response.url.path}, "(.)/?$", `$1{extension}`)`. That is Java `Matcher.replaceAll` syntax; pattern is a Java regex. Replaces **all** matches (INFERRED from the name and Java semantics). |
| `to_lower(s)` / `to_upper(s)` | 1 arg | Case conversion. Locale unspecified — **INFERRED: use ASCII/root locale**, not the platform default (avoids the Turkish-İ class of bug). |
| `base64_decode(s)` | 1 arg | **Standard alphabet, padding accepted. OBSERVED** — `PathSuffix_WAF_Proxy.bcheck:32-34` decodes `"DA=="`→`\x0C`, `"oA=="`→`\xA0`, `"hQ=="`→`\x85`. Note these produce **non-UTF-8 bytes** used directly in a URL path, so your value type must be byte-safe, not `String`-only. |
| `base64_encode(s)` | 1 arg | **INFERRED: standard alphabet, padded.** Montoya's `Base64EncodingOptions` enum is exactly `{URL, NO_PADDING}` — both are *opt-in* modifiers, so the default is standard + padded. BCheck exposes no options argument. |
| `generate_collaborator_address()` | 0 args | Fresh Collaborator address per call (54 call sites / 27 files). **When Collaborator is disabled Burp substitutes a random string and skips polling — OBSERVED (scanner error reference).** Copy that behaviour: it lets the 10.2% Collaborator checks run harmlessly without an interaction server. |
| `md5(s)` / `sha1(s)` / `sha256(s)` | 1 arg | **UNVERIFIED.** Zero corpus users, and the docs give only `sha1(String)` with no return format. Hex vs raw bytes vs base64 is a coin flip. Montoya's separate `CryptoUtils.generateDigest(ByteArray, DigestAlgorithm)` returns a raw `ByteArray`, but that is a different API surface and I would not extrapolate. **Do not guess — implement as hex-lowercase, mark it provisional, and note it in the check-compat table.** No corpus check will exercise it. |

Nesting is supported and used: `regex_replace({payload}, "__calc__", {calc})` inside a backtick string
inside another `regex_replace` (`path-bypass.bcheck:46`). DOCS confirm `{base64_encode(to_lower(var))}`.

**There is no `urlencode`.** Already established; worth restating because base64-decoded raw bytes go
into paths unencoded (`PathSuffix:32-34`), so **do not URL-encode interpolated values automatically** —
that would break these checks.

**Functions accept object properties, not just strings. OBSERVED** —
`vulnerabilities-CVEd/CVE-2011-3192-Apache DoS.bcheck:28`:
```
    28	            ({response_payload} in {to_lower(DoS.response.body)})
```
`to_lower` is applied to a named response's body and the result is the right operand of `in`. Your
function arguments must accept the full value grammar (variable refs, object paths, nested calls,
interpolatable strings), not a string literal.

Note also the argument form: inside a function call the operand is written **bare**, without braces —
`to_lower(DoS.response.body)`, `regex_replace(insertion_point_base_value, …)`
(`other/tokens/jwt-none-algorithm.bcheck:15,23`) — while the same names take braces outside a call.
**OBSERVED**

Variable interpolation is **cycle-checked at runtime**: `Zpa0.Zr(String)` (`Zpa0.java:276-289`) throws
`IllegalArgumentException("Recursive variable reference. Referenced variables: [a, b], current
variable: c")` — a recovered ZKM string. Implement the same guard. **OBSERVED**

---

## Q7 — `differs from`

Both corpus uses are the **same idiom**: send the real candidate, send a random-garbage control, and
report only if the candidate's response is distinguishable from the garbage one. Both quoted in full.

`examples/exposed-backup-file.bcheck:11-27`:
```
    11	given path then
    12	    if not({base.response.status_code} is "404") then
    13	        send request called check:
    14	            replacing path: {regex_replace({base.response.url.path}, "(.)/?$", `$1{extension}`)}
    15	
    16	        if {check.response.status_code} is {base.response.status_code} then
    17	            send request called garbage:
    18	                replacing path: {regex_replace({base.response.url.path}, "(.)/?$", `$1.{random_str(10)}`)}
    19	
    20	            if {garbage} differs from {check} then
    21	                report issue and continue:
    22	                    severity: info
    23	                    confidence: firm
    24	                    detail: `Backup file found at {check.request.url}`
    25	                    remediation: "Ensure your backup files are not exposed."
    26	            end if
    27	        end if
```

`other/bypass/PathSuffix_WAF_Proxy.bcheck:42-66`:
```
    42	given path then
    43	    if not ({base.response.status_code} is "200") then
    44	        send request called check:
    45	            appending path: {suffix}
    46	
    47	        if not({check.response.status_code} is {base.response.status_code}) then
    48	            send request called garbage:
    49	                appending path: `{random_str(10)}{suffix}`
    50	            if {garbage} differs from {check} then
    51	                if {base.response.status_code} matches "40(1|3)" and {check.response.status_code} is "200" then
    52	                    report issue and continue:
    53	                        severity: high
    54	                        confidence: firm
    55	                        detail: `Path access control bypass at {check.request.url}`
    56	                        remediation: "Ensure that the requested endpoint is only accessible to authorized users."
    57	                else if {check.response.status_code} matches "[12]0[0-9]" or {check.response.status_code} is "500" then
    58	                    report issue and continue:
    59	                        severity: high
    60	                        confidence: tentative
    61	                        detail: `Potential path access control bypass at {check.request.url}`
    62	                        remediation: "Manual review is required to confirm this issue. If there is a bypass, ensure that the requested endpoint is only accessible to authorized users."
    63	                end if
    64	            end if
    65	        end if
```

**Operands are whole named objects** — `{garbage}`, `{check}` — never properties. **OBSERVED**

**It is not byte equality. INFERRED, strongly.** In both files the two responses are for *different*
URLs (`/x.bak` vs `/x.<random>`, or `path+suffix` vs `path+random+suffix`). Any error page that reflects
the requested path — the overwhelmingly common case — would make the responses differ byte-for-byte
every time, so a byte comparison would make both checks fire on every path. They are published,
`#Verified` checks; the comparison must tolerate incidental variation.

Note also that both files **already compare status codes separately** (lines 16 / 47, 51, 57), so
`differs from` is contributing something *beyond* the status line — i.e. content.

**BURP tells us the mechanism. OBSERVED:** the context keeps request/responses under keys prefixed
`repeat:diff:`, exempt from the duplicate-name rule, with a dedicated cleanup pass:
```java
// Zpao.java:222
private static boolean lambda$getRequestToDiffAgainst$0(Map.Entry entry) {
    return ((String)entry.getKey()).startsWith(Zpao."repeat:diff:");
}
// Zpa0.java:294-299  (method name recovered from the lambda)
public void Zr() {   // clearRepeatedDiffRequestResponses
    this.Zb.keySet().stream().filter(Zpa0::lambda$clearRepeatedDiffRequestResponses$2).toList()
        .forEach(this.Zb::remove);
}
private static boolean lambda$clearRepeatedDiffRequestResponses$2(String string) {
    return string.startsWith(Zpa0."repeat:diff:");
}
```
"Repeat … to diff against" means Burp **re-issues a request to learn which parts of the response are
naturally volatile**, then compares only the stable parts.

That is precisely the machinery Burp exposes publicly as `ResponseVariationsAnalyzer` — confirmed
present in `montoya-api-2026.7.jar`:
```java
interface ResponseVariationsAnalyzer {
    Set<AttributeType> variantAttributes();
    Set<AttributeType> invariantAttributes();
    void updateWith(HttpResponse response);
}
```
with 33 `AttributeType`s:
`STATUS_CODE, ETAG_HEADER, LAST_MODIFIED_HEADER, CONTENT_TYPE, CONTENT_LENGTH, COOKIE_NAMES, TAG_NAMES,
TAG_IDS, DIV_IDS, BODY_CONTENT, VISIBLE_TEXT, WORD_COUNT, VISIBLE_WORD_COUNT, COMMENTS, INITIAL_CONTENT,
CANONICAL_LINK, PAGE_TITLE, FIRST_HEADER_TAG, HEADER_TAGS, ANCHOR_LABELS, INPUT_SUBMIT_LABELS,
BUTTON_SUBMIT_LABELS, CSS_CLASSES, LINE_COUNT, LIMITED_BODY_CONTENT, OUTBOUND_EDGE_COUNT,
OUTBOUND_EDGE_TAG_NAMES, INPUT_IMAGE_LABELS, CONTENT_LOCATION, LOCATION,
NON_HIDDEN_FORM_INPUT_TYPES, COLON_COUNT, HEADER_NAMES`

**Recommended implementation:** `A differs from B` = compute an attribute vector over both responses and
report a difference if any **invariant** attribute differs. A defensible starting subset that needs no
HTML parser: `STATUS_CODE`, `CONTENT_TYPE`, `WORD_COUNT`, `LINE_COUNT`, `COLON_COUNT`, `HEADER_NAMES`,
plus `PAGE_TITLE` if you have a cheap `<title>` extractor. Deliberately **exclude** `CONTENT_LENGTH` and
`BODY_CONTENT` — they are the ones a reflected path breaks. Tune against the two corpus checks; they are
your only regression tests for this operator, and at 0.8% of the corpus it is fine to ship M2 with
`differs from` unimplemented (raise a "check skipped" rather than a wrong finding).

---

---

## Property inventory (what the evaluator must actually resolve)

Every dotted path the corpus reads, with counts. Anything not listed is documented-but-unused.

| off `base` | n | off `latest` | n | off a named request | n |
|---|---|---|---|---|---|
| `.request.url.host` | 21 | `latest.response` (bare) | 1712 | `.response.body` | 196 |
| `.request.body` | 19 | `.response.body` | 114 | `.response.status_code` | 111 |
| `.response.status_code` | 17 | `.response.headers` | 23 | `.response.headers` | 100 |
| `.request.url` | 16 | `.response.status_code` | 19 | `.response` (bare) | 14 |
| `.request.headers` | 14 | `.request.url` | 5 | `.response.url` | 5 |
| `base.response` (bare) | 12 | `.response.url.path` | 3 | `.request.url` | 4 |
| `.request.method` | 9 | `.response.url.file` | 2 | `.request` (bare) | 1 |
| `.response.headers` | 9 | `.request.url.path` | 2 | | |
| `.request.url.path` | 4 | `.response.url.host` | 1 | | |
| `base.request` (bare) | 4 | | | | |
| `.response.url.path` | 2 | | | | |
| `.request.url.port` | 2 | | | | |
| `.response.body` | 1 | | | | |
| `.request.url.query` | 1 | | | | |
| `.request.url.file` | 1 | | | | |

Implementation notes that fall out of this:
- A **bare object** (`{base.response}`, `{latest.response}`, `{NAME.response}`) must stringify to the
  whole message for `in`/`matches`. `{latest.response}` bare is the single most common expression in
  the corpus by an order of magnitude — optimise that path.
- **`.url` is reachable from a response, not just a request** (`latest.response.url.path`,
  `base.response.url.path`), and `.url` itself decomposes into `.host .port .path .file .query`
  (`.protocol` is documented but unused).
- `{NAME.request}` bare is used once, inside a `detail:` string — so named requests must stringify too.

### Pre-defined variables

| variable | corpus uses | notes |
|---|---|---|
| `{user_agent}` | 6 | Always a `User-Agent:` value inside a **raw-request** backtick template, e.g. `CVE-2019-17662 - ThinVNC 10b1 - Auth Bypass.bcheck:16`. Never defined locally in any of the 6 files, confirming it is a builtin. Needed for M2 because raw requests otherwise ship no UA. |
| `{insertion_point_base_value}` | 3 | Only in `other/tokens/jwt-none-algorithm.bcheck:10,15,23`. v2-beta feature; M3 concern. Registered by BURP in the *variable* map at `Zpao.java:69`, guarded on `V1_BETA`-or-later **and** a non-null insertion point — so it is simply absent outside insertion-point checks. |
| `{query_string}` | 0 reads | Only ever seen as the write-side modifier `replacing query_string:` (`Perl Jam 2 - RCE.bcheck:22`). Documented as readable; unexercised. |
| `.http_version` | 0 | Documented on both request and response; never used. Safe to defer. |

---

## Runtime invariants (evaluator assertions)

1. `latest` is **never unbound**. At check entry `latest == base`. Assert on read.
2. `base` is **immutable** for the lifetime of a check execution; nothing may rebind it.
3. Every send — named, unnamed, `send request`, `send payload` — updates `latest` **before** any name
   binding, and **before** the next statement executes.
4. Request names are unique per check execution. Binding a name that already exists in *either* the
   request map or the variable map is an **error**, not a shadow.
5. `base` and `latest` are reserved; `send … called base:` / `called latest:` is an **error**.
6. Reading an unbound request name is an **error**, not an empty string.
7. Reserve an internal namespace (Burp uses the `repeat:` prefix) that is exempt from rules 4–6, and
   make sure user names can never enter it.
8. Variable interpolation is acyclic; detect cycles and fail with the referenced-variable chain.
9. `run for each` with k iterables of sizes n₁…n_k produces **∏nᵢ independent executions**, each with a
   **deep-copied context**. No named request, no `latest`, and no issue state leaks between iterations.
10. Modifiers on a send apply to a copy of `base.request` in source order; the outgoing request is never
    built from an empty template (except the raw-string form, which *is* the whole request).
11. `given response` checks must issue **zero** outbound requests — assert it; 105/105 corpus files hold.
12. A failed send binds an empty response and continues; it never propagates an exception out of the
    check, and it never reports an issue.
13. `report issue` (no `and continue`) halts the check; `report issue and continue` does not. Exactly one
    of these two must terminate.
14. Issues consolidate on (BCheck identity, issue name) — DOCS: *"Issues consolidate if same BCheck and
    same name"* — so the `name:` field is the dedup key, not the detail text.
15. Interpolated values are inserted **raw** — never auto-URL-encode, never assume UTF-8. Values must be
    byte-safe (`base64_decode` legitimately yields `\x0C`, `\xA0`, `\x85` straight into a path).

## Open items worth an A/B against real Burp

| Item | Status | Impact if wrong |
|---|---|---|
| Does plain `report issue` kill remaining `run for each` iterations? | AMBIGUOUS | **77 files** report differently depending on the answer — by far the biggest open risk |
| `given host` implicit base request composition | AMBIGUOUS | 9 header-appending host checks |
| `differs from` attribute set | INFERRED | 2 files; skip rather than guess wrong |
| Failed-send behaviour | INFERRED | multi-send checks where an early send fails |
| `removing X` then `appending X` | not in corpus (`removing` has **0** uses corpus-wide) | none today; accumulator model answers it |
| Repeated *scalar* same-part modifier | not in corpus | none today; last-write-wins |
| `md5`/`sha1`/`sha256` output encoding | UNVERIFIED | none today (0 users) |
| `send payload called NAME:` binding | UNVERIFIED | none today (0 uses); M3 concern |

Two counts worth reconciling with yours: by the strict rule "the `given` line is exactly
`given host|request|path then`", the corpus has **150** active files (99 + 40 + 11), not 139 — the
gap is presumably whether the 9 insertion-point files are being counted as active. Response files are
105 and every one of them issues **zero** sends, which is worth asserting in your dispatcher.
