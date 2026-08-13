# Ghauri-Go Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** A standalone, faithful Go port of ghauri 1.4.3 — the cross-platform SQL injection detection & exploitation framework — with core-logic parity (identical payloads, SQL extraction queries, detection control flow, and session-resume behavior) and idiomatic Go CLI/formatting.

**Architecture:** Single Go module `ghauri` with a `cmd/ghauri` CLI and `internal/` packages mirroring ghauri's Python package boundaries (`config`, `httpx`, `payload`, `tests`, `fingerprint`, `extract`, `inject`, `session`, `output`). Detection stays deterministic and sequential per-parameter; only data extraction is parallelized (bounded by `--threads`), exactly as in the Python original.

**Tech Stack:** Go 1.26, stdlib `net/http`, `modernc.org/sqlite` (pure-Go session resume, no cgo), `golang.org/x/net/html/charset`, `golang.org/x/term`, `fatih/color`.

**Reference source:** ghauri @ `https://github.com/r0oth3x49/ghauri` (cloned at `/tmp/opencode/ghauri`, tag v1.4.3). Every task names the exact Python file/line to port from.

**Fidelity contract** (agreed with user, "core logic parity"):
- MUST be byte-identical: payload SQL strings, placeholder substitution, extraction query construction, detection control flow order, session SQLite schema, regex patterns, page-ratio/unified-diff algorithms, sleep-time scheduling.
- MAY differ (idiomatic Go): CLI flag parsing (stdlib `flag`), ANSI output lib, pretty-table internals, session dir default (`os.UserConfigDir()`), UA randomizer (embedded list instead of `ua_generator`), and dropped features (`--update` live-fetch, `--version-check`, ASCII banner).
- The value of the port is that ghauri's Python binary and this Go binary, pointed at the same target, produce the same extracted data.

**Verification contract** (agreed with user): live vulnerable target — a Dockerized MySQL + PostgreSQL vulnerable app, with the Python original as a reference oracle for same-answer comparisons.

---

## Milestone 0: Workspace bootstrap

New module lives at `/root/ghauri-go` (sibling of `/root/burpsy-react-ui/burpsy-go`; it is intentionally NOT part of the burpsy workspace).

```bash
mkdir -p /root/ghauri-go && cd /root/ghauri-go
go mod init ghauri
git init
```

`verify.sh` analog: a top-level `verify.sh` that runs `gofmt -l .` (empty), `go vet ./...`, `go build ./...`, and `go test ./...`.

---

## Milestone 1: Foundation packages

### Task 1: `internal/config` — runtime options (`common/config.py`)

**Files:**
- Create: `internal/config/config.go`
- Reference: `ghauri/common/config.py` (154 lines)
- Test: `internal/config/config_test.go`

Port `GhauriConfigs` verbatim as `type Config struct`, one field per Python kwarg:

```go
type Config struct {
    Vectors            string
    IsString           bool
    IsJSON             bool
    IsXML              bool
    IsMultipart        bool
    SkipURLEncoding    bool
    Filepaths          string
    Proxy              string
    TextOnly           bool
    String             string
    NotString          string
    Code               string
    MatchRatio         float64
    Retry              int
    Base               string
    Attack01           string
    Delay              float64
    TimeSec            int
    Timeout            float64
    Backend            string
    Batch              bool
    ContinueOnHTTPError bool
    FollowRedirects    *bool
    Threads            int
    // added for port: parsed session/log/target filepaths, injectable payload list
    SessionFilepath string
    // runtime state set by CLI/engine (mirrors conf._multitarget_csv etc.)
}
```

Also port the `SessionFactory` filepath logic (`common/session.py:95-140`): `~/.ghauri/<host>` becomes `os.UserConfigDir()/ghauri/<host>/` with `session.sqlite`, `log`, `target.txt`. Flush semantics identical.

**Step 1: Write the failing test** — assert default config values match Python defaults (retry=3, timesec=5, delay=0).

**Step 2: Run** — `go test ./internal/config/` → FAIL (file missing).

**Step 3: Implement.**

**Step 4: Run** — PASS.

**Step 5: Commit** — `feat(config): port GhauriConfigs + session filepath layout`.

### Task 2: `internal/httpx` — request engine (`core/request.py` + `common/utils.py` HTTP parts)

**Files:**
- Create: `internal/httpx/request.go`, `internal/httpx/urlencode.go`, `internal/httpx/burpparse.go`, `internal/httpx/ua.go`
- Reference: `ghauri/core/request.py` (277 lines), `ghauri/common/utils.py` (`HTTPRequest`, `parse_burp_request`, `urlencode`, `urldecode`, `is_encoded`, `check_encoded`)
- Test: `internal/httpx/request_test.go`, `internal/httpx/urlencode_test.go`, `internal/httpx/burpparse_test.go`

Port `HTTPRequestHandler` (request.py) to a `Client` struct wrapping `*http.Client`:

- **Retries** (`--retries`, default 3): identical backoff behavior.
- **Redirects**: port `SmartRedirectHandler` — ghauri's 302 handling that re-issues the original method/body on redirect (not GET-follow). Implement via custom `CheckRedirect`.
- **Proxy** (`--proxy`): `http.ProxyURL`.
- **Timeout** (`--timeout`): per-request `context.WithTimeout`.
- **Delay** (`--delay`): sleep before each request.
- **TLS** (`--force-ssl`): force `https://`; also honor ghauri's `verify=False`-style behavior — ghauri disables cert verification; port that deliberately (it is an attacker tool; keep a `InsecureSkipVerify` flag, default true, documented).
- **`--random-agent` / `--mobile` / `--user-agent`**: `internal/httpx/ua.go` embedded UA list.
- **Response body**: keep raw bytes + detect charset via `x/net/html/charset` (`NewReader`-equivalent on a `bytes.Reader`), decode to UTF-8 string — this replaces `chardet`.

`urlencode.go` ports `urlencode(value)` (which Python-`quote`s preserving some chars — read the ghauri source and mirror the safe set), `urldecode`, `is_encoded`, `check_encoded` — used by detection to decide whether to encode payloads.

`burpparse.go` ports `parse_burp_request(request_text)` → a struct `BurpRequest{Method, URL, Headers, Body, Cookies}`. It reuses the `HTTPRequest` stdlib-based parser. Write a fixture test with a real Burp capture.

**Step 1: Write failing tests** — (a) `parse_burp_request` over a fixture raw request; (b) urlencode round-trip; (c) redirect re-issues POST (mock server).

**Step 2: Run** — FAIL.

**Step 3: Implement.**

**Step 4: Run** — PASS.

**Step 5: Commit** — `feat(httpx): port request handler, Burp parser, urlencoding, UA`.

### Task 3: `internal/payload` — the SQL corpus (`common/payloads.py`, 2128 lines)

**Files:**
- Create: `internal/payload/payloads.go`, `internal/payload/extraction.go`, `internal/payload/regexes.go`, `internal/payload/gen/main.go` (generator), `internal/payload/payloads_test.go`
- Reference: `ghauri/common/payloads.py`

This is the largest mechanical task. The corpus is four big dicts:

1. `PAYLOADS` — `{"BooleanTests": {"boolean-based": [ {payload, comments[], title, vector, dbms} ]}, "MySQL": {"inline-query": [], "stacked-queries": [...], "union": [...]}, ...}` for MySQL (line 326), MSSQL (1157), PostgreSQL (1494), Oracle (1654).
2. `PAYLOADS_BANNER/CURRENT_USER/CURRENT_DATABASE/HOSTNAME` — per-DBMS expression lists.
3. `PAYLOADS_DBS_COUNT/DBS_NAMES/TBLS_COUNT/TBLS_NAMES/COLS_COUNT/COLS_NAMES/RECS_COUNT/RECS_DUMP` — extraction query templates (line 1906+).
4. `NUMBER_OF_CHARACTERS_PAYLOADS`, `LENGTH_PAYLOADS`, `DATA_EXTRACTION_PAYLOADS` (line 27-89).

**Strategy: a code generator.** Write `internal/payload/gen/main.go` that parses `payloads.py` with a small Python-to-Go converter (regex over the dict literal structure — do NOT hand-transcribe 2100 lines; the risk of silent transcription error is exactly the honesty trap this project must avoid). Output typed Go:

```go
type Comment struct{ Pref, Suf string }

type Payload struct {
    Payload  string
    Comments []Comment
    Title    string
    Vector   string
    DBMS     string
}

type TestGroup struct {
    BooleanTests map[string][]Payload // keyed "boolean-based"
    DBMS         map[string]DBMSTests // MySQL, Microsoft SQL Server, PostgreSQL, Oracle
}
```

The generator is checked in along with its output; `go:generate` regenerates. **A conformance test** reads `payloads.py` again and asserts the generated Go data round-trips (same count of payloads per section, same payload strings). This conformance test is the anti-`LIMIT_EXCEEDED` guard of this task — it makes "honest counting" enforceable at CI time.

**Step 1: Write the failing test** — conformance test asserts generated payload count == Python count (parse Python, compare). FAIL initially (no generator yet).

**Step 2: Run** — FAIL.

**Step 3: Implement generator + generated data.**

**Step 4: Run** — PASS (counts + string equality).

**Step 5: Commit** — `feat(payload): generate SQL corpus from payloads.py with conformance test`.

---

## Milestone 2: Detection engine

### Task 4: `internal/tests` — basic check + DBMS candidates (`core/tests.py` part 1)

**Files:**
- Create: `internal/tests/basic.go`, `internal/tests/errors.go`
- Reference: `ghauri/core/tests.py` `basic_check` (lines ~100-180), `ghauri/common/lib.py` `SQL_ERRORS` (line 105)
- Test: `internal/tests/basic_test.go`

Port `basic_check` — sends benign requests, applies `SQL_ERRORS` DBMS-specific regexes to raw responses, returns candidate DBMSes. `internal/tests/errors.go` ports `SQL_ERRORS` as a `map[string][]*regexp.Regexp` (MySQL, PostgreSQL, Oracle, MSSQL, Access, SQLite). Conformance test: every regex must compile (Python `re` → Go `regexp` — note Go lacks `(?s)`/`(?i)` inline multi-flag quirks; convert flags via `(?is)` prefix which Go supports as `(?is)` — verify each pattern compiles and matches its own Python-compiled counterpart on sample strings).

**Step 1-4:** TDD as above.

**Step 5: Commit** — `feat(tests): basic_check + DBMS SQL_ERRORS port`.

### Task 5: `internal/tests` — boolean detection (`check_booleanbased_sqli`, `confirm_booleanbased_sqli`)

**Files:**
- Create: `internal/tests/boolean.go`, `internal/page/page.go` (moved here for cohesion)
- Reference: `ghauri/core/tests.py` lines 466-980; `common/utils.py` `get_page_ratio_difference`, `check_page_difference`, `check_boolean_responses`, `get_filtered_page_content`, `html_escape`, `get_boolean_ratio`
- Test: `internal/tests/boolean_test.go`

Port the page-difference machinery first (`internal/page`): `get_filtered_page_content`, `html_escape`, `get_boolean_ratio`, `get_page_ratio_difference`, `check_page_difference`, `get_page_by_unified_diff` (needs a Go port of Python's `difflib.SequenceMatcher` — implement `sequenceMatcher` in `internal/page/difflib.go`; it is ~150 lines and well-specified). Then port `confirm_booleanbased_sqli`/`check_booleanbased_sqli`: iterate `BooleanTests` payloads, apply each `comments` pref/suf, compare true vs false response pages, record matches. Preserve iteration order.

**Step 1-5:** TDD; commit `feat(tests): boolean-based detection with page-diff machinery`.

### Task 6: `internal/tests` — time-based detection (`check_timebased_sqli`)

**Files:**
- Create: `internal/tests/time.go`
- Reference: `ghauri/core/tests.py` lines 985-1266
- Test: `internal/tests/time_test.go`

Port calibration exactly: benchmark normal latency; build sleep candidates from `range(0, 10) != injected_sleep_time`; run the inference set; compare response times against the `[SLEEPTIME]` threshold. Uses `internal/httpx` delay mechanism. **Determinism note:** ghauri picks the sleep value from `time-sec`; keep the same candidate selection.

**Step 1-5:** TDD; commit `feat(tests): time-based detection`.

### Task 7: `internal/tests` — error + union detection + `check_injections` orchestrator

**Files:**
- Create: `internal/tests/error.go`, `internal/tests/union.go`, `internal/tests/discover.go`, `internal/tests/check_session.go`
- Reference: `ghauri/core/tests.py` `check_errorbased_sqli` (1267-1553), union checks (1554-2140), `check_injections` (2141-2519)
- Test: `internal/tests/injections_test.go`

Port `check_errorbased_sqli` (uses `REGEX_*` capture groups from payload/regexes.go). Port union detection: column count via `ORDER BY`/`NULL` padding, then position discovery. Finally port `check_injections`: the full orchestration — per-param, per-technique (BTEU order honoring `--technique`), producing `[]InjectablePayload` (`{Parameter, Technique, Title, Vector, Payload, DBMS, ...}`) with session-resume integration (`check_session`). This struct is the handoff to extraction.

**Step 1-5:** TDD; commit `feat(tests): error/union detection + check_injections orchestration`.

### Task 8: `internal/fingerprint` — DBMS fingerprint (`dbms/fingerprint.py`)

**Files:**
- Create: `internal/fingerprint/fingerprint.go`
- Reference: `ghauri/dbms/fingerprint.py` (603 lines)
- Test: `internal/fingerprint/fingerprint_test.go`

Port `FingerPrintDBMS`: heuristic tests per candidate DBMS (versions, banner, error messages), then extended tests. Honors `--dbms`. Preserves the "the back-end DBMS is not X" negative confirmation flow.

**Step 1-5:** TDD; commit `feat(fingerprint): DBMS fingerprinting`.

---

## Milestone 3: Extraction engine

### Task 9: `internal/extract` — core extractor (`core/extract.py`, 2852 lines — biggest single port)

**Files:**
- Create: `internal/extract/extractor.go`, `internal/extract/operators.go`, `internal/extract/search.go`
- Reference: `ghauri/core/extract.py`
- Test: `internal/extract/extractor_test.go`

Port `GhauriExtractor` method-by-method:
- `_check_operator` / `--fetch-using` dispatch (`in`, `between`, `binary`, `equal` operators)
- `validate_character`
- `fetch_noc` (number of characters), `fetch_length`, `fetch_characters`
- `_search_using_in_operator`, `_search_using_between_operator`, `_binary_search`, `_linear_search` — the char-space search strategies
- `fetch_using_error_based_vector` (error-based reflection extraction)
- The main extraction loop (`fetch_characters` → `fetch_length` → repeat), with `fetch-using` divergence

The SQL expression templates come from `internal/payload/extraction.go` (`NUMBER_OF_CHARACTERS_PAYLOADS` etc.). Conformance: extracted value == Python ghauri value on the live target.

**Step 1-5:** TDD (unit-test each search strategy against a mock response injector first, then live target in Milestone 5); commit `feat(extract): GhauriExtractor core`.

### Task 10: `internal/extract` — advanced extraction (`extractor/common.py` + `advance.py`)

**Files:**
- Create: `internal/extract/common.go`, `internal/extract/advance.go`
- Reference: `ghauri/extractor/common.py` (407), `ghauri/extractor/advance.py` (1029)
- Test: `internal/extract/advance_test.go`

Port `GhauriCommon` (banner, current-user/current-db/hostname retrieval) and `GhauriAdvance`: `fetch_dbs`, `fetch_tables`, `fetch_columns`, `dump_table` (with `--start`/`--stop` paging and `--count`), and the `__execute_expression` loop. This is where `PAYLOADS_DBS_NAMES`/`TBLS_NAMES`/`COLS_NAMES`/`RECS_DUMP` templates get executed per technique.

**Step 1-5:** TDD; commit `feat(extract): advance extraction (dbs/tables/columns/dump)`.

### Task 11: `internal/session` — SQLite resume (`common/session.py`)

**Files:**
- Create: `internal/session/session.go`, `internal/session/storage.go`
- Reference: `ghauri/common/session.py`, `ghauri/common/lib.py` `SESSION_STATEMENETS` (line 252)
- Test: `internal/session/session_test.go`

Port the full `SessionFactory` over `modernc.org/sqlite`: `fetchall`, `execute_query`, `generate_filepath`, `dump_to_csv`, and the schema (`tbl_payload`, `storage` with `idx_type`). `PAYLOAD_STATEMENT`, `STORAGE_*` statements port as constants. Conformance test: create a DB with the Go port, run the Python ghauri against the same DB file and assert compatible schema/rows (cross-tool resume is a stretch goal — same-schema is the requirement).

**Step 1-5:** TDD; commit `feat(session): SQLite session/resume`.

### Task 12: `internal/inject` — expression injection + SQL shell (`core/inject.py`)

**Files:**
- Create: `internal/inject/inject.go`
- Reference: `ghauri/core/inject.py` (209), `ghauri/scripts/ghauri.py` sql-shell
- Test: `internal/inject/inject_test.go`

Port `inject_expression` (used by `--fetch-using` and dump internals). Port `--sql-shell` interactive loop (read line → inject_expression → print) with `x/term` for the optional password prompt.

**Step 1-5:** TDD; commit `feat(inject): expression injection + sql-shell`.

---

## Milestone 4: CLI + output

### Task 13: `internal/output` — pretty table + ratio/banner utils

**Files:**
- Create: `internal/output/table.go`, `internal/output/ratio.go`
- Reference: `ghauri/common/prettytable.py` (1475), `ghauri/common/colors.py`, `ghauri/common/banner.py`
- Test: `internal/output/table_test.go`

Port the pretty-table layout (column alignment, wrapping, unicode box drawing) to `internal/output/table.go`. `colors.py` → `fatih/color` mapping table. Skip banner; port `get_boolean_ratio`/`get_page_ratio_difference` into `internal/page` (moved in Task 5).

**Step 1-5:** TDD; commit `feat(output): pretty table + colors`.

### Task 14: `cmd/ghauri` — CLI (`scripts/ghauri.py`)

**Files:**
- Create: `cmd/ghauri/main.go`, `cmd/ghauri/flags.go`
- Reference: `ghauri/scripts/ghauri.py` (611) + `ghauri/ghauri.py` (1271)
- Test: `cmd/ghauri/main_test.go`

Port every flag per the mapping table in the design doc (Section 4). Wire: parse flags → build `config.Config` → `perform_injection` equivalent (`ghauri/ghauri.py` `perform_injection`, `perform_multitarget_injection`) → print results. `--batch` auto-answers prompts; `--confirm` forces a prompt. Multi-target `-m` mode supported if present in source.

**Step 1-5:** TDD (flag-parsing tests + a help-output golden test); commit `feat(cli): ghauri CLI entrypoint`.

---

## Milestone 5: Verification (the gate)

### Task 15: Live vulnerable target harness

**Files:**
- Create: `testdata/docker-compose.yml`, `testdata/vulnapp/` (minimal Go/PHP app with SQLi), `testdata/README.md`, `e2e-live.sh`
- Reference: none (new)

Docker Compose bringing up:
- **MySQL 8** + **PostgreSQL 16** containers
- A minimal vulnerable app (Go `net/http`, one endpoint per injection class: GET param, POST form, JSON body) whose queries interpolate raw input (refuse-by-default is a burpsy value, but this is a *test target* — its whole purpose is to be vulnerable; document that clearly).

**Step 1:** Write `e2e-live.sh` that brings up compose, waits for health, runs both binaries.
**Step 2:** Run the Python ghauri (`/tmp/opencode/ghauri`) against each endpoint → record answers (banner, current-db, dbs, tables, columns, dump, boolean/time/error/union technique detection) into `testdata/expected/*.json`.
**Step 3:** Run the Go port with identical flags → produce `testdata/actual/*.json`.
**Step 4:** A comparison script (`testdata/compare.go` or shell) asserts actual == expected for every field.
**Step 5: Commit** — `test(verify): live vulnerable target + Python oracle comparison`.

### Task 16: Final gate + docs

**Files:**
- Modify: `verify.sh`, create `README.md`, `docs/PORT_STATUS.md`

`verify.sh` (the gate, modeled on burpsy's): gofmt clean, `go vet`, zero-warning `go build ./...`, `go test ./...`, payload conformance test, then `e2e-live.sh` unless `QUICK=1`. `PORT_STATUS.md` reports honestly: which ghauri features are ported, which differ deliberately, and which are unimplemented — mirroring burpsy's "honest counting" value.

---

## Milestone 6: Stretch (only after all above green)

- Union-based in-band data extraction fast path (`extractor/common.py` union dump) — port if time allows; otherwise the blind loop covers union targets (documented as a gap in PORT_STATUS.md).
- Cross-tool resume: run Python ghauri, then Go ghauri `--fresh-queries=false` against the same session.sqlite.
- Multi-target `-m`/CSV batch mode parity.

---

## Sequencing notes

- Task 3 (payload generator + conformance test) blocks Tasks 4-12; do it early and get the conformance gate running — it is the anti-honesty-trap control of the whole port.
- Task 5 (page-diff machinery) must precede Task 6 and Task 9; both depend on `internal/page`.
- Milestone 5 can be partially parallelized: compose file can be written while extraction tasks are in flight, but the oracle-record/compare steps wait on a working CLI.
- Each task commits atomically with the "full sentence" commit style this project's AGENTS.md demands.

## Verification checklist (definition of done for the whole port)

- [ ] `go build ./...` zero warnings; `go vet` clean; `gofmt` clean.
- [ ] `go test ./...` green.
- [ ] Payload conformance test green: generated Go corpus == Python `payloads.py` (counts + strings).
- [ ] All regexes compile and match their Python-compiled behavior on sample strings.
- [ ] `e2e-live.sh` green: Go output == Python oracle output for banner/current-db/dbs/tables/columns/dump and boolean/time/error/union detection on MySQL and PostgreSQL.
- [ ] `PORT_STATUS.md` names every unimplemented feature honestly.
