# Burp Scanner — engine architecture, file map, and mechanics

Derived from the deobfuscated tree (`out/clean/root/`), bytecode specs (`out/specs/`), recovered
method names (`out/names/all_renames.tsv`), recovered string literals (`out/strings/map_root.tsv`),
and the shipped data resources. Every claim below cites the artifact it came from.

> **Two corrections to `SCANNER_MAP.md`**, found by reading the actual code:
> - `burp.Zi96` is **not** the audit-item store — it is the *custom scan-check tester* UI
>   (`JTabbedPane` with tabs `Audit items` / `Issue activity` / `Event log` / `Logger`).
> - `burp.Zq5` is **not** the insertion-point cap — it is the **audit-item status enum** (15 states).
>   The cap message lives on its `LIMIT_EXCEEDED` constant.

---

## 1. The three taxonomy enums — the engine's backbone

These are the spine of the whole scanner, and crucially **their constant names survived obfuscation**
(enum constant names are retained by the `Enum` machinery).

### 1.1 `burp.Zcot` — issue types. **Exactly 183 constants.**

Matches the 183 `resources/KnowledgeBase/Issues/*.json` files 1:1. Implements `burp.Zp9h`.

```java
OS_COMMAND_INJECTION, SQL_INJECTION, SQL_INJECTION_2ND_ORDER, ASP_NET_TRACING_ENABLED,
FILE_PATH_TRAVERSAL, XML_EXTERNAL_ENTITY_INJECTION, LDAP_INJECTION, XPATH_INJECTION,
XML_INJECTION, ASP_NET_DEBUGGING_ENABLED, BROKEN_ACCESS_CONTROL, HTTP_PUT_METHOD_IS_ENABLED,
OUT_OF_BAND_RESOURCE_LOAD_HTTP, FILE_PATH_MANIPULATION, PHP_CODE_INJECTION,
SERVER_SIDE_JAVASCRIPT_CODE_INJECTION, PERL_CODE_INJECTION, RUBY_CODE_INJECTION,
PYTHON_CODE_INJECTION, … (183 total)
```

Each pairs with a JSON definition carrying `typeIndex` (stable numeric ID), `name`,
`typicalSeverity`, `description`, `remediation`, `references[]`,
`vulnerabilityClassifications[]` (CWE). Severity distribution across the catalog:
**68 INFO, 57 HIGH, 36 LOW, 22 MEDIUM**. Filenames encode the ID in hex —
`00100200_SqlInjection.json` ⇒ `typeIndex 1049088 = 0x00100200`.

Extracted to `out/scanner_spec/issue_catalog.tsv`; raw data copied to `out/scanner_spec/issues/`.

### 1.2 `burp.Zefx` — audit phases. 7 constants.

```java
A1, A2, A3, A4, A5, S2, S3
    private final byte ZT;                                      // permanent index
    private final BiFunction<Zggx, Boolean, Boolean> Zs;        // enablement predicate vs config
    public boolean ZH(Zggx config, boolean flag);               // "is this phase enabled?"
    public boolean ZK();
```

`A*` = active phases, `S*` = stored/second-order phases. The `BiFunction` against `Zggx` (the
scan-configuration object) is how a phase is switched on/off by config — this is the code-side
counterpart of the `scan_type_*` keys in §4.

`Zcud` passes `Zefx.A1` for ordinary active checks and `Zefx.A4` for *stored* per-insertion-point
checks.

### 1.3 `burp.Zq5` — audit-item status machine. 15 states.

```java
PENDING, AUDITING, AUDITED,
LIGHT_AUDITING, LIGHT_AUDITED, NOT_LIGHT_AUDITED,
SKIPPED_PARAMETER_TYPE, SKIPPED_INSERTION_POINT_TYPE, SKIPPED_BY_SELECTION,
NO_PARAMETER_MOVEMENT, NO_INSERTION_POINT_CHECKS, NO_NESTING_ALLOWED,
LIMIT_EXCEEDED, FAILED_TO_SCAN, CANCELLED;

public static final Set<Zq5> NON_TERMINAL_STATUSES;
public static final Set<Zq5> COMPLETED_AUDIT_STATUSES;
public final byte permanentIndex;      // persisted in the project file
public final String shortLabel, label;
public final Zuiw icon;
public static Zq5 ZI(byte permanentIndex);   // recovered name: fromPermanentIndex
```

This is the per-insertion-point lifecycle. `LIMIT_EXCEEDED` carries the strings
*"Burp Scanner didn't audit this insertion point, as it reached the maximum limit of insertion
points to audit per request"*, and `CANCELLED` the *"…as this audit item was cancelled"* variant.

`NON_TERMINAL_STATUSES` / `COMPLETED_AUDIT_STATUSES` are how the engine decides what is still
outstanding — the basis of progress reporting and resumability.

---

## 2. Check dispatch — `burp.Zcud` (135 lines, abstract)

**The most important file in the engine.** It defines *how often* a check runs, which is the primary
determinant of both coverage and cost. Seven dispatch scopes, each a paired
public-factory / protected-abstract-supplier:

| Scope (recovered name) | Factory | Supplier | Runs |
|---|---|---|---|
| `getActivePerUrlChecksFactory` | `Zh` | `Zj` | once per URL |
| `getActivePerPathChecksFactory` | `Zu` | `Zx` | once per path |
| `getActivePerHostChecksFactory` | `ZQ` | `ZG` | once per host |
| `getActivePerRequestChecksFactory` | `Zn` | `Zm` | once per request |
| `getInSessionActivePerRequestChecksFactory` | `ZM` | `ZL` | per request, session-valid |
| **`getActivePerInsertionPointChecksFactory`** | `Zk` | `Zr` | **per insertion point** ← cost centre |
| **`getStoredActivePerInsertionPointChecksFactory`** | `ZP` | `ZC` | per insertion point, stored/2nd-order |

Type split: `Zi28` = check for non-insertion-point scopes, `Zuit` = insertion-point check.
`Zb79<T>` is the returned **lazy factory** — checks are *not* instantiated at registration.

### The filter-then-instantiate pipeline

```java
private <T extends Zi28> List<T> Zh(Zckx phase, Zgx0 ctx, Collection<Zb2q> pts, List<Zwy6<T>> descriptors) {
   return descriptors.stream()
       .filter(this::lambda$filterChecks$7)   // d.Zr(ZN)  -> enabled in config?
       .filter(this::lambda$filterChecks$8)   // d.Zz(ZY, phase, ctx, pts) -> applicable here?
       .map(Zwy6::ZP)                          // instantiate ONLY survivors
       .collect(Collectors.toList());
}
```

Three properties worth copying in any reimplementation:

1. **Two-stage filtering before construction.** `Zwy6<T>` is a check *descriptor*; `.ZP()` is the
   instantiation. Config-disabled and non-applicable checks are eliminated while still cheap
   descriptors. Nothing heavyweight is allocated for a check that will not run.
2. **Laziness at the scope boundary.** Returning `Zb79<T>` (a supplier) means the check list for a
   scope is built on demand, not eagerly for the whole scan.
3. **Phase is a first-class argument** (`Zefx.A1` vs `Zefx.A4`), so the same descriptor set is
   reused across phases with different applicability.

`Zhgv Zd` supplies per-scope context: `Zd.ZG(req, ctx)` for live insertion points,
`Zd.Zf(req, storedReq, ctx)` for the stored variant — i.e. the stored path threads *two* requests.

---

## 3. Insertion-point pipeline

The expansion step: one request ⇒ N attack positions. Memory and request count both scale here.

### 3.1 `burp.Zuq` (1,479 lines) — the builder

Recovered method names give the full taxonomy directly:

```
addUrlFilenameInsertionPoint                        addUrlFoldersInsertionPoints
addUrlAndBodyParameterInsertionPoints               addNewParameterNameInsertionPoint
addStandaloneTagInsertionPoint                      addNewReferHeaderInsertionPoint
addPhpFileRequestInsertionPoint                     addSwitchedBodyParameterLocationInsertionPoints
buildNestedInsertionPoint                           getMovedParameterInsertionPoint
```

Its string constants — `Referer`, `User-Agent`, `\r\n\r\n`, `https://example.com/` — confirm it
synthesises headers as attack surface, not merely existing parameters. Note
`addSwitchedBodyParameterLocationInsertionPoints` and `getMovedParameterInsertionPoint`: Burp
*relocates* parameters (body↔query) to find parsing inconsistencies, and
`buildNestedInsertionPoint` recurses into nested encodings (JSON-in-param, base64, etc.).
`NO_NESTING_ALLOWED` in `Zq5` is the corresponding stop condition.

These map **1:1 onto the config keys** in §4 (`insert_url_path_filename`, `insert_body_params`,
`insert_param_name`, `insert_http_headers`, …), so this taxonomy is authoritative from two
independent directions.

### 3.2 Supporting cast

| Class | Role | Evidence |
|---|---|---|
| `burp.Zeed` (615) | provider registry | string `Scanner insertion point providers` |
| `burp.Zemw` (413) | provider validation | `Insertion point provider cannot be null.` |
| `burp.Zg9v` (70) | strategy selection | string `Insertion points strategy` |
| `burp.Zcur` | user-defined points | `Scan defined insertion points` |
| `burp.Zb2q` | the point type itself | `current insertion point`; appears as `Collection<Zb2q>` throughout `Zcud` |
| `burp.Zbju` (29) | **legacy→Montoya adapter** | see below |

`Zbju` is the cleanest file in the subsystem and shows the extension boundary exactly:

```java
public class Zbju implements AuditInsertionPointProvider {          // Montoya (public)
   private final IScannerInsertionPointProvider Zd;                 // legacy (pre-Montoya)
   public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse rr) {
      Zgzf wrapped = new Zgzf(rr, this.Zy);
      List raw = this.Zd.getInsertionPoints(wrapped);
      return raw == null ? null
           : raw.stream().filter(Objects::nonNull)
                .map(p -> new Zcpl(p, this.Zy))   // adapter per point
                .collect(Collectors.toList());
   }
}
```

So third-party insertion points enter through a legacy shim wrapped per-item — `Zcpl` is the
adapter, `Zgzf` the request wrapper.

---

## 4. Configuration — the engine is largely data-driven

Union of keys across the 29 files in `resources/BuiltInConfigs/` (copied to
`out/scanner_spec/configs/`). This *is* the engine's rule surface.

**Scan-type buckets** (`/scanner/issues_reported/`) — 5 phases, matching `Zefx`:
```
scan_type_passive              scan_type_light_active     scan_type_medium_active
scan_type_intrusive_active     scan_type_javascript_analysis
select_individual_issues       selected_issues[]          store_issues_within_queue_items
```

**Insertion-point types** (`/scanner/insertion_point_types/`) — 8, matching `Zuq`:
```
insert_url_params  insert_body_params  insert_param_name  insert_cookies
insert_http_headers  insert_entire_body  insert_url_path_filename  insert_url_path_folders
```

**Frequently-occurring shortcut** (`/scanner/frequently_occurring_insertion_points/`) — the same 8
as `quick_scan_*`. A cheaper pass over common positions.

**Skips** (`/scanner/ignored_insertion_points/`):
```
skip_all_tests_for_parameters[]      skip_server_side_injection_for_parameters[]
```

**Audit tuning** (`/scanner/audit_optimization/`):
```
scan_accuracy   scan_speed   skip_ineffective_checks   consolidate_passive_issues
follow_redirections   maintain_session   maximum_crawl_and_audit_time
```

**Error handling / backpressure** (`/scanner/error_handling/`) — the resilience model:
```
consecutive_audit_check_failures_to_skip_insertion_point
consecutive_insertion_point_failures_to_fail_audit_item
number_of_follow_up_passes
pause_task_failed_audit_item_count
pause_task_failed_audit_item_percentage
```
Confirmed live in `burp.Zgff`, which ships a "Disable error handling" preset setting all five to 0.
This is a **two-level circuit breaker**: N check failures ⇒ skip the insertion point; N insertion-point
failures ⇒ fail the audit item; then count/percentage thresholds pause the whole task.

**Crawler** (`/crawler/`): `crawl_limits/{maximum_crawl_time,maximum_request_count,maximum_unique_locations}`,
`crawl_optimization/{crawl_strategy,dom_idle_threshold,network_idle_threshold,await_navigation_timeout}`,
`live_passive_crawl/{add_all_urls,add_links,add_form_submissions,add_item_itself,add_same_domain,add_urls_in_scope,scope_type,custom_scope}`.

---

## 5. Issue consolidation — `burp.Zbvp` (86 lines)

A **chain-of-responsibility** handler (`extends Zbvm`, delegates via `this.ZE.ZE(issue)`):

```java
private final Map<Short, List<Zco9>> Zd;   // issues bucketed by short key (type index)
private final Zwlr ZY;                     // match counter
private final List<Zco9> ZT;               // existing issues to compare against
private final short ZN;                    // this handler's bucket key

public void ZE(Zco9 issue) {               // recovered: handle
   if (Zd(issue)) {
      List same = Zo(issue, this.ZT);      // recovered: findIssuesOfSameType
      if (this.Zu(issue, same)) {          // recovered: shouldMergeIssues
         this.Zd.computeIfAbsent(this.ZN, …).add(issue);
      }
   }
   this.ZE.ZE(issue);                      // pass down the chain
}

private boolean Zu(Zco9 issue, List<Zco9> same) {
   if (issue.ZxR() == Zcot.JWT_WEAK_HMAC_SECRET)          // per-type special case
      return same.stream().map(…).anyMatch(issue.Zxi().ZZ()::equals);
   return this.ZY.Zn(same) + 1 > 1;                        // generic: merge if a match exists
}
```

Two things to note: dedup is **keyed on `Zcot`** (so on the 183-type taxonomy), and it has
**per-type override hooks** — `JWT_WEAK_HMAC_SECRET` merges on the *recovered secret value* rather
than on generic equality. Expect other special cases in sibling handlers.

`burp.Zby4` (118) supplies the metrics side: `getNumberOfUniqueValuesScanned`,
`getNumberOfDifferentSetsOfIssueTypes`, `getCrcForIssueTypes`, `getScanCountForValue` — a CRC over
the issue-type set, used to recognise "same finding shape" cheaply.

Other issue-lifecycle files: `Zc_q` `makeIssue`, `Zb2g` `writeIssue`, `Zcjj` `findIssues`,
`Zc8l` `deleteIssues`, `Ze3h` model/tree events (`onIssuesAdded/Removed/Superseded/Updated`,
`notifyIssueSignificancePropagationListeners`), `Zcps` (1,567) `refreshAuditIssueHandlers` +
`getScannerCheckWrapperFor` (the extension check bridge).

---

## 6. Task launch, crawl, and live audit

| Class | Lines | Role |
|---|---|---|
| `burp.Zeqc` | 1,273 | **scan launcher** — `launchScan`, `launchScanTask`, `resumeScan`, `scanConfig`, `validateSeedUrls`, `getOpenApiScanLaunchConfiguration`, `getGenericApiScanLaunchConfiguration`, `getAuthenticationModels`, `applicationLoginConfig`, `resourcePoolSelectionConfig`; string `No scan task found` |
| `burp.Ze0s` | — | `launchApiScan`, `launchWebappScan` |
| `burp.Zc16` | 223 | `startCrawl`, `finishCrawl` |
| `burp.Zbcc` | 118 | `adaptCrawlToRelativeProgress`, `adaptAuditToRelativeProgress`, `adaptEvents` — normalises crawl and audit progress onto one scale |
| `burp.Zrb9` | 286 | task views — `buildCrawlTaskView`, `buildAuditTaskView`, `buildCrawlAndAuditTaskView`, **`buildLiveAuditTaskView`**, `buildLivePassiveCrawlTaskView` |
| `burp.Zhwl` | — | live-audit launcher UI — `Live audit`, `Live audit (Pro version only)`, `liveTaskLauncherScanDetailsLiveAuditTaskTypeRadioButton` |
| `burp.Zmps` | — | `livePassiveCrawlTaskAdded` |
| `burp.Zc0e` / `Zpxe` | — | `crawler.live_passive_crawl.*` config binding |
| `burp.Zf9d` | 190 | audit-item observable wrapper — guards `Should not be adding/removing/setting new audit items via the observable wrapper` |
| `burp.Zb56` | — | project migration — `migrateActiveScanQueue`, `migrateIssueActivityLog`, `Legacy scan queue items` |
| `burp.Zbmw` | — | `convertAuditItems` |

`Zrb9` shows the five task shapes are one family: **Crawl**, **Audit**, **Crawl+Audit**,
**Live audit**, **Live passive crawl**. Live audit is not a separate engine — it is the same audit
pipeline fed from proxy traffic instead of a crawler frontier.

---

## 7. Data resources the engine consumes

| Path | Size | Purpose |
|---|---|---|
| `resources/KnowledgeBase/Issues/` | 1.6 MB, 366 files | 183 JSON definitions + 183 HTML descriptions |
| `resources/BuiltInConfigs/` | 124 KB, 29 files | scan/crawl presets (the rule surface) |
| `resources/Scanner/jwt_secrets.txt` | 1.1 MB | JWT weak-secret wordlist (feeds `JWT_WEAK_HMAC_SECRET`) |
| `resources/RetireJS/retirejs_repository.json` | ~500 KB | vulnerable JS library database |
| `resources/PayloadStrings/*.pay` | — | Intruder/fuzz payload lists (local files Linux/Windows/Java, HTTP verbs/headers, out-of-band fuzzing, …) |
| `resources/Community/SampleIssues.json` | — | demo issues for Community edition |

**BCheck DSL** — `burp.Zht9` embeds a full v2-beta script as a literal, giving the grammar:
`metadata:` → `define:` → `given insertion point then` → `send payload: appending:` →
`report issue: severity/confidence/detail/remediation`. Public corpus:
<https://github.com/PortSwigger/BChecks>.

---

## 8. End-to-end path — how a request becomes an issue

```
 request (crawler frontier │ proxy traffic for Live audit)
   │
   ├─ scope check ─────────────────────────────────── burp/api/montoya/scope
   │
   ├─ INSERTION POINT EXPANSION ......................... Zuq (+ Zeed/Zemw/Zg9v/Zcur/Zbju)
   │     8 built-in types, header synthesis, parameter
   │     relocation, nested-encoding recursion
   │     → Collection<Zb2q>
   │
   ├─ CHECK SELECTION per scope ......................... Zcud
   │     7 scopes (perUrl/perPath/perHost/perRequest/
   │     inSessionPerRequest/perInsertionPoint/storedPerInsertionPoint)
   │     phase = Zefx.A1 (active) or Zefx.A4 (stored)
   │     filter(enabled) → filter(applicable) → instantiate
   │
   ├─ AUDIT ITEM EXECUTION
   │     status transitions ............................ Zq5 (15 states)
   │     PENDING → AUDITING → AUDITED
   │             ↘ LIMIT_EXCEEDED / SKIPPED_* / FAILED_TO_SCAN / CANCELLED
   │     circuit breakers ............................... scanner/error_handling/*
   │     item collection ............................... Zf9d
   │
   ├─ ISSUE CREATION ................................... Zc_q makeIssue
   │     typed by ..................................... Zcot (183 types)
   │     enriched from ................................ KnowledgeBase/Issues/<hex>_<Name>.json
   │
   ├─ CONSOLIDATION / DEDUP ............................ Zbvp (+ Zby4 CRC metrics)
   │     findIssuesOfSameType → shouldMergeIssues
   │     per-type overrides (e.g. JWT_WEAK_HMAC_SECRET)
   │
   └─ PERSIST + NOTIFY ................................. Zb2g writeIssue, Ze3h events, Zcps handlers
```

## 9. Where the memory goes

Directly relevant to a lower-RAM reimplementation:

1. **`store_issues_within_queue_items: true`** (`Zgff`) — issues are retained *on* audit items, so
   the audit queue holds finding payloads, not just work descriptors.
2. **Audit items are held in an observable collection** (`Zf9d`) with listener notification —
   liveness prevents releasing completed items while a view is attached.
3. **Insertion points are materialised as objects** (`Collection<Zb2q>` threaded through every
   `Zcud` call) rather than as offsets into the request buffer.
4. **Stored/second-order checks thread two requests** (`Zd.Zf(req, storedReq, ctx)`), doubling
   retained message state on that path.
5. **The cap is a symptom, not a design** — `Zq5.LIMIT_EXCEEDED` exists because
   `requests × insertion points × checks` is unbounded. PortSwigger bounds it by *discarding work*.

An offset-based model (audit items holding `(log_offset, len)` into an append-only memory-mapped
traffic log, insertion points as `(offset, len, kind)` triples, streaming check evaluation) removes
1, 3 and 4 outright, and turns 5 from "drop work" into "apply backpressure".
