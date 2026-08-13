# Burp Suite Java Scanner & Crawler: Deep-Dive Architecture Report
# Target: Make burpsy-go Match It Exactly

**Evidence sources (all code-grounded, no inference):**
- `/root/burp-re/out/clean/root/` — 19,307 named/renamed Java classes
- `/root/burp-re/SCAN_ENGINE.md` — engine file map with recovered method names
- `/root/burp-re/out/names/all_renames.tsv` — 4,244 verified method name recoveries
- `/root/burp-re/out/strings/map_root.tsv` — ZKM-stripped string literals
- `/root/burpsy-react-ui/burpsy-go/internal/{scanner,crawler,bcheck}/` — Go source

---

## PART 1: JAVA SCANNER — Exact Internal Architecture

### 1.1 The Three Backbone Enums (names survive obfuscation — Java preserves enum constants)

---

#### `burp.Zcot` → `IssueType` — 183 constants

Every constant pairs 1:1 with a JSON file in `resources/KnowledgeBase/Issues/<hex>_<Name>.json`.
The hex filename encodes the `typeIndex`: `00100200_SqlInjection.json` → typeIndex `1049088 = 0x00100200`.

Severity distribution across the full catalog: **68 INFO, 57 HIGH, 36 LOW, 22 MEDIUM**.

Each JSON carries: `typeIndex`, `name`, `typicalSeverity`, `description`, `remediation`,
`references[]`, `vulnerabilityClassifications[]` (CWE numbers).

Key constants with special dedup behaviour:
```
IssueType.JWT_WEAK_HMAC_SECRET   → dedup on recovered secret VALUE, not generic equality
IssueType.CROSS_DOMAIN_POST      → exempt from dedup entirely
IssueType.SERIALIZED_OBJECT_IN_HTTP_MESSAGE → exempt from dedup entirely
IssueType.INPUT_RETRIEVAL_REFLECTED → INFO; triggers S3 stored phase
IssueType.XSS_STORED             → triggers S2 Collaborator phase
```

**burpsy-go:** `catalog_data.go` — 183/183 entries, `TypeIndex` fields match exactly. ✅
**Gap:** JWT_WEAK_HMAC_SECRET merge-on-secret-value logic not implemented.

---

#### `burp.Zefx` → `AuditPhase` — 7 phase constants

```java
// out/clean/root/AuditPhase.java
public enum AuditPhase implements Zckx {
    A1,   // ordinary active       → config.ZB0() || config.ZBI()
    A2,   // light active          → config.ZBX()
    A3,   // medium active         → config.ZBR() && config.ZL8()
    A4,   // stored/second-order   → config.ZBx() && config.ZL8()   ← TWO REQUESTS
    S2,   // stored + Collaborator → config.ZBx() && config.ZL8()   ← OOB
    S3,   // stored XSS+reflected  → config.Zr(XSS_STORED, COLLABORATOR_BASED)
          //                           || config.ZG(INPUT_RETRIEVAL_REFLECTED)
    A5;   // javascript analysis   → (separate config flag)

    public byte permanentIndex;   // on-disk serialisation byte for project migration
    BiFunction<Zggx, Boolean, Boolean> Zs;  // applicability predicate against scan config
}
```

`A*` = active phases. `S*` = stored/second-order (thread TWO requests through the pipeline).
`CheckDispatch` passes `A1` for normal active checks and `A4` for stored per-insertion-point checks.
`AuditPhase.notifyNotApplicable` with `A1` iterates `Zr21<Zg4r>` listeners to notify
`AuditItemStatus.NO_INSERTION_POINT_CHECKS` on every child.

**burpsy-go:** `DispatchScope` in `audit.go` — 7 scopes mapped. `DispatchScopeStoredPerInsertionPoint.IsReachable() = false`.
**Gap:** A4, S2, S3, A5 not dispatched. No two-request threading. No JavaScript analysis pass.

---

#### `burp.Zq5` → `AuditItemStatus` — 15 per-insertion-point lifecycle states

```java
// out/clean/root/AuditItemStatus.java
public enum AuditItemStatus {
    PENDING,                    // just expanded, not yet dispatched
    AUDITED,                    // fully audited
    LIGHT_AUDITED,              // light-active pass only
    SKIPPED_PARAMETER_TYPE,     // param type excluded by config
    LIMIT_EXCEEDED,             // "reached the maximum limit of insertion points to audit per request"
    FAILED_TO_SCAN,             // consecutive insertion-point failures hit threshold
    AUDITING,                   // currently running
    LIGHT_AUDITING,             // currently running light pass
    NOT_LIGHT_AUDITED,          // eligible but light pass skipped
    NO_PARAMETER_MOVEMENT,      // body↔query relocation found no movement
    SKIPPED_INSERTION_POINT_TYPE, // type excluded by scanner.insertion_point_types config
    NO_INSERTION_POINT_CHECKS,  // no checks applicable to this point
    NO_NESTING_ALLOWED,         // recursion depth limit hit (nested insertion points off)
    CANCELLED,                  // "…as this audit item was cancelled"
    SKIPPED_BY_SELECTION;       // user selected specific issues, this point excluded

    public static final Set<AuditItemStatus> NON_TERMINAL_STATUSES;
    public static final Set<AuditItemStatus> COMPLETED_AUDIT_STATUSES;
    public final byte permanentIndex;    // stable byte for on-disk project serialisation
    public final String shortLabel;
    public final String label;
    public final Zuiw icon;
}
```

`NON_TERMINAL_STATUSES` and `COMPLETED_AUDIT_STATUSES` drive progress reporting and task resumability.
`LIMIT_EXCEEDED` = expansion already happened, memory already allocated, work then discarded.
`permanentIndex` survives project migration via `burp.Zb56::migrateActiveScanQueue`.

**burpsy-go:** `Disposition` (9 values, admission-side). Different semantics — admission gate,
not per-insertion-point lifecycle.
**Gap:** No 15-state lifecycle. No `permanentIndex` for resumable project serialisation.
No `NON_TERMINAL_STATUSES`/`COMPLETED_AUDIT_STATUSES` progress sets.

---

### 1.2 Check Dispatch — `burp.Zcud` → `CheckDispatch` (135 lines, abstract)

**The most important class in the scanner.** Defines how often every check runs.
Seven dispatch scopes — each is a paired (public factory / protected abstract supplier):

```
Scope                                        Factory method                         Runs per
─────────────────────────────────────────────────────────────────────────────────────────────
getActivePerUrlChecksFactory                 once per URL (path + query string)
getActivePerPathChecksFactory                once per path (query string ignored)
getActivePerHostChecksFactory                once per host:port
getActivePerRequestChecksFactory             once per individual request
getInSessionActivePerRequestChecksFactory    per request, session-valid only
getActivePerInsertionPointChecksFactory      PER INSERTION POINT ← primary cost centre
getStoredActivePerInsertionPointChecksFactory per insertion point, stored/2nd-order (A4)
```

Type split: `Zi28` = check for non-insertion-point scopes.
`Zuit` = insertion-point check (carries the point itself).
`Zb79<T>` = **lazy factory** — checks are NOT instantiated at registration.

**The filter-then-instantiate pipeline (CheckDispatch.java:103-112):**

```java
private <T extends Zi28> List<T> Zh(
        Zckx phase, Zgx0 ctx,
        Collection<InsertionPoint> pts,
        List<Zwy6<T>> descriptors) {

    return descriptors.stream()
        .filter(this::lambda$filterChecks$7)   // d.Zr(this.ZN)   → enabled in scan config?
        .filter(this::lambda$filterChecks$8)   // d.Zz(ZY, phase, ctx, pts) → applicable to scope?
        .map(Zwy6::ZP)                          // instantiate ONLY survivors
        .collect(Collectors.toList());
}
```

Per-scope context supplier `Zhgv Zd`:
- `Zd.ZG(req, ctx)` → live insertion points (A1 path)
- `Zd.Zf(req, storedReq, ctx)` → stored variant (A4 path) — TWO requests

Three critical properties for any reimplementation:
1. **Two-stage filter before construction.** `Zwy6<T>` is a check descriptor; `.ZP()` instantiates.
   Config-disabled and non-applicable checks are eliminated as cheap descriptors — nothing
   heavyweight allocated for checks that won't run.
2. **Laziness at scope boundary.** Returns `Zb79<T>` (Supplier) — check list built on demand,
   not eagerly for the whole scan.
3. **Phase is a first-class argument.** Same descriptor set reused across A1/A4 with different
   applicability predicates.

**burpsy-go:** `audit_engine.go` — `activeCheck` table with `scope`, `enabled func`, `run func`.
Admission gate via `AuditLedger.Admit(unit, check)`.
**Gap:** Missing `getInSessionActivePerRequestChecksFactory` and
`getStoredActivePerInsertionPointChecksFactory`. No two-request A4 threading.

---

### 1.3 Insertion Point Pipeline — `burp.Zuq` (1,479 lines)

The expansion step: **one request → N attack positions**.
Both memory usage and request count scale linearly here.

**Full method taxonomy (recovered from lambda synthetic method names):**

```
addUrlFilenameInsertionPoint
    → inject into URL path filename: /path/to/FILE.php → /path/to/PAYLOAD.php

addUrlFoldersInsertionPoints
    → each URL path folder segment: /FOLDER/to/file → /PAYLOAD/to/file

addUrlAndBodyParameterInsertionPoints
    → query params AND body params (form-encoded and JSON)

addNewParameterNameInsertionPoint
    → the parameter NAME itself: name=value → PAYLOAD=value (HPP, mass assignment)

addStandaloneTagInsertionPoint
    → bare tag injected into body text

addNewReferHeaderInsertionPoint
    → synthesised Referer: header (always injected, even absent from original)

addPhpFileRequestInsertionPoint
    → PHP-specific file path injection

addSwitchedBodyParameterLocationInsertionPoints
    → relocate body params to query string (and vice versa)
      finds parsing inconsistencies between body and query parsers

buildNestedInsertionPoint
    → recursion into encoded params: JSON-in-param, base64, XML-in-param
      stops when AuditItemStatus.NO_NESTING_ALLOWED fires

getMovedParameterInsertionPoint
    → parameter location relocation (distinct from switched, single param)
```

**8 config keys map 1:1 to these (from `resources/BuiltInConfigs/scanner/insertion_point_types/`):**

```
insert_url_params             → addUrlAndBodyParameterInsertionPoints (query side)
insert_body_params            → addUrlAndBodyParameterInsertionPoints (body side)
insert_param_name             → addNewParameterNameInsertionPoint
insert_cookies                → cookie value insertion points
insert_http_headers           → addNewReferHeaderInsertionPoint + User-Agent synthesis
insert_entire_body            → whole body as single insertion point
insert_url_path_filename      → addUrlFilenameInsertionPoint
insert_url_path_folders       → addUrlFoldersInsertionPoints
```

**Supporting classes:**

| Class | Lines | Role |
|---|---|---|
| `burp.Zeed` | 615 | Provider registry — `Scanner insertion point providers` |
| `burp.Zemw` | 413 | Provider validation — `Insertion point provider cannot be null.` |
| `burp.Zg9v` → `InsertionPointsStrategy` | 70 | Strategy: wires 6 sub-strategies to config keys |
| `burp.Zcur` | — | User-defined insertion points — `Scan defined insertion points` |
| `burp.Zbju` → `LegacyInsertionPointAdapter` | 29 | Legacy IScannerInsertionPointProvider → Montoya shim |

`InsertionPointsStrategy` wires exactly 6 sub-strategy objects:

```java
// out/clean/root/InsertionPointsStrategy.java
public List<? extends Zma2> ZY() {
    return List.of(this.ZN, this.ZB, this.Zg, this.ZT, this.ZW, this.Zn);
    // Zrdv, Zrdo, Zrdr, Zrdj, Zrd_, Zrdu
    // Each maps to one group of config keys under scanner.insertion_point_types
}
```

Config keys watched: `scanner.insertion_point_types`, `scanner.ignored_insertion_points`,
`scanner.frequently_occurring_insertion_points`, `scanner.misc_insertion_point_options`,
`scanner.modifying_parameter_locations`.

**burpsy-go `insertion.go`:** 4 families only — query, body, cookie, header.
Offset-based `(start, end int)` into request bytes (not object copies).

**Gaps in burpsy-go:**
- `addUrlFilenameInsertionPoint` — URL path filename ❌
- `addUrlFoldersInsertionPoints` — URL path folder segments ❌
- `addNewParameterNameInsertionPoint` — param name as payload position ❌
- `addSwitchedBodyParameterLocationInsertionPoints` — body↔query relocation ❌
- `buildNestedInsertionPoint` — nested encoding recursion ❌
- `addNewReferHeaderInsertionPoint` + User-Agent synthesis — synthesised headers ❌
- `insert_entire_body` — whole body mode ❌

---

### 1.4 Configuration — The Engine is Data-Driven

Source: union of keys across 29 files in `resources/BuiltInConfigs/`.

**Scan-type buckets (`/scanner/issues_reported/`):**
```
scan_type_passive                 → passive checks only
scan_type_light_active            → A2 phase
scan_type_medium_active           → A3 phase
scan_type_intrusive_active        → A1 phase (full)
scan_type_javascript_analysis     → A5 phase
select_individual_issues          → bool: user picks specific issues
selected_issues[]                 → array of typeIndex values
store_issues_within_queue_items   → bool: issues held on audit items (memory cost)
```

**Insertion-point types (`/scanner/insertion_point_types/`):**
```
insert_url_params     insert_body_params    insert_param_name    insert_cookies
insert_http_headers   insert_entire_body    insert_url_path_filename
insert_url_path_folders
```

**Frequently-occurring shortcut (`/scanner/frequently_occurring_insertion_points/`):**
Same 8 keys as `quick_scan_*`. A cheaper pass over common positions — runs before full expansion.

**Skips (`/scanner/ignored_insertion_points/`):**
```
skip_all_tests_for_parameters[]           → param names to never inject
skip_server_side_injection_for_parameters[] → param names to skip server-side checks
```

**Audit tuning (`/scanner/audit_optimization/`):**
```
scan_accuracy
scan_speed
skip_ineffective_checks
consolidate_passive_issues
follow_redirections
maintain_session
maximum_crawl_and_audit_time
```

**Error handling / circuit breakers (`/scanner/error_handling/`):**
```
consecutive_audit_check_failures_to_skip_insertion_point
    → N check failures on one point → skip remaining checks for that point (ItemBreaker)

consecutive_insertion_point_failures_to_fail_audit_item
    → N point failures → mark audit item FAILED_TO_SCAN (SessionBreaker)

number_of_follow_up_passes
    → how many re-passes over the insertion point set

pause_task_failed_audit_item_count
    → absolute count of FAILED_TO_SCAN items → pause entire task

pause_task_failed_audit_item_percentage
    → percentage of FAILED_TO_SCAN items → pause entire task
```

Implemented in `burp.Zgff`. Ships a "Disable error handling" preset that sets all five to 0.
This is a **two-level circuit breaker** + task-level pause:

```
Level 1 (ItemBreaker):   N check failures   → skip insertion point → LIMIT_EXCEEDED
Level 2 (SessionBreaker): N point failures  → fail audit item      → FAILED_TO_SCAN
Level 3 (Task):          count OR %         → pause entire scan task
```

**burpsy-go:** `ItemBreaker` and `SessionBreaker` in `audit.go` — levels 1 and 2 present.
**Gap:** Missing `number_of_follow_up_passes`, `pause_task_failed_audit_item_percentage` (level 3 % threshold).

---

### 1.5 Issue Consolidation — `burp.Zbvp` → `IssueDedupChain` (86 lines)

Chain-of-responsibility pattern (`extends Zbvm`, delegates via `this.handle.handle(issue)`):

```java
// out/clean/root/IssueDedupChain.java
public class IssueDedupChain extends Zbvm {
    private final Map<Short, List<Zco9>> Zd;   // pending-merge buckets, keyed by scope index
    private final Zwlr ZY;                     // Zby4 CRC metric supplier
    private final List<Zco9> ZT;               // live issues list for same-type lookup
    private final short ZN;                    // current scope bucket key

    public void handle(Zco9 issue) {
        if (isEligibleForDedup(issue)) {        // not CROSS_DOMAIN_POST, not SERIALIZED_OBJECT,
                                                // not blank detail value
            List<Zco9> same = findIssuesOfSameType(issue, this.ZT);
            if (shouldMergeIssues(issue, same)) {
                this.Zd.computeIfAbsent(this.ZN, k -> new ArrayList<>()).add(issue);
                return;   // swallowed — do not propagate
            }
        }
        this.handle.handle(issue);   // pass through chain to next handler
    }

    private boolean shouldMergeIssues(Zco9 issue, List<Zco9> same) {
        if (issue.type() == IssueType.JWT_WEAK_HMAC_SECRET) {
            // JWT: merge on recovered secret VALUE identity, not generic equality
            return same.stream()
                       .map(i -> i.detail().value())
                       .anyMatch(issue.detail().value()::equals);
        }
        // Default: merge when CRC count (Zwlr.Zn(same)) + 1 > 1
        // i.e. there is already a same-type issue with identical CRC signature
        int count = this.ZY.Zn(same) + 1;
        return count > 1;
    }

    private static List<Zco9> findIssuesOfSameType(Zco9 issue, List<Zco9> all) {
        return all.stream()
            .filter(i -> i.type() == issue.type())   // same IssueType constant
            .filter(i -> !i.ZA(issue))               // not already the same object
            .collect(toList());
    }
}
```

`burp.Zby4` (118 lines) — CRC metrics side:
```
getNumberOfUniqueValuesScanned(issueType)
getNumberOfDifferentSetsOfIssueTypes()
getCrcForIssueTypes(issueSet)         → CRC32 over the issue-type set
getScanCountForValue(value)           → how many times this detail value was scanned
```

Used to recognise "same finding shape" cheaply without full string comparison.

Other issue-lifecycle classes:
- `burp.Zc_q` → `makeIssue` — constructs typed issue from check result
- `burp.Zb2g` → `writeIssue` — persists to storage
- `burp.Zcjj` → `findIssues` — queries issue store
- `burp.Zc8l` → `deleteIssues` — removes superseded issues
- `burp.Ze3h` → model/tree events: `onIssuesAdded`, `onIssuesRemoved`, `onIssuesSuperseded`, `onIssuesUpdated`, `notifyIssueSignificancePropagationListeners`
- `burp.Zcps` (1,567 lines) → `refreshAuditIssueHandlers` + `getScannerCheckWrapperFor` (extension check bridge)

**burpsy-go:** `breakdown.go` — `Breakdown` struct with per-issue-type counts.
**Gap:** No chain-of-responsibility handler. No JWT merge-on-secret-value. No CRC32 dedup metric.

---

### 1.6 Task Launch & Five Task Shapes — `burp.Zrb9` (286 lines)

All five scan task shapes are one family from `buildCrawlTaskView` through to `buildLivePassiveCrawlTaskView`.

**`burp.LiveAudit` enum — all 12 task types (out/clean/root/LiveAudit.java):**

```java
public enum LiveAudit {
    SCAN_CRAWL,
    SCAN_AUDIT,
    SCAN_CRAWL_AND_AUDIT,
    LIVE_AUDIT,              // same pipeline fed from proxy traffic
    LIVE_PASSIVE_CRAWL,
    LEGACY_EXTENSION_PASSIVE_AUDIT,
    LEGACY_EXTENSION_ACTIVE_AUDIT,
    INTRUDER_ATTACK,
    API_AUDIT,
    SCAN_RETEST,
    ISSUE_EXPLORE,
    BULK_REQUEST_SEND;

    public static final Set<LiveAudit> SCAN_TASK_TYPES;  // first 5
    // LIVE_AUDIT is NOT a separate engine — it is the same audit pipeline
    // fed from proxy traffic instead of a crawler frontier
}
```

`burp.Zbcc` (118 lines) — progress normalisation:
```
adaptCrawlToRelativeProgress(crawlProgress)  → maps crawl 0–100 to combined 0–50
adaptAuditToRelativeProgress(auditProgress)  → maps audit 0–100 to combined 50–100
adaptEvents(rawEvents)                       → normalises event stream across both phases
```

**Task launch chain:**
```
burp.Zeqc (1,273 lines) → launchScan → launchScanTask → resumeScan
    → validates seed URLs (validateSeedUrls)
    → resolves auth models (getAuthenticationModels, applicationLoginConfig)
    → selects resource pool (resourcePoolSelectionConfig)
    → builds task view via Zrb9
```

**burpsy-go:** `scanner.go` has `RunPassiveScan` (proxy-fed) and `ActiveScanner.RunAuditSession`.
**Gap:** No named task types. No progress normalisation. No RETEST, ISSUE_EXPLORE, API_AUDIT, BULK_REQUEST_SEND.

---

### 1.7 End-to-End Path: How a Request Becomes an Issue

```
request (crawler frontier | proxy traffic for LIVE_AUDIT)
  │
  ├─ SCOPE CHECK ───────────────────────── burp.api.montoya.scope
  │     prefix/regex rules from suite scope or custom scope
  │
  ├─ INSERTION POINT EXPANSION ........... burp.Zuq (1,479 lines)
  │     8 built-in types via InsertionPointsStrategy
  │     header synthesis (Referer, User-Agent always injected)
  │     parameter relocation (body↔query)
  │     nested encoding recursion (JSON-in-param, base64)
  │     frequently-occurring shortcut pass first
  │     → Collection<InsertionPoint>
  │
  ├─ CHECK SELECTION per scope ........... burp.Zcud (CheckDispatch, 135 lines)
  │     7 scopes; phase = A1 (active) or A4 (stored)
  │     Stage 1 filter: enabled in config?    (cheap, descriptor-level)
  │     Stage 2 filter: applicable to scope? (cheap, descriptor-level)
  │     Stage 3: instantiate ONLY survivors  (lazy factory Zb79<T>)
  │
  ├─ AUDIT ITEM EXECUTION
  │     per-insertion-point status ......... AuditItemStatus (15 states)
  │     PENDING → AUDITING → AUDITED
  │             ↘ LIMIT_EXCEEDED           (cap hit after expansion)
  │             ↘ SKIPPED_*                (type/param excluded by config)
  │             ↘ FAILED_TO_SCAN           (consecutive failures threshold)
  │             ↘ NO_NESTING_ALLOWED       (recursion depth limit)
  │             ↘ CANCELLED                (user cancelled)
  │     ItemBreaker: N check failures  → skip insertion point
  │     SessionBreaker: N point failures → fail audit item
  │     Task pause: count OR % threshold → pause whole scan task
  │     observable collection ............. burp.Zf9d (190 lines)
  │
  ├─ ISSUE CREATION ........................ burp.Zc_q makeIssue
  │     typed by .......................... IssueType (183 constants)
  │     enriched from ..................... KnowledgeBase/Issues/<hex>_<Name>.json
  │     fields: name, severity, confidence, detail, remediation, CWE
  │
  ├─ CONSOLIDATION / DEDUP ................. burp.Zbvp IssueDedupChain (86 lines)
  │     chain-of-responsibility handler
  │     eligible? (not CROSS_DOMAIN_POST, not blank detail)
  │     findIssuesOfSameType → shouldMergeIssues
  │     JWT_WEAK_HMAC_SECRET: merge on secret value identity
  │     default: merge on CRC32 of issue-type set (burp.Zby4)
  │
  └─ PERSIST + NOTIFY ...................... burp.Zb2g writeIssue
                                            burp.Ze3h onIssuesAdded events
                                            burp.Zcps refreshAuditIssueHandlers
```

---

### 1.8 Memory Model (why Burp uses 2–4 GB JVM; how Go avoids it)

Five sources of memory pressure in the Java engine:

1. **`store_issues_within_queue_items: true`** — issues retained *on* audit items; the scan queue
   holds full finding payloads, not just work descriptors.
2. **Observable collection** (`Zf9d`) with listener notification — liveness prevents releasing
   completed items while a UI view is attached.
3. **Insertion points are object graphs** — `Collection<InsertionPoint>` threaded through every
   `CheckDispatch` call. Every check for every scope sees the full Collection.
4. **Stored/second-order checks (A4)** — `Zd.Zf(req, storedReq, ctx)` threads two full request
   objects, doubling retained message state on the A4 path.
5. **The cap is a symptom** — `LIMIT_EXCEEDED` fires after expansion already happened;
   `requests × insertion points × checks` is unbounded and bounded by discarding.

**burpsy-go's design choice:** Insertion points are offset-based `(start, end int)` structs.
`AuditLedger.Admit` gates work before expansion — nothing is allocated and abandoned.
Targets ~50 MB baseline vs Burp's 2–4 GB.

---

## PART 2: JAVA CRAWLER — Exact Internal Architecture

### 2.1 CrawlTaskManager — `burp.Zc16` (223 lines)

Guice-injected component. Constructor receives 19 injected dependencies.
Key fields:

```java
public class CrawlTaskManager implements Zivq<Zg49, Zg44> {
    private final Queue<Zb47>   Zk;          // task queue (ConcurrentLinkedQueue)
    private final Zx1c          startCrawl;  // StartCrawl — builds crawl session handle
    private final Queue<Zrbd>   Zi;          // recorded login sequences (authenticated crawl)
    private final Zpny          Zs;          // proxy config (upstream chaining)
    private final Zu89          ZF;          // scan config
    private final Zur5          ZR;          // logger
    private final Zmit          ZW;          // scan task settings
    private final Zp6h<Zg4i>   ZA;          // audit event bus
    private final Zs06          ZB;          // project storage
    private final Zuyy          Zv;          // crawl config applicator
    private final Zrwf          ZZ;          // crawler↔audit pipeline wiring
}
```

At construction, if `!scanTaskSettings.Zt3().ZKK()` (not audit-only):
```java
this.Zk.add(new Ziuo(this));   // enqueue the crawl task
```

`startCrawl(Zc58 config)` wires 6 components in sequence:
```java
private void startCrawl(Zc58 config) {
    this.Zv.Zs(config);                                // 1. apply scan config to crawl
    new Zplt(scope, scanConf, ...).ZF(eventBus);        // 2. bind crawl limits to event bus
    new Zwee(eventBus, project, ...).Zg(eventBus);      // 3. bind audit-item events
    new Zw9f(sitemap).ZU(strategyProvider, eventBus);   // 4. bind strategy → sitemap updates
    new Zgkr(project, scanTask).ZT(eventBus, ...);      // 5. bind progress tracking
    new Zfm6(settings, eventBus).Zl(eventBus);          // 6. bind live config change listeners
    this.ZZ.ZZ(eventBus);                              // 7. wire crawler output to audit pipeline
}
```

`finishCrawl()`:
```java
private void finishCrawl() {
    if (this.Zj.Zb()) {                          // all crawl tasks done
        settings.ZKv();                           // mark crawl complete
        settings.ZKn().forEach(this::checkLoginSequenceResult);
        this.ZA.ZK(Zg4i.ZL);                     // fire AUDIT_STARTED event
        this.ZB.ZB().Z_();                        // flush project storage
    }
}
```

Recorded login sequences in `Queue<Zrbd> Zi` are consumed before starting:
```java
while (!this.Zi.isEmpty() && this.Zi.peek().ZW() < (byte)var5) {
    this.Zi.poll();   // drain sequences below current speed threshold
}
```

---

### 2.2 Crawler Configuration Keys

Source: `resources/BuiltInConfigs/crawler/`

**Crawl limits:**
```
crawl_limits/maximum_crawl_time           → wall-clock budget (minutes)
crawl_limits/maximum_request_count        → total requests across entire crawl
crawl_limits/maximum_unique_locations     → content-fingerprint-distinct locations cap
```

**Crawl optimisation:**
```
crawl_optimization/crawl_strategy         → "fastest" | "fast" | "normal" | "thorough" | "user-directed"
crawl_optimization/dom_idle_threshold     → ms to wait after DOM events settle (JS engine)
crawl_optimization/network_idle_threshold → ms to wait after network quiesces (JS engine)
crawl_optimization/await_navigation_timeout → ms timeout for page navigation (JS engine)
```

**Live passive crawl (proxy-fed mode):**
```
live_passive_crawl/add_all_urls           → capture all traffic, not just in-scope
live_passive_crawl/add_links             → extract links from captured responses
live_passive_crawl/add_form_submissions  → extract form actions from captured responses
live_passive_crawl/add_item_itself       → add the intercepted request to frontier
live_passive_crawl/add_same_domain       → include same-domain out-of-path links
live_passive_crawl/add_urls_in_scope     → only queue URLs in current suite scope
live_passive_crawl/scope_type            → "suite_scope" | "custom_scope"
live_passive_crawl/custom_scope          → prefix/regex rules for crawl-only scope
```

**Key difference from burpsy-go:** `dom_idle_threshold`, `network_idle_threshold`,
`await_navigation_timeout` require an embedded browser (Burp uses Chromium DevTools Protocol internally).
burpsy-go has no JS execution — this is its stated architectural limit.

---

### 2.3 Location Identity — Content Fingerprinting

Burp does **not** use URL-keyed deduplication. A location is identified by what came back,
not by the URL used to reach it.

**Why URL-keyed deduplication fails on real applications:**

| Application pattern | URL-keyed result |
|---|---|
| Per-request CSRF token in form action | Every link looks new |
| Cache-busting `?_=timestamp` on nav links | Same page, infinite URLs |
| Session ID embedded in URL path (`/(S(abc123))/`) | Entire app looks new after login |
| Paginated list or calendar | Unbounded URLs, bounded pages |

Burp bounds by content-fingerprint identity. `maximum_unique_locations` caps
*content-distinct* locations, not URL count.

**burpsy-go `fingerprint.go` implements the same design:**

Two-fingerprint model:
1. **`requestFingerprint`** (pre-fetch, URL-derived) — strips volatile params (CSRF tokens,
   cache-busters) so two links differing only in a token are one queue entry.
2. **`locationFingerprint`** (post-fetch, via `discover.go` tree walk) — hashes 4 components:
   - Depth-annotated HTML tag skeleton (attribute values dropped except `name`, `type`,
     `method`, `action`, `rel`)
   - Each form's `method`/`action`/sorted-field-names signature
   - Page's outgoing link targets, sorted and **raw** (not templated — see bias below)
   - `log2` bucket of visible-text length

Excluded from skeleton: text content, `class`, `id`, inline script bodies, comments.
These carry per-render data; including them would make every render a new location.

**Bias — false-split over false-merge:** A false merge is invisible lost coverage; a false split
is a visible re-fetch bounded by per-template quota. Link targets stay raw: `/users/1` and
`/users/2` differ only in link target → kept distinct. Templating them would merge and
cause the crawler to scan one row of a 50,000-row table and report completion.

---

### 2.4 Traversal Model

**Burp — directed graph, re-navigation:**
Models the application as a directed graph of locations and edges.
Re-navigates from a known point rather than jumping at a queued URL.
A link reachable only as step 3 of a wizard is reached by walking the wizard from step 1.
Recorded login sequences (`Queue<Zrbd>`) provide the authenticated entry points.

**burpsy-go — breadth-first frontier queue:**
Each queued URL is issued directly in isolation.
`crawler.go` comment (line 67): *"Any location only reachable through a sequence of
state-changing requests is not reached."*

Scope of the gap (from the source comment): only matters when form submission is ON (`CRAWL-03`).
A default crawl (form submission off) cannot encounter POST-only intermediate states.
The gap becomes real exactly when an operator enables form submission and the target has
multi-step wizard flows.

---

### 2.5 Link & Form Extraction — `discover.go`

**Discovered and queued:**
```
a[href]        → navigational link (href attribute)
area[href]     → image map area
iframe[src]    → embedded frame source
frame[src]     → frameset frame source
<form>         → form action (GET or POST; GET forms count too per CRAWL-03 decision)
```

**Neither queued nor fingerprinted (subresources):**
```
img[src]       script[src]    link[href]     source[src]
embed[src]     video[src]     audio[src]
```
Excluded from location skeleton too — rebuilt asset hash filenames would make every page
look like a new location on every deploy.

**Not discovered at all (named limits):**
```
URLs built by script              → no JS execution
URLs in CSS                       → no CSS parser
srcset candidate lists            → not implemented
<meta http-equiv=refresh> targets → not implemented
data-* attribute conventions      → not implemented
```

**Link text collection:** Descendant text + `title` attribute + `aria-label` attribute,
normalised to single spaces.
Required for the destructive-action check — modern delete buttons are:
```html
<a href="/x/8814" aria-label="Delete"><svg/></a>
```
No text node, so without `aria-label` the destructive check would miss it.

**`maxLinkTextBytes = 512`** — bounds per-link text to prevent a megabyte anchor from
consuming the frontier's memory budget.

**Burp's additional discovery (not in burpsy-go):**
- JavaScript execution → dynamically built navigation, SPA routes
- Sitemap XML parsing (Burp walks `<loc>` elements; Go queues the sitemap URL only)
- DOM event handlers (`onclick`, `onsubmit`)

---

### 2.6 Destructive Action Refusal — `destructive.go` (CRAWL-04)

Both Burp and burpsy-go refuse to follow links whose text signals a destructive action.

Pattern vocabulary (recovered from string literals, confirmed in `destructive.go`):
```
logout  log out  sign out  signout
delete  remove   purge     clear   reset   destroy
unsubscribe  deactivate  disable  revoke
```

Matching is case-insensitive, on normalised link text (text + aria-label + title).

**Gate order in `admit` (crawler.go:1097-1111):**
```
1. resolution        → href cannot be resolved → skip
2. scheme            → not http/https → skip
3. userinfo          → URL has credentials → skip
4. destructive check → BEFORE scope (so logout out-of-scope reports as logout refusal)
5. engagement scope  → pre-fetch pre-filter
6. crawl-scope query → DSL-03 filter
7. depth / duplicate / capacity → bookkeeping (cheapest, fires most often)
```

Every refusal produces a `SkipRecord` naming the URL, link text, and (for destructive) the exact signal.

**Seeds bypass destructive check.** Seeds are the operator's instruction.
Robots.txt-derived paths do NOT bypass it — they are target-supplied input.

---

### 2.7 Safety & SSRF Mitigations (both implementations)

| Check | Java (Burp) | Go (burpsy-go) |
|---|---|---|
| Scheme allowlist (http/https only) | ✓ | ✓ `supportedScheme()` |
| Userinfo in URL refused | ✓ | ✓ |
| Redirects re-enter frontier as links | ✓ | ✓ (re-authorised via scope) |
| Rate limiter per authority | ✓ | ✓ `limiterFor()` per-authority AutoThrottle |
| Crawl-wide aggregate rate cap | ✓ | ✓ separate `Crawler.limiter` |
| Scope gate enforced at dial (not just queue) | ✓ | ✓ `AuthorisedSender` |
| robots.txt read as discovery, not obeyed | ✓ | ✓ `RobotsPolicy` const |

---

### 2.8 Session Gate — `session_gate.go`

burpsy-go has `internal/crawler/session_gate.go`.
Detects session expiry (401 / redirect to login page) and triggers re-authentication.
After re-auth, re-enters the same `perform()` pipeline with refreshed cookies.

Java equivalent: `CrawlTaskManager.Zi` — recorded login sequences replayed.
Java also supports CSRF token refresh during session recovery (state-aware navigation).
burpsy-go: `handleExpired` retries with refreshed cookie but does not replay a full login sequence.

---

## PART 3: GAP TABLE — Burp Java vs. burpsy-go

### Scanner Gaps

| Gap | Java Source | burpsy-go Status |
|---|---|---|
| URL path filename insertion points | `Zuq::addUrlFilenameInsertionPoint` | ❌ Missing |
| URL path folder insertion points | `Zuq::addUrlFoldersInsertionPoints` | ❌ Missing |
| Parameter name as insertion point | `Zuq::addNewParameterNameInsertionPoint` | ❌ Missing |
| Body↔query parameter relocation | `Zuq::addSwitchedBodyParameterLocationInsertionPoints` | ❌ Missing |
| Nested encoding recursion | `Zuq::buildNestedInsertionPoint` | ❌ Missing |
| Synthesised Referer/User-Agent headers | `Zuq::addNewReferHeaderInsertionPoint` | ❌ Missing |
| Entire-body insertion point | `insert_entire_body` config key | ❌ Missing |
| Stored/second-order checks (A4 phase) | `AuditPhase.A4`, two-request threading | ❌ `IsReachable=false` |
| JavaScript analysis (A5 phase) | `scan_type_javascript_analysis` | ❌ Missing |
| In-session per-request scope | `getInSessionActivePerRequestChecksFactory` | ❌ Missing |
| Per-type dedup chain-of-responsibility | `IssueDedupChain` (86 lines) | ❌ Missing |
| JWT merge-on-secret-value | `shouldMergeIssues` JWT override | ❌ Missing |
| CRC32 issue-shape metric | `burp.Zby4` (118 lines) | ❌ Missing |
| 15-state AuditItemStatus + permanentIndex | `AuditItemStatus` enum | ❌ 9 Dispositions only |
| Follow-up passes | `number_of_follow_up_passes` | ❌ Missing |
| Task % pause threshold | `pause_task_failed_audit_item_percentage` | ❌ Missing |
| Named task types (LIVE_AUDIT etc.) | `LiveAudit` enum (12 types) | ❌ Missing |
| Progress normalisation | `Zbcc` adaptCrawl/adaptAudit | ❌ Missing |
| RETEST / ISSUE_EXPLORE / API_AUDIT | `LiveAudit.SCAN_RETEST` etc. | ❌ Missing |

### Crawler Gaps

| Gap | Java Behaviour | burpsy-go Status |
|---|---|---|
| JavaScript execution | Embedded browser, `dom_idle_threshold` | ❌ Named architectural limit |
| Graph re-navigation (multi-step wizard) | Directed graph + re-navigate from known point | ❌ Frontier-only |
| Sitemap XML parsing | Walks `<loc>` elements, queues all | ❌ Queues sitemap URL only |
| DOM event handlers (`onclick` etc.) | JS execution | ❌ No JS |
| `crawl_strategy` levels (5) | fastest/fast/normal/thorough/user-directed | ❌ Fixed rate only |
| Full login sequence replay | `Queue<Zrbd>` with CSRF token refresh | ⚠️ Partial (`session_gate.go`) |
| `meta http-equiv=refresh` targets | Discovered and queued | ❌ Not implemented |

---

## PART 4: IMPLEMENTATION RECIPE — How to Close Each Gap

### Priority 1 — Insertion Points (largest coverage miss, affects every active check)

Add to `internal/bcheck/insertion.go`, wire behind `ScanConfig` flags:

```go
// 1. URL path filename
// /path/to/file.php → inject before and after "file", URL-encoded
// Config key: insert_url_path_filename
func enumerateURLPathFilename(req []byte) []InsertionPoint

// 2. URL path folders
// /folder1/folder2/file → each folder segment as a point
// Config key: insert_url_path_folders
func enumerateURLPathFolders(req []byte) []InsertionPoint

// 3. Parameter name
// name=value → PAYLOAD=value (finds HPP, mass assignment, prototype pollution)
// Config key: insert_param_name
func enumerateParamNames(req []byte) []InsertionPoint

// 4. Switched parameter location (body↔query relocation)
// For each body param, add a point that relocates it to query string.
// For each query param, add a point that relocates it to body.
// Finds parsers that treat the same name differently by location.
// Config key: scanner.modifying_parameter_locations
func enumerateSwitchedParamLocations(req []byte) []InsertionPoint

// 5. Synthesised headers
// Always insert these even if absent from original request:
//   X-Forwarded-For, Referer, User-Agent, Origin, X-Forwarded-Host
// Config key: insert_http_headers
func enumerateSynthesisedHeaders(req []byte) []InsertionPoint

// 6. Nested encoding recursion
// If a param value is base64 → decode → enumerate points inside → re-encode on Apply
// If a param value is JSON  → enumerate JSON keys as points
// Stop when IpKind == IpNested and ScanConfig.AllowNesting == false
func enumerateNestedParams(req []byte, maxDepth int) []InsertionPoint
```

---

### Priority 2 — Issue Dedup Chain (fixes duplicate findings)

New file `internal/scanner/dedup.go`:

```go
type DedupChain struct {
    mu      sync.Mutex
    pending map[uint16][]Finding  // keyed by IssueType short ordinal
}

// Admit returns true if the finding should be emitted, false if merged/suppressed.
// Must be called before writing the finding to storage.
func (d *DedupChain) Admit(f *Finding) bool {
    d.mu.Lock()
    defer d.mu.Unlock()

    // Exempt from dedup entirely
    if f.TypeIndex == TypeIndexCrossDomainPost ||
       f.TypeIndex == TypeIndexSerializedObject {
        return true
    }

    same := d.findSameType(f)

    // JWT: merge on recovered secret value, not generic equality
    if f.TypeIndex == TypeIndexJWTWeakHMAC {
        for _, s := range same {
            if s.Detail == f.Detail {
                return false   // suppress duplicate JWT finding with same secret
            }
        }
        d.pending[f.TypeIndex] = append(d.pending[f.TypeIndex], *f)
        return true
    }

    // Default: suppress when CRC32 of detail matches an existing finding
    crc := crc32.ChecksumIEEE([]byte(f.Detail))
    for _, s := range same {
        if crc32.ChecksumIEEE([]byte(s.Detail)) == crc {
            return false
        }
    }
    d.pending[f.TypeIndex] = append(d.pending[f.TypeIndex], *f)
    return true
}
```

---

### Priority 3 — Stored/Second-Order Checks (A4 phase)

To make `DispatchScopeStoredPerInsertionPoint.IsReachable() = true`:

1. `core.TrafficStore` needs a method to retrieve the "stored" prior exchange for a URL.
2. `AuditLedger` unit key for A4 scope: `"originA#reqID + originB#storedID"`.
3. `activeCheckSet` needs A4-phase entries (blind SQLi, stored XSS via Collaborator).
4. `ActiveScanner.RunAuditSession` must pass `storedEx` alongside `ex` to A4 checks.

---

### Priority 4 — Crawler: Sitemap XML Parsing

In `crawler.go`, after fetching a URL whose Content-Type is `application/xml` / `text/xml`:

```go
// parseSitemapLinks extracts <loc> elements from a sitemap XML body.
// Each loc is offered as a discovered link (not a seed) — passes destructive check.
func parseSitemapLinks(body []byte, base *url.URL) []discoveredLink {
    dec := xml.NewDecoder(bytes.NewReader(body))
    var locs []string
    for {
        tok, err := dec.Token()
        if err != nil { break }
        if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "loc" {
            var v string
            dec.DecodeElement(&v, &start)
            locs = append(locs, strings.TrimSpace(v))
        }
    }
    // convert to discoveredLink list with empty link text
    // these pass destructive check, scope gate, crawl-scope query
}
```

---

### Priority 5 — Named Task Types & Progress Normalisation

Add to `internal/dash/tasks.go`:

```go
type LiveAuditKind int

const (
    TaskScanCrawl LiveAuditKind = iota
    TaskScanAudit
    TaskScanCrawlAndAudit
    TaskLiveAudit         // same pipeline, proxy traffic feeds audit
    TaskLivePassiveCrawl
    TaskAPIAudit
    TaskScanRetest
    TaskIssueExplore
    TaskBulkRequestSend
)

// TaskProgress normalises crawl + audit phases onto one 0–100 scale.
// Maps Burp's Zbcc::adaptCrawlToRelativeProgress + adaptAuditToRelativeProgress.
type TaskProgress struct {
    CrawlPercent int   // 0–100 within crawl phase
    AuditPercent int   // 0–100 within audit phase
    Combined     int   // 0–50 = crawl, 50–100 = audit; matches Burp's display
}
```

---

## Quick Reference: Java Class → Go File Exact Mapping

| Java (recovered name) | Lines | Go File | Parity |
|---|---|---|---|
| `burp.Zcot` → `IssueType` | 183 consts | `scanner/catalog_data.go` | ✅ 183/183 |
| `burp.Zefx` → `AuditPhase` | 7 phases | `scanner/audit.go` `DispatchScope` | ⚠️ A4/S2/S3/A5 missing |
| `burp.Zq5` → `AuditItemStatus` | 15 states | `scanner/audit.go` `Disposition` | ⚠️ 9 values, no permanentIndex |
| `burp.Zcud` → `CheckDispatch` | 135 lines | `scanner/audit_engine.go` | ⚠️ 2 scopes missing |
| `burp.Zuq` → insertion builder | 1,479 lines | `bcheck/insertion.go` | ⚠️ 4/10 families |
| `burp.Zbvp` → `IssueDedupChain` | 86 lines | — | ❌ Missing |
| `burp.Zby4` → CRC dedup metrics | 118 lines | — | ❌ Missing |
| `burp.Zgff` → circuit breakers | — | `scanner/audit.go` `ItemBreaker` | ⚠️ % threshold missing |
| `burp.Zc16` → `CrawlTaskManager` | 223 lines | `crawler/crawler.go` | ⚠️ Frontier-only, no JS |
| `burp.Zrb9` → task shapes | 286 lines | `scanner/scanner.go` | ❌ No named task types |
| `burp.Zbcc` → progress normalise | 118 lines | — | ❌ Missing |
| `burp.Zeqc` → scan launcher | 1,273 lines | `internal/web/api_tools.go` | ⚠️ Partial REST only |
| `out/clean/root/LiveAudit.java` | 12 constants | — | ❌ Missing enum |
| `out/clean/root/AuditPhase.java` | 7 constants | `scanner/audit.go` | ⚠️ A4–A5 not reachable |
| `out/clean/root/IssueDedupChain.java` | 86 lines | — | ❌ No chain-of-resp dedup |
| `out/clean/root/CrawlTaskManager.java` | 223 lines | `crawler/crawler.go` | ⚠️ Graph model missing |
| `crawler/discover.go` | 568 lines | `crawler/discover.go` | ✅ HTML extraction match |
| `crawler/fingerprint.go` | 382 lines | `crawler/fingerprint.go` | ✅ Content fingerprint match |
| `crawler/destructive.go` | — | `crawler/destructive.go` | ✅ Pattern matching match |
| `crawler/session_gate.go` | — | `crawler/session_gate.go` | ⚠️ Partial (no full sequence) |
