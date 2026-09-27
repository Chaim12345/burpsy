# Burp scanner LOGIC vs burpsy-go — evidence-backed gap report

Scout 1 of 2 (SmartScanLogicScout). Scope: the decision layer, not individual check logic.
Evidence conventions: `map_root.tsv:N` = line in /root/burp-re/out/strings/map_root.tsv (recovered
literal bank — GROUND TRUTH for string constants); `Class.java:N` = decompiled source under
/root/burp-re/out/clean/root/; `go:N` = /root/burpsy-react-ui/burpsy-go/internal/<...> at that line,
as read 2026-09-17 (siblings edit the tree). Where a decompiled body is ZKM-opaque the tsv wins.

---

## §1 INSERTION-POINT SELECTION — how Burp decides WHERE to probe

### (a) Burp's mechanism

Burp's insertion-point layer is a *strategy object* with per-kind switches, two parallel profiles
(full audit vs quick scan), operator exclusion lists, nested expansion, a per-request cap, and a
behavioral light-audit tier. The pieces, with citations:

1. **One strategy class grouping six config sub-panels.** `InsertionPointsStrategy` (renamed from
   Zg9v, map_root.tsv:3738-3743) aggregates six settings groups —
   `scanner.insertion_point_types`, `scanner.ignored_insertion_points`,
   `scanner.frequently_occurring_insertion_points`, `scanner.misc_insertion_point_options`,
   `scanner.modifying_parameter_locations` — in `InsertionPointsStrategy.java:48`, and fans
   config changes out to six listeners (`InsertionPointsStrategy.java:58-65`).

2. **The insertion-point kind enum is richer than query/body/cookie.** `Zbg8.java:7-28` (the
   parameterType enum): `URL_PARAM, BODY_PARAM_URL_ENCODED, COOKIE, XML_PARAM, XML_ATTR,
   MULTIPART_PARAM_ATTR, PATH_FOLDER_PARAM, PATH_FILENAME_PARAM, JSON_PARAM,
   BODY_PARAM_MULTIPART, PARAM_NAME_URL, PARAM_NAME_BODY_URL_ENCODED, PARAM_NAME_BODY_MULTIPART,
   HEADER, MANUAL_INSERTION_POINT, AMF_PARAM, ENTIRE_BODY, EXTENSION_PROVIDED,
   BASE64_ENCODED, BASE64URL_ENCODED` — 20 kinds, each with a numeric id and a
   `Zg6r parameterType` (`Zbg8.java:35`).

3. **Two parallel profiles: full audit vs quick scan.** The interface `Zb1q` (insertion-point
   config) carries BOTH families of keys (map_root.tsv:7698-7745):
   `scanner.insertion_point_types.insert_url_params|insert_body_params|insert_cookies|
   insert_param_name|insert_http_headers|insert_entire_body|insert_url_path_filename|
   insert_url_path_folders` (full audit) AND `scanner.frequently_occurring_insertion_points.
   quick_scan_url_params|quick_scan_body_params|quick_scan_cookies|quick_scan_param_name|
   quick_scan_http_headers|quick_scan_entire_body|quick_scan_url_path_filename|
   quick_scan_url_path_folders` (quick scan) — loaded/stored symmetrically at
   `Zb1q.java:106-121` (load) and `Zb1q.java:136-151` (store). `Zb1q.ZU(Zbg8)` at
   `Zb1q.java:67-101` is the **quick-scan profile decision switch**: per enum ordinal it maps
   URL_PARAM→quick_scan_url_params, the body/XML/multipart/JSON family (cases 2-8)→
   quick_scan_body_params, COOKIE→quick_scan_cookies, the three PARAM_NAME kinds (10-12)→
   quick_scan_param_name, HEADER→quick_scan_http_headers, ENTIRE_BODY→quick_scan_entire_body,
   PATH_FILENAME→quick_scan_url_path_filename, PATH_FOLDER (19)→quick_scan_url_path_folders,
   and hard-codes **cases 16-18 → false** — i.e. quick scan NEVER audits the parameter-relocation
   kinds. The UI panels are separate classes: `Zrdv` = full-audit types
   (map_root.tsv:24822-24826: "URL parameter values", "Entire body (for relevant content types)",
   "Cookie parameter values"), `Zrdr` = frequently-occurring/quick-scan panel
   (map_root.tsv:14883-14886: "Parameter name", "HTTP headers", "Body parameter values",
   "URL path folders").

4. **Operator exclusion lists — two severities of skip.** `Zwh1.java:8-13` builds the config from
   `scanner.ignored_insertion_points.skip_server_side_injection_for_parameters` and
   `...skip_all_tests_for_parameters` (map_root.tsv:14969-14972). The distinction is a judgment:
   a parameter can be exempted from *server-side-injection* checks only (passive/other checks
   still apply), or from *all* tests. UI copy at map_root.tsv:11808-11811 ("Ignore specific
   insertion points", "Skip all tests for these parameters:").

5. **Per-request cap, with an explanation string.** Key
   `scanner.misc_insertion_point_options.max_insertion_points_per_base_request`
   (map_root.tsv:7702, 7730, 16246) and the operator-facing status: "Burp Scanner didn't audit
   this insertion point, as it reached the maximum limit of insertion points to audit per
   request." (map_root.tsv:321, status `Limit exceeded` / `Skipped as limit exceeded` at :303,
   :332, :338).

6. **Nested insertion points, toggleable.** Key
   `scanner.misc_insertion_point_options.use_nested_insertion_points` (map_root.tsv:7706, 7744,
   14865), UI copy map_root.tsv:14868 ("Choose whether Burp places payloads into insertion points
   within nested data structures, such as JSON within URL parameters."), and the skip status
   "Skipped as nested insertion points not enabled" (map_root.tsv:297) / "…because your scan
   configuration doesn't enable auditing of nested insertion points" (map_root.tsv:311). The
   *implementation* is `InsertionPointBuilder.ZV(Zuzp)` (`InsertionPointBuilder.java:567-644`):
   a worklist stack that decodes a point's value, re-detects its container (`Za` at :648-657:
   URL_ENCODED / XML / JSON), builds nested points (`buildNestedInsertionPoint` at :668-687,
   with a JSON-quote special case `Zm` at :689-691), and additionally recognises
   **BASE64_ENCODED / BASE64URL_ENCODED** nested encodings (`:615, :635` via
   `net.portswigger.Zq0.getMovedParameterInsertionPoint` / `net.portswigger.Zan.ZG`).

7. **Parameter relocation (movement).** `InsertionPointBuilder.Zv(Zwwc)` (`:931-941`),
   `addSwitchedBodyParameterLocationInsertionPoints(Zwwc)` (`:943-968`) and `ZO(Zwwc)`
   (`:970-980`) build moved-parameter points for the six `scanner.modifying_parameter_locations.*`
   pairs (map_root.tsv:7711-7742). A subtlety: for POST requests Burp picks the *matching URL
   parameter* in the query and moves it to the corresponding body kind, matching by name AND value
   (`lambda$addSwitchedBodyParameterLocationInsertionPoints$9/10/11` at `:1035-1045`) — not
   "move every parameter". Skip status: "Burp Scanner didn't audit this insertion point, because
   your scan configuration doesn't enable %s to be moved to %s." (map_root.tsv:324), "Skipped as
   parameter movement not enabled" (:325).

8. **Synthesised points from request shape, not configuration.** The builder derives extra points
   from what the request *is*: an XML body gets a standalone-tag point when a tag is self-closing
   (`addStandaloneTagInsertionPoint`, `InsertionPointBuilder.java:467-479`); an XML/JSON body
   gets an ENTIRE_BODY point (`ZT`, `:448-465`); a PHP target gets a `PARAM_NAME_URL` point after
   the path filename (`addPhpFileRequestInsertionPoint`, `:777-783`; the "php" content-type check
   is visible in the `Zp()` bytecode at `:741-751`); a User-Agent header point and (for requests
   with no Referer) a *synthesised Referer header point* seeded with
   `Referer: https://example.com/` (`Zb`/`buildNestedInsertionPoint`/`addNewReferHeaderInsertionPoint`,
   `:785-843`). These are judgment calls about what an app actually reads.

9. **Behavioral light-audit tier (the smartest piece).** Status strings recovered for
   `burp.Zq5` (the per-insertion-point audit status enum — **UPDATE 2026-09-27: now
   decompiled**, `out/clean/jdt_src/burp/Zq5.java` (124 lines, via the CFR worklist run that
   decompiled all 39 want-not-got classes; 0 failure markers). The enum's structure is
   code-proven: 15 constants `PENDING, AUDITED, LIGHT_AUDITED, SKIPPED_PARAMETER_TYPE,
   LIMIT_EXCEEDED, FAILED_TO_SCAN, AUDITING, LIGHT_AUDITING, NOT_LIGHT_AUDITED,
   NO_PARAMETER_MOVEMENT, SKIPPED_INSERTION_POINT_TYPE, NO_INSERTION_POINT_CHECKS,
   NO_NESTING_ALLOWED, CANCELLED, SKIPPED_BY_SELECTION`, and two label builders:
   `Zd(Zuzp)` (`Zq5.java:48-62`) formats `NO_PARAMETER_MOVEMENT` with **two** insertion-point
   types (a from→to pair: `this.Zs(var1.Z_()), this.Zs(var1.Zr())`) and
   `SKIPPED_INSERTION_POINT_TYPE` with one (`Zhs3.Zd(var1).Zr()`), so the skip label *names
   the parameter type*; `Zs(Zbg8)` (`Zq5.java:65-85`) is the complete IPType→English table
   (URL parameters, body parameters, cookies, HTTP headers, XML parameters, XML attributes,
   multipart parameter attributes, URL path folders, URL path filenames, JSON parameters,
   parameter names (ordinals 12-14), the entire body, manual insertion points). The
   distinct `burp.agentic.Zq5` is an unrelated confidence/severity ordinal table): "Light-audited"
   (:283,:287), "Light-auditing" (:286,:289,:331,:333), "Burp Scanner is sending a small number of
   requests to this insertion point, to determine whether it behaves similarly to other insertion
   points of the same type." (:280), "Skipped due to repetitive behavior" (:288), "Burp Scanner has
   sent a small number of requests to this insertion point. It hasn't been fully audited as it
   behaves similarly to other insertion points of the same type that didn't raise interesting
   behavior." (:313), and "Burp Scanner didn't audit this insertion point. This type of insertion
   point has occurred frequently without raising interesting behavior and it's likely that its
   behavior will stay consistent." (:330). I.e. Burp runs a **cheap probe on the Nth occurrence of
   an insertion-point type and, if the response looks like the ones before, skips the rest of
   that type** — a cross-request behavioral dedup keyed on (type, similarity), reported honestly
   per point. Runtime trace confirms the engine touches this machinery during SCANNER feature
   activity (feature_trace.tsv:94 PRELOADED burp.Zq5).

10. **Skip attribution vocabulary** (all from the Zq5 bank, map_root.tsv:289-338): "Skipped by
    selection", "Skipped due to parameter type", "Skipped as insertion point checks not enabled",
    "Skipped as nested insertion points not enabled", "Skipped as parameter movement not enabled",
    "Skipped as limit exceeded", "Skipped due to repetitive behavior", plus full-sentence
    explanations (:284, :310, :311, :312, :318, :320, :321, :324, :329, :336) and the kind labels
    ("URL parameters", "body parameters", "cookies", "parameter names", "HTTP headers", "XML
    parameters", "XML attributes", "multipart parameter attributes", "URL path folders", "URL
    path filenames", "the entire body", "manual insertion points").

11. **HTTP/2 awareness in point construction.** `Zee2.java:12-63` classifies the four HTTP/2
    pseudo-headers (`:scheme`, `:method`, `:path`, `:authority` — literals at map_root.tsv:10712-
    10715) as a distinct header class via `ZC`, used by `Ze0j.findInvalidHeaderNames`
    (`Ze0j.java:170-171`) to keep pseudo-headers out of the ordinary-header point path (they carry
    a different regex validity rule, `Zee2.ZS`, literal `^(?=.*[A-Z:]).+$` at map_root.tsv:10712).

### (b) burpsy's current equivalent

- Enumeration lives in `internal/bcheck/insertion.go`: `EnumerateWith` (fixed order — query,
  headers, cookies, body, param-name-url, param-name-body, entire body, url-path filename,
  url-path folders, synthesised headers, body→query and query→body relocations — doc at
  `insertion.go:378-398`). Kinds: query/body/cookie/header DSL-addressable (`:72-74`), Go-only
  kinds named after Burp's settings keys (`:23-31`). Per-container payload escaping
  (`percentEscape` :1806, `jsonEscape` :1828, `xmlEscape` :2119, `multipartAttrEscape` :2149)
  and refusal semantics (`refusal` :217-244) — Burp's encode-the-payload-not-the-base-value rule
  is deliberately NOT copied (`:48-58` documents the divergence and why).
- **The per-request cap EXISTS**: `DefaultMaxInsertionPoints = 30` at `insertion.go:320`, enforced
  by `capPoints` (`:704-713`) which records the dropped count as a Declined via
  `DeclinedPastLimitWhat` (`:322-333`) — and the comment cites Burp's key + default 30 + Burp's
  exact operator string (insertion.go:308-315). Status surfaced through `AuditItemPointSkippedLimit`
  (audit_items.go:244-247).
- **Nested expansion EXISTS** (JSON/base64/base64-wrapping-JSON/XML): `expandNested`
  (`:1903-1953`), toggle `EnumerateOptions.NoNested` mapping Burp's
  `use_nested_insertion_points` default-true semantics (`:39-46`), per-point status
  `AuditItemPointSkippedNested` in audit_items.go:244-247. Burp's BASE64URL variant is NOT modelled
  (nestedKind list at :250-260 has base64 only).
- **Relocations exist but only 2 of Burp's 6 directions** (per the file's own doc,
  `insertion.go:28-31`): body→query and query→body are enumerated (:381), cookie relocation is
  implemented on the Apply side (`addToCookie` :1636-1647) but Burp's six `modifying_parameter_
  locations` toggles (map_root.tsv:7711-7742) have no per-direction config surface.
- Per-check kind selection: the three core rows (SQL injection, reflected XSS, file path
  traversal) originally passed a package-level `coreInjectionKinds = []string{"query","body",
  "cookie"}` — no `header`, so a header-borne reflection was structurally unreachable, and the
  literal also overrode the operator's `scanner/insertion_point_types/*` choice, which every other
  probe site honours through `cc.ProbeInsertionKinds()`. Fixed: all three now call
  `cc.ProbeInsertionKinds()`, so the configured kinds govern and `header` is in the default set.
  There is still no per-run *profile* object that varies kinds by check family.
- `isReservedHeader` (`insertion.go:725-741`) excludes Host/Content-Length/Transfer-Encoding/
  Connection/whole-Cookie from header points — a judgment Burp makes in `Zp`-family checks; not
  key-for-key identical but same intent.

### (c) The gap, one sentence

burpsy enumerates a *fixed* point set per request with a cap and nested expansion, but has none
of Burp's three decision overlays — no operator skip-lists (`skip_all_tests_for_parameters` /
`skip_server_side_injection_for_parameters`), no quick-scan profile keyed per kind, and no
behavioral light-audit tier that probes the Nth same-typed point and skips the rest when nothing
interesting happened — so a 300-parameter request pays full price for every parameter, and the
operator has no way to exempt a parameter that must never be touched.

### (d) Ranked smallest-honest-steps

1. **Behavioral light-audit tier (highest value, medium size).** Burp: Zq5 literals
   map_root.tsv:280-288, :313, :330. burpsy integration point: `auditItem`'s dispatch loop
   (audit_engine.go:1075-1194) already walks plan steps — the honest shape is a per-(IpKind)
   similarity ledger in `auditRun` (audit_engine.go:843 `newAuditRun`): after a configurable
   number N of same-kind points audited clean on the same host, mark further same-kind points
   `AuditItemPointSkippedDeclined`-style with a NEW status (not reusing Declined — Burp's string
   "Skipped due to repetitive behavior") and count them in the outcome so the partition identity
   (audit_engine.go:1222) still holds. Decline-and-document: if similarity is judged too
   speculative without response-diff infrastructure, implement only the *type-occurrence* half
   (Burp's :330 sentence is type-keyed, not content-keyed — "this TYPE of insertion point has
   occurred frequently") — that half needs no similarity metric, just a counter keyed on
   (IpKind, host).
2. **Operator skip lists (small, directly evidenced).** Burp: Zwh1.java:8-13,
   map_root.tsv:14969-14972, UI :11808-11811. burpsy integration: `EnumerateOptions`
   (insertion.go:335-362) gains two name lists; `EnumerateWith` filters points whose
   `Name` matches, and the filtered count becomes a Declined with a new What (mirroring
   DeclinedPastLimitWhat at :322-333). The two-tier split (all tests vs server-side injection
   only) can ship as ONE list first + document the second tier as declined, because burpsy's
   check families don't yet partition cleanly into "server-side injection" vs rest.
3. **Quick-scan profile (small-medium).** Burp: Zb1q.java:67-101 + Zb1q.java:114-121;
   map_root.tsv:7698-7745. burpsy already has the per-check switch set (enabledChecks,
   audit_engine.go:71-89) and AuditConfig; the honest shape is an AuditConfig boolean
   (quickScan) that narrows `run.cfg.insertionKinds()` (audit_engine.go:1067) to the
   quick-scan kind list — a new key on the existing EnumerateOptions rather than a second
   registry. Burp's hard "never relocate in quick scan" (Zb1q.java:94) is exactly the kind of
   judgment worth copying verbatim.
4. **BASE64URL nested kind + six-direction relocation toggles**: smallest of the batch — add
   `nestedKindBase64URL` beside :250-260 (Burp: InsertionPointBuilder.java:635) and per-direction
   booleans on EnumerateOptions. Low coverage value per effort; do after 1-3.

---

## §2 APPLICATION-AWARE AUDITING — how Burp decides WHAT an app is

### (a) Burp's mechanism

Burp builds an explicit *application model* during the crawl and feeds it to audit decisions.

1. **The crawl-optimization keys ARE the app model.** `crawler.crawl_optimization.*`
   (map_root.tsv:243-267, class Zeuc; duplicate key bank in Zgjj at :20516-20574; UI strings
   Zxs7 at :7347-7351) decide *what counts as the same place*: `link_fingerprinting_threshold`
   (:256), `clickable_fingerprinting_threshold` (:261), `loopback_link_fingerprinting_threshold`
   (:262), `maximum_unmatched_anchor/form/redirect/frame/iframe/image_area_tolerance`
   (:243,:245-246,:254,:264,:267), `dom_idle_threshold` (:258), `network_idle_threshold` (:265),
   `form_submission_optimization_threshold` (:253), `form_destination_optimization_threshold`
   (:266), `maximum_form_permutations` (:259), `fully_explore_floating_forms` (:257),
   `drop_advert_requests` (:260), `use_browser_cache` (:244), `await_navigation_timeout` (:247).
   The "unmatched-X tolerance" family is the judgment: after a link/anchor/form/redirect
   navigation, how much the rendered page may differ before Burp decides this is a *different*
   application place rather than the same one re-rendered.
2. **Operator-declared application facts.** `crawler.customization.*` keys carry answers only
   the operator knows: `application_uses_fragments_for_routing` (map_root.tsv:18369),
   `guess_hidden_graphql_endpoints` (:6158), `allow_all_clickables` (:6159-6160,:18382,:18390),
   `maximum_speculative_links` (:6162,:18392), `maximum_items_from_sitemap` (:18391),
   `request_sitemap` (:6161,:18370), `submit_forms` (:18383). Login model:
   `crawler.login_functions` (:5164), `crawl_using_provided_logins_only` (:7645-7646,:10365),
   and ScanLauncher's `applicationLoginConfig` (ScanLauncher.java:1218).
3. **Site-map reuse as audit input.** `CrawlTaskManager` seeds itself from persisted state:
   `this.Zi = var11.ZG()` re-hydrates a prior crawl queue (CrawlTaskManager.java:86), and
   `var10.startCrawl().ifPresent(...)` resumes a live passive crawl if one is running (:89) —
   the site map a previous task built is *the* discovery source for the next audit, not a
   re-crawl.
4. **Logging the application as it is observed**: `scanner.audit_optimization.logging_enabled`
   and `crawler.crawl_optimization.logging_enabled/logging_directory`
   (map_root.tsv:248,:20542,:20547,:20559,:20520) — Burp can dump its application
   observations (fingerprint decisions) for inspection.

### (b) burpsy's current equivalent

burpsy's "what the app is" reduces to two structures. (1) `plan()` groups checks into dispatch
units by `DispatchScope` (host/path/request), coarsest first — audit_engine.go:957-990 — the
per-unit key is the ONLY application identity the audit engine has. (2) The crawler has a
fingerprint concept (`internal/crawler/fingerprint.go`, with `fingerprint_budget_test.go`,
`urlTemplate` identity per session_gate.go:18) used for frontier quota and crawl dedup. The
crawl→audit coupling is a **batch at the end**: `auditCrawledExchanges` (api_crawl.go:439-441)
collects `rep.Fetches[].ExchangeID` into `ids` and calls `runBulkAudit`
(api_crawl.go:451-465) — the report's fetch list is the entire app model handed to the audit.

### (c) The gap, one sentence

burpsy never builds an application model the audit can consult — no URL/parameter
fingerprinting thresholds feeding "same place" decisions, no operator application facts
(fragment routing, graphql guessing, clickable policy), and no site-map reuse across tasks — so
every audit is flat over whatever exchanges one crawl happened to collect, with host/path keys
as the only notion of "same application".

### (d) Ranked smallest-honest-steps

1. **Site-map/crawl-report reuse across tasks (smallest, real value).** Persist the crawler
   Report (fetches + urlTemplate fingerprints) keyed by seed host, and have
   `auditCrawledExchanges` merge a prior report's un-audited exchanges. Burp evidence:
   CrawlTaskManager.java:86 (`var11.ZG()`), :89 (startCrawl resume). Decline: the full
   `crawl_optimization` tolerance-key family — it needs a rendered-DOM comparator burpsy's
   crawler does not have (no browser), and porting thresholds without the comparator would be
   knobs that read config and decide nothing.
2. **Operator application facts → audit-visible Declined rows.** Ship
   `application_uses_fragments_for_routing` and `allow_all_clickables` as *crawl-config*
   booleans that change link admission (crawler frontier), documented as crawl-only: audit
   behavior is unchanged. Evidence: map_root.tsv:18369,:18382. Decline: graphql-endpoint
   guessing — speculative-request generation is a new traffic surface that needs its own
   budget accounting first.
3. **`scanner.audit_optimization.logging_enabled` analog**: a debug dump of dispatch-unit
   admission decisions (the AuditLedger's Admit/AlreadyCovered answers). Burp: tsv:248. burpsy
   seam: `run.ledger` (audit_engine.go:808-810 per-run; :1108 Admit). Small, purely
   observability, directly matches a Burp key.

---

## §3 AUDIT QUEUE + SCHEDULING — how Burp orders, paces and dedupes audit work

### (a) Burp's mechanism

1. **Two typed event buses, not a batch call.** `Zg4f` (crawl/audit request bus:
   Zg4f.java:5-24 — typed `Zu1p<Zmpw>`/`Zu1p<Zc4q>` subscribe channels + `Zpt0<Void>` publish
   channels) and `Zg4i` (audit-side bus: Zg4i.java:5-29 — 14 typed channels incl.
   `Zu1p<Zxna>` Ze8k items, `Zu1p<Zsx7>` URLs, `Zu1p<Integer>` counters, `Zu1p<Zxjz>`
   disposition events). `CrawlTaskManager` wires both plus the crawl-phase bus `Zg45`
   (CrawlTaskManager.java:24-36,67,71-72,91).
2. **Crawl→audit bridge is per-URL and event-driven.** `Zrwf` subscribes crawl-phase events
   (Zrwf.java:29-35: `subscribingTo` on Zg4f+Zg4i, `subscribeToCrawlPhaseEvents` on Zg45) and
   *publishes each newly-reached URL immediately* to the audit bus: `Zg4i.ZP` (new URL,
   Zrwf.java:75-84) and `Zg4i.Zz` (audit-item event, Zrwf.java:74-76). Audit work starts
   while the crawl is still walking — this is what `scanner.audit_optimization.
   parallel_crawl_and_audit` (map_root.tsv:252,8768) actually means.
3. **Per-URL disposition = the priority decision.** `Zwee` subscribes crawl-traffic events and
   emits one `Zeze` per URL (Zwee.java:131-134 → `Zg4i.Zp`). The dispositions are the queue
   admission policy: `ACTION_TAKEN_AUDITABLE` (default, Zwee.java:69), demoted to
   `ACTION_TAKEN_LOW_VALUE` when the page action was a *floating form / speculative
   navigation* match (Zwee.java:125-129: `Zms6`/`Zsp4`/`Zm63` type checks — the low-value
   judgment is "this URL exists only because the crawler poked a form, not because the app
   surfaced it"), `ACTION_TAKEN_NO_TRAFFIC` (:83-85), `URL_OUT_OF_SCOPE` (:44-46), and
   per-traffic-tool reclassification (`ACTION_TAKEN_NETWORK_ERROR` for error-ish statuses,
   Zwee.java:96-110, with `REDIRECT_FROM_URL_OUT_OF_SCOPE` propagation :115-117). Full enum:
   Zeze.java:5-17, incl. `FINAL_GRAPH_PAGE_INACCESSIBLE`, `FINAL_GRAPH_CRAWL_LIMIT`,
   `FINAL_GRAPH_AUDITABLE`, **`REQUEST_TO_AUDIT_DEDUPLICATED`** — a first-class "we already
   queued an audit for this request" state, i.e. queue-level dedup BEFORE work is planned.
4. **Resource pools pace every task.** `project_options.resource_pools.*`
   (map_root.tsv:17469-17504 default pool, :23192-23213 custom pools): `concurrent_request_limit`
   (+enabled), `throttle_interval_millis` (+enabled, +`throttle_random_enabled`), and
   **`auto_backoff` / `auto_backoff_after_429_status_returned` /
   `auto_backoff_after_503_status_returned` / `custom_auto_backoff_status_codes`** — the pool
   watches status codes and backs off, per-pool. Runtime state keys: `scan_resource_pool_
   in_progress_requests` (:28564), `scan_resource_pool_latest_request_time` (:13895),
   `request-queue-%d` (Zr9n :28563).
5. **Live passive crawl keeps the site map warm for audits.** Task types "Live passive crawl"
   (map_root.tsv:362,1605,18829,23614,26637) with dashboards warning "Live passive crawl task
   is paused - Site map will not be populated" (:27746,:27754) — passive crawling is a
   continuously-running discovery service whose output (the site map) is the audit target
   source; CrawlTaskManager re-attaches to one at startup (CrawlTaskManager.java:89).
6. **Error-driven queue policy.** `Zgff.java:10` ships a "Disable error handling" preset whose
   JSON zeroes `consecutive_audit_check_failures_to_skip_insertion_point`,
   `consecutive_insertion_point_failures_to_fail_audit_item`, `number_of_follow_up_passes`,
   `pause_task_failed_audit_item_count`, `pause_task_failed_audit_item_percentage` — see §4.

### (b) burpsy's current equivalent

The queue is the `AuditItemLedger` (audit_items.go:420-686): Enqueue in caller order with a Seq
(:452-486), `moveToBackLocked` for re-audit (:639-647), `evictLocked` bounded retention
(:650-661), Begin/Step/Resolve lifecycle (:488-543). `AuditSession` feeds an ordered channel
to a fixed worker pool under MaxConcurrency (audit_engine.go:852-914), with dash task registry
rows (`s.tasks.Start(dash.KindAuditSession, ...)` api_crawl.go:457) and the suiteGate pause
(audit_engine.go:1094-1096). The live-audit sweep calls `auditFetchedExchanges` per tick —
batch-at-end per tick (api_crawl.go:451-465). Pacing: session-wide time/request budgets
(audit_engine.go:886-897) — but no throttle interval, no per-pool concurrency limit, no
status-code backoff.

### (c) The gap, one sentence

burpsy's audit queue is a bounded *log* with caller-order dispatch, while Burp's is an
*event-driven, deduplicating, disposition-prioritized* queue — per-URL dispositions
(AUDITABLE vs LOW_VALUE vs NETWORK_ERROR), cross-task request dedup
(REQUEST_TO_AUDIT_DEDUPLICATED), resource-pool throttling with status-code backoff, and audit
work starting mid-crawl rather than after it.

### (d) Ranked smallest-honest-steps

1. **REQUEST_TO_AUDIT_DEDUPLICATED across sessions (highest value).** Burp: Zeze.java:17.
   burpsy seam: `AuditLedger.Admit` is per-run (fresh per AuditWithin, audit_engine.go:802-810;
   shared within one AuditSession :841-844) — the honest shape is a *host-scoped persisted
   ledger* the live-audit sweep consults so re-seeing an already-audited exchange is counted as
   a new DispositionAlreadyCovered-style row, not re-audited. Decline: nothing — small and
   directly evidenced.
2. **Status-code auto-backoff (429/503).** Burp: map_root.tsv:14776,:14781-14787,
   :23198-23211. burpsy seam: `run.foldSent`/probeMeter in audit_engine.go:1214-1217 — a
   backoff that delays the next step after a 429/503 response. Note this needs the probe
   harness to surface response status; smallest shape is a counter+sleep in the dispatch loop.
3. **Per-URL incremental audit push.** Burp: Zrwf.java:74-84. burpsy seam: the crawler
   captures via the shared seam already; smallest shape is a callback from the capture path
   into a pending-audit channel consumed by the sweep, replacing one batch tick. Decline the
   full Zg4i event bus — 14 typed channels for a two-consumer system is ceremony; a Go channel
   of pending ExchangeIDs is the same semantics.
4. **LOW_VALUE disposition.** Burp: Zwee.java:125-129 + Zeze. burpsy: no equivalent. Honest
   decline: the judgment keys on crawler *action types* (floating forms, speculative nav)
   burpsy's crawler doesn't record — porting the constant without the action metadata would be
   a label over nothing. Document as declined in the parity ledger.

---

## §4 DYNAMIC DECISIONS DURING SCAN — how Burp adapts mid-scan

### (a) Burp's mechanism

1. **The error-handling block is a TWO-LEVEL breaker + follow-up passes + task pause.**
   `Zgff.java:10` ships the "Disable error handling" preset whose JSON zeroes five keys —
   `consecutive_audit_check_failures_to_skip_insertion_point`,
   `consecutive_insertion_point_failures_to_fail_audit_item`,
   `number_of_follow_up_passes`, `pause_task_failed_audit_item_count`,
   `pause_task_failed_audit_item_percentage`. The shipped defaults (the JSON's non-zero
   counterparts) are the model: skip the *insertion point* after N consecutive check failures,
   fail the *audit item* after N point-failures, then RE-RUN the item `number_of_follow_up_passes`
   times, and pause the whole task when failed-item count/percentage crosses a threshold.
2. **Status-code auto-backoff lives in the resource pools, not the checks.**
   `project_options.resource_pools.*` (map_root.tsv:17469-17504, 23192-23213):
   `auto_backoff`, `auto_backoff_after_429_status_returned`, `auto_backoff_after_503_status_returned`,
   `custom_auto_backoff_status_codes` — the pool watches response statuses and backs the whole
   task off, per-pool, before the next request.
3. **Scan speed / skip-ineffective / consolidate.** `scanner.audit_optimization.*`
   (map_root.tsv:8754-8768): `scan_speed`, `skip_ineffective_checks`,
   `consolidate_passive_issues`, `follow_redirections` depth (:8755,:8765) — run-level
   judgments that change HOW the engine walks, not what a check finds.
4. **Session handling during audit.** `scanner.session_handling_rules` keys
   (map_root.tsv:2894, 5850-5851, 20198) — a named rule set the audit can invoke to re-auth
   mid-scan (macro re-run on session break). Burp's audit issues can record that a session
   rule fired during the scan.

### (b) burpsy's current equivalent

- **Both breaker levels already modeled** (scout read 2026-09-17): `newSessionBreaker(cfg)`
  audit_engine.go:844 and `newItemBreaker(run.cfg)` audit_engine.go:1054, with
  `breaker.checkFailed()`/`itemFinished()` interplay at audit_engine.go:1156-1193; and
  `AuditItemBreakers` carries `ConsecutiveCheckFailuresToAbandonUnit` with Burp's exact key
  names (audit_items.go:301-304). The transcript's own words: "burpsy's breaker model is
  richer than I assumed: it already implements the two-level model AND the session
  count/percentage breaker with Burp's exact key names."
- **Budget hard-stops** at audit_engine.go:1081-1090; **suiteGate pause** at :1094-1096.
- **No follow-up re-passes**: `number_of_follow_up_passes` has no burpsy analog — a failed
  audit item is resolved once (audit_items.go:488-543 lifecycle, `moveToBackLocked` re-audit
  exists for re-SEEING (:639-647) but not as an automatic re-pass after failure).
- **No status-code auto-backoff**: pacing is session-wide time/request budgets
  (audit_engine.go:886-897) only — no throttle interval, no per-pool concurrency, no 429/503
  backoff.
- **No session rules during audit**: session recovery lives in the crawler
  (`internal/crawler/session_gate.go`, read 2026-09-17); the audit dispatch has no re-login
  or session-rule invocation mid-scan.

### (c) The gap, one sentence

burpsy has both breaker levels and the pause but none of the three adaptive responses — no
automatic follow-up re-passes after a failed item, no 429/503 auto-backoff in the probe loop,
and no session-rule invocation during an audit — so a failing item is abandoned rather than
retried, a rate-limiting target keeps getting hit at full pace, and a session that dies
mid-audit leaves every subsequent probe unauthenticated.

### (d) Ranked smallest-honest-steps

1. **429/503 auto-backoff in the probe dispatch loop (smallest, directly evidenced).** Burp:
   map_root.tsv:14776, 14781-14787, 23198-23211. burpsy seam: the dispatch loop's response
   handling (audit_engine.go:1156-1193 area) — after a 429/503, delay the next step by a
   configurable backoff and count the back-offs in the outcome. Config key on AuditConfig;
   the honest shape is a counter+sleep, not a resource-pool rewrite.
2. **Follow-up re-passes (medium).** Burp: `number_of_follow_up_passes` (Zgff.java:10). Shape:
   on item failure, re-run the item's plan up to N times with only the failed steps, reported
   as follow-up passes in the item's lifecycle. Needs the item ledger's Begin/Step/Resolve to
   allow a second pass — small state change, real behavior.
3. **Session rules during audit: DECLINE-AND-DOCUMENT.** Needs the macro/session infra the
   audit engine does not own (internal/session has Coordinator but no audit-side wiring);
   porting the key without the invocation path would be a config row that decides nothing.
   Document in gaps.md as declined pending the session epic.

---

## §5 SMART HEURISTICS WORTH PORTING — judgment beyond per-check logic

### (a) Burp's five concrete judgments

1. **Cross-request behavioral dedup ("light-audit" tier)** — §1 item 9: cheap probe on the Nth
   occurrence of an insertion-point TYPE; if responses look like earlier ones, skip the rest
   of that type (map_root.tsv:280-288, 313, 330 — full-sentence statuses).
2. **Uninteresting-response skipping** — `user_options.misc.uninteresting_response_headers`
   family (map_root.tsv:2827-2828, 4582-4588, 6646-6649, 26542-26704): headers whose presence
   marks a response as not worth deeper audit.
3. **HTTP/2 pseudo-header awareness** — `Zee2.java:12-63` classifies `:scheme/:method/:path/:
   authority` as a distinct header class (literals map_root.tsv:10712-10715), used by
   `Ze0j.findInvalidHeaderNames` (Ze0j.java:170-171) to keep pseudo-headers out of the
   ordinary-header point path with a different validity rule.
4. **Queue-level audit dedup before work is planned** — `Zeze.java:17`
   REQUEST_TO_AUDIT_DEDUPLICATED: a first-class disposition for "already queued this audit".
5. **Parameter movement matched by name AND value, not blanket** —
   `InsertionPointBuilder.java:1035-1045` lambdas: for POST, the matching URL parameter is
   moved to the corresponding body kind, matched by name+value. Plus
   `REDIRECT_FROM_URL_OUT_OF_SCOPE` propagation (Zwee.java:115-117) — scope decisions carry
   to redirected-from URLs.

### (b) burpsy's current equivalent

1. No cross-request dedup: each audit item is planned from its own request; the AuditLedger
   is per-run (fresh per AuditWithin, audit_engine.go:802-810; shared within one session,
   :841-844) and keys units, not point-types.
2. No uninteresting-response filter on the audit side.
3. No HTTP/2 pseudo-header modeling (sender is HTTP/1.1 `writeHTTP1`, sender.go:597; header
   points come from HTTP/1 head parsing).
4. No cross-task queue dedup (the ledger's AlreadyCovered is per-run).
5. Relocations are blanket clause moves (insertion.go:381 doc, 2 of Burp's 6 directions); no
   name+value matching.

### (c) The gap, one sentence

burpsy treats every request and every response as equally interesting, while Burp spends four
separate judgments deciding otherwise — same-typed points that behave alike, headers that mark
boring responses, audits already queued, parameters matched by name+value before moving.

### (d) Ranked smallest-honest-steps

1. Type-occurrence light-audit tier (§1 (d)1 — the counter half needs no similarity metric).
2. Uninteresting-response header filter (small: a name-list check in the item planner that
   skips deep probes on marked responses, counted honestly).
3. REQUEST_TO_AUDIT_DEDUPLICATED cross-task dedup (§3 (d)1 — persisted ledger consulted by
   the live sweep).
4. DECLINE: name+value relocation matching (2-of-6 directions already shipped; the matching
   adds cost for a kind that rarely fires) and HTTP/2 pseudo-headers (no HTTP/2 sender).


---

## §6 MACHINE LEARNING — does Burp use it, and would it improve burpsy?

### (a) What Burp actually ships (verified 2026-09-17)

**No ML in the scanner core.** Three decompiled + documentary findings:

1. **The "statistical" battery is classical statistics, not learning.** `burp.Zr8b`'s payload
   analysis (map_root.tsv:5899-6035) is FIPS monobit/long-run/runs tests, chi-square,
   ZLIB-compression ratio, spectral and correlation tests — each computes a significance
   level and rejects the "randomly generated" hypothesis. Zr8b:3999's own caveat says it:
   "statistical tests provide only an indicative guide... may contain false positives and
   negatives". This is ALREADY PORTED — burpsy's sequencer (i4u, verified live: bit-level
   840/452/0.9958 + by-index refusal of non-base64 tokens).
2. **"training" in the literals is the license trial** (Zepn:8713-8719 "full training"/"trial"
   — the licensing modal), not model training.
3. **Burp's actual "AI" is Burp AI — an LLM post-scan investigator, not ML in the engine.**
   (portswigger.net/burp/documentation/dast/user-guide/managing-your-sites/site-settings/
   configuring-ai-enhanced-scanning, updated 2026-09-09): after crawl+audit finish, Burp AI
   investigates issues matching severity/confidence criteria (Standard = High + Medium-
   tentative; Extended = High+Medium + Low-firm/tentative; Custom), "checks each issue to
   determine whether it represents a real and exploitable risk, and returns detailed evidence
   and remediation steps". It "does not affect the crawl or audit phases of the scan".
   Excluded: Collaborator/Infiltrator issues. Plus Repeater prompting (analyze/explain/test
   messages) and an MCP server.

### (b) burpsy's current equivalent

The sequencer covers the statistical half. The issue-triage half has a seam already: findings
carry Name/Severity/Confidence/Description/Evidence (scanner finds: catalog.go:47-53
TypicalSeverity; checks_* set Confidence "tentative"/"firm"/"certain" per evidence tier —
checks_injection_test.go:82-84, :174-176; dom_confirm.go:157-163 promotes/retires via browser
observation). There is no post-scan investigation pass that revisits findings with context.

### (c) The gap, one sentence

burpsy's verdicts are per-check and final, while Burp's highest-value triage layer (Burp AI)
is a second look at findings gated by severity+confidence — and an LLM-validated finding with
reproduction steps is materially more useful than the same finding raw, for exactly the
issue classes where burpsy's evidence is weakest (tentative differentials).

### (d) Ranked smallest-honest-steps

1. **Do NOT add an ML model to the engine core.** Burp doesn't; classical statistics already
   covers the statistical-detection niche and IS ported; an in-engine model would add a
   nondeterministic verdict to a scanner whose entire value is honest counting, and would
   need a training corpus burpsy does not have. Decline-and-document in gaps.md.
2. **Landing-ground: an LLM post-scan "second look" (Burp AI's actual shape), gated exactly
   like Burp's Standard profile** — investigate High-severity + Medium-tentative findings
   after a scan completes, produce evidence/validation text, and mark them distinctly (never
   promote confidence past the evidence; the finding's own words: "Severity is never
   overwritten" — enrich.go:3-6). Seam: a deferred phase on the scan task rows (the gxbk
   pattern — FinishScan already runs at both audit tails), or a `/api/findings/triage`
   surface. Needs: an LLM endpoint decision (operator-supplied; the OMP free models are
   unreliable) — ASK THE OPERATOR before implementing. The count of investigated findings is
   the honest metric.
3. **Honest decline for "ML improves detection":** the xsschallenge corpus is 23 vulnerable +
   9 safe with ZERO false positives — the detector already has no FP problem for ML to fix;
   the misses (hvez/2p9u/1a3z) are capability gaps (kinds, container codec, breakout confirm),
   not precision gaps. ML would add risk, not recall.

### §7 RANKED TOP-5 (evidence strength x burpsy feasibility x coverage value)

1. **Behavioral light-audit tier (type-occurrence counter)** — §1 (d)1. Burp: Zq5 full-sentence
   statuses (map_root.tsv:280-288, 313, 330); integration: audit_engine.go dispatch loop +
   a per-(IpKind, host) counter in newAuditRun (:843); shape: after N same-kind clean points,
   skip the rest with a NEW "Skipped due to repetitive behavior" status, counted in the
   outcome so the partition identity (:1222) holds. Declines: the similarity metric half.
2. **429/503 auto-backoff in the probe loop** — §4 (d)1. Burp: resource-pool keys
   (map_root.tsv:14776, 14781-14787, 23198-23211); integration: audit_engine.go:1156-1193
   response handling; shape: counter+sleep + counted back-offs.
3. **REQUEST_TO_AUDIT_DEDUPLICATED cross-task dedup** — §3 (d)1. Burp: Zeze.java:17;
   integration: a host-scoped persisted ledger consulted by the live-audit sweep
   (liveaudit.go:631-653); shape: re-seeing an audited exchange = counted Disposition row.
4. **Operator insertion-point skip lists** — §1 (d)2. Burp: Zwh1.java:8-13,
   map_root.tsv:14969-14972; integration: EnumerateOptions (insertion.go:335-362) + a filter
   in EnumerateWith producing a new Declined What; shape: one list first, second tier
   declined.
5. **Per-URL incremental audit push** — §3 (d)3. Burp: Zrwf.java:74-84 (event-driven, vs
   burpsy's batch-at-end api_crawl.go:451-465); integration: a capture-path callback into a
   pending channel consumed by the sweep; decline: the 14-channel Zg4i bus.

Explicit declines (document in gaps.md): ML in the engine core (§6 (d)1); session rules
during audit (§4 (d)3 — pending the session epic); LOW_VALUE disposition (§3 (d)4 — needs
crawler action metadata); full crawl_optimization tolerance family (§2 (d)1 — needs a
browser); HTTP/2 pseudo-headers (no HTTP/2 sender); name+value relocation matching (§5 (d)4).
