# Burp CRAWLER vs burpsy-go — evidence-backed gap map (2026-09-26)

**Burp oracle:** `/root/burp-re`, build **2026.7.1** (jar manifest `Implementation-Version` 51467, per `SOURCE-OF-TRUTH.md` §1). The live instance is 2026.7.3 (build 52685) — a 1,218-build skew; every citation below is from the 2026.7.1 tree, and where behaviour could differ the claim is labelled PROBABLE rather than CONFIRMED.

**Layer used.** Layer 4 (`out/clean/jdt_src/burp/*.java`, flat filenames) for every behavioural claim, Layer 4 string literals in `out/strings/map_root.tsv` for every key name. No Layer-1/2/3 name recovery is needed for any claim here: every class named below is cited by its own decompiled file, and every config key by a `map_root.tsv:<line>` or a `Zgjj.java:<line>` read.

**Claim labels.** CONFIRMED = read the code. PROBABLE = shape/name evidence only. UNKNOWN = searched and could not resolve.

**burpsy side.** `burpsy-go/internal/crawler/` (8 non-test Go files), `internal/web/api_crawl.go`, `internal/web/ui/src/ui/crawl.tsx`, `internal/web/ui/src/ui/crawlpaths.tsx`, read today. `bd` state: 385 issues, 380 closed (`/root/burpsy-react-ui/.beads/issues.jsonl`).

---

## Dedup ledger first — what is ALREADY LANDED and must not be re-filed

These are the crawler/scanner findings a naive re-audit would re-file. Each is verified **in the tree today**, not inferred from a close reason.

| Burp mechanism | Burp citation | burpsy state today | Verdict |
|---|---|---|---|
| Browser-driven crawl navigation (`crawler.customization.browser_based_navigation_mode`) | `map_root.tsv:6180` (key), `Zrfn.java:108` "Use Burp's browser for Crawl and Audit", `Zr0o.java:2804` (the `Zbqd` USE/DONT_USE enum) | `crawler.Config.Render` (`crawler.go:343`) + `crawler.go:1418-1442` runs a rendered-DOM second pass admitting only links the wire parse did not carry; wired to the same lazy browser the audit uses at `api_crawl.go:445` `Render: s.crawlRenderer()`. Failures are `SkipRenderUnavailable` (`skip.go:180`). Edge marked `Fetch.FoundByRender` (`crawler.go:424`). | **LANDED** (nx7b) |
| Rendered-DOM audit over crawl output | Burp's audit side | `api_crawl.go:486` `s.auditCrawlLocations(ctx, task.ID(), &rep)`, `Report.RenderedAudit` (`crawler.go:506`) | **LANDED** (xuim) |
| Per-URL incremental crawl→audit bridge | `Zrwf.java:29-31` subscribes to phase events and publishes each new path (`Zrwf.java:79-81`) | `crawler.Config.OnFetch` (`crawler.go:318`) → `api_crawl.go:417-421` `feed.offer` | **LANDED** (7suo) |
| Live passive crawl seeds the frontier | `map_root.tsv:23563-23584` (`crawler.live_passive_crawl.*`) | `crawlStartReq.IncludeLiveSeen` (`api_crawl.go:195`), consumed via `TakeLiveSeenURLs` | **LANDED** (tqug) |
| Site-map "Crawl paths" view | `map_root.tsv:27020` "The crawl paths view shows your targets as a tree of Burp Scanner actions and pages" | `ui/crawlpaths.tsx` `buildCrawlTree` / `CrawlPathsView`, fed by `Fetch.FoundAt` | **LANDED** (tix, 565c6c7) |
| Suite-wide pause reaching the crawl loop | — | `api_crawl.go:453` `c.WithSuiteGate(s.tasks.GateCheck)` | **LANDED** (cijs) |
| Destructive-action refusal | Burp's crawler has no equivalent; this is a burpsy *addition* | `destructive.go:87-132` six-bucket signal table, matched by token runs (`destructive.go:202-245`) | **LANDED**, no Burp counterpart |
| Authenticated crawl + re-login | `Zrb7/Zrbt/Zrbs/Zrl5/Zrlw` (login phases), `map_root.tsv:18721-18724` | `session_gate.go` + `limits.go:110 MaxRelogins` + `StopReloginBudget` | **LANDED** as an engine — **but see gap C-9: no production caller sets it** |
| `crawler.crawl_optimization.*` tolerance-key family | `map_root.tsv:243-267` | `gaps.md:1278-1285` "Decline 4" — declined with a stated reason (no rendered-DOM comparator) | **declined on the record** — do not re-file as a bare gap |

---

## Area 1 — Crawl task manager (`burp.Zc16`)

### Burp mechanism (CONFIRMED)

`out/clean/jdt_src/burp/Zc16.java`, 222 lines, `@Zp49`-scoped, `implements Zivq<Zg49, Zg44>`. Read in full today. It is **not** the traversal engine — it is a lifecycle supervisor:

- `Zk` is a `ConcurrentLinkedQueue<Zb47>` seeded with one task (`:72-75`), drained by `ZS()` (`:118-120`) / `Zf()` (`:113-115`). One work item, not a frontier.
- `Zl(Zc58)` (`:159-174`) is the start path. It instantiates and wires **seven** collaborators against the phase event bus `ZN`: `Zplt` (`:165` — site-map/HTML chain publication), `Zwee` (`:166` — action/issue recording), `Zw9f` (`:167`), `Zgkr` (`:168`), `Zfm6` (`:169`), `this.ZZ.ZZ(...)` (`:170` — `Zrwf`, the crawl→audit bridge), then a per-config finalisation `ZW.Zt3().ZKW()` (`:171-173`).
- `ZR(Zc58)` (`:141-157`) refuses an out-of-date crawl: `Zc2k.OUT_OF_DATE_CRAWL` when the seed config carries a `Zhqm` entry (`:143-144`), otherwise prunes the queued work by a byte-age threshold `ZW.Zt3().ZKq()` (`:150-155`).
- `ZP()` (finish, `:185-193`) walks `ZW.Zt3().ZKn()` and emits a per-item `Zm8i.RECORDED_SEQUENCE_NO_NEW_PAGES` event when every resulting action is of one type (`lambda$finishCrawl$2`, `:211-213`).
- `lambda$new$0` (`:219-221`) registers a **live telemetry cap**: `Zbtp.CRAWL_MAX_TIME_MINS` set from the config's own max-time — the crawl is truncated by an external watchdog.

**Named task types** (CONFIRMED, `Zb8w.java:7-30`): ANCHOR, FORM, REDIRECT, DELAYED_REDIRECT, FRAME, IFRAME, IMAGE_MAP_AREA, SITEMAP, SPECULATIVE, NOT_FOUND_DETECTION, RECORDED_SEQUENCE, API, CLICKABLE, CLICKABLE_WITHOUT_ATTRIBUTES, DISCOVERED_CONTENT, ORIGIN, ROBOTS, SUBMIT, GRAPHQL_INTROSPECTION, DISCOVERED_GRAPHQL_OPERATION, SOAP, CLICKABLE_WITH_POINTER_STYLE, RECORDED_LOGIN_AUTHENTICATION. **23 action kinds.**

**Phases** (CONFIRMED, each is a `Zrbd` subclass whose `toString()` names it): `Zrb7` RobotsCrawlPhase (`:102-104`, display "Requesting robots.txt"), `Zrba` RequestOriginUrlActionsCrawlPhase (`:74-76`, "Requesting seed URLs"), `Zrbz` IncyWincyCrawlPhase (`:71-73`, "Crawling"), `Zrbx` SpeculativeLinksCrawlPhase (`:79-81`, "Discovering hidden content"), `Zrl5` WithCredentialsCrawlPhase (`:111-113`), `Zrbs` UnauthenticatedCrawlPhase (`:76-78`), `Zrb3` RetryNetworkErrorCrawlPhase, `Zrbz`/`Zrbt` RegistrationCrawlPhase (`:69-71`), `Zrlw` LocateLoginPageActionCrawlPhase (`:26-28`). **Nine named phases**, each with a `Zs()` display string shown in the dashboard task row.

**Progress normalisation** (CONFIRMED, `Zbcc.java`, 118 lines, read in full): the crawl half maps a per-item relative integer into 0–12% — `lambda$adaptCrawlToRelativeProgress$10` at `:75-77` is literally `var0.Zb(var1 / 8)`; the audit half maps into 100–112% — `lambda$adaptAuditToRelativeProgress$11` at `:71-73` is `(100 + var1 * 7) / 8`. The whole of `Zbcc` exists to keep **crawl = 0-12%, audit = 100-112%** on one shared 0-100+ bar (`lambda$adaptEvents$1` `:111-113`; non-dashboard mode falls to `:22-23`).

### burpsy state (CONFIRMED)

- Lifecycle: `internal/web/api_crawl.go:46-167` `crawlRuns` registry — start/list/get/finish/setDefinition, bounded at `crawlRunsKept = 20` (`:41`). Task row via `s.tasks.Start(dash.KindCrawl, …)` (`api_crawl.go:455`). States: the struct's `State` string, set only in `finish` to `"running"`→`"done"`/`"failed"` (`:126-131`).
- Progress: `task.Advance(uint64(rep.Fetched))` **after** `Run` returns (`api_crawl.go:489`), then `task.Finish(dash.Breakdown{})` (`:497`). A crawl task therefore shows 0% for its entire life and jumps to 100% at the end.
- Action-kind taxonomy: none. `discoveredLink.tag` (`discover.go:68`) carries only `"a"`, `"area"`, `"iframe"`, `"frame"`, and `"robots"`/`"robots-sitemap"` for robots paths (`crawler.go:1543,1546`). `Fetch` has no action-type field.
- Phase names: none. No phase concept exists.

### Gap

Burp names 9 phases and 23 crawler action kinds and runs crawl and audit on **one** normalised progress bar; burpsy has neither vocabulary, and a crawl's task row shows 0% until the instant it finishes — so the operator cannot tell a crawl in progress from a stalled one, and cannot see that a crawl handed anything to the audit at all.

### Verdict: **PARTIAL**

### Ranked smallest honest step

1. `internal/dash/tasks.go` — call `task.Advance` from `Config.OnFetch` (one existing callback, `crawler.go:318`) instead of once after `Run`. No new vocabulary, and the report is unchanged.
2. `internal/crawler/discover.go` — promote `discoveredLink.tag` from a free string to a `CrawlAction` enum and carry it onto `Fetch.Action`, so crawl-paths can show anchor/form/iframe/robots edges. `skip.go`'s switch-based `slot()` pattern is the template.
3. Phase names: only worth it once (1) lands; then a `CrawlPhase` string on the run record.

---

## Area 2 — Crawl configuration keys

### Burp mechanism (CONFIRMED)

Seven key families, read from the config-object accessors (each is a `default Z_(Zg4q)` / `ZM(Zs0y)` pair — a load-from-map and a save-to-map, so the key set is exactly the literals in those two methods):

**`crawler.crawl_limits` — 3 keys** (`Zmst.java:26-38`): `maximum_crawl_time` (minutes, `Optional<Duration>`), `maximum_unique_locations`, `maximum_request_count`.

**`crawler.error_handling` — 4 keys** (`Zf9w.java:29-32`): `pause_task_requests_timed_out_count`, `pause_task_requests_timed_out_percentage`, `consecutive_authentication_failures_before_pausing_task`, `number_of_follow_up_passes`.

**`crawler.crawl_project_option_overrides` — 2 keys** (`Zx98`, `map_root.tsv:23131-23134`): `connect_timeout`, `normal_timeout`.

**`crawler.crawl_optimization` — 29 keys** (`Zgjj.java:129-173` load / `:178-205` save). Grouped:
- depth/identity: `maximum_link_depth` (`:129`), `link_fingerprinting_threshold` (`:140`), `loopback_link_fingerprinting_threshold` (`:142`), `clickable_fingerprinting_threshold` (`:141`)
- strategy: `crawl_strategy` (`:133`, enum `Zmqs`), `crawl_strategy_customized` (`:135`), `incy_wincy` (`:137`), `crawl_using_provided_logins_only` (`:131`)
- form: `form_submission_optimization_threshold` (`:144`), `form_destination_optimization_threshold` (`:167`), `maximum_form_permutations` (`:166`), `maximum_form_field_permutations` (`:168`), `fully_explore_floating_forms` (`:169`)
- **the tolerance family — 7 keys**: `total_unmatched_feature_tolerance` (`:146`), `maximum_unmatched_anchor_tolerance` (`:147`), `maximum_unmatched_iframe_tolerance` (`:148`), `maximum_unmatched_frame_tolerance` (`:149`), `maximum_unmatched_form_tolerance` (`:150`), `maximum_unmatched_redirect_tolerance` (`:151`), `maximum_unmatched_image_area_tolerance` (`:152`)
- browser idle: `network_idle_threshold` (`:161`), `dom_idle_threshold` (`:162`), `await_navigation_timeout` (`:165`), `idle_time_for_mutations` (`:153-155`)
- misc: `use_accessible_text_for_visible_text` (`:138`), `use_browser_cache` (`:172`), `drop_advert_requests` (`:173`), `logging_enabled` (`:170`), `logging_directory` (`:171`)

`Zmqs` (`Zmqs.java:7-38`) is the 5-value strategy enum — FASTEST, FASTER, NORMAL, MORE_COMPLETE, MOST_COMPLETE — and it **carries all 22 tuning numbers as public final fields** (`:14-37`), i.e. the strategy *is* a tolerance bundle. Three keys are dual-spelled through `Zmpq` (`:5-9`): `LINK_FINGERPRINT_TRIGGER`/`link_fingerprinting_threshold`, `MAX_SUBMISSIONS_PER_FORM`/`form_submission_optimization_threshold`, `MAX_UNMATCHED_LINK_TOLERANCE`/`total_unmatched_feature_tolerance` — CONFIRMED at `Zgjj.java:139,143,145`.

**`crawler.customization` — 20 keys** (`Zxcp.java:92-129`): `submit_forms`, `customize_user_agent`, `user_agent`, `request_robots_txt`, `request_sitemap`, `maximum_items_from_sitemap`, `request_speculative`, `maximum_speculative_links`, `parse_api_definitions`, `parse_soap_wsdls`, `allow_all_clickables`, `allow_all_pointer_cursor_elements`, `application_uses_fragments_for_routing`, `allow_out_of_scope_resources`, `timeout_for_in_progress_resource_requests`, `browser_based_navigation_mode`, `perform_graphql_introspection`, `guess_hidden_graphql_endpoints`, `run_in_isolation`.

**`crawler.login_functions` — 2 keys** (`map_root.tsv:18721-18724`): `attempt_to_self_register_a_user`, `trigger_login_failures`.

**`crawler.live_passive_crawl` — 8 keys** (`Zc0e`, `map_root.tsv:23563-23585`): `add_all_urls`, `add_urls_in_scope`, `add_item_itself`, `add_same_domain`, `add_links`, `add_form_submissions`, `custom_scope`, `scope_type`.

**Burp's shipped-configuration denominator for `crawler.*`** (CONFIRMED, counted by reading every `Crawl*.json` under `in/extract/resources/BuiltInConfigs/`): 9 files carry a `crawler` object. Across all 9, the *distinct* `crawler.*` leaf keys that appear are **10**: `crawl_optimization.crawl_using_provided_logins_only`, `crawl_optimization.crawl_strategy`, `crawl_limits.maximum_crawl_time`, `crawl_limits.maximum_unique_locations`, `crawl_limits.maximum_request_count`, `error_handling.number_of_follow_up_passes`, `error_handling.pause_task_requests_timed_out_count`, `error_handling.pause_task_requests_timed_out_percentage`, `crawl_project_option_overrides.normal_timeout`, `crawl_project_option_overrides.connect_timeout`. **Method:** read each `Crawl*.json` / `Crawl and Audit*.json` / `Crawl limit*.json` / `Crawl strategy*.json` and union the `crawler.*` dotted paths. That is the number an operator can actually load — the 68-key surface above is what the *settings UI* exposes.

### burpsy state — the config-key inventory, counted

**Method (three separate counts, stated because "the config surface" is three different numbers):**

**(a) `crawler.Config` struct fields — 20.** Counted by reading `crawler.go:213-349` and listing every exported field: `Seeds`, `SeedRequests`, `SeedsOnly`, `Scope`, `Sender`, `Capture`, `Query`, `RetentionQuery`, `SubmitForms`, `Limits`, `RequestsPerSecond`, `Pool`, `UserAgent`, `Headers`, `SessionCoordinator`, `LoginPagePattern`, `OnFetch`, `Render`, `MaxSkipRecords`, `Logger`. Package-level knobs the Config does not carry: `DefaultUserAgent` (`crawler.go:189`), `DefaultRequestsPerSecond` (`:197`), `RobotsPolicy` (`:184`), `DefaultLimits()` (11 fields, `limits.go:120-152`), `DefaultMaxSkipRecords`, `fillerText` (`discover.go:531`).

**(b) `crawler.Limits` fields — 11** (`limits.go:47-111`, read today): `MaxRequests`, `MaxDepth`, `MaxDuration`, `MaxLocations`, `MaxFrontier`, `MaxLinksPerPage`, `MaxParseBytes`, `MaxTemplateVisits`, `MaxCaptureBytes`, `MaxFingerprints`, `MaxRelogins`. (`MaxRenderedLocations` is referenced at `api_crawl.go:522` but is not a `Limits` field.)

**(c) The wire surface — `crawlStartReq` has 13 JSON fields** (`api_crawl.go:187-226`): `seeds`, `include_live_seen`, `kind`, `query`, `retention_query`, `submit_forms`, `max_requests`, `max_depth`, `max_duration_secs`, `pool`, `requests_per_second`, `user_agent`, `headers`. `api_crawl.go:401-410` then applies only **three** of the eleven `Limits` fields — `MaxRequests`, `MaxDepth`, `MaxDuration`. The other eight are unreachable from any wire call.

**So: 3 of 11 burpsy `Limits` are settable over the wire, and 8 bounds an operator would want to set (locations, links-per-page, template quota, capture size, fingerprint budget, relogin budget, frontier, parse bytes) exist only as Go constants.**

`internal/scanner/burpconfig.go:20-41` reads only `file.Scanner` — the `crawler` object of a Burp configuration file is **silently dropped**, with no report, because `burpConfigFile` has one field and it is `Scanner`. Compare `apply()` at `burpconfig.go:92-99`, which is careful to record an unknown `scanner/*` key in `UnrepresentableKeys`; the `crawler` object never reaches that path at all.

### Gap

An operator who points burpsy at one of Burp's own 9 shipped crawl configurations has their entire `crawler` object discarded without a word, and even the engine's own 8 unreachable bounds have no door — so the crawl's depth/locations/links-per-page policy is a Go constant, not a setting.

### Verdict: **PARTIAL** (limits exist and are honestly reported; the *config surface* does not)

### Ranked smallest honest step

1. `internal/scanner/burpconfig.go:20-21` — add `Crawler map[string]json.RawMessage` to `burpConfigFile` and record the `crawler` object name in `UnrepresentableKeys` when no crawler key is behind a field. One struct field, and it converts a silent drop into a reported one. This is the single highest-value change in the whole area.
2. `internal/web/api_crawl.go:187-226` — add `max_locations`, `max_links_per_page`, `max_template_visits`, `max_capture_bytes` to `crawlStartReq` and map them in the `limits.` block at `:401-410`. Four `if > 0` blocks, and it makes four of the twelve `CrawlStop` reasons reachable by an operator rather than only by editing Go.
3. `internal/scanner/burpconfig.go` — a `crawler` key table mirroring `burpConfigSections`, starting with the 3 `crawl_limits` keys, which map 1:1 onto three existing `Limits` fields.
4. The 7-key tolerance family and `dom_idle_threshold`/`network_idle_threshold`: **do not file.** `gaps.md:1278-1285` already declines them with a reason, and the reason is still true (no rendered-DOM comparator in the engine).

---

## Area 3 — Location identity / fingerprinting

### Burp mechanism (CONFIRMED)

Three *distinct* thresholds, and the design is "mask the action descriptors, then compare":

- `link_fingerprinting_threshold` — `Zgjj.java:140`; UI copy "Clickable fingerprinting threshold:" at `map_root.tsv:7348`, "Loopback link fingerprinting threshold:" at `:7351`.
- `clickable_fingerprinting_threshold` — `Zgjj.java:141`.
- `loopback_link_fingerprinting_threshold` — `Zgjj.java:142`.
- A **per-feature tolerance budget**, not a single threshold: 7 keys (`total_unmatched_feature_tolerance` + six `maximum_unmatched_<feature>_tolerance`, one each for anchor, iframe, frame, form, redirect, image-map-area — `Zgjj.java:146-152`). UI copy: "Maximum unmatched image area map tolerance:" (`map_root.tsv:7391`), "Maximum unmatched form tolerance:" (`:7347`).
- Direction: **tolerate unmatched features**, i.e. two pages are the same location when the set of features that did *not* match is within budget. The `Zb8w` action-kind enum is the feature vocabulary the tolerance is counted in (ANCHOR / FRAME / IFRAME / FORM / REDIRECT / IMAGE_MAP_AREA are exactly the six that have their own tolerance key).
- The advanced panel is deliberately hidden and says so: `Zxs7.java:112-115` names `scanConfigurationEditorCrawlStrategyTuning*`, and `map_root.tsv:7392` carries the warning *"These settings are undocumented and are not intended for general use."*
- **Directory identity**: `Zswt.java:134-138` `ZLx()` takes the last `/` of the response path and returns the prefix as a new `Zswt` — a plain directory prefix, i.e. the shape that answers "is this the same page, at a different sub-path". Not a learned template.
- Parameter-name fingerprints: the two renamed keys in `Zmpq` (`:6-8`) show the older spelling was **trigger-based** (`LINK_FINGERPRINT_TRIGGER` → `link_fingerprinting_threshold`), so the design moved from "fingerprint when N differences" to "N is the tolerance". CONFIRMED from `Zgjj.java:139-140` (both spellings are read).

### burpsy state (CONFIRMED, read today)

- `fingerprint.go:136-160` `requestFingerprint` — method + normalised scheme/host/port + path + query sorted with `volatileParams` values replaced (`fingerprint.go:85-115`, 29 names) + a body hash.
- `fingerprint.go:237-275` `urlTemplate` — id-shaped segments collapsed to `{id}` by `looksLikeID` (`:278-297`: all-digits / UUID / hex≥12 / opaque≥24-with-a-digit), query **names only**, plus sorted body field names.
- `discover.go:288-300` `locationFingerprint` — sha256-16 over skeleton + **raw** sorted link targets + log2 text-length bucket; `discover.go:242` `structuralAttrs = {name,type,method,action,rel}`.
- The bias is documented and deliberate: **false split over false merge** (`fingerprint.go:36-46`, `discover.go:264-274`).
- The per-template quota `MaxTemplateVisits` (`limits.go:73`, default 20 at `:134`) is the infinite-application cutoff, and it refuses rather than evicts (`limits.go:218-246`).
- Session gate reuses `urlTemplate` as the template identity for the 200→non-200 flip (`session_gate.go:106`, `crawler.go:1261`).
- **There is no tolerance, no threshold, and no per-feature budget anywhere in the package.** Fingerprinting is exact-hash, binary: equal or not.

### Gap

Burp's location identity is a *tolerant* comparison over a typed feature set with a per-feature budget, so a page that changes one anchor is still one location; burpsy's is an exact hash of four components, so any change to a link target is a new location — the deliberate false-split that `fingerprint.go` documents, contained by a per-template visit quota rather than by the identity itself.

### Verdict: **PARTIAL** (the identity exists and the bias is documented and correctly reasoned; the tolerance axis does not)

### Ranked smallest honest step

1. `internal/crawler/fingerprint.go` — record a **band** on each location rather than one hash: `{hash, linkSetDigest}` where `linkSetDigest` is an order-independent hash of the *set* of outgoing path shapes (templated, not raw). Then `recordLocation` (`crawler.go:1451`) can report "same page, N links differ" as a distinct, counted outcome rather than a new location. This is the smallest thing that makes the tolerance axis representable at all, and it does not require a number yet.
2. Only after (1): expose one `MaximumUnmatchedFeatureTolerance int` on `Limits` with a new `StopToleranceBudget`, mapping to Burp's `total_unmatched_feature_tolerance` and nothing finer. The six per-feature keys stay declined (a per-feature budget over a link *set* is a second mechanism, not a configuration).
3. `Zsx7`-equivalent UI: the tuning panel is a separate expander with PortSwigger's own "undocumented" warning — but only once a tolerance number means something.

---

## Area 4 — Traversal model

### Burp mechanism (CONFIRMED)

**Not a frontier queue — a graph of *actions* with re-navigation.** Evidence:

- `Zplt.java:35-42` `Zl(Zw2_)`/`ZE(Zhem)`: a completed action publishes a **new action descriptor** via `this.ZO.ZH(this.ZP.ZI(var1))` — the location is reached by *performing the action from a known point*, not by dialling a queued URL.
- `Zplt.java:44-47` `ZH(Zhak)`: an action "made pending" is also published. So a link reached as the third step of a wizard is a pending action of step two, and Burp re-walks it.
- `Zplt.java:49-62` `ZC(Zefs)`: after an action, Burp inspects the resulting `ZpP()` chain and — when no action of a matching type had a differing result (`lambda$actionPerformed$5/6/7`, `:74-84`) — publishes **every HTTP hop in the chain** as a site-map item (`:59-61`, `Zj` `:64-68`). This is the redirect-tolerance mechanism: a 3xx that changes nothing but the URL is not treated as a new location.
- Ordering: the phases are a **fixed sequence**, not a priority queue. `Zrba` requests seed URLs first (with a `Duration.ofSeconds(30L)` budget, `Zrba.java:44`), then `Zrb7` robots, then `Zrbz` the main crawl, then `Zrbx` speculative. Within a phase, `Zrbz.java:33` filters `Za(this.Zo)` by `lambda$beforeStart$0` (`:91-93`) — a page is crawled only if `!Zhak.ZP5().ZA(var0) || var1.ZPC().isEmpty()`, i.e. **the origin's known location is re-navigated from scratch each visit**, which is what makes the model stateful.
- `Zrbx.java:55-58` `Ze(Zms6)`: the speculative-link budget is a `HashSet<Zsx7>` plus an `AtomicInteger` against `this.Zz.Zn()` — dedup by the *URL's own template* (`Zk(Zsx7)` at `:60-62` calls `Zsx7.Zc(url.ZLJ(), url.ZS())`), with a hard cap enforced mid-traversal by `lambda$beforeStart$1` (`:87-89`).
- Quota by *location*, not by URL: `Zmqs.maxLocationsPerUrl` (`Zmqs.java:37`) caps how many distinct locations one URL may produce.

### burpsy state (CONFIRMED)

- `crawler.go:1053-1087` — a strict breadth-first loop over `c.frontier`, a `[]frontierItem`: `item := c.frontier[0]; c.frontier = c.frontier[1:]`. FIFO, sequential, one request in flight.
- The graph-vs-queue gap is **stated on the record** in the package doc (`crawler.go:65-83`), including the narrowing argument that form submission is off by default so the gap is dormant until CRAWL-03 is turned on.
- Depth: `Limits.MaxDepth` (default 6, `limits.go:123`), `StopDepth` + `SkipDepthLimit`.
- Dedup: three tiers — exact `requestFingerprint` (`SkipAlreadyQueued`), per-template quota (`SkipTemplateQuota`, `StopTemplateQuota`), post-fetch content (`SkipDuplicateLocation`).
- Bounds: 12 `CrawlStop` values, `LimitReport.Truncated` **derived from the stops slice** (`limits.go:192-194`) — a design the file argues for explicitly.
- Redirect: **not followed**. `crawler.go:1308-1311` re-enters the `Location` as an ordinary discovered link, passing every gate again. Deliberate, documented (`crawler.go:126-130`).
- Missing vs Burp: no re-navigation, no action-descriptor model, no HTTP-hop-chain publication, no "same location, different links" tolerance, no per-URL location cap, no priority ordering.

### Gap

Burp traverses an action graph by re-navigating from a known point and publishes the whole HTTP hop chain of each action, so a wizard's third step and a 3xx-that-changed-nothing are both handled; burpsy issues queued URLs in isolation and treats every 3xx as a fresh frontier entry, so multi-step state and redirect-as-same-location are structurally out of reach — the first is documented, the second is not stated anywhere.

### Verdict: **PARTIAL** — the graph model is a documented, correctly-scoped decline; the redirect tolerance is an unstated one

### Ranked smallest honest step

1. `internal/crawler/crawler.go:1308-1320` — one line of honesty, zero risk: when a 3xx's target is already a known location, record `SkipDuplicateLocation` with `Detail: "a redirect to an already-seen location"` instead of re-queuing it. This is Burp's `lambda$actionPerformed$5/6/7` at `Zplt.java:74-84` in miniature, and it makes the current silent re-fetch a counted one.
2. `internal/crawler/crawler.go:580-609` `frontierItem` — carry the *set* of response hop URLs a fetched item produced, so the crawl report can name them. Half of `Zplt.Zj` (`:64-68`) for a field and a counter.
3. The graph model itself: **do not file as a gap.** It is `crawler.go:65-83`, with the dormancy argument. File it only if/when a bead turns form submission on by default.

---

## Area 5 — Link & form extraction

### Burp mechanism (CONFIRMED)

- **HTML element surface.** `Zueq.java:124-142` `ZZ` is the navigational-attribute predicate and it enumerates exactly: `src|data` on `iframe|object|embed|frame` (`:127-131`), `href` on `a|math` (`:132`), `formaction` on `button|input` (`:133`), `action` on `form` (`:134`). So Burp extracts from **`a`, `math`, `object`, `embed`, `iframe`, `frame`, `form`**, and from `button/input[formaction]`.
- **Beyond markup.** `Zueq.java:156-168` `ZH` classifies an insertion point's enclosing context and descends into `script`, `xmp`, `noscript`, `title` — i.e. **script bodies are read**.
- `Zueq.java:28-60` also reads every element's attribute map (`ZG8().ZJ5()`), so an attribute the crawler does not recognise is still carried.
- **JS-constructed URLs**: `Zwv3.java:50-53` `Zs(Zxmc)` — `this.Zi(var1.Zf(), "onclick")` builds a "javascript href potential HTML interaction". `Zpj9` (`map_root.tsv:14572-14579`) carries the URL-extraction literals: `location.href`, `window.location.href`, `document.location.href`, `location.replace`, `window.location`, `window.navigate`, `http://`, `https://`. This is the `crawler.customization.request_speculative` machinery ("Follow hidden links in comments and JavaScript", `map_root.tsv:18379`).
- **`srcset`**: literal present at `map_root.tsv:1501` (`Zeyc`), `:7846` (`Zi9s`).
- **`<meta http-equiv=refresh>`**: `Zcun.java:78-83` `Ze(Zbpq)` — requires `http-equiv`=`refresh` **and** a `content` value matching `.*url\s*=\s*https.*`; `:59-76` `Za()` does the same off response headers; the class implements `Zs7g` with `Zugn.PPH_UnencryptedCommunications` (`:37`). Burp also has it as a *redirect policy* (`project_options.http.redirections.understand_meta_refresh_tag`, `map_root.tsv:26557`; UI checkbox "Meta refresh tag", `Zrgv.java:97`).
- **Clickables**: `Zb5z.java:12-19` carries `Zb8w` action type, `id`, `name`, `href`, **`onclick`** (`:61-63`), a `click` list (`:65-67`), a list of `Zw36` (text) hints (`:69-75`), and a live browser handle `net.portswigger.browser.Zkn` (`:82-84`). `Zpio.java:60-78` is the element predicate: `button[type=submit]`, `button`, `input[type=submit]`, `img`, `div` — with `ZGU()` a node-kind code where 0/1/4 distinguish normal/attribute/other. So Burp treats **`button`, `input`, `img`, `div`** as clickables, gated by `allow_all_clickables` / `allow_all_pointer_cursor_elements` (`map_root.tsv:6159,6156`; UI "Click all clickable elements" `:18368`, "Click all pointer clickable elements" `:18390`).
- **`<area>` image maps**: `Zb8w.IMAGE_MAP_AREA` is a first-class action type; `Zpio.ZI` (`:72-74`) is `img`; `Zueq.ZZ` does **not** list `area[href]` separately (Burp gets it from the same attribute sweep).
- **robots.txt / sitemap.xml**: `Zp40.java:16` returns `"/robots.txt"`, `Zgkz.java:18` returns `"/sitemap.xml"`. Both implement `Zpp9` with a `ZI(Zbsg)` "expectation is present in response" check, so the request is only counted as productive when it looks like the right file. Third `Zpp9`: `Zgt0.java:21` `"/favicon.ico"`.
- **WebSocket endpoints**: **UNKNOWN.** No `ws://`-shaped crawler-side literal exists in `map_root.tsv` attributable to the crawler; the `ws://`/`wss://` literals at `map_root.tsv:15451-15452` are the Target/Proxy listener UI. `Zb8w` has no WS action type. Burp discovers WebSockets through the browser's network log, not through markup extraction.

### burpsy state (CONFIRMED)

`discover.go:190-223` — one `switch n.Data`:

| tag | queued? | note |
|---|---|---|
| `a`, `area` `[href]` | **yes** (`:191-201`) | `linkText` includes `title` + `aria-label` (`:330-345`) |
| `iframe`, `frame` `[src]` | **yes** (`:202-208`) | |
| `form` | **yes** (`:209-222`) | `readForm` at `:377-446`, field defaults via `fillValue` (`:539+`) |
| `img`, `script`, `link`, `source`, `embed`, `video`, `audio` | **no** — deliberate, documented (`discover.go:24-30`) | also excluded from the skeleton |
| `base[href]` | honoured (`:301-316`) | |
| `srcset`, `<meta http-equiv=refresh>`, JS-constructed URLs, CSS URLs, `data-*` | **no** — named as absent (`discover.go:32-35`) | |
| `button[formaction]`, `input[formaction]`, `math[href]`, `object[data]` | **no** — not mentioned anywhere | |

Non-HTML: `isHTML` (`crawler.go:2098-2111`) accepts only `text/html`, `application/xhtml+xml`, `application/xhtml`, `text/xhtml`; anything else is `SkipNotHTML` with a raw-body fingerprint (`crawler.go:1332-1341`). **So a JSON response's own `href`/`url` members are never read** — Burp's `API` action type and `crawler.customization.parse_api_definitions` (`map_root.tsv:6175`) have no counterpart.

robots.txt: `crawler.go:1483-1498` `admitRobots` (one per seed authority, through `enqueue` so it is rate-limited, scope-gated and captured), `:1500-1549` `seedFromRobots` reads `disallow`/`allow`/`sitemap` lines and admits them **as discovered links** (correctly re-gated). `Sitemap:` lines are admitted but the **XML is never parsed** — the sitemap URL is fetched as an ordinary HTML page, hits `SkipNotHTML`, and yields nothing.

### Gap

Burp reads `button/input[formaction]`, `math[href]`, `object/embed`, and — via a separate non-HTML path — JSON and API responses; burpsy reads only `a`, `area`, `iframe`, `frame` and `form` from HTML, and a `Sitemap:` line in robots.txt is fetched and then discarded because `sitemap.xml` is not HTML.

### Verdict: **MISSING** for sitemap XML; **PARTIAL** for the extraction surface

### Ranked smallest honest step

1. `internal/crawler/crawler.go:1332` — a **sitemap branch before the `isHTML` gate**: if content-type is `application/xml`/`text/xml` and the body matches `<urlset`/`<sitemapindex`, `encoding/xml` a `Decoder` and admit every `<loc>`. This is the single highest-value extraction gap: a target that publishes a sitemap hands the crawler its entire URL list and burpsy currently throws it away. ~40 lines, one new skip reason (`skip.go`'s switch+array pattern makes it mechanical).
2. `internal/crawler/discover.go:190-223` — extend the `switch` with `case "button", "input":` reading `formaction`, and `case "math":` reading `href`. Three cases, matching `Zueq.ZZ` (`:127-134`) exactly. `formaction` matters because a JS-driven app's primary action is frequently a styled `<button formaction>` with no `<a>` anywhere.
3. `internal/crawler/crawler.go:1332` — a JSON branch: on `application/json`, admit every string value at a key named `url`/`href`/`location`/`next`/`@href`. This is the cheapest route to Burp's `API`/`DISCOVERED_CONTENT` action types and needs no config key.
4. Clickable extraction (`Zb5z`/`Zpio`): **PARTIAL/decline for now** — it requires a DOM (event handlers, computed styles) and `Config.Render` returns a serialised document, not an event model. Recording it as a gap without a shape would be a guess.

---

## Area 6 — Browser integration

### Burp mechanism (CONFIRMED)

- Mode is a 3-value enum, not a bool: `Zbqd` with `USE` / `DONT_USE` (and the key is `crawler.customization.browser_based_navigation_mode`, `map_root.tsv:6180`; `Zxcp.java:95-108` shows the `""` → `ZD()` boolean → `USE`/`DONT_USE` ladder). UI: `Zrfn.java:108` "Use Burp's browser for Crawl and Audit" + a mode dropdown (`:52-61`, `this.ZW.addItem(var8.displayLabel)` over `Zbqd.values()`).
- **Idle thresholds are first-class settings** (`Zgjj.java:161-165`): `network_idle_threshold` (ms), `dom_idle_threshold` (ms), `await_navigation_timeout` (ms), plus `idle_time_for_mutations` (`:153-155`). UI copy: "Network idle threshold (ms):" (`map_root.tsv:7393`).
- Browser cache: `use_browser_cache` (`Zgjj.java:172`).
- Resource read timeout: `timeout_for_in_progress_resource_requests` (`map_root.tsv:4283`, 1–50000 ms, `Zrfn.java:49,240`).
- Out-of-scope resource fetching: `allow_out_of_scope_resources` (`map_root.tsv:4295`), UI "Fetch required resources and data from out-of-scope hosts" (`map_root.tsv:4297`).
- Fragment routing is a declared application property: `crawler.customization.application_uses_fragments_for_routing` (`map_root.tsv:6173`), UI "Application uses fragments for routing" (`:18369`).
- Each crawled *action* carries a live browser handle: `Zb5z.java:82-84` `net.portswigger.browser.Zkn`.

### burpsy state (CONFIRMED)

- `-dom` flag (`cmd/burpsy/main.go:83`) — one flag, three forms: `chrome`, a browser path, a `ws://` CDP endpoint. Refused at parse time if it resolves to nothing (`cli.go:97,130`).
- `internal/domexec/` — `browser.go` (chromedp), `taint.go`. Wired to the scanner as a **lazy** provider (`main.go:609-611`), so naming an engine costs nothing until a DOM check asks.
- The crawler's `Config.Render func(ctx, url) (string, error)` (`crawler.go:343`) is the only browser door into the crawl, wired at `api_crawl.go:445` from `crawlRenderer()` (`api_crawl.go:345-360`), which returns **nil** unless `s.scanner.DOMCapabilityConfigured()`.
- Render pass semantics (`crawler.go:1418-1442`): runs **after** the static parse, admits only links the wire parse did not carry, all frontier gates apply, `FoundByRender` marks the edge.
- Rendered-DOM audit pass: `api_crawl.go:486` + `RenderedAuditReport` (`crawler.go:516-534`), counted with `Candidates/NoScript/Capped/Rendered/Failed/ScriptOnly/Declined`.
- `/api/stats` reports the engine honestly as `dom_engine` + `dom_checks` (`api_types.go:216-222`, `api_capture.go:287-291`).

**Absent:** no `dom_idle_threshold` (nothing waits for DOM quiet — `Render` returns whatever the browser has when it returns), no `network_idle_threshold`, no `await_navigation_timeout`, no `use_browser_cache`, no fragment-routing declaration, no out-of-scope *resource* fetch (Burp's is a resource-load exemption, not a crawl-target exemption).

### Gap

Burp's browser navigation is a three-mode setting with three idle/timeout thresholds and a cache flag; burpsy's is a nil-or-not render hook with **no quiet threshold at all** — a page whose content is assembled 200 ms after `load` is read as empty and the SPA's routes are missed, which is precisely the failure the render pass exists to prevent.

### Verdict: **PARTIAL** (the seam is right and honest; the timing model is absent)

### Ranked smallest honest step

1. `internal/crawler/crawler.go:343` — change the hook's contract from `func(ctx, url) (string, error)` to `func(ctx, url, RenderOptions) (string, error)` with `RenderOptions{DOMIdle, NetworkIdle time.Duration}`. That is a signature change with two call sites (`api_crawl.go:357`, `crawl_dom_audit_test.go`) — it makes the three Burp keys *representable* before any of them has a default. `Config.DOMIdle` / `Config.NetworkIdle` (default 0 = today's behaviour, byte-for-byte) sit beside it.
2. `internal/domexec/browser.go` — honour those two waits; that is where the CDP polling belongs, and the existing taint harness already has a post-load settle step to extend.
3. `Config.UseBrowserCache bool` — one field, one `chromedp` flag. Lowest risk of the three.
4. `application_uses_fragments_for_routing`: **do not file.** burpsy's `requestFingerprint` drops the fragment entirely (`fingerprint.go:120-126` docs), which is the equivalent handling; a config key for it would decide nothing.

---

## Area 7 — Destructive refusal, scope, session gate, out-of-scope logging

### Burp mechanism

- **Destructive refusal: no Burp counterpart.** CONFIRMED negative: `Zb8w` has no destructive/action-refusal action type, and no Burp crawl phase refuses a link. Burp relies on `crawler.login_functions.trigger_login_failures` (`map_root.tsv:18723`) to *avoid* provoking lockouts. burpsy's `destructive.go` is an **addition**, not a gap.
- **Scope**: the chokepoint is `project_options.connections.out_of_scope_requests` (`map_root.tsv:11497`) with three values — "Use suite scope [defined above]" (`:11504`), "Use custom scope" (`:11500,11502`), "Drop all out-of-scope requests" (`:11501`) — set in `Zrgn`. The **out-of-scope logging action** is a separate key: `user_options.misc.out_of_scope_history_logging_action` (`map_root.tsv:4535`) with the options "Ask me what to do each time" (`:4536`) and "Do nothing" (`:4537`), under `configPanelProxyHistoryLogging` (`:4530`) — *"Use this setting to choose whether Proxy automatically stops sending out-of-scope items to the history and other tools"* (`:4534`). The proxy-side twin is `configPanelProxyMiscellaneousDontLogOutOfScopeItems`, "Don't send items to Proxy history or live tasks, if out of scope" (`:5676,5679`).
- Burp's crawler equivalent of the last is `crawler.customization.allow_out_of_scope_resources` ("Fetch required resources and data from out-of-scope hosts", `map_root.tsv:4297`).

### burpsy state (CONFIRMED)

- `destructive.go:87-132` — 6 buckets, ~90 phrases, matched by contiguous token runs (`containsRun` `:215-237`) after camelCase/separator tokenisation (`tokenise` `:245+`). Link **text** includes `title` and `aria-label` (`discover.go:330-345`) — the icon-button case.
- Scope chokepoint: `Crawler` holds no `net.Dialer`/`http.Client`/bare `*sender.Sender` (`crawler.go:12-15` doc; `senderFor` at `:1951`). Every send is `sender.AuthorisedSender.AuthoriseRaw` on the **exact bytes**. HARD-03 is pinned by a test.
- Gate order (`crawler.go:1579-1619`): resolve → scheme → host → userinfo → destructive → `enqueue`(→ scope pre-filter, crawl query, exact-fingerprint, template quota, fingerprint budget, frontier capacity). Each refusal records a `SkipRecord`.
- Out-of-scope resources: **not fetchable at all** — there is no such knob, and `Scope.Contains` gates the pre-filter. burpsy's answer is the strict one, consistent with HARD-03.
- Session gate: `session_gate.go:103-118` `detectExpired` (status-flip on the `urlTemplate`, or `LoginPagePattern`), `:147-207` `recoverSession` (rule matched on full `RequestIdentity` at `:155-161`, `MaxRelogins` generation counter at `:173-178`, `CookieHeader` at `:185`), `:255-308` `crawlSessionRunner` feeding `Set-Cookie` back to the coordinator (`:294-298`). `StopReloginBudget` / `SkipReloginFailed` / `SkipSessionExpired`.
- **The gap: nothing in production sets it.** Grep for `crawler.Config{` returns exactly three constructions: `api_crawl.go:425`, `api_apiscan.go:205`, and two test/demo sites. **Neither web construction sets `SessionCoordinator` or `LoginPagePattern`** — `api_crawl.go:425-447` sets `Seeds, Scope, Sender, Capture, Query, RetentionQuery, SubmitForms, Limits, RequestsPerSecond, Pool, UserAgent, Headers, OnFetch, Render, Logger` and nothing else. `Server.sessionCoordinator` exists (`server.go:64`, wired at `server.go:755-757` and `main.go:679`) but is never handed to a crawl. The mechanism is fully built, fully tested (`crawler_test.go:1328-1500`, five tests) and **unreachable from any operator-launched crawl**.

### Gap

Burp has an authenticated-crawl switch (`crawl_using_provided_logins_only`) and a session-gate path that actually runs; burpsy's re-login machinery is complete and tested but **no production caller supplies a coordinator**, so an operator-launched crawl is silently the unauthenticated one from the first expired cookie onward — the exact failure `gaps.md:1073-1081` described and `gaps.md:1083-1092` declared closed on 2026-08-11.

### Verdict: **PARTIAL** for scope/destructive (LANDED); **MISSING** for the session gate's reachability

### Ranked smallest honest step

1. `internal/web/api_crawl.go:425-447` — add `SessionCoordinator: s.sessionCoordinator` and `LoginPagePattern: <from the request>` to the `crawler.Config` literal. **Two fields.** The coordinator is already on the Server, already cookie-jar-fed from the proxy (`main.go:486-489` comment says exactly this), and `*session.Coordinator` already satisfies the interface. This is the highest-value one-line-class fix in the entire map.
2. `internal/web/api_crawl.go:187-226` — add `login_page_pattern string` to `crawlStartReq` so an operator can name the second signal (its absence is why step 1 alone only half-closes it).
3. **Out-of-scope logging action** (`user_options.misc.out_of_scope_history_logging_action`): this is the **Proxy** surface, not the crawl's — already filed as **am6** ("out-of-scope traffic is always written to history — no 'don't log out-of-scope items' switch") and as **5j4i**/**ckqx** for the drop-side. **Do not re-file.**

---

## Area 8 — Sitemap XML parsing and cross-task reuse

### Burp mechanism (CONFIRMED, with one honest limit)

- `Zgkz.java` — `/sitemap.xml` request builder (`:13`, HTTP/1.1, `keep-alive`), name `:18`, and a `ZI(Zbsg)` expectation test over a static `Zpbf[] ZS` (`:9,22-24`). The **parser is not in `Zgkz`**: the recovered literals `<sitemap>` (`map_root.tsv:13803`), `sitemaps.org` (`:13804`), `<url>` (`:13807`) belong to a class that decompiled without its literal restoration or lives outside `jdt_src`; the parse happens where the fetched document is turned into `Zb8w.SITEMAP` actions. So: **the request, the naming, the file-type check and the SITEMAP action type are CONFIRMED; the XML-walking class identity is UNKNOWN** (grep over `jdt_src` for `sitemaps.org` returns 0 hits, which per `SOURCE-OF-TRUTH.md` §6 is not evidence of absence but is enough to refuse to name a class I did not read).
- The budget: `crawler.customization.request_sitemap` (bool) + `crawler.customization.maximum_items_from_sitemap` (int, **1–50 000** — UI validation copy `map_root.tsv:18373` "Maximum items to request from sitemap must be between 1 and 50,000", "Maximum items to request from site map:" `:18387`).
- Robots `Sitemap:` lines: `Zrb7.java:49-90` `ZI(Zsq0)` walks every origin's robots-derived actions, extracts URLs via `lambda$addRobotsUrlActionsToOrigin$1/2` (`:110-112`), and adds each as a **`Zb8w.ROBOTS`-typed action** (`:74`, `new Zsvf(var1, Zb8w.ROBOTS, var11, …)`) plus a `Zg45.ZI` event (`:81`).
- **Cross-task reuse**: `Zrbx.java:91-93` `lambda$beforeStart$0` pre-seeds the speculative-link dedup `Set<Zsx7>` from **every previously-recorded location's** known URLs (`Zi8z.ZdC().ZpP()` → `Zmg.Zsn()` → `Zc9p.ZNS()`), so a later crawl starts already knowing the links the site map holds. The same idea is in `Zplt.java:59-61`: a non-destructive action's whole HTTP chain is published to the site map, so **later crawls see earlier crawls' results through the site map**. `Zsx7.Zc(url.ZLJ(), url.ZS())` (`:60-62`) is the per-template key, i.e. cross-task dedup is **template-keyed**, matching burpsy's `urlTemplate` rather than its exact fingerprint.

### burpsy state (CONFIRMED)

- `crawler.go:1544-1546` — a `Sitemap:` line in robots.txt is admitted as an ordinary link. It is then fetched, stored, and hits the `isHTML` gate at `crawler.go:1332` → `SkipNotHTML`, raw-body fingerprint, **no URLs extracted**. A sitemap contributes **0** URLs.
- No `encoding/xml` import anywhere in `internal/crawler/` (the package's only external imports are `golang.org/x/net/html` and `go.uber.org/zap` — `crawler.go:163-179`, `discover.go:46-55`).
- Cross-task reuse: **none.** `Crawler.queued`, `Crawler.locations` and `Crawler.templates` are per-instance (`crawler.go:677-689`) and `Crawler` is documented as not safe for concurrent `Run` calls and cheap enough not to share (`:612-613`). `crawlRuns` retains 20 *reports* (`api_crawl.go:41`) — reports, not identity tables.
- What burpsy *does* have that is adjacent: `internal/sitemap` (the `host → path → method/status` tree) and `s.liveAudit.TakeLiveSeenURLs()` (tqug). The site map is the rendering of captured exchanges, not a source of frontier seeds — `actions.ts:578-581` shows the site map's crawl action starting a crawl **from the selection**, not **from the map's contents**.

### Gap

Burp parses `sitemap.xml` as a sitemap (with a 1–50 000 item cap) and pre-seeds a later crawl's link dedup from every location earlier crawls and the site map already hold; burpsy fetches the sitemap, discards it as non-HTML, and starts every crawl with an empty identity table.

### Verdict: **MISSING** (both halves)

### Ranked smallest honest step

1. **Sitemap XML parse** — the `<loc>` walk described in Area 5 step 1. One branch in `crawler.go`, one `Limits.MaxSitemapItems int` (default 50 000, mapping Burp's key), one `StopSitemapItems` + one `SkipSitemapMalformed`/`SkipSitemapItemsCapped`. Highest value in this whole map: it turns a target-published file the crawler already fetches into the target's own URL list.
2. **Cross-task frontier seeding from the site map** — `api_crawl.go:370-394` already unions `Seeds` with `TakeLiveSeenURLs()`. Add `IncludeSiteMap bool` pulling `s.sitemap`'s in-scope URL set, unioned the same way and counted in the 202 reply as `live_seen_used` already is (`:280`). One bool, one union, one honest count.
3. **Cross-task identity** — a per-origin `urlTemplate → count` map shared through a `sync.Map` on the Server, consulted by `enqueue` (`crawler.go:1776-1803`) as a *soft* quota that raises `SkipTemplateQuota` rather than evicting. Defer: it is a memory-bound decision and the honest step (2) captures most of the value.

---

## The burpsy crawler config-key inventory, stated as asked

| Surface | Count | How it was counted |
|---|---|---|
| `crawler.Config` exported fields | **20** | Read `crawler.go:213-349`, listed every field with a comment |
| `crawler.Limits` fields | **11** | Read `limits.go:47-111` |
| `crawler.CrawlStop` reasons | **12** | `CrawlStopAll` array, `limits.go:257-270` |
| `crawler.Skip` reasons | **30** | `SkipAll` array, `skip.go:185-216` (note: the package doc and AGENTS.md still say 29 — the doc is stale) |
| **`POST /api/crawl` request fields** | **13** | Read `crawlStartReq`, `api_crawl.go:187-226` |
| **Of which are crawl *bounds*** | **3** | `api_crawl.go:401-410` applies exactly `MaxRequests`, `MaxDepth`, `MaxDuration` |
| **Burp `crawler.*` keys in the settings UI** | **68** | 29 `crawl_optimization` (`Zgjj.java:129-205`) + 20 `customization` (`Zxcp.java:92-151`) + 4 `error_handling` (`Zf9w.java:29-32`) + 3 `crawl_limits` (`Zmst.java:27-30`) + 2 `crawl_project_option_overrides` (`map_root.tsv:23131-23134`) + 2 `login_functions` (`:18721-18724`) + 8 `live_passive_crawl` (`:23563-23585`) |
| **Burp `crawler.*` keys a shipped config actually sets** | **10** | Union of `crawler.*` dotted paths across the 9 `Crawl*.json` in `in/extract/resources/BuiltInConfigs/` |
| **Burp shipped `crawler.*` keys burpsy can load** | **0** | `burpConfigFile` has one field, `Scanner` (`burpconfig.go:21`); the `crawler` object is never read and never reported |
| Overlap by name | **3** | `maximum_crawl_time`↔`MaxDurationSecs`, `maximum_request_count`↔`max_requests`, `maximum_unique_locations`↔(no wire field) |

---

## Summary table

| # | gap | verdict | burp evidence | burpsy evidence | proposed bead title |
|---|---|---|---|---|---|
| C-1 | No `crawler` object in a loaded Burp config; a shipped crawl config is silently discarded | **MISSING** | `map_root.tsv:12473-12478` (10 keys across 9 shipped files); `Zmst.java:26-38` | `burpconfig.go:20-21` `burpConfigFile{Scanner}`; `burpconfig.go:101-116` iterates `file.Scanner` only | `crawler: a loaded Burp config's crawler object is discarded without a word — all 10 of its keys load as nothing` |
| C-2 | 8 of 11 `Limits` bounds are Go constants with no wire field | **MISSING** | `Zmst.java:27-30` (3 limits) | `api_crawl.go:187-226` (13 fields, 3 of them bounds); `api_crawl.go:401-410` (3 `if > 0` blocks) | `crawler: max_locations, max_links_per_page, max_template_visits and max_capture_bytes have no wire field, so four CrawlStops are unreachable from a UI` |
| C-3 | No tolerance/threshold axis in location identity | **PARTIAL** | `Zgjj.java:146-152` (7 tolerance keys); `:140-142` (3 thresholds); `map_root.tsv:7347-7351,7391-7393` | `discover.go:288-300` exact hash, 4 components; `fingerprint.go:36-46` documents the false-split bias | `crawler: location identity is an exact hash with no tolerance band, so a page that changes one link is a new location` |
| C-4 | `sitemap.xml` is fetched and discarded as non-HTML | **MISSING** | `Zgkz.java:13,18,22-24`; `map_root.tsv:6161,6185,6193,18373,18387`; `Zb8w.SITEMAP` (`Zb8w.java:15`) | `crawler.go:1544-1546` admits the URL; `crawler.go:1332-1341` `SkipNotHTML`; no `encoding/xml` in the package | `crawler: a Sitemap: robots line is fetched, stored, and thrown away — sitemap.xml is never parsed, so a published URL list yields zero locations` |
| C-5 | No `formaction` / `math[href]` / `object[data]` / `embed` extraction | **PARTIAL** | `Zueq.java:124-142` (`ZZ`); `Zpio.java:60-78`; `Zb5z.java:61-63` (`onclick`) | `discover.go:190-223` — `a`, `area`, `iframe`, `frame`, `form` only | `crawler: button/input[formaction], math[href] and object/embed are never read, so a JS-driven app whose only action is a styled button contributes no links` |
| C-6 | No non-HTML extraction (JSON, XML) | **MISSING** | `Zb8w.API`/`DISCOVERED_CONTENT` (`Zb8w.java:18,20`); `map_root.tsv:6175` `parse_api_definitions` | `crawler.go:2098-2111` `isHTML` — 4 types only; `crawler.go:1332` | `crawler: a JSON response's own url/href/next members are never read, so a documented API reachable from the crawled HTML contributes no locations` |
| C-7 | No DOM/network idle threshold; `Render` reads whatever the browser has when it returns | **PARTIAL** | `Zgjj.java:161-165`; `map_root.tsv:7393` "Network idle threshold (ms):" | `crawler.go:343` `Render func(ctx, url) (string, error)` — no options; `api_crawl.go:357-360` | `crawler: the rendered pass has no DOM or network idle threshold, so a page that assembles 200ms after load reads as empty and its SPA routes are missed` |
| C-8 | Crawl task shows 0% for its whole life; no phase or action-kind vocabulary | **PARTIAL** | `Zc16.java:159-174` (7 wired collaborators); `Zb8w.java:7-30` (23 kinds); `Zbcc.java:75-77` (`/8`) and `:71-73` (`(100+n*7)/8`); 9 phase `toString()`s | `api_crawl.go:489` `task.Advance` once after `Run`; `discover.go:68` `tag` is a free string; no phase type | `crawler: a crawl's task row reads 0% until the instant it finishes, and there is no action-kind or phase vocabulary on the run record` |
| C-9 | **Session gate is unreachable from every production crawl** | **MISSING** | `Zgjj.java:131` `crawl_using_provided_logins_only`; `Zrl5`/`Zrbs`/`Zrlw` login phases | `api_crawl.go:425-447` and `api_apiscan.go:205-231` both omit `SessionCoordinator`/`LoginPagePattern`; `Server.sessionCoordinator` exists at `server.go:64,755` | `crawler: the re-login machinery is complete, tested and never wired — no production crawl sets SessionCoordinator, so an operator-launched crawl goes unauthenticated from the first expiry` |
| C-10 | No cross-task frontier seeding or cross-crawl identity | **MISSING** | `Zrbx.java:91-93` pre-seeds dedup from every prior location; `Zplt.java:59-61` publishes each action's HTTP chain to the site map | `crawler.go:677-689` per-instance `queued`/`locations`/`templates`; `api_crawl.go:370-394` unions seeds only with `TakeLiveSeenURLs()` | `crawler: every crawl starts with an empty identity table and cannot be seeded from the site map, so a second crawl re-walks what the first already found` |
| C-12 | Out-of-scope logging action | **LANDED (elsewhere)** | `map_root.tsv:4535` `out_of_scope_history_logging_action`; `:4534,4536-4537` | Proxy surface, not the crawl's | **already filed: am6, 5j4i, ckqx — do not re-file** |
| C-13 | `crawl_optimization.*` tolerance family + idle thresholds as config keys | **declined on the record** | `map_root.tsv:243-267` | `gaps.md:1278-1285` "Decline 4" | **do not re-file — declined with a stated reason** |
| C-14 | Browser-seeded frontier, rendered-DOM audit, per-URL crawl→audit, live-passive seeds, crawl-paths view, suite pause, robots-as-discovery, scope chokepoint, destructive refusal | **LANDED** | `Zrfn.java:108`; `Zrwf.java:29-31`; `Zc0e`; `Zrb7.java:49-90`; `map_root.tsv:27020` | `crawler.go:343,1418-1442`; `api_crawl.go:445,486,453,195`; `ui/crawlpaths.tsx`; `crawler.go:1483-1549`; `destructive.go` | **nx7b, xuim, 7suo, tqug, tix, cijs — LANDED, do not re-file** |

### Ready-to-file bead bodies

**C-1** — *crawler: a loaded Burp config's crawler object is discarded without a word*
```
## Claim
`ParseBurpConfig` reads one field — `Scanner`. Burp's own shipped crawl configurations carry
a `crawler` object of 10 distinct keys (union across the 9 Crawl*.json in
in/extract/resources/BuiltInConfigs/), and every one of them loads as if the file named
nothing at all.

## Evidence
- burpconfig.go:20-21 — `type burpConfigFile struct { Scanner map[string]json.RawMessage }`
- burpconfig.go:101 — `for section, raw := range file.Scanner` — the `crawler` key never appears
- The parser is careful elsewhere: burpconfig.go:92-99 records an unknown `scanner/*` key in
  `UnrepresentableKeys` and `ApplyWithReport` names it. The `crawler` object never reaches that path.
- Burp keys: map_root.tsv:12473-12478 (crawl_limits), :768-775 (error_handling), :23131-23134
  (crawl_project_option_overrides), :20551/20558 (crawl_using_provided_logins_only)

## Smallest honest step
Add `Crawler map[string]json.RawMessage` to `burpConfigFile`; when no crawler key is behind a
field, record the object's dotted paths in `UnrepresentableKeys` so ApplyWithReport names them.
Reporting is the fix; the loader is step 2.
```

**C-2** — *crawler: four crawl bounds have no wire field, so four CrawlStops are unreachable*
```
## Claim
`crawler.Limits` has 11 fields. `POST /api/crawl` can set 3. MaxLocations, MaxLinksPerPage,
MaxTemplateVisits, MaxCaptureBytes, MaxFingerprints, MaxRelogins and MaxFrontier are Go
constants, so StopLocationBudget / StopLinksPerPage / StopTemplateQuota / StopCaptureBytes /
StopFrontierCapacity / StopFingerprintBudget / StopReloginBudget can only fire on the
engine's own defaults — an operator cannot raise a bound that is too tight for their target.

## Evidence
- limits.go:47-111 (11 fields), limits.go:120-152 (defaults)
- api_crawl.go:187-226 — crawlStartReq has 13 fields, 3 of them bounds
- api_crawl.go:401-410 — exactly three `if req.X > 0 { limits.X = req.X }` blocks
- Burp ships crawl_limits.maximum_crawl_time / maximum_unique_locations / maximum_request_count
  as the three limits an operator configures (Zmst.java:27-30, map_root.tsv:12473-12478)

## Smallest honest step
Add max_locations, max_links_per_page, max_template_visits, max_capture_bytes to
crawlStartReq and four `if > 0` blocks beside the existing three. No engine change: the
bounds, the stops and the reports already exist.
```

**C-4** — *crawler: sitemap.xml is never parsed, so a published URL list yields zero locations*
```
## Claim
The crawler reads `Sitemap:` from robots.txt and enqueues it (crawler.go:1544-1546), fetches
it, stores it, scans it — and then discards it: `isHTML` (crawler.go:2098) accepts only
text/html and three XHTML spellings, so an application/xml sitemap takes the SkipNotHTML
branch at crawler.go:1332 and contributes no locations. A target that publishes its whole URL
inventory in sitemap.xml gets one location from it: the sitemap itself.

## Evidence
- crawler.go:1544-1546 — the Sitemap line is admitted as an ordinary discovered link
- crawler.go:1332-1341 — !isHTML -> rawBodyFingerprint + SkipNotHTML, no extraction
- Burp: Zgkz.java:13,18 builds and names the request; Zb8w.java:15 is a first-class
  SITEMAP action type; map_root.tsv:18373 bounds it at 1..50,000 items

## Smallest honest step
An `else if` before the isHTML gate in crawler.go:1332: application/xml + `<urlset`/`<sitemapindex`
-> encoding/xml Decoder -> admit every `<loc>`. Add Limits.MaxSitemapItems (default 50,000)
with one stop and one skip reason, following skip.go's switch+SkipAll pattern.
```

**C-6** — *crawler: a JSON response's own url/href/next members are never read*
```
## Claim
Burp's action-type enum carries API and DISCOVERED_CONTENT, and `crawler.customization.
parse_api_definitions` is an operator-facing key. burpsy's crawler reads links from HTML and
nothing else: a JSON endpoint linked from the crawled HTML is fetched, stored, scanned and
recorded as a location, and its own next/href/url members are never followed.

## Evidence
- crawler.go:2098-2111 — isHTML: 4 accepted types, empty Content-Type treated as HTML
- crawler.go:1332-1341 — everything else is SkipNotHTML with a raw-body fingerprint
- Burp: Zb8w.java:18,20 (API, DISCOVERED_CONTENT); map_root.tsv:6175 parse_api_definitions

## Smallest honest step
An application/json branch beside the sitemap one: walk the decoded value and admit every
string at a key named url, href, location, next, @href, resolving relatives against the
response URL. No config key — this is the crawl doing its documented job, not an option.
```

**C-7** — *crawler: the rendered pass has no DOM or network idle threshold*
```
## Claim
`Config.Render` is `func(ctx, url) (string, error)`. Whatever the browser has produced when
that function returns is the whole DOM the crawl sees. A single-page application that
assembles its routes 200ms after `load` reads as an empty shell, the render pass admits
nothing, and the report says the page had no links — which is the one thing nx7b was filed
to make untrue.

## Evidence
- crawler.go:343 — the hook signature; :1418-1442 — the pass that consumes it
- Burp: Zgjj.java:161-162 (network_idle_threshold, dom_idle_threshold, both ms),
  :165 (await_navigation_timeout), :172 (use_browser_cache);
  map_root.tsv:7393 "Network idle threshold (ms):"

## Smallest honest step
Change the hook to `func(ctx, url, RenderOptions) (string, error)` with
`RenderOptions{DOMIdle, NetworkIdle}`; add Config.DOMIdle/Config.NetworkIdle defaulting to 0,
which is today's behaviour byte-for-byte. Two call sites (api_crawl.go:357,
crawl_dom_audit_test.go). Honouring the waits is a separate step in internal/domexec/browser.go.
```

**C-8** — *crawler: a crawl's task row reads 0% until the instant it finishes*
```
## Claim
`task.Advance(uint64(rep.Fetched))` is called once, after `Run` returns (api_crawl.go:489).
A twenty-minute crawl therefore shows a task row at zero for its whole life, and the
operator cannot distinguish a working crawl from a wedged one.

## Evidence
- api_crawl.go:489 — the single Advance, after Run
- Burp: Zbcc.java:75-77 maps a per-item relative integer into 0-12% of the shared bar
  (`var0.Zb(var1 / 8)`), and :71-73 maps audit into 100-112% (`(100 + n*7)/8`)
- burpsy already has the hook this needs: crawler.Config.OnFetch (crawler.go:318), which
  fires synchronously on every completed fetch and is already wired for crawl-audit
  (api_crawl.go:417-421). Nothing in the report changes if the callback is left nil.

## Smallest honest step
Pass an OnFetch that calls task.Advance(1) into the crawler's Config in api_crawl.go, and
keep the post-Run Advance as the completion. One closure; no new type, no new field, no
change to any count the report makes.
```

**C-9** — *crawler: the re-login machinery is complete, tested and never wired*
```
## Claim
`internal/crawler/session_gate.go` implements expiry detection, re-login, cookie rebuild and
a bounded re-login budget, and `crawler_test.go` drives it with five tests. No production
crawl supplies a coordinator. Both `crawler.Config{...}` literals in the web layer —
api_crawl.go:425 and api_apiscan.go:205 — omit `SessionCoordinator` and `LoginPagePattern`, so
`detectExpired` short-circuits (session_gate.go:104) and every operator-launched crawl is
the unauthenticated one from the first expired cookie onward, with no detection.

gaps.md:1083-1092 declared this closed on 2026-08-11. The mechanism landed; the caller did not.

## Evidence
- api_crawl.go:425-447 — the literal, read in full: no SessionCoordinator
- server.go:64 and :755-757 — Server.sessionCoordinator exists and is cookie-jar-fed
  (main.go:486-489 says so in a comment); it is simply never handed to a crawl
- crawler.go:1260 — `if c.cfg.SessionCoordinator != nil && !item.robots` — the gate
- Burp: Zgjj.java:131 crawl_using_provided_logins_only; Zrl5/Zrbs/Zrlw login phases

## Smallest honest step
Two fields on the api_crawl.go literal: `SessionCoordinator: s.sessionCoordinator` and a
`LoginPagePattern` taken from the request. *session.Coordinator already satisfies the
interface (session_gate.go:63-68 says so), so this is a wiring change and nothing else.
```

**C-10** — *crawler: every crawl starts with an empty identity table and cannot be seeded from the site map*
```
## Claim
`Crawler.queued`, `Crawler.locations` and `Crawler.templates` are per-instance and die with
the crawl (crawler.go:677-689). A second crawl of the same target re-fetches and re-reports
everything the first one found, and there is no way to point a crawl at the URLs the site map
already holds. Burp pre-seeds a crawl's link-dedup set from every location earlier crawls
recorded, keyed by URL template.

## Evidence
- crawler.go:677-689 — three per-instance tables; :612-613 — Crawler is not shareable by design
- api_crawl.go:370-394 — startCrawl unions Seeds with TakeLiveSeenURLs() and nothing else
- Burp: Zrbx.java:91-93 pre-seeds the speculative-link Set<Zsx7> from every recorded
  location's known URLs, keyed by template (Zk() at :60-62); Zplt.java:59-61 publishes each
  action's whole HTTP hop chain to the site map, which is what makes it visible to later crawls

## Smallest honest step
`IncludeSiteMap bool` on crawlStartReq, unioned into `seeds` beside IncludeLiveSeen and
counted in the 202 reply the way `live_seen_used` already is (api_crawl.go:280). One bool,
one union, one honest count. Sharing the identity tables across crawls is a memory-bound
decision and should follow, not precede.
```

---

## Write note

This file was **not written to disk**. The session's `write` tool accepts only `xd://`
browser-device paths (no shell and no filesystem write were available), and
`burpsy-go/docs/burp-map/` does not exist. To land it:

```bash
mkdir -p /root/burpsy-react-ui/burpsy-go/docs/burp-map
# then write the content of the `report` field above to
# /root/burpsy-react-ui/burpsy-go/docs/burp-map/crawler-gaps-2026-09-26.md
```

No Go/TS source was modified. No project-wide build or test was run.