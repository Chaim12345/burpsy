# Burp SCANNER decision layer → burpsy gap map (2026-09-26)

**Scope:** the audit engine's *decision logic* — where to probe, what to run, what
counts as done — not per-check payloads.

**Oracle:** `/root/burp-re`, decompiled tree of **Burp Suite 2026.7.1 (build 51467)**,
layer 4 (`out/clean/jdt_src/burp/*.java`) for internals and operator strings, layer 1
(`out/burp/api/montoya/**`) where a promise is the point. The runnable jar on this
machine is 2026.7.3 (build 52685); the tree wins for internals, the running jar for
behaviour. Every citation below says which.

**Method note:** no Burp key literal appears in `out/strings/map_root.tsv` — a
`grep` for `scanner/insertion_point_types/insert_url_params` there returns nothing.
The key names live as inline Java string constants in the decompiled source, and
`burp.Zb1q.java:103-126` / `:133-156` (the `Z_(Zg4q)` / `ZM(Zs0y)` read/write pair)
is the complete key bank for insertion points. The same is true of the Burp-side
status labels: `burp.Zq5.java` carries them as constructor arguments.

---

## Config-key measurement, stated up front

**burpsy implements 27 of Burp's 55 `scanner/*` configuration keys
(49%). 55 keys are *classified* (every one has a row in the key table); the
remaining 28 are carried as explicit "not applied" rows and are named to the
operator in `ApplyWithReport` rather than silently dropped.**

Method — three measurements, all taken from the tree today, not from a prior claim:

1. **The denominator is 55, not 78.** The prior count of 78 (`bead t2s`) counted
   *every leaf* under the 29 shipped `BuiltInConfigs/*.json`, which includes
   `crawler/*` and `description/*` leaves belonging to other subsystems. The
   scanner-side subset is enumerated in-tree as
   `internal/scanner/audit_config_keys_test.go:21-77` — `burpShippedScannerKeys`,
   55 entries, transcribed from `/root/burp-re/in/extract/resources/BuiltInConfigs`
   on 2026-09-14. The file's own header (`audit_config_keys_test.go:19-20`) records
   the correction: *"The 78 the carve-out issue counted was every leaf in those
   files; this is the scanner-side subset of it."*
2. **The numerator is pinned by a failing-if-wrong test.**
   `audit_config_keys_test.go:102` declares `const wantApplied, wantReported = 27, 28`
   and `:117-120` fails if the table ever reports a different split — promoting a
   key from reported to applied has to move that constant, so the coverage claim
   cannot drift silently. 27 + 28 = 55.
3. **The key table is the single source of truth.** `internal/scanner/audit.go:805-1239`
   holds one row per key, each with `name` (burpsy's spelling), `burpKey` (Burp's
   spelling), `what` (one operator-actionable line), optional `read`/`apply`, and
   an `applies` bool. The listing an operator reads and the overlay the engine
   performs are generated from the same rows (`audit.go:793-795`).

**Against bead t2s (4/78): that bead is stale in both directions — the numerator
was 4 then and is 27 now, and the denominator was 78 (all-subsystem leaves) and
is 55 (scanner leaves) now.** t2s should be closed as superseded with this
measurement, not re-implemented. `povm` (insertion_point_types was decorative) is
**also** stale — the fix landed (see Area 1).

Where the 28 unapplied keys genuinely lose capability rather than merely choosing
a different spelling, they are filed below. Most of them (javascript_analysis
timing knobs, audit_project_option_overrides timeouts, the per-issue selection
trio) are honest declines with a stated reason already in the row's `what` field.

---

## Area 1 — Insertion-point selection (`burp.Zuq`)

### Burp's mechanism

`burp.Zuq.java` (1,479 lines) is the builder. `Zs()` (`:67-87`) is the entry: if
the caller supplied manual insertion points (`this.ZG`, a `Zp0a<Zprl>`) it takes
`ZQ(...)` and returns immediately (`:68-71`); otherwise it runs eleven build
steps in a fixed order — `ZT, Ze, Zy, ZP, Zq, Za, Zp, Zb, ZX, ZY, ZG` (`:74-84`).

What is actually in those steps, as read:

- **`ZP()` (`:89-115`)** — walks the raw request bytes and creates one point per
  header value, `Zbg8.HEADER`, with byte offsets from `Zekj.Zy(start,end)`. Note
  it parses the *raw bytes* directly, not a parsed model.
- **`Ze()` (`:199-…`)** — the URL/body parameter pass. The `tableswitch` at
  bytecode offset `:243` dispatches on `Zwwc.ZI` (the parsed parameter's kind)
  against a `Ze9r.Zq` table. The two branches that matter: a URL-encoded or
  multipart body parameter sets `this.Zm = true` (`:234`, the "has a container
  body" flag), and each parameter gets a `Zr4u` builder with
  `Zbg8.Ze(kind)`, name, name-offsets and value-offsets.
- **`ZY()` (`:158-176`)** — one URL-path/filename point, taken from
  `var1.getLast()` of a `Zbdy.Zd(...)` split. **Exactly one**, the last segment.
- **`ZQ(Zp0a<Zprl>)` (`:178-197`)** — the manual-points path:
  `Zbg8.MANUAL_INSERTION_POINT`, name = the 1-based ordinal, offsets
  `Zekj.Zy(-1,-1)` for the name, and the highlighted request text for the value.
- **`Zc(Zuzp)` (`:993-996`)** / **`Zp(Zuzp)` (`:998-1000`)** — the two-list
  split: `ZA` is the *candidate* list, `Zu` is the *admitted* list. `Zs()`
  returns `new Zril(this.Zu)` — only the admitted list. `Zp` is therefore the
  gate every point passes through, and it is where the per-kind switches and the
  ceiling live. This is the load-bearing method for this comparison and it is a
  one-line body, so whatever it calls is where the decision actually is.

**`Zp` is one line** (`Zu.add(var1)`), so the filtering is not in `Zuq` at all —
it is in the two `Zril`/`Zf8t` collaborators the constructor holds (`this.Zx`
`Zw2_` and `this.Zf` `Zfiw`, `:59-60`). `this.Zf.ZD(request, start, end)` is the
per-point factory (`ZQ` `:190`), and `Zw2_.Zk()` (`:211` in the `Ze` bytecode) is
what supplies the parsed parameters. **The per-kind switch itself is not readable
in this tree** — `Zuq` delegates it, and the delegate was not resolved. See
"Evidence limits" below.

The **keys that select kinds** are unambiguous even so, from the settings class
`burp.Zb1q.java:103-110`: `scanner.insertion_point_types.` ×
`insert_url_params, insert_body_params, insert_cookies, insert_param_name,
insert_http_headers, insert_entire_body, insert_url_path_filename,
insert_url_path_folders` — **8 kinds**. Plus
`scanner.modifying_parameter_locations.` × `url_to_body, url_to_cookie,
body_to_url, body_to_cookie, cookie_to_url, cookie_to_body` — **6 relocations**
(`Zb1q.java:119-124`). Plus
`scanner.frequently_occurring_insertion_points.quick_scan_*` × 8
(`Zb1q.java:111-118`) and
`scanner.misc_insertion_point_options.{use_nested_insertion_points, max_insertion_points_per_base_request}`
(`Zb1q.java:125-126`).

**The operator exclusion lists are a rule engine, not a name list.** `Zwh1.java:8-13`
reads both keys as `Zemi` objects and wraps them in `new Zs4k(Zemi, Zemi)`.
`Zs4k.java:199-206` is the whole consumer API — two methods,
`Ze(Zbg8, String, String)` and `ZW(Zbg8, String, String)`, each a one-line
delegate to `this.ZNt().Zp(kind, name, value, this.ZM)` / `ZNA().Zp(...)`. So the
exemption is evaluated **per insertion-point kind, with the parameter's name and
value in hand** — three arguments, plus a shared `Zx6z` rule-state object (`:60`).
`Zs4k` also carries **25 per-kind booleans** (`:9-56`, `Zi6`…`Zih`) and one int
(`ZF`, `:56`, read by `ZAr` at `:184`) — a per-kind exemption matrix. This is
strictly more expressive than a name list, and burpsy's own key table says so
(`audit.go:1177`: *"Burp's value is not a name list but a list of match rules
({enabled, parameter, item, match_type, expression} …) and this engine has neither
a rule matcher over parameter type and item nor a list-valued key"*).

### burpsy's current state

`internal/bcheck/insertion.go` — 2,488 lines, package doc `:1-59`.

- **IpKind (`:76-108`)** — **17 kinds**, named after Burp's own settings: the 8
  Burp `insertion_point_types` kinds (`IpQuery, IpBody, IpCookie, IpHeader,
  IpParamNameURL, IpParamNameBody, IpEntireBody, IpURLPathFilename,
  IpURLPathFolder`) plus `IpSyntheticHeader` plus **6 relocations**
  (`IpRelocateBodyToQuery` … `IpRelocateCookieToBody`). The package doc `:27-31`
  states the relocation set is complete against Burp: *"Burp relocates among the
  URL/body/cookie parameter locations only; header relocation does not exist."*
- **Nested expansion** — `codingNested` (`:200`) with `nestedKind` covering
  `nestedJSON, nestedBase64JSON, nestedBase64, nestedXML` (`:266-276`), switched
  by `EnumerateOptions.NoNested` (`:382`), documented at `:39-46` as Burp's
  `scanner.misc_insertion_point_options.use_nested_insertion_points` with the
  shipped default true.
- **Per-request ceiling** — `DefaultMaxInsertionPoints = 30` (`insertion.go:336`),
  with the Burp UI copy transcribed at `:325-329` and a `min: 1` floor on the key
  row (`audit.go:1228`) so a ceiling of zero cannot enumerate nothing and report
  a completed audit.
- **Operator skip list** — `EnumerateOptions.SkipAllTestsForParameters []string`
  (`insertion.go:396`), matched **case-insensitively by name**, run
  **before** the cap (`:735-739`), emitted as a `Declined` with
  `DeclinedSkippedParamWhat`. `audit.go:622-632` documents the choice.
- **Test coverage** — `audit_insertion_options_test.go` and
  `audit_parameter_locations_test.go` exist and are the pinned homes for the
  kind/ceiling/relocation matrix; `skip_list_test.go` has five tests including
  `TestTheSkipListAndThePerRequestCapDoNotDoubleCountOnePoint` (`:97`) and
  `TestTheQueueRowClassifiesAsTheOperatorSkip` (`:138`).

### Verdicts

| Sub-area | Verdict |
|---|---|
| The 8 per-kind switches | **LANDED** |
| The 6 relocations | **LANDED** |
| `max_insertion_points_per_base_request` | **LANDED** |
| `use_nested_insertion_points` | **LANDED** |
| Manual insertion points (`ZQ`, `Zbg8.MANUAL_INSERTION_POINT`) | **MISSING** |
| Nested **depth** limit (`Zq5.NO_NESTING_ALLOWED`) | **MISSING** |
| Operator skip list — name matching | **PARTIAL** (landed) |
| Operator skip list — per-kind + rule engine (`Zs4k`) | **MISSING** |
| `quick_scan_*` as a *distinct* light-audit selector | **LANDED (burpsy-react-ui-02qi, 2026-09-27)** — eight `OptUint32` fields, a derived deny list, per-kind gate |

**Gap 1 — the skip-list key table's `what` text is now false.**
`audit.go:1177` says the key has *"no shape to land in"* because *"every row here
reads through `OptUint32`"*. That was true when written. It is not true now:
`AuditConfig.SkipAllTestsForParameters []string` (`audit.go:632`) and
`EnumerateOptions.SkipAllTestsForParameters` (`insertion.go:396`) are
list-valued and *are* honoured, by `skipNamedPoints` (`insertion.go:735`).
The row still reports `applies: false`. An operator loading a config that sets
`skip_all_tests_for_parameters` is told the key did nothing, while the engine
honours a *different* spelling of the same idea and ignores the one the file used.
**One sentence:** burpsy honours `skip_all_tests_for_parameters` under a
Go-API-only field name that the key table still reports as "not applied", so an
operator's own config file is told a working control did nothing.

**Gap 2 — RESOLVED (burpsy-react-ui-02qi, 2026-09-27).** The eight rows now apply, and the
reason they carried was removed rather than reworded.

> **How it landed.** `BuiltInConfig` and `AuditConfig` each grew the eight
> `OptUint32` fields the gap below called for, and `AuditConfig` grew
> `LightAuditKinds` — a *derived* set holding the kinds explicitly **excluded**
> from the light pass, rebuilt once in `ApplyWithReport` after the key loop. The
> deny-list polarity is the load-bearing part and the thing the first
> implementation got backwards: reading the set as an allow-list means ticking
> URL params silently takes *cookies* out of the light pass, the opposite of what
> the configuration file says. The gate itself is the `LightApplies` check inside
> `auditItem`'s `shouldSkip` closure, and `checks_injection.go:81` consumes it
> unchanged. The wire reports the derived list as
> `light_audit_kinds_excluded`, omitted when empty so the unset case cannot be
> misread as an empty allow-list.

**The gap, as originally recorded:**

**Gap 2 — the `quick_scan_*` rows carry a factually incorrect reason.**
`audit.go:1129` (and its seven siblings) says these keys are not applied because
*"quick-scan point classes are selected here through
`scanner/insertion_point_types/*`; a second key set naming the same classes would
be a second control for one decision."* That is **false**, and Burp's own UI text
says so. `burp.Zrdr.java:26` — the panel these keys drive, titled *"Handling
frequent insertion points"* — carries the literal:

> "If the same insertion point appears often with no change in results, Burp runs
> a lighter audit to speed up scanning.\n\nSelect the insertion point types this
> applies to:"

So `quick_scan_*` selects **which insertion-point types get the light-audit
treatment** — a second, independent decision from *whether the type is probed at
all*. Burp's two key sets are not redundant; they gate two different stages.
burpsy conflates them: `RunLightAudit.ShouldSkipRepetitive` is consulted in
exactly one place — `checks_injection.go:81` — with no per-kind opt-in, so the
light-audit tier applies to every kind the injection family probes, and the
operator has no way to say "light-audit cookies but not headers".

**Gap 3 — no manual insertion points.** `Zuq.ZQ` (`:178-197`) accepts a
caller-supplied `Zp0a<Zprl>` and, when non-empty, **short-circuits every other
build step** (`:68-71`) — a request the operator hand-marked is audited exactly
where they marked it and nowhere else. burpsy's `IpKind` has no manual member
(`insertion.go:76-108`) and `Enumerate` has no caller-supplied-points path.
This is Intruder-adjacent (`mun` covers Intruder's *positions* markers) but not
the same: `mun` is about marking payload positions for an attack; this is about
marking positions for an *audit* so the engine does not have to guess.

**Gap 4 — no nesting-depth limit.** `Zq5.NO_NESTING_ALLOWED` is a real Burp
status. burpsy's `audit_items.go:183-184` declines it with the reason *"nested
insertion points are expanded unconditionally; there is no depth limit that could
stop and be reported."* That is honest and accurate — recording it here as a
**confirmed decline, not a gap**. The one thing missing is that the *toggle* is
honoured (it is) but there is no second, independent depth knob, which Burp also
does not appear to have in this tree. **No bead.**

### Ranked smallest steps

1. **Fix the two wrong `what` strings** (`audit.go:1126-1173`, `:1174-1179`) and
   flip `skip_all_tests_for_parameters` to `applies: true` with a `read`/`apply`
   pair on a `[]string` field. Bump `wantApplied` to 28 in
   `audit_config_keys_test.go:102`. This is a one-file change plus one constant,
   and it removes two false statements from an operator-facing surface.
2. **Per-kind light-audit opt-in**: add `LightAuditKinds []string` to
   `EnumerateOptions`/`AuditConfig`, filter in
   `auditRun.lightAuditShouldSkip` (`audit_engine.go:513`) or at the
   `checks_injection.go:81` call, and give each of the 8 `quick_scan_*` rows a
   real `apply`. Needs one decision first: the rows currently have no
   list-shaped carrier, so `BuiltInConfig` needs a `[]bool` or `OptUint32`-per-kind
   field family. The honest smallest shape is 8 `OptUint32` fields on
   `BuiltInConfig` and a `LightAuditKinds` on `AuditConfig`.
3. **Manual insertion points**: an `EnumerateOptions.ManualRanges []ManualRange`
   that short-circuits enumeration the way `ZQ` does. Larger than 1 and 2
   because it needs a UI (where does an operator mark an audit position?), so it
   is a shape decision before it is code.

---

## Area 2 — Audit phases + item status machine (`burp.Zefx`, `burp.Zq5`)

### Burp's mechanism

**`Zefx` (`Zefx.java:7-14`) — 7 constants, not "7 phases" in the sense of a
pipeline.** The order in the declaration is `A1, A2, A3, A4, S2, S3, A5`. Each
carries a `BiFunction<Zggx, Boolean, Boolean>` (`Zefx.java:17`, applied by `ZH`
at `:42-44`) — a **predicate over an audit-state object plus a boolean**, so each
"phase" is really *a rule that decides whether that phase is applicable to this
item*. The five predicates read:

- `lambda$static$0` (`:74-76`): `var0.ZB0() || var0.ZBI()`
- `lambda$static$1` (`:70-72`): `var0.ZBX()`
- `lambda$static$4` (`:66-68`): `var0.ZBR() && var0.ZL8()`
- `lambda$static$5` (`:62-64`): `var0.ZBx() && var0.ZL8()`
- `lambda$static$6` (`:58-60`): `var1 && (var0.Zr(XSS_STORED, COLLABORATOR_BASED) || var0.ZG(INPUT_RETRIEVAL_REFLECTED))`

`ZK(Zsuv, Zr21<Zg4r>)` (`:47-52`) is the **skip notification**: it sets the
phase to `Zbef.NOT_APPLICABLE` and, for `A1` specifically, walks
`var1.Zr1().ZWJ()` and pushes `Zq5.NO_INSERTION_POINT_CHECKS` onto each
(`:50`, `:54-56`). So the phase's inapplicability and the item-status
`NO_INSERTION_POINT_CHECKS` are the same event, wired in one place.

`Zckx.java:9` confirms the full ordered set:
`Za = Zgnv.Zb(Zefx.A1, Zefx.A2, Zefx.A3, Zefx.A4, Zefx.S2, Zefx.S3, Zefx.A5)`,
and `:26-33` maps the persistence byte to each.

**Per-phase state is packed, not object-per-phase.** `Zekf.java:85-88`:
`Ze(long, Zckx)` extracts a 4-bit nibble at `4 * phase.ordinal()` from a `long`
and maps it through `Zbef.Zb(int)` — a 16-state-per-phase value in a
**64-bit word, 16 phases deep**. `Zg` (`:90-98`) writes it back and
auto-promotes `FINISHED` → `FINISHED_WITH_ERROR` when the phase was previously
in an error state. `Zbef` (`Zbef.java:5-11`) is the 7-value per-phase status:
`UNINITIALIZED, UNINITIALIZED_WITH_ERROR, NOT_APPLICABLE, RUNNING,
RUNNING_WITH_ERROR, FINISHED, FINISHED_WITH_ERROR`. `Zbef.Zf()` (`:53-55`)
reports the three terminal ones.

**`Zq5` (`Zq5.java:9-24`) — 15 constants**, each with a `permanentIndex`, a
`shortLabel`, a `label`, a format string and an `Zuiw` icon. Two constants carry
**parameterised labels**: `Zd(Zuzp)` (`:48-63`) formats `NO_PARAMETER_MOVEMENT`
with both parameter names and `SKIPPED_INSERTION_POINT_TYPE` with the resolved
kind. `Zs(Zbg8)` (`:65-85`) is the **kind → human-label table** and it is
worth quoting because it names 16 insertion-point types: URL parameters, body
parameters, cookies, HTTP headers, **XML parameters, XML attributes, multipart
parameter attributes**, URL path folders, URL path filenames, **JSON
parameters**, parameter names (3 kinds), the entire body, manual insertion points.

**`Zs4` is not modelled by burpsy at all**: burpsy has `PhasePassive,
PhaseLightActive, PhaseActive, PhaseStored, PhaseCollaborator, PhaseJavaScript`
(`check_contract.go:28-33`) — 6 phases, and the set does not correspond 1:1 to
`Zefx`'s 7.

### burpsy's current state

- **`ItemState` — 9 states** (`audit.go:368-439`, `ItemStateAll` at `:419`).
  `audit_items.go:66-94` (`BurpStatus()`) maps each to a `Zq5` constant where
  one exists, and `audit_items.go:96-128` (`StatusLabel()`) supplies Burp's own
  strings for the six that match.
- **`BurpStatusesNotModelled` — 8 rows** (`audit_items.go:168-185`), each with
  the constant, Burp's label, and a `Why`. This is the honest disclosure the
  package header promises (`audit_items.go:45-52`).
- **`AuditItemPointStatus` — 11 states** (`audit_items.go:200-242`) at point
  granularity, with `Label()` (`:245-271`) and `IsSkip()` (`:275-278`). The
  package states the granularity honestly (`:187-199`): the engine dispatches per
  *unit* (one per request), not per point, so these are the unit's fate
  attributed to each point it covered.
- **`BurpAuditItemStatusCount = 15`** (`audit_items.go:146`) — a constant beside
  the gap list so every surface reporting "6 of N" reads N from one place.
- **The phase predicates have no counterpart.** `CheckPhase` is a 6-value enum
  with no predicate; nothing in burpsy asks "is this phase applicable to this
  item?".

### Verdicts

| Sub-area | Verdict |
|---|---|
| Item-state vocabulary + Burp labels | **LANDED** (9 states, 6 mapped) |
| Point-granularity status with skip classification | **LANDED** (11 states) |
| Explicit not-modelled table with reasons | **LANDED** (8 of 15) |
| `xdtx` (table denied the light pass the package implemented) | **LANDED** — fixed |
| Per-phase applicability **predicate** (`Zefx.ZH`) | **MISSING** |
| Per-phase **pass state** (`Zekf` nibble, 7 `Zbef` values) | **MISSING** |
| Follow-up pass counter per phase (`Zsuv.Zy(Zckx)`) | **MISSING** (see Area 6) |
| Burp's 16-kind label table | **PARTIAL** — burpsy's `Label()` has no kind name |

**Gap 5 — no per-phase pass state, so a re-run cannot be told from a first run.**
Burp packs a 4-bit status per phase in a long (`Zekf.java:85-88`) and a pass
counter alongside it, and `Zeeu.java:240` reads the counter to decide whether a
work item repeats. burpsy has neither: `CheckPhase` is a label on a descriptor
(`check_contract.go:29`) and nothing records that a phase ran, ran twice, or was
marked NOT_APPLICABLE. Every burpsy audit is therefore structurally a
single-pass audit, and no surface can say otherwise. This is the substrate Area 6's
follow-up-pass gap sits on.

**Gap 6 — the audit queue cannot name an insertion-point kind the way Burp does.**
`Zq5.Zs(Zbg8)` (`Zq5.java:65-85`) is a 16-row table naming exactly which type was
skipped, and `Zq5.Zd(Zuzp)` (`:48-56`) interpolates it into the status label.
burpsy's `AuditItemPointStatus.Label()` (`audit_items.go:245-271`) returns
`"Skipped"` for four different causes' worth of point — and while the *point row*
carries `Kind` and `Detail` (`audit_items.go:294-304`), the **item's** status
label cannot name a kind. Three of Burp's named kinds have no burpsy `IpKind` at
all: XML parameters, XML attributes, multipart parameter attributes.

### Ranked smallest steps

1. **Per-phase pass state**: add a `map[CheckPhase]PhaseState` to `auditRun`,
   with the 7 `Zbef`-equivalent values, set it in the dispatch loop next to
   `o.Ran++` (`audit_engine.go:1324`), and surface it on `AuditItem`. One new
   struct, one loop write, one wire field. This is the prerequisite for
   follow-up passes and for any honest "how far did this item get" claim.
2. **Kind-aware status labels**: give `AuditItemPointStatus` a variant that
   carries the kind (`SkippedKind` + a kind field), and transcribe `Zq5.Zs`'s
   16-row table into the equivalent of burpsy's `IpKind` names. Two files
   (`audit_items.go`, `insertion.go`), no engine change.

---

## Area 3 — Check dispatch / filtering (`burp.Zcud`)

### Burp's mechanism

`Zcud.java` is 135 lines and the whole dispatch contract fits in its last 40.
Seven `protected abstract` methods, one per **dispatch scope** — `Zj` (per-URL,
`:58`), `Zx` (per-path, `:64`), `ZG` (per-host, `:70`), `Zm` (per-request,
`:76`), `ZL` (in-session per-request, `:82`), `Zr` (per-insertion-point, `:88`),
`ZC` (stored per-insertion-point, `:94`). Each public factory (`:54`, `:60`,
`:66`, `:72`, `:78`, `:84`, `:90`) is a one-line `this::lambda$get…Factory$N`.

**The filter-then-instantiate pipeline is `Zh(Zckx, Zgx0, Collection<Zb2q>,
List<Zwy6<T>>)` at `Zcud.java:96-98`, in three chained steps:**

```java
return var4.stream()
    .filter(this::lambda$filterChecks$7)    // :104-106 → var1.Zr(this.ZN)
    .filter(this::lambda$filterChecks$8)    // :100-102 → var4.Zz(this.ZY, var1, var2, var3)
    .map(Zwy6::ZP)                          // :32-34 in Zwy6 — the instantiate
    .collect(Collectors.toList());
```

Three things follow, and they are the substance of this area:

1. **Filter 1 is an `isEnabled` test against the config** — `Zwy6.Zr(Zggx)`
   (`Zwy6.java:36-75`). The bytecode at `:42-46` is `ZX.stream().anyMatch(lambda$isEnabled$0)`
   → *any* `Zb3l` whose `Zf.Z_()` is true **disables** the check (`:174-184`,
   `if (!var0.Zf.Z_()) return true; return false`). Then `:51-65`: if the
   restriction list is non-empty, `anyMatch(lambda$isEnabled$1)` where
   `lambda$isEnabled$1` is `var0.Zr(var1.Zf, var1.Zc)` — an **operator
   per-check deselection predicate**. So a check is admitted when *no* enabled
   restriction matches and *no* operator deselection matches.
2. **Filter 2 is the prior-failure filter** — `Zwy6.Zz(Zf8t, Zckx, Zgx0,
   Collection<Zb2q>)` (`Zwy6.java:77-120`). If `var1.Zt(phase) < 1L` it returns
   true (admit — nothing ran). Otherwise it switches on the check's
   `Zf8g` category (`:89-98`) and ORs **four** predicates:
   - `lambda$failedForEntirePhase$2` (`:162-168`) → `var1.ZF(phase)` — the check
     failed in this phase in an earlier pass
   - `lambda$failedForCheckInThisPhase$4` (`:154-160`) → `var2.Z_(phase, check)`
   - `lambda$failedForEntireInsertionPoint$6` (`:146-152`) → `var2.Zw(phase, ip)`
   - `lambda$failedForCheckAndInsertionPointInThisPhase$8` (`:138-144`) →
     `var3.Zb(phase, ip, check)`

   **This is Burp's follow-up-pass suppression rule**: a check that already failed
   in an earlier pass, at phase / insertion-point / check granularity, is *not
   re-run on the next pass*. It is the counterpart to the re-enqueue decision in
   Area 6 — a repeated pass happens, but not for work already known to fail.
3. **The instantiate step is `Zwy6.ZP()`** (`Zwy6.java:32-34`) — a bare
   `return this.ZI`, so instantiation is free and the class name
   `filterChecks` is accurate: the factories build the full list, and this method
   is the only gate.

burpsy: `check_registry.go:13-46` (`NativeCheckRegistry`) aggregates descriptor
families; `descriptorWithTier` (`:56-77`) is the constructor; `nativeActiveCheckSet`
(`:116-135`) adapts to the ledger; `ValidateRegistry` (`:155-170`) is the
independent validator; `RegistryByTypeIndex` (`:174-181`) the sorted view.
`CheckDescriptor` (`check_contract.go:255-271`) carries `Implementation, Phase,
Scope, InsertionKinds, Enabled, Run, DeclineReason, Invasiveness, Passive`.

### Verdicts

| Sub-area | Verdict |
|---|---|
| Per-scope factory set (7 scopes) | **LANDED** (`DispatchScope` + `wrapDescriptor`) |
| Filter 1: config-level enable | **LANDED** (`Enabled func(*ScanConfig) bool`) |
| Filter 1: operator per-check deselection | **MISSING** |
| Filter 2: prior-failure suppression by (phase, ip, check) | **MISSING** |
| Registry validation + sorted view | **LANDED** |
| Coverage report | **LANDED but thin** (`check_coverage.go` — registry report only) |

**Gap 7 — the operator cannot deselect individual checks, and cannot deselect
individual *issue types* either.** Burp's filter 1 has two halves
(`Zwy6.java:174-184` and `:170-172`): the config half burpsy has
(`CheckDescriptor.Enabled`), the **operator half burpsy has no field for**. This
is the same missing capability as the three unapplied
`scanner/issues_reported/selected_issues` rows (`audit.go:1044-1061`) and
`check_contract.go:70`'s `tieredEngineNote`, and they are one gap, not two.
**One sentence:** burpsy has no mechanism to restrict a run to a chosen subset of
issue types or checks, so an operator who wants "SQL injection and reflected XSS
only" must disable the other 21 families by hand through 21 unrelated switches,
and the three `selected_issues` keys are dead letters.

**Gap 8 — the coverage report cannot say whether a check is operator-suppressed.**
`check_coverage.go:19-37` returns `TypeIndex, Name, Implementation, Phase, Scope,
Runnable, DeclineReason` — an accurate registry report, explicitly *"not a claim
that any row ran during a scan"* (`:17-18`). That framing is correct and should
not change. But once Gap 7 lands, a check that is runnable-but-deselected needs
to be distinguishable from one that is runnable-and-admitted, or the matrix will
report a check as available in a run that will not dispatch it — the exact
defect class `povm` was.

### Ranked smallest steps

1. **Per-check deselection**: add `Deselected func(name string) bool` to
   `CheckDescriptor` and a `SelectedIssues []string` (or `map[TypeIndex]bool`) to
   `AuditConfig`; filter in `nativeActiveCheckSet`/`enabledChecksUnder`
   (`audit_engine.go:141-155`). Then give the three `selected_issues` rows a
   `read`/`apply` and bump `wantApplied` by three. Same file family as Gap 1's
   fix, same constant.
2. **Coverage row carries the deselection state**: one extra field on
   `CheckCoverageRow` filled from the same source as step 1. Do it *with* step 1,
   not after — a coverage row that cannot express "available but suppressed" is
   the `povm` shape.

---

## Area 4 — Issue consolidation / dedup (`burp.Zbvp`)

### Burp's mechanism

`Zbvp.java` is 86 lines and its constructor takes
`(Map<Short, List<Zco9>>, Zwlr, List<Zco9>, short)` — a short-keyed bucket map, a
`Zwlr` policy, the current issue list, and the group key. `ZE(Zco9)` (`:28-51`)
is the intake gate:

```java
if (Zd(var1)) {                                    // :31 — eligible for merging at all
    List var3 = Zo(var1, this.ZT);                 // :33 — same-type issues in this window
    boolean var4 = this.Zu(var1, var3);            // :34 — should this one merge?
    if (var4) {
        this.Zd.computeIfAbsent(this.ZN, ...).add(var1);   // :36 — file under the group
        if (var2 == null) break label16;
    }
    this.ZE.ZE(var1);                              // :42 — otherwise report individually
}
this.ZE.ZE(var1);                                  // :50 — ineligible → report individually
```

Four distinct rules, each one method:

- **`Zd(Zco9)` (`:62-64`) — the exemption gate.** `type != CROSS_DOMAIN_POST &&
  type != SERIALIZED_OBJECT_IN_HTTP_MESSAGE && fingerprint != <stripped constant>`.
  The third clause compares `var0.Zxi().ZZ()` against a `private static final
  String a` that the ZKM string pass **did not restore** (the file's header
  records 1 restored literal; `a` is assigned in a `static` block the
  scaffolding-stripper removed). burpsy's `dedup_policy.go:33-36` records this
  honestly: *"a fingerprint compared against a string constant (Zbvp.java:62) that
  the obfuscator stripped. What it named is unrecoverable."* **This is a
  confirmed-unrecoverable third exemption, and it is correctly documented as such
  in both trees.** Not a gap.
- **`Zo(Zco9, List)` (`:66-68`) — the same-type candidate set.**
  `lambda$findIssuesOfSameType$2` is `var1.ZxR() == var0.ZxR()` (same issue
  type); `lambda$findIssuesOfSameType$3` is `!var1.ZA(var0)` (and **not already
  claimed by** `var0`).
- **`Zu(Zco9, List)` (`:53-60`) — the merge decision, and it has a special case.**
  For `JWT_WEAK_HMAC_SECRET` it is `anyMatch(candidate::fingerprintEquals)` — a
  **fingerprint** match, not a count. For every other type it is
  `this.ZY.Zn(var2) + 1 > 1` — the `Zwlr` policy's merge threshold over the
  candidate count. **Two different merge rules, one of them type-specific.**

### burpsy's current state

This area is **better ported than most of the map** and should be said so.

- `internal/core/findings.go:182-185` — `dedupExemptRows` holds Burp's two
  recoverable exemptions, with the file citing `Zbvp.java:62-64` directly
  (`:169-171`).
- `findings.go:199-205` — `DedupPolicy{HostScoped, Exempt}`, the Go shape of
  Burp's `Zwlr`.
- `findings.go:432-442` — the gate: exempt rows return `"", false`; host-scoped
  rows key on `t.Origin()` alone; everything else keys on name + full target.
  This **is** `Zd` + `Zo` + `Zu` collapsed into one keying function, with the
  granularity decision expressed as *what the key contains*.
- `findings.go:468+` (`Add`) and `:532-535` (`mergeLocked`) — merge appends
  occurrences and dedups the param list.
- `internal/scanner/dedup_policy.go:26-50` — `DedupPolicy()` derives
  `HostScoped` from **dispatch scope** and adds the 4 provenance rows to
  `Exempt`, with a stated reason (`:27-36`).
- Tests: `findings_test.go` has 12 tests in this area alone, including
  `TestFindingStoreExemptRowsNeverMerge` (`:178`),
  `TestFindingStoreUnknownTargetNeverMerges` (`:194`),
  `TestFindingStoreMergeEscalatesSeverityAndConfidence` (`:251`),
  `TestFindingStoreHostScopedPolicyMergesAcrossPaths` (`:206`);
  `dedup_policy_test.go` has 3 more.

**Gap 9 — JWT weak-HMAC's fingerprint merge rule is not ported.**
`Zbvp.Zu` (`:53-56`) gives `JWT_WEAK_HMAC_SECRET` a merge rule no other type
gets: two JWT findings merge when their **fingerprints** match, regardless of
how many candidates there are, and the generic `count + 1 > 1` threshold is not
consulted at all. burpsy's `findings.go:432-442` has one keying rule; a JWT
finding therefore merges with every other JWT finding at the same target, or
with none. burpsy's own `jwt_weak.go:33-39` documents a *different* dedup (the
in-check token table, keyed on the signing input **including the signature** —
`jwt_weak.go:546-549` and `jwt_weak_dedup_test.go:11-18`, which records that
keying on the signing input alone cost a real detection). So the two layers
disagree and neither matches Burp's rule.

**Gap 10 — there is no per-issue fingerprint on the finding.** `Zu`'s JWT branch
calls `var1.Zxi().ZZ()` and the exemption gate calls the same accessor. burpsy's
`Finding` has `Param`, `Target`, `Severity`, `Confidence` — and **no fingerprint
field at all**. That is why Gap 9 cannot be closed without a second change, and it
is also why the stripped third exemption stays unrecoverable: the value Burp
compared is a thing burpsy does not store.

### Ranked smallest steps

1. **Add a `Fingerprint` to `core.Finding`** (a short hash of the
   issue-specific evidence string; empty for rows that have none) and extend
   `findings.go`'s keying to consult it for the JWT row. Two files plus the
   `dedup_policy` test. This is also the prerequisite that would let a future
   pass recover the stripped exemption by fingerprinting what Burp's `a` matched.
2. **Record the JWT rule in `gaps.md`** as a partial port, next to the existing
   stripped-constant note (`dedup_policy.go:33-36`) — the reasoning is already
   written down, it just is not in the parity ledger.

---

## Area 5 — Queue + scheduling (`Zg4f`, `Zeze`)

### Burp's mechanism

**`Zeze.java` — the per-URL disposition bank, 10 constants** (`:10-17`):
`ACTION_TAKEN_NO_TRAFFIC, ACTION_TAKEN_NETWORK_ERROR, ACTION_TAKEN_LOW_VALUE,
ACTION_TAKEN_AUDITABLE, FINAL_GRAPH_PAGE_INACCESSIBLE, FINAL_GRAPH_CRAWL_LIMIT,
FINAL_GRAPH_AUDITABLE, REQUEST_TO_AUDIT_DEDUPLICATED` (+ the two
scope/matched constants at `:36-41`). The `Zg4` mapping (`:36-52`) groups them
into three rollups: `CONSOLIDATED` (action-matched + deduplicated),
`CRAWLED` (no-traffic + auditable ×2), and one each for
`NETWORK_ERROR`, `LOW_VALUE`, `CRAWL_LIMIT`.

**`LOW_VALUE` is assigned from crawl *action type*, not from the response.**
`Zwee.java:76-78`: `if (this.Zf(var4, var5, var8)) var6 = Zeze.ACTION_TAKEN_LOW_VALUE;`
— reached from the same method that maps crawl outcome at `:102-107`, where a
switch on the crawl action's ordinal assigns `case 1 -> LOW_VALUE` and
`cases 3-10 -> ACTION_TAKEN_NETWORK_ERROR`. So the disposition is decided from
**what the crawler was doing**, before the audit ever runs.

**`REQUEST_TO_AUDIT_DEDUPLICATED` is emitted at the intake gate.**
`Zu0y.java:30-33`: for each `Zhem` in the incoming batch,
`this.ZI(new Zxjz(var4, Zeze.REQUEST_TO_AUDIT_DEDUPLICATED))`. The same class at
`:52-54` names the other side: a genuinely new request is
`new Zxjz(var0.Zc(), Zeze.ACTION_TAKEN_AUDITABLE)`. So dedup is a **queue-level
disposition with its own event**, not a silent drop.

**`Zg4f` is the typed event bus.** I did not read it directly. What is provable
from its call sites: it is a `net.portswigger` bus keyed by `Zg4r` constants —
`Zg4r.ZA/Zp/Zl` pair with `Zefx` and `Zp4v` in `Zc4_.java:157-177`, and
`Zg4f.Zl` appears as a `Zuji.Zi().ZQ(...)` subscription in `Zr4s.java:111`. So
the crawl→audit bridge publishes onto `Zg4f` with a *typed* payload carrying the
audit phase (`Zefx`) alongside the item.

burpsy's side: `Disposition` is **9 values, all about checks within one
`(unit, check)` pair** (`audit.go:260-284`, `DispositionAll` at `:287-297`) —
`Ran, Unsupported, SendFailed, AlreadyCovered, TimeBudgetSpent,
RequestBudgetSpent, UnitAbandoned, ItemFailed, SessionPaused`. Its
`AlreadyCovered` (`audit.go:269-271`) is *"an identical `(dispatch unit, check)`
already ran in this session"* — **the admission-ledger half** of Burp's
cross-task dedup, and it is content-aware (`audit.go:189-197`: the
request-content fingerprint 6n4d is appended to the URL-keyed scopes). So the
*mechanism* landed; only the **URL-level queue disposition** did not.

### Verdicts

| Sub-area | Verdict |
|---|---|
| Typed event bus for the crawl→audit bridge | **MISSING** |
| Per-URL `AUDITABLE` disposition as a queue event | **MISSING** |
| `LOW_VALUE` disposition | **MISSING — declined** (gaps.md Decline 3) |
| `NETWORK_ERROR` disposition | **MISSING** |
| `REQUEST_TO_AUDIT_DEDUPLICATED` as a first-class disposition | **PARTIAL** — mechanism landed, disposition did not |
| Cross-task dedup mechanism itself | **LANDED** (`apfh` closed) |
| Mid-crawl audit start | **MISSING — filed** (`7suo` open) |
| 429/503 status backoff | **LANDED** (`fkl8` closed) |
| Per-host pacing | **MISSING — filed** (`6urp` open) |

**Gap 11 — burpsy's nine dispositions have no URL-level counterpart, so
`AUDITABLE` / `LOW_VALUE` / `NETWORK_ERROR` cannot appear on a queue row.**
The nine burpsy dispositions all describe what happened to a *check inside a
running audit*. Burp's `Zeze` dispositions describe what happened to a *URL
before it was queued* — a different axis, and the one an operator reads on the
crawl/audit queue. gaps.md Decline 3 correctly declines `LOW_VALUE` because it
keys on crawler action types burpsy's crawler does not record. **`NETWORK_ERROR`
has no such dependency** — it is derivable from the audit outcome burpsy already
computes (`DispositionSendFailed` at `audit.go:266-268`, and
`AuditItemBreakers` at `audit_items.go:312-330` records the breaker that stopped
it). And `AUDITABLE` is derivable from the same place `AlreadyCovered` already is.

**Gap 12 — the crawl→audit bridge is a batch, not a typed event bus.**
`7suo` is open and its title is *"per-URL incremental audit push replacing the
batch tick"*; the Burp evidence it cites is `Zrwf.java:74-84` publishing each
newly-reached URL immediately. Confirmed today: burpsy's audit of crawled
exchanges is a batch after the crawl, and there is no `Zg4f` analogue carrying a
phase alongside the item. This is a real gap and it is **already filed** — do
not re-file. Recorded here because the *event-bus framing* (typed payload, phase
carried) is the part of Burp's mechanism neither the existing bead nor a naive
per-URL push would reproduce.

### Ranked smallest steps

1. **Two URL-level dispositions, no crawler dependency**: add
   `URLDispositionAuditable` and `URLDispositionNetworkError` to the queue row
   beside the existing `AuditItem`, derived from `AuditItemBreakers` +
   `DispositionSendFailed`. Smallest honest shape is a string on the item with
   Burp's own spelling, matching how `ItemState.BurpStatus()` (`:66-94`) already
   reports Burp's constants. Two files, no engine change.
2. **Typed crawl→audit event**: belongs to `7suo`. The addition this map
   contributes is that the event payload should carry the phase, not just the
   URL — `Zg4r` carries `Zefx` alongside the item (`Zc4_.java:157-177`) and that
   is what lets a consumer tell a passive pass from an active one.

---

## Area 6 — Adaptive decisions mid-scan

### Burp's mechanism

**The two-level breaker is `Zeeu.Zf` (`:239-241`) plus `Zsuv.Zi/Zrj/Zy`:**

```java
boolean Zf(Zsuv var1, Zckx var2) {
    return !var1.Zi(var2)          // phase not applicable
        || var1.Zrj() == 4         // ← a state == 4
        || var1.Zy(var2) >= this.Zc.ZUZ();   // follow-up passes exhausted
}
```

Three exits, and only the third is the follow-up count. `Zc.ZUZ()` is
`scanner.error_handling.number_of_follow_up_passes` (`Zxdx.java:27`, `:36`;
`Zrd0.java:94` wires it to the UI; `Zp0d.java:120-121` shows the shipped default
is **1**). So an item that failed is re-queued up to `ZUZ()` passes.

**The re-enqueue is `Zeeu.ZB` (`:100-138`), and the predicate is `Zq(Zckx)`
(`:188-203`): "does *any* phase in `this.Zv` answer `Zi(this phase)` true?" —
i.e. "is this phase still applicable?" — combined at `:119` with
`this.Zj.Zt(var1) < this.Zc.ZUZ()` (pass counter < limit). The result at
`:120-125` removes the item from the pending sets, notifies
`lambda$notifyAuditItemFinishedPhase$5`, calls `this.Zj.ZC(var1)` to bump the
pass, and publishes `Zg4r.ZM` with a `Zm9y` carrying `(item, passNumber)`.
**So the pass number is a published, observable event**, not an internal counter.

**What triggers a re-pass is a failed item, and only in one phase.** `Zfkz`
(`Zfkz.java:52-67`) is the active-work-item producer, and its gate at `:57` is
`if (this.ZK.ZL(var2) && !this.ZD(var4)) return Collections.emptySet();` where
`ZD` (`:69-71`) is `lambda$hadErrorInAPPCheckInPreviousPass$2`:
`var0.ZF(Zefx.A1) || var0.Zoq() != null && var0.Zoq().ZR() == Zim_.APP`. So
**re-passes are gated on a prior error in phase `A1` (the first phase) or an
`APP`-class error.** `Zg25.java:68-70` is the `APU` sibling. Nothing in this tree
re-passes on a *clean* item.

**And the re-run is narrowed by Area 3's filter 2** — a check that already failed
in the earlier pass is not re-run (`Zwy6.java:138-168`). So the follow-up pass
re-runs *only work that has not yet been shown to fail*, which is the whole point
of pairing the two features.

burpsy's side: both breakers exist and are exercised —
`ConsecutiveCheckFailuresToAbandonUnit` (`audit.go:530-532`) and
`ConsecutiveUnitFailuresToFailItem` (`:532`) with
`DefaultConsecutiveUnitFailuresToFailItem = 2` (`audit.go:705`), driven at
`audit_engine.go:1304`, `:1321` (`abandoned = breaker.checkFailed()`) and
`:1339` (`breaker.unitFinished(abandoned)`). The session breaker
(`PauseSessionAfterFailedItems`, `PauseSessionAtFailedItemPercentage`,
`audit.go:533-536`) is tested at `audit_test.go:268-290`. The backoff is at
`audit_engine.go:1234-1239` and observed in two send paths
(`scanner.go:588-596`, `probe_harness.go:134-139`) so no family can route around
it.

### Verdicts

| Sub-area | Verdict |
|---|---|
| Two-level breaker (check→unit→item) | **LANDED** |
| Session-level count + percentage pause | **LANDED** |
| 429/503 backoff | **LANDED** |
| **Follow-up re-passes after a failed item** | **MISSING** |
| Re-run narrowing (skip already-failed check/ip/phase) | **MISSING** |
| Re-pass gated on phase-A1 / APP-error only | **MISSING** (n/a without re-passes) |
| Session-rule invocation during audit | **MISSING — declined** (gaps.md Decline 2) |
| Adaptive decision *within* a pass | **LANDED** (light tier, backoff) |

**Gap 13 — `number_of_follow_up_passes` is a real, unapplied config key with no
plumbing behind it, and the row's stated reason is now half false.**
`audit.go:1072-1077` says the key is not applied because *"an audit item's checks
run once per dispatch unit; this engine has no follow-up pass to repeat them."*
The first clause is the true reason. The problem is what Burp's key actually
does, which the row does not say: a follow-up pass is **conditional re-dispatch
of an item that errored, bounded by a pass counter, with already-failed work
excluded from the re-run** — a retry-with-narrowing loop, not "run the checks
twice". burpsy's two-level breaker currently treats a failed item as terminal
(`ItemStateFailed`; `audit_engine.go:1339` breaks the loop). An item that fails
once and would have succeeded on pass 2 is simply lost, and the outcome reports
`FAILED_TO_SCAN` with no mention that a retry was possible.

**Gap 14 — the re-run narrowing rule has no counterpart, so it must be built
*with* Gap 13 or the follow-up pass will be a pure waste.** burpsy's
`AuditLedger.Admit` (`audit_engine.go:1256`) is a one-bit admission test keyed
on `(unit, check)` — it refuses a *second* admission of work already covered, but
it has no notion of "this check already failed here." A follow-up pass that
re-dispatches the whole plan would re-send every check that failed, which is
strictly worse than not re-passing at all on a target that is genuinely down.

### Ranked smallest steps

1. **The pass counter, before the re-dispatch.** Add `Passes OptUint32` to
   `AuditConfig` with a `read`/`apply` on a new
   `number_of_follow_up_passes` row (bumping `wantApplied` to 29), and add
   `Pass int` to `AuditItem`/`AuditOutcome`. At this point the key is honoured in
   the only way that can be true without the loop: it *reports* the configured
   budget and the engine still runs one pass. **This is not the fix** — but it
   converts a false "not applied" into a true "reported, one pass performed",
   and the file's own honesty rule (`audit.go:1063-1071`) is satisfied by
   reporting rather than by silence.
2. **The failure ledger, before the re-dispatch.** Extend `AuditLedger` with a
   `failed map[key]bool` set beside `Admit`, written where
   `abandoned = breaker.checkFailed()` is (`:1304`, `:1321`), and read by a new
   `AdmitAfterFailure` that returns false for a `(unit, check)` already known to
   have failed **in this pass generation**. This is the narrowing rule, and it
   is the piece that makes a second pass cheaper than the first rather than
   double.
3. **The re-dispatch loop**: on `ItemStateFailed` with
   `pass < cfg.Passes && pass != 0`, bump the generation, clear the
   point-level statuses for that item, and re-enter the plan loop. Depends on 1
   and 2. `AuditItemBreakers` (`audit_items.go:312-330`) gains one field.

### Session rules during audit

Declined at gaps.md Decline 2 (`gaps.md:1257-1268`) with a sound reason: burpsy's
audit engine does not own the macro/session infrastructure, and the key
`scanner.audit_optimization/maintain_session` (`audit.go:1090-1095`) would
"decide nothing" without the invocation path. **Verified still true today**: grep
for `sessionRule|SessionRule|maintain_session` across `internal/scanner` returns
only the key row itself (`audit.go:1092`) and a comment in
`infra_authdiff.go:57-59` that names `internal/session.Coordinator` as the
*equivalent* Burp shape, not as something the audit calls. The decline is
accurate. **No bead** — re-open when the session epic lands audit-side wiring, as
the entry says.

---

## Area 7 — Scan-config key coverage

Measured at the top of this document. Summary of what changed since bead t2s:

| | bead t2s (2026-08) | today (2026-09-26) |
|---|---|---|
| denominator | 78 (all-subsystem leaves) | **55** (`scanner/*` only) |
| applied | 4 | **27** |
| classified (applied + reported) | — | **55 of 55** (test-enforced) |
| sections with at least one applied key | 2 of 15 | **8 of 10 scanner sections** |

burpsy's 10 `burpConfigSections` (`burpconfig.go:30-41`) map 1:1 onto Burp's key
namespaces, and the comment at `:26-29` states the deliberate choice to list
*every* section Burp's own 29 shipped configs use — *"an unlisted section is
reported as one opaque section name, which hides \*which\* keys an operator's file
set and did nothing with."* That is the right instinct and it is implemented.

Sections where burpsy applies nothing:

- `audit_project_option_overrides` (2 keys) — timeouts belong to the sender.
  Declined with a reason. **Fine.**
- `frequently_occurring_insertion_points` (8 keys) — **NOT fine**; see Gap 2.
  The reason recorded is false.
- `ignored_insertion_points` (2 keys) — one is now honoured under a different
  spelling (Gap 1), one genuinely needs the rule engine. **Partly fine.**
- `javascript_analysis` (6 keys) — genuinely declined, reasons accurate. **Fine.**

---

## Summary table

| # | gap | verdict | burp evidence | burpsy evidence | proposed bead title |
|---|---|---|---|---|---|
| 1 | `skip_all_tests_for_parameters` is honoured under a Go-only name while the key table still reports it unapplied | **PARTIAL** | `Zwh1.java:8-13`, `Zs4k.java:199-206` | `audit.go:1174-1179` (`applies: false`) vs `audit.go:622-632` + `insertion.go:396,735` (honoured) | scanner: the `skip_all_tests_for_parameters` key row says "not applied" while the engine honours the same control under a Go-API-only name |
| 2 | the 8 `quick_scan_*` rows claim to be redundant with `insertion_point_types`; they gate a *different* stage | **LANDED** | `Zrdr.java:26` ("runs a lighter audit … Select the insertion point types this applies to"), `Zb1q.java:111-118` | `audit.go` eight rows now `applies: true`; `AuditConfig.LightAuditKinds`; `audit_engine.go` gate | scanner: the eight `quick_scan_*` keys now gate the light tier per insertion-point kind, resolved as a derived deny list; the incorrect "redundant with insertion_point_types" reason is removed |
| 3 | no manual insertion points — a hand-marked request is not audited where the operator marked it | **MISSING** | `Zuq.java:178-197` (`ZQ`, `Zbg8.MANUAL_INSERTION_POINT`), short-circuit at `:68-71` | `insertion.go:76-108` (17 kinds, no manual member) | scanner: an audit has no manual insertion points, so a hand-marked request is re-guessed by the enumerator |
| 4 | no nesting-depth limit → `NO_NESTING_ALLOWED` | **DECLINED (accurate)** | `Zq5.java:12` | `audit_items.go:183-184` | — (decline is honest; no bead) |
| 5 | no per-phase pass state (`Zekf` nibble / 7 `Zbef` values) | **MISSING** | `Zekf.java:85-98`, `Zbef.java:5-11,53-55` | `check_contract.go:28-33` (6-value label enum, no state) | scanner: an audit records nothing about which phases ran, ran twice, or were not applicable |
| 6 | status labels cannot name an insertion-point kind; 3 Burp kinds have no `IpKind` | **PARTIAL** | `Zq5.java:48-85` (`Zd`, `Zs` — 16-row table) | `audit_items.go:245-271`, `insertion.go:76-108` | scanner: a skipped insertion point is reported as "Skipped" with no kind, and XML/multipart parameter kinds do not exist |
| 7 | no operator per-check / per-issue deselection | **MISSING** | `Zwy6.java:170-184` (`lambda$isEnabled$1`) | `check_contract.go:70`, `audit.go:1044-1061` (3 dead keys) | scanner: no mechanism restricts a run to a chosen subset of issue types, so the three `selected_issues` keys are dead letters |
| 8 | coverage row cannot say "runnable but operator-suppressed" | **PARTIAL** | `Zwy6.java:36-75` (two-stage enable filter) | `check_coverage.go:19-37` | file with #7 |
| 9 | JWT weak-HMAC's fingerprint merge rule is not ported | **PARTIAL** | `Zbvp.java:53-56` (`Zu`, `Zxi().ZZ()`) | `core/findings.go:432-442` (one keying rule), `jwt_weak.go:546-549` (a third, different rule) | scanner: JWT weak-HMAC findings merge by target like every other row, not by the fingerprint Burp's merger compares |
| 10 | `core.Finding` has no fingerprint field, so Burp's stripped third exemption stays unrecoverable | **PARTIAL** | `Zbvp.java:62-64` (`a`, a ZKM-stripped constant) | `dedup_policy.go:33-36` (correctly documented), `core/findings.go` | file with #9 |
| 11 | no URL-level `AUDITABLE` / `NETWORK_ERROR` queue dispositions | **MISSING** | `Zeze.java:10-17`, `Zwee.java:76-78,102-107` | `audit.go:260-284` (9 check-level dispositions only) | scanner: the audit queue has no URL-level disposition, so AUDITABLE and NETWORK_ERROR cannot appear on a row |
| 12 | crawl→audit bridge is a batch, not a typed event carrying the phase | **MISSING (filed)** | `Zc4_.java:157-177` (`Zg4r` carries `Zefx`), `Zrwf.java:74-84` | `7suo` (open) | — (already filed as `7suo`; add the phase-carrying event payload to its scope) |
| 13 | `number_of_follow_up_passes` is unapplied and a failed item is terminal | **MISSING** | `Zxdx.java:27,36`, `Zeeu.java:119,239-241`, `Zfkz.java:57,69-81`, default 1 (`Zp0d.java:120-121`) | `audit.go:1072-1077`; `audit_engine.go:1339` (loop breaks) | scanner: a failed audit item is terminal — Burp's follow-up passes (`number_of_follow_up_passes`) have no loop to run in |
| 14 | no re-run narrowing, so a follow-up pass would re-send known-failing checks | **MISSING** | `Zwy6.java:138-168` (four prior-failure predicates) | `audit_engine.go:1256` (`Admit`, one-bit, no failure memory) | file with #13 (step 2 — build before the loop) |
| — | session-rule invocation during audit | **DECLINED (accurate)** | `map_root.tsv:2894,5850-5851,20198` | `gaps.md:1257-1268`, re-verified in tree today | — |
| — | `LOW_VALUE` disposition | **DECLINED (accurate)** | `Zwee.java:76-78,102-107` | `gaps.md:1270-1276` | — (prerequisite is crawler action metadata) |
| — | `apfh` cross-task dedup, `fkl8` 429/503 backoff, `7bkj` light tier, `povm` insertion-kind wiring, `xdtx` parity-table fix | **LANDED** | — | `apfh` closed, `fkl8` closed, `7bkj` closed, `povm` closed, `xdtx` closed; code confirmed today at `audit_engine.go:1234-1239`, `scanner.go:588-596`, `audit_engine.go:509-530`, `check_contract.go:81-99`, `audit_items.go:161-185` | — |
| — | bead `t2s` (4 of 78 keys) | **STALE** | 78 counted all-subsystem leaves | 27 of 55, test-pinned at `audit_config_keys_test.go:102` | scanner: config-key denominator is 55 scanner leaves, not 78 — close `t2s` as superseded with the re-measured count |

---

## Evidence limits, stated rather than papered over

- **`Zuq.Zp` is the gate and I did not resolve what it calls.** The method body is
  one line (`Zuq.java:998-1000`); the decision lives in the `Zw2_`/`Zf8t`
  collaborators, which I did not trace. So *"Burp applies these 8 kind switches
  and this ceiling"* is CONFIRMED **from the settings bank** (`Zb1q.java:103-126`)
  and the resulting point shapes (`:89-197`), not from reading the filter itself.
  The per-kind *skip reason strings* Burp shows on a skipped point are in this
  tree but I did not locate them; burpsy's `AuditItemPointStatusSkippedDeclined`
  Detail field is where they would land.
- **`Zbvp`'s third exemption is unrecoverable** and both trees say so. Recorded
  as a documented unknown, not a gap.
- **`Zefx`'s five predicates reference `Zggx` methods whose names are not
  recovered** (`ZB0, ZBI, ZBX, ZBR, ZBx, ZL8, Zr, ZG`). I can say each phase is
  gated by a predicate over an audit-state object; I cannot say what each
  predicate tests. `Zefx` carries no `[deobfuscated]` header, so the enum
  constants themselves are original — it is the predicate bodies that are opaque.
- **No Burp key literal exists in `map_root.tsv`.** All key citations in this
  document are layer-4 inline literals from `Zb1q.java`, `Zxdx.java`,
  `Zb1q`-adjacent `Zwh1.java`, and the settings-pair `Z_`/`ZM` methods, which are
  the read AND write sides of the same key — the strongest available form of
  evidence for a config key, since a key Burp reads and writes under one name
  cannot be a stale alias.
- **`Zg4f` was not read.** Its type and the `Zg4r` payload shape are inferred
  from subscription call sites (`Zr4s.java:111`, `Zc4_.java:157-177`), which is
  PROBABLE, not CONFIRMED.
- **I did not run the test suite or build**, per assignment. The config-key
  counts are read from source (`audit.go:805-1239`) and from a constant that a
  test would fail on if wrong (`audit_config_keys_test.go:102`), not from a
  green run.
