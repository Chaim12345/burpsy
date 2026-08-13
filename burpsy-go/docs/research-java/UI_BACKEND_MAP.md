# Burp UI → backend map: the tab architecture, Dashboard, and Repeater

Derived from `out/clean/root/`, `out/names/all_renames.tsv`, `out/strings/map_root.tsv`, and
`out/specs/`. The decisive lever: **Burp calls `setName()` on Swing components for UI-test
addressability**, so component names survive as string literals and tie UI classes to their tabs.

---

## 1. The universal tab pattern (applies to every tool)

### 1.1 `burp.Zgdx` — the tool registry enum

`Zgdx.DASHBOARD`, `Zgdx.REPEATER`, … with `.Zw()` returning the tab identity key used by the
frame manager. This is the tool taxonomy, analogous to `Zcot` for issue types.

### 1.2 Every tool is a Guice module

`burp.Zigd` (Dashboard) and `burp.Ziy4` (Repeater) both `extend com.google.inject.Zc`
(= `AbstractModule`) and expose `@com.google.inject.Zw` (= `@Provides`) methods. Burp shades Guice
into `burp.*` / `com.google.inject.Z*`.

Recovered annotation vocabulary:

| Obfuscated | Almost certainly |
|---|---|
| `com.google.inject.Zc` | `AbstractModule` |
| `com.google.inject.Zw` | `@Provides` |
| `@Zgs7` | `@Singleton` |
| `@Zh1e` | `@Inject` |
| `@Zhrq` | Dashboard-scoped binding qualifier |
| `@Zea1` | Repeater-scoped binding qualifier |

### 1.3 The two bindings every tool module supplies

```java
@Provides @Singleton @<ToolQualifier>
Zrm8 <tool>ToolTabFlasher(Zg13 frames) {          // Zrm8 = tab flasher fn
   return (frames, evt) -> frames.Zo(Zgdx.<TOOL>.Zw(),
                                     evt.ZNz(), evt.ZN5(), evt.ZNT(), evt.ZNe(), evt.ZNZ());
}

@Provides @Singleton @<ToolQualifier>
Zuk4 <tool>ToolFrameProvider(Zg13 frames) {       // Zuk4 = frame provider fn
   return frames -> frames.Zf(Zgdx.<TOOL>.Zw());  // Zrpi = the tool's frame
}
```

`Zg13` is the **frame/tab manager**: `.Zf(key)` resolves a tool's frame, `.Zo(key, …5 args)`
flashes the tab for attention. This pair is the entire UI-shell contract — a tool plugs in by
providing a frame and a flasher, keyed by its `Zgdx` constant.

**To map any other tab**, search `out/names/all_renames.tsv` for
`<toolname>ToolFrameProvider` / `<toolname>ToolTabFlasher`; that names the tool's Guice module
class, and its `@Provides` methods enumerate the backend services.

---

## 2. Dashboard

### 2.1 Wiring — `burp.Zigd` (32 lines)

```java
public class Zigd extends AbstractModule {
   @Provides @Singleton @Zhrq Zur5 ZV(@Zb__ Zur5 v) { return v.Zz().Zy(Zgdx.DASHBOARD); }
   @Provides @Singleton @Zhrq Zrm8 ZD(Zg13 f) { … }   // dashboardToolTabFlasher
   @Provides @Singleton @Zhrq Zuk4 ZY(Zg13 f) { … }   // dashboardToolFrameProvider
}
```

Minimal — Dashboard is a *view over the task engine*, so it owns almost no backend of its own.

### 2.2 UI construction

| Class | Lines | Role | Evidence |
|---|---|---|---|
| **`burp.Zsq4`** | 311 | **main panel builder** | recovered `buildDashboardPanel` (`ZDZ`); string `Dashboard` |
| `burp.Zr_o` | — | task toolbar | `dashboardPauseAllTasksButton`, `dashboardResumeAllTasksButton`, `dashboardTasksFilterLine` |
| `burp.Zrex` | — | per-task progress | `dashboardTaskProgressBar` |
| `burp.Zr__` | — | paused warning banner | `dashboardTasksPausedWarningBar` |
| `burp.Zbuz` | — | event log table | `dashboardEventLogTable` |
| `burp.Zr_h` | — | event log empty state | `dashboardEventLogEmptyState` |
| `burp.Zhnf` | — | activity log table | `dashboardActivityLogTable` |
| `burp.Zgdu`, `burp.Zrar` | — | tab label | string `Dashboard` |

### 2.3 Backend it observes

| Class | Role |
|---|---|
| `burp.Zgjx` | `dashboardContainsTaskOfType` — task-type query |
| `burp.Zrb9` | task view construction — `buildCrawlTaskView`, `buildAuditTaskView`, `buildCrawlAndAuditTaskView`, `buildLiveAuditTaskView`, `buildLivePassiveCrawlTaskView` |
| `burp.Zbcc` | `adaptCrawlToRelativeProgress`, `adaptAuditToRelativeProgress`, `adaptEvents` — normalises heterogeneous task progress to one scale for the progress bars |
| `burp.Za0` | OpenTelemetry — `tool.dashboard.task.task_id`, `tool.dashboard.task.task_type`, `tool.dashboard.task_viewed` |

So the Dashboard reads: **scan engine tasks** (§ `SCAN_ENGINE.md`), the event log, and the activity
log. `Zrb9` is the seam — it is shared with the scanner and turns engine tasks into renderable views.

Intruder also surfaces here: `burp.Zpnh` carries *"You can access your attack history from the
Dashboard tab"* and *"If you keep the attack in memory, you can access it from the Dashboard until
you close Burp Suite."*, and `Zrus`/`Zrvw` the project-file persistence variants.

---

## 3. Repeater

### 3.1 Wiring — `burp.Ziy4` (55 lines) — richer, because Repeater owns real state

```java
public class Ziy4 extends AbstractModule {
   protected void configure() { super.configure(); this.ZQ(new Zigx()); }   // installs sub-module

   @Provides @Singleton Zhtt ZP(Ze4r root) { return root.ZlS().Zdv(); }
   @Provides @Singleton Zb_y Zx(Ze4r root) { return root.Zlm(); }           // ← Repeater core service
   @Provides @Singleton Zu8_ Zm(Zb_y svc) { return svc.ZEQ(); }
   @Provides @Singleton Zp0a<Zmls> Zk(Zb_y svc) { return svc.ZEt(); }       // ← observable tab list

   @Provides @Singleton @Zea1 Zrm8 ZF(Zg13 f) { … }   // repeaterToolTabFlasher
   @Provides @Singleton @Zea1 Zuk4 ZN(Zg13 f) { … }   // repeaterToolFrameProvider
}
```

Key inferred types:

| Type | Role |
|---|---|
| `Ze4r` | root service locator (`.Zlm()` → Repeater service, `.ZlS()` → related registry) |
| **`Zb_y`** | **the Repeater backend service** — the object to study next |
| `Zp0a<Zmls>` | observable collection of `Zmls` = Repeater tab/item models |
| `Zigx` | installed sub-module (further Repeater bindings) |

### 3.2 UI

| Class | Lines | Role | Evidence |
|---|---|---|---|
| **`burp.Zcu0`** | 144 | **top-level Repeater menu** | `mainRepeaterMenu`, `repeaterConfigurationGlobalMenuItemEnableH1ConnectionReuse`, `…EnableH2ConnectionReuse`, `…UpdateContentLength` |
| `burp.Zfw8` | 20 | "New HTTP tab" menu option | `newHttpRepeaterTabOption`, action id `266848` |
| `burp.Zfw1` | 16 | "New WebSocket tab" menu option | `newWSRepeaterTabOption`, action id `266864` |
| `burp.Zg6w` | 30 | request-validation warnings | Content-Length mismatch + `Connection: close`/`keep-alive` vs connection-reuse advisories |
| `burp.Zrp8` | — | `createSendToRepeaterButton` |
| `burp.Zr86` | — | `searchRepeaterCheckboxActionPerformed` |
| `burp.Zgkb` | — | `Burp Repeater documentation` link |

`Zfw8`/`Zfw1` both extend `Zfwh` (menu-option base) and call `.Zt(label)` + `.Zr(componentName)` —
that's the reusable menu-item idiom, with a numeric action id passed to `super`.

### 3.3 Backend

| Class | Lines | Role |
|---|---|---|
| **`Zb_y`** | — | core service (from `Ziy4`): owns `ZEt()` observable tab list and `ZEQ()` |
| `burp.Zmlu` | 207 | `sendRequestToRepeater` |
| `burp.Zmbv` | 140 | `createRepeaterItem` |
| `burp.Zsd9` | 45 | `createRepeaterItem` (second creation path) |
| `burp.Zm9_` | — | `newRequestFromRepeater` |
| `burp.Zbfn`, `burp.Ze7n` | — | `sendToRepeater` (`Ze7n` is the **legacy `IBurpExtenderCallbacks`** façade) |
| `burp.Zcur` | — | `Send to Repeater` context-menu action |
| `burp.Zgbr` | — | config `repeater.streaming_response_timeout_millis` |
| `burp.Zcso` | 28 | OpenTelemetry — `tool.repeater.tab.{index,uuid,shown}` |

### 3.4 Public contract

`burp/api/montoya/repeater/` — 3 classes: `Repeater`, `HttpEditor`, `EditorPane`.
Reached via `MontoyaApi.repeater()`.

### 3.5 What Repeater's config surface tells you

Connection reuse is a first-class, per-scope setting: **global** (top-level Repeater menu, via
`Zcu0`) and **per-tab** (settings icon next to Send) — `Zg6w`'s warning text states both paths
explicitly. Separately tracked for HTTP/1 and HTTP/2 (`EnableH1ConnectionReuse` /
`EnableH2ConnectionReuse`), plus automatic `Content-Length` correction (`UpdateContentLength`).

---

## 4. Observations that generalise

1. **Guice module per tool** is the extension seam. Adding a tab means a module providing a
   `Zuk4` frame provider and `Zrm8` flasher keyed on a `Zgdx` constant.
2. **`Zg13` is the single UI shell** — all tabs resolve and flash through it.
3. **OpenTelemetry is pervasive and per-tool** (`Za0` dashboard, `Zcso` repeater), using
   `tool.<name>.*` attribute namespacing. Useful for enumerating tools: grep
   `out/strings/map_root.tsv` for `^tool\.`.
4. **Component names are the reliable UI↔class index.** Pattern
   `<tab><Widget><Role>` (`dashboardEventLogTable`, `newHttpRepeaterTabOption`).
5. **Legacy vs Montoya coexist** — `Ze7n` implements the pre-Montoya callbacks; `burp/api/montoya/**`
   is the modern contract. Both route to the same backend services.

### Next tabs — the recipe

```bash
# 1. find the tool's Guice module
grep -iE '(proxy|intruder|logger|target|sequencer|decoder|comparer|organizer)Tool(FrameProvider|TabFlasher)' \
     out/names/all_renames.tsv

# 2. find its UI classes via component names
awk -F'\t' 'tolower($4) ~ /^proxy[a-z]/ {print $1"\t"$4}' out/strings/map_root.tsv | sort -u

# 3. find its telemetry namespace (confirms the tool key)
awk -F'\t' '$4 ~ /^tool\.proxy\./ {print $1"\t"$4}' out/strings/map_root.tsv | sort -u
```
