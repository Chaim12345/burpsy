# W6 — Burp's ~90 Top-Level Config Panels vs burpsy

Baseline (this worktree): see BASELINE section below.
Reference corpus: `/root/burp-re/out/strings/map_root.tsv` (Burp 2026.7.1 teardown).
Taxonomy: `/root/burpsy-parity/TAXONOMY.md` (six states, cited per RULES 1-8).

Already settled by prior work — SKIPPED here, not recounted:
- `configPanelUpstreamProxyServers`, `configPanelSocksProxy` — STATE 4 (conditionally),
  merged into `UpstreamProxySection` at `settings.tsx:1448`, honest wired/attached/persisted
  disclosure at `settings.tsx:1610-1624`.
- `configPanelPlatformAuthentication` — STATE 4 at `settings.network.tsx:44`, persistence
  undisclosed in the UI.

## BASELINE

```
$ git rev-parse --short HEAD
9194df6
$ git status --short --branch
## orchestry/tsk_ME-uK_h/parity-w6-enumerate-burp-s-90-top-level-  (clean, 0 changed files)
```
Worktree: `/root/burpsy-react-ui/.orchestry/workspaces/tsk_ME-uK_h` (linked worktree of `burpsy-react-ui`; production code is under `burpsy-go/`). READ-ONLY — no production file was edited to produce this report.

## THE COLLAPSE RULE (denominator derivation, fully reproducible)

Start: 134 distinct `configPanel*` identifiers in `map_root.tsv` (135 raw occurrences, 1 duplicate
row `configPanelClosingBehavior` — matches `verified_configpanel_count`).

**Step 1 — remove leaf widgets by suffix.** A leaf widget is a control INSIDE a panel
(a table, textfield, checkbox, button, combo, radio, label, or the settings-gear icon), not
a panel itself. Exact-suffix match, case-sensitive, against:
`Table TextField ToggleCheckBox CheckBox Checkbox AddButton RemoveButton DeleteBtn EditBtn NewBtn ComboBox Radio Label Cog IconButton`.

```
$ grep -o 'configPanel[A-Za-z0-9_]*' map_root.tsv | sort -u > configpanel_unique.txt   # 134 lines
$ grep -E '(Table|TextField|ToggleCheckBox|CheckBox|Checkbox|AddButton|RemoveButton|DeleteBtn|EditBtn|NewBtn|ComboBox|Radio|Label|Cog|IconButton)$' configpanel_unique.txt
```
Result: **25** leaf widgets (prior docs said 26 — I recount 25; the discrepancy is one
identifier, `configPanelIntruderSettingsGrepExtractAdd`, which ends in `Add` not `AddButton`
and I instead grouped it semantically in Step 3, not by suffix — see below. Net effect on the
final denominator is the same either way since it's absorbed downstream.)
Leaving **109** panel candidates.

**Step 2 — mechanical prefix collapse.** For each of the 109 candidates, if another candidate
in the same 109 is a strict string-prefix of it, the longer one is a documented SUB-CONTROL of
the shorter one's panel (e.g. `configPanelProxyMessageDisplayEditedReq` is one of nine tabs
inside the single `configPanelProxyMessageDisplay` panel), not a separate panel. Script: for
every c in candidates, parent(c) = the longest other candidate p such that c.startswith(p);
c is top-level iff parent(c) is None.

Result: **95** top-level, **14** absorbed as documented sub-controls of 5 parents:
`configPanelHotkeys` (+1: `HotkeysSettingsPanel`), `configPanelProxyMessageDisplay` (+9: the
Edited/Modified/Original × Req/Res/Ws grid), `configPanelProxyMiscellaneous` (+2),
`configPanelProxyTlsPassThrough` (+1), `configPanelRepeaterStreamingResponses` (+1).

**Step 3 — manual semantic collapse (documented, not mechanical).** Two clusters share a
common multi-segment prefix denoting ONE settings screen but have NO bare parent identifier
in the corpus, so Step 2's rule doesn't catch them:
- `configPanelIntruderPayloadSettings{NullCount,NumbersBaseHex,NumbersFrom,NumbersMaxIntegerDigits,NumbersMinIntegerDigits,NumbersTo,RecursiveGrepList}`
  (7 identifiers) → **1** panel: Intruder's built-in payload-generator settings (Numbers /
  Null generators + recursive grep list), reached from the attack config dialog.
- `configPanelIntruderSettingsGrepExtract{Add,EndAtDelimiter,StartAfterExpression}`
  (3 identifiers, including the one suffix-mismatch from Step 1) → **1** panel: the
  grep-extract rule editor.
This removes 8 more entries: **95 − 8 = 87**.

**Step 4 — structural chrome, not screens.** `configPanelTitle` and `configPanelDescription`
survive Steps 1-3 as top-level (no other candidate is their prefix), but both read as generic
per-panel template chrome (every settings screen has a title and a description string), not a
distinct settings screen in their own right. I exclude these 2 from the panel-mapping
denominator, flagged explicitly rather than silently dropped: **87 − 2 = 85**.

**FINAL DENOMINATOR: 85 top-level config panels.** This is lower than the "~90" estimate in
the task brief; I show the rule rather than force the number. If Step 4 is rejected (Title/
Description count as panels), the denominator is 87. If Step 3's manual clustering is rejected
in favor of pure mechanical Step 2, the denominator is 95. All three numbers and their exact
derivation are reproducible from the commands above — pick the one that matches your definition
of "panel"; I use **85** for the table below and say so at every total.


---

# W6b — THE MAPPING TABLE (analyst W6b, continuation pass)

The predecessor's derivation above establishes the DENOMINATOR (85). This pass supplies the
NUMERATOR: one row per panel, with a TAXONOMY state.

## BASELINE (W6b pass)

```
$ git rev-parse --short HEAD
638c480
$ git status --short --branch
## orchestry/tsk_KBUxW7m/auto-cto-burp-parity-gap-analysis-measur
(no modified files — clean tree)
```
Worktree: `/root/burpsy-react-ui/.orchestry/workspaces/tsk_KBUxW7m` (linked worktree of
`burpsy-react-ui`). All `file:line` citations below are relative to the repo root and were
read at `638c480` with a clean tree. READ-ONLY: no production file was edited.

**Denominator re-derived independently by W6b** (RULE 2 — I did not take 85 on trust):
```
$ grep -o 'configPanel[A-Za-z0-9_]*' /root/burp-re/out/strings/map_root.tsv | sort -u | wc -l
134
$ python3 <steps 1-4 of the collapse rule above>
leaf 25   cand 109   top 95   -> step3 -8 = 87   -> step4 -2 = 85
FINAL 85
```
Reproduces exactly. The 85-name list is the one enumerated in the table below; every row
name is a literal identifier from `map_root.tsv` (or a documented Step-3 cluster, marked `*`).

