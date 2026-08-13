# Burp Scanner & Live Audit — source file map

Located by cross-referencing recovered method names (`out/names/all_renames.tsv`, from
`lambda$<name>$n` synthetics) against recovered string literals (`out/strings/map_root.tsv`).
Every row cites the evidence that identifies it. Source lives in `out/clean/root/<Class>.java`
(readable) and `out/specs/md/<Class>.md` (bytecode spec).

**164 classes** carry audit/scan/crawl/issue-related recovered names. The ones that matter:

---

## 1. Insertion-point engine — the heart of active auditing

This is where a request becomes N attack positions. For a RAM-focused rewrite this is the
single most important subsystem: memory scales as
`requests × insertion points × checks × stored req/resp bytes`.

| Class | Evidence |
|---|---|
| **`burp.Zuq`** | **THE insertion-point builder.** Recovered: `addUrlFilenameInsertionPoint`, `addUrlAndBodyParameterInsertionPoints`, `addStandaloneTagInsertionPoint`, `buildNestedInsertionPoint`, `addNewParameterNameInsertionPoint`, `addPhpFileRequestInsertionPoint`, `addNewReferHeaderInsertionPoint`, `addUrlFoldersInsertionPoints`, `addSwitchedBodyParameterLocationInsertionPoints`, `getMovedParameterInsertionPoint` |
| `burp.Zeed` | string: `Scanner insertion point providers` |
| `burp.Zemw` | string: `Insertion point provider cannot be null.` |
| `burp.Zg9v` | string: `Insertion points strategy` |
| `burp.Zcur` | string: `Scan defined insertion points` |
| `burp.Zbju` | method: `provideInsertionPoints` |
| `burp.Zb2q` | string: `current insertion point` |
| `burp.Zcud` | `getActivePerInsertionPointChecksFactory`, `getStoredActivePerInsertionPointChecksFactory` |
| **`burp.Zq5`** | **the per-request cap** — `Burp Scanner didn't audit this insertion point, as it reached the maximum limit of insertion points to audit per request` / `…as this audit item was cancelled` |

`Zuq` + `Zq5` together define the combinatorial explosion and how Burp bounds it. Read these first.

## 2. Live audit — the specific subsystem asked about

| Class | Evidence |
|---|---|
| **`burp.Zrb9`** | `buildLiveAuditTaskView`, `buildLivePassiveCrawlTaskView` |
| **`burp.Zhwl`** | strings: `Live audit`, `Live audit (Pro version only)`, `liveTaskLauncherScanDetailsLiveAuditTaskTypeRadioButton` |
| `burp.Zcvb` | string: `Live audit` |
| `burp.Zmps` | `livePassiveCrawlTaskAdded` |
| `burp.Zc0e` | live-passive-crawl config keys: `crawler.live_passive_crawl.{add_all_urls,add_form_submissions,add_item_itself,add_links,add_same_domain,add_urls_in_scope,custom_scope,scope_type}` |
| `burp.Zpxe` | config prefix `crawler.live_passive_crawl.` |

## 3. Scan launch & task orchestration

| Class | Evidence |
|---|---|
| **`burp.Zeqc`** | `launchScan`, `launchScanTask`, `resumeScan`, `scanConfig`, `validateSeedUrls`, `getOpenApiScanLaunchConfiguration`, `getGenericApiScanLaunchConfiguration`, `getAuthenticationModels`, `applicationLoginConfig`, `resourcePoolSelectionConfig`; strings `No scan task found` |
| `burp.Ze0s` | `launchApiScan`, `launchWebappScan` |
| `burp.Zc16` | `startCrawl`, `finishCrawl` |
| `burp.Zbcc` | `adaptAuditToRelativeProgress`, `adaptCrawlToRelativeProgress` |

## 4. Audit items & queue — the memory hotspot

| Class | Evidence |
|---|---|
| `burp.Zf9d` | `Should not be adding/removing/setting new audit items via the observable wrapper` |
| `burp.Zi96` | string: `Audit items` |
| `burp.Zgff` | string: `Store issues on audit items` |
| `burp.Zc4b` | `configureAuditDataKnobs`; string `Retest blob has no audit items.` |
| `burp.Zb56` | `migrateActiveScanQueue`, `migrateIssueActivityLog`; `Legacy scan queue items` |
| `burp.Zbmw` | `convertAuditItems` |

## 5. Issue lifecycle, dedup & persistence

| Class | Evidence |
|---|---|
| **`burp.Zbvp`** | **dedup logic** — `findIssuesOfSameType`, `shouldMergeIssues` |
| **`burp.Zby4`** | dedup metrics — `getNumberOfUniqueValuesScanned`, `getNumberOfDifferentSetsOfIssueTypes`, `getCrcForIssueTypes`, `getScanCountForValue` |
| `burp.Zcjj` | `findIssues` |
| `burp.Zc_q` | `makeIssue` |
| `burp.Zb2g` | `writeIssue` |
| `burp.Zc8l` | `deleteIssues` |
| `burp.Ze3h` | issue model/tree — `onIssuesAdded`, `onIssuesRemoved`, `onIssuesSuperseded`, `onIssuesUpdated`, `updateIssuesForNode`, `notifyIssueSignificancePropagationListeners` |
| `burp.Zcps` | `refreshAuditIssueHandlers`, `getScannerCheckWrapperFor` |

## 6. BCheck DSL — the scan-check language

**`burp.Zht9`** embeds a complete BCheck script as a string literal, revealing the DSL grammar:

```
metadata:
    language: v2-beta
    name: "Insertion-point-level"
    description: "Inserts a calculation into each parameter to detect suspicious input transformation"
    author: "Carlos Montoya"
define:
    calculation = "{{1337*1337}}"
    answer = "1787569"
given insertion point then
    if not({answer} in {base.response}) then
        send payload: appending: {calculation}
        if {answer} in {latest.response} then
            report issue:
                severity: high
                confidence: tentative
                detail: "..."
        end if
    end if
```

This matters for a rewrite: **the checks are data, not code.** If you implement the BCheck
interpreter, you inherit check logic rather than porting hundreds of Java checks. Public BChecks
live at <https://github.com/PortSwigger/BChecks>.

## 7. NOT the scanner — don't be misled

**`burp.Ze7n`** shows `doPassiveScan`, `getScanIssues`, `sendToRepeater`, `sendToIntruder`,
`sendToSpider`, `getProxyHistory`, `addToSiteMap`. That is the **legacy `IBurpExtenderCallbacks`
implementation** (the pre-Montoya extension API), not scanner internals. It is a thin façade.

## Public contract

`burp/api/montoya/scanner/**` (12 classes) is unobfuscated and defines the supported surface:
`Scanner`, `AuditResult`, `ScanCheck`, `ConsolidationAction`, `audit/` and `bchecks/` subpackages.
For a reimplementation this is the interface to honour.
