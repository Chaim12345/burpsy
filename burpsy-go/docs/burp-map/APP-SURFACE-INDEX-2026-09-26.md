# Burp app surface -> burpsy: the index (2026-09-26)

**Oracle:** `/root/burp-re`, Burp Suite **2026.7.1 (build 51467)**. The runnable jar on this
machine is 2026.7.3 (build 52685) — a 1,218-build skew, so the tree wins for internals and the
running jar wins for behaviour, and every citation says which.

**Protocol:** the four evidence layers of `SOURCE-OF-TRUTH.md`, in order — (1) Montoya javadoc
`out/burp/api/montoya/**` (277 files, the only complete unobfuscated source), (2)
`out/montoya_api/IMPL-BRIDGE.tsv`, (3) `out/names/*.tsv`, (4) decompiled internals
`out/clean/jdt_src/burp/*.java` (19,309 files, flat). One command searches all four:
`python3 tools/burp_lookup.py "<term>"`. Layer 4 is the only source of operator-visible strings.

**What this document is:** the map of Burp's surface, the per-area verdict against burpsy, and
the pointer to the detailed gap maps. It is the entry point; the three companion files carry the
evidence.

| companion | covers |
|---|---|
| `scanner-gaps-2026-09-26.md` | the audit decision layer: insertion points, phases, dispatch, consolidation, queue, adaptive decisions, config keys |
| `crawler-gaps-2026-09-26.md` | crawl supervision, config keys, location identity, traversal, extraction, browser integration, gates, sitemap XML |
| `tools-gaps-2026-09-26.md` | Proxy, Intruder, Repeater, Comparer, Sequencer, Collaborator, Organizer, Logger, Decoder, Replayer, Discover |
| `platform-gaps-2026-09-26.md` | extension substrate, extension UI kit, AI surface, persistence/project, scope, sitemap, suite settings, extension utilities, themes |

---

## 1. Burp's tool enumeration (the spine)

`burp.Zgdx` — 16 constants, read from `out/specs/md/Zgdx.md` (a public final enum implementing
`burp.Zr6j`, `burp.Zs2f`):

`DASHBOARD · TARGET · PROXY · SCANNER · INTRUDER · REPEATER · COLLABORATOR · SEQUENCER ·
COMPARER · LOGGER · ORGANISER · BURP_AI · EXTENDER · REPLAYER · DISCOVER · SUITE`

burpsy's console covers 13 of the 16 as pages (Dashboard, Target, Proxy, Scanner, Intruder,
Repeater, Collaborator, Sequencer, Comparer, Logger, Organizer, Extensions, Discover);
`BURP_AI` is partially served by the LLM-triage surface (bead `ei0v`, closed); `REPLAYER` has no
page and no recorder (filed); `SUITE` has no settings section (filed).

## 2. The public API surface (what Burp *promises*)

277 Montoya javadoc files, counted by top-level family:

| family | files | what it is |
|---|---|---|
| `http` | 52 | the message model: requests, responses, params, sessions, handlers |
| `ui` | 43 | everything an extension may add to the interface |
| `utilities` | 35 | shell, JSON, rank, bytes/strings/crypto |
| `proxy` | 26 | interception, match/replace, TLS, WebSockets |
| `scanner` | 26 | audit, scan checks, insertion points, issues |
| `collaborator` | 16 | payloads, interactions, polling |
| `websocket` | 15 | frames, handlers, extensions |
| `intruder` | 12 | payloads, generators, attack types |
| `core` | 11 | BurpSuite, BurpExtension, callbacks |
| `ai` | 6 | chat prompts and options |
| `persistence`, `organizer` | 4 + 4 | extension data; stored items |
| `scope`, `sitemap`, `repeater` | 3 each | scope rules; site-map nodes; Repeater |
| `burpsuite` | 3 | `BurpExtension`, `EnhancedCapability`, `MontoyaApi` |
| `bambda`, `extension` | 2 each | scripted filters; extension identity |
| `logger`, `comparer`, `decoder`, `project` | 1 each | tool roots |

## 3. Verdicts by surface

| surface | verdict | the one-line gap | bead |
|---|---|---|---|
| **Scanner — insertion points** | PARTIAL | no operator step-lists per kind, no quick-scan profile, no manual markers | `806w`, `02qi` |
| **Scanner — phases/status** | MISSING | no per-phase state at all, so every audit is single-pass by construction | `0qhf` |
| **Scanner — check selection** | MISSING | no issue-type subset; three `selected_issues` keys are dead | `kvmx` |
| **Scanner — queue dispositions** | MISSING | no URL-level disposition, so AUDITABLE / NETWORK_ERROR cannot appear | `87fq` |
| **Scanner — follow-up passes** | MISSING | a failed item is terminal; `number_of_follow_up_passes` has no loop | `5efx` |
| **Scanner — config honesty** | PARTIAL | two key rows state reasons that are now false | `86le`, `yfhz` |
| **Scanner — light-audit opt-in** | MISSING | tier exists, per-kind control does not; 8 rows declined for a false reason | `02qi` |
| **Crawler — session gate** | MISSING | machinery complete and tested, never wired into a production crawl | `nc9s` |
| **Crawler — sitemap.xml** | MISSING | fetched, stored, discarded as non-HTML | `qjtx` |
| **Crawler — Burp config import** | MISSING | a loaded config's `crawler` object is discarded without a word | `3ok6` |
| **Crawler — identity tolerance** | PARTIAL | exact hash, no tolerance band; a rotating link makes a new location | `9x67` |
| **Crawler — render timing** | PARTIAL | no DOM/network idle threshold; a late-assembling page reads empty | `efra` |
| **Crawler — extraction** | PARTIAL | no `formaction`, `math[href]`, `object`/`embed`, no non-HTML documents | `u967`, `mz1n` |
| **Crawler — progress** | PARTIAL | 0% until the instant it finishes; no phase or action vocabulary | `hbjo` |
| **Crawler — cross-task reuse** | MISSING | empty identity per crawl; site map never seeds a frontier | `z8qf` |
| **Proxy — interception** | PARTIAL | 7 match types to Burp's 18 | `1cuc` |
| **Proxy — TLS passthrough** | PARTIAL | no scope coupling, no auto-add on negotiation failure | `n1fi` |
| **Repeater** | PARTIAL | no restore-to-global, no default tab group | `aa0p` |
| **Sequencer** | PARTIAL | no analysis-settings surface | `3iao` |
| **Collaborator** | PARTIAL | no custom data, no WITHOUT_SERVER_LOCATION | `80tc` |
| **Extender** | PARTIAL | 4 of 13 registration points; no hotkey kind | `wsu4` |
| **Suite settings** | PARTIAL | no Suite page; six settings absent and unnamed | `fyua` |
| **REST API surface** | MISSING | ~200 routes with nothing describing or gating them | `wt0r` |
| **Scope** | PARTIAL | no change notification | `e05t` |
| **Theme** | PARTIAL | no group/status/severity families; no cookie tokens | `axm9` |
| **Decompile completeness** | MISSING | 72 method bodies lost, all recoverable, incl. the insertion-point builder | `xqlr` |

## 4. Where the oracle itself is incomplete

Stated so that no parity claim silently rests on a hole:

- **71 lost method bodies** across 33 classes (`// $VF: Couldn't be decompiled`). Measured
  per-method against the definitions — an earlier pass of this document measured call sites and
  over-counted what was recoverable, so the numbers here are the corrected ones:
  **65 of the 71 are present and decompiled in `out/cfr_fixed`** (23 files fully clean there) but
  were never merged, because `tools/merge_decompilers.sh:34` tests CFR cleanliness with an
  unanchored `failed to decompile`, which matches the provenance comment every one of those CFR
  files carries. Filed as `gl30`.
  **6 bodies are lost by every decompiler on this machine**: `Zuq.ZG/Ze/Zy` (the insertion-point
  builder), `Zrjq.e/j`, `Zx61.a`, `Zppj.l/n`, `Zr86.6/c/d`, `Zbp4.m`, `Zfj.U`, `Zgs4.d`,
  `Zhub.y`, `Zm1u.S`. Filed as `xqlr`, re-scoped to recovery-or-honest-decline rather than a merge.
  **What this means for a parity claim:** for `Zuq` in particular, "Burp enumerates insertion-point
  kind X" rests on one of three things in decreasing strength — the parts of `Zuq` that DID
  decompile, the Montoya javadoc, or `map_root.tsv` literals. A claim must say which it stands on,
  because three of `Zuq`'s methods cannot be read at all on this machine.
- **210 further files** carry only `// $VF: Irreducible bytecode was duplicated…` on a synthetic
  static initializer that rebuilds a ZKM string array. These are **not** losses — the literals are
  already restored into `out/strings/map_root.tsv`.
- **13,942 of 19,314** files in `renamed_final` are `BurpClass####` placeholders, so "human-readable
  browsing" there is partly cosmetic. Symbol-level work belongs in `jdt_src`, whose filenames match
  `class_map.tsv` keys.
- **Name recovery is incomplete by construction.** The strongest signal is javac's synthetic
  `lambda$<enclosingMethod>$N` names surviving ZKM. A guessed name is worse than `Zxxx`, so the
  maps label every claim CONFIRMED / PROBABLE / UNKNOWN.
- **No UI string resource bundle.** Every operator-visible string is an inline Java literal, which
  is why layer 4 must be in the search path: `"false positive"` returns zero hits in layers 1–3 and
  45 in layer 4.
- **The tree is not compilable as-is** (`out/clean/compilable` is the attempt); "it doesn't compile"
  is not a defect in the decompile.
- **A namespace outside `jdt_src`:** `out/ai_agentic/burp/agentic/` (818 classes) and
  `out/theme/burp/theme/` (98) have their own trees, so grepping `jdt_src` alone reports the AI and
  theming surfaces as absent.

## 5. How the next pass should use this

1. Read `SOURCE-OF-TRUTH.md` first, then this file, then the companion for the area.
2. Before calling anything a gap: grep the Go/TS source, then the tracker (`bd list --all --json`).
   Each companion carries an explicit "already landed, do not re-file" list with evidence.
3. Cite build + layer: `Zuq.java:178-197` (2026.7.1, layer 4) or `Scope.java:28-55` (2026.7.1,
   layer 1). A citation without both is not evidence.
4. Treat a decline as a deliverable: `gaps.md` records the declines with their unblocking
   condition, and this pass added none that contradict them.
