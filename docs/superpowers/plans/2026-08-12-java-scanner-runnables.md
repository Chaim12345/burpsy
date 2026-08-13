# Java Scanner Runnables Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the behavior of Burp Java's 65 concrete scanner-check implementations into BurpSy's Go scanner without confusing catalog metadata or parsed BChecks with executable coverage.

**Architecture:** Use a data-driven Go check registry keyed by Java-derived `TypeIndex` values. Keep transport, insertion-point expansion, phase dispatch, finding enrichment, deduplication, and persistence separate from individual check evaluators. Port behavior from observable Java evidence and differential fixtures; do not copy proprietary Java source or preserve obfuscated class boundaries.

**Tech Stack:** Go 1.25, existing `internal/scanner`, `internal/bcheck`, `internal/core`, `internal/sender`, SQLite/segment persistence, React/HTTP API reporting.

## Global Constraints

- Preserve BurpSy's honest-counting rule: catalog entries, parsed BChecks, runnable checks, executed checks, skipped checks, declined checks, and unsupported checks are separate counts.
- Every check must declare its `TypeIndex`, phase, dispatch scope, required insertion-point kinds, prerequisites, and finding shape.
- Unsupported behavior must return an explicit unsupported/declined outcome; it must never appear as a clean scan.
- Keep raw request/response storage offset-based and bounded; do not materialize duplicate message bodies for every insertion point.
- Do not port obfuscated class names or decompiled control-flow artifacts; port externally observable behavior only.
- Every implementation slice needs focused tests before integration into the full registry.
- Existing BCheck parsing and conformance must remain green.

---

## Baseline and Target Counts

Current measured state:

- Java: 67 scanner-interface classes found; 2 are abstract bases; **65 concrete implementations**.
- Java issue catalog: **183 issue types**.
- BurpSy native Go registry: 7 entries; **5 executable runners**, 2 unsupported (`SSRF`, `XXE`).
- BurpSy BCheck corpus: **264 parsed files**, which are separate scripted checks and not substitutes for the native Java check implementations.

Target state:

- 183 issue types mapped to an executable evaluator, a BCheck-backed evaluator, an extension/tool evaluator, or an explicit declined implementation.
- 65 Java implementation families represented by registry entries and behavior fixtures. One evaluator may cover multiple TypeIndex values only when the mapping and output differences are explicit and tested.
- Coverage report distinguishes native implementation coverage from BCheck corpus coverage.

---

## File Map

### Create

- `burpsy-go/internal/scanner/check_registry.go` — typed registry and implementation status for all 183 TypeIndex values.
- `burpsy-go/internal/scanner/check_contract.go` — evaluator input/output contracts, phase/scope declarations, and prerequisite types.
- `burpsy-go/internal/scanner/check_coverage.go` — coverage accounting and machine-readable report generation.
- `burpsy-go/internal/scanner/fixtures/` — request/response fixtures grouped by check family and phase.
- `burpsy-go/internal/scanner/*_parity_test.go` — differential behavior tests for each ported family.
- `burpsy-go/internal/scanner/tools/generate_registry.go` or the existing generator location — validates the complete TypeIndex registry.
- `burpsy-go/docs/SCANNER-COVERAGE.md` — current native/BCheck/declined coverage report and update procedure.

### Modify

- `burpsy-go/internal/scanner/audit_engine.go` — replace the five-runner table with registry-driven dispatch while preserving the existing admission/ledger engine.
- `burpsy-go/internal/scanner/audit.go` — add phase and scope support required by registry entries, including stored/second-order contexts.
- `burpsy-go/internal/scanner/catalog.go` and `catalog_data.go` — expose strict TypeIndex lookup and validate registry/catalog parity.
- `burpsy-go/internal/scanner/finding.go` and enrichment code — preserve Java-equivalent severity, confidence, evidence, remediation, CWE/CAPEC, and issue detail fields.
- `burpsy-go/internal/bcheck/insertion.go` — add the insertion families required by registry entries.
- `burpsy-go/internal/core/store.go` and `persist/` — expose bounded stored-exchange lookup and resumable audit state.
- `burpsy-go/internal/scanner/passive.go` — connect passive evaluators and coverage counters to the common registry.
- `burpsy-go/internal/web/api_scanner_coverage.go` — expose native, BCheck, executed, skipped, declined, and unsupported counts.
- `burpsy-go/internal/web/ui/src/pages/scanner.tsx` and scanner components — render per-check status and reasons rather than only aggregate issue counts.
- `burpsy-go/burpsy-go` CLI/report wiring — print the same coverage categories in non-UI runs.

### Java evidence inputs

- `/root/burp-re/SCANNER_CRAWLER_DEEPDIVE.md`
- `/root/burp-re/SCAN_ENGINE.md`
- `/root/burp-re/UI_FILES_MAP.md`
- `/root/burp-re/out/clean/root/`
- `/root/burp-re/out/strings/map_root.tsv`

---

## Task 1: Freeze the Java Runnable Inventory

**Files:**
- Create: `burpsy-go/internal/scanner/tools/java_check_inventory.json`
- Create: `burpsy-go/internal/scanner/tools/inventory_java_checks.py` (or use the repository's existing analysis-tool convention)
- Test: `burpsy-go/internal/scanner/tools/inventory_java_checks_test.*` if the tool has tests

**Interfaces:**
- Produces one row per concrete Java implementation: source class, interface (`Zi28`, `Zuit`, or `Zrm7`), inferred check family, Java issue type(s), phase, dispatch scope, and evidence references.
- Produces the baseline count assertion: 37 concrete `Zi28` + 27 concrete `Zuit` + 1 concrete `Zrm7` = 65.

- [ ] Enumerate Java classes by interface and exclude the two abstract `Zi28` bases.
- [ ] Resolve each concrete class to issue-type and lambda/method evidence using `all_renames.tsv`, `SCAN_ENGINE.md`, and string literals.
- [ ] Mark uncertain mappings as `needs_fixture`, not as implemented.
- [ ] Check the inventory into the repository so later changes are reviewable.
- [ ] Add a test that fails if the concrete count changes without an inventory update.

**Verification:**

```bash
cd burpsy-go
python3 internal/scanner/tools/inventory_java_checks.py --verify
```

Expected: 65 concrete implementations and no class mapped to two incompatible families.

---

## Task 2: Define the Go Evaluator Contract and Registry

**Files:**
- Create: `internal/scanner/check_contract.go`
- Create: `internal/scanner/check_registry.go`
- Modify: `internal/scanner/catalog.go`
- Test: `internal/scanner/check_registry_test.go`

**Interfaces:**

```go
type CheckPhase uint8
const (
    PhasePassive CheckPhase = iota
    PhaseLightActive
    PhaseActive
    PhaseStored
    PhaseCollaborator
    PhaseJavascript
)

type CheckDescriptor struct {
    TypeIndex       uint32
    Name            string
    Implementation string // native, bcheck, tool, declined
    Phase           CheckPhase
    Scope           DispatchScope
    InsertionKinds  []bcheck.InsertionKind
    Run             CheckRunner
    DeclineReason   string
}

type CheckRunner func(context.Context, *CheckContext) ([]*Finding, error)
```

- [ ] Keep `CheckDescriptor` independent of `activeCheck` so registry validation can run without a live scanner.
- [ ] Require exactly one descriptor for every catalog `TypeIndex`.
- [ ] Reject a descriptor that has both a runner and a decline reason.
- [ ] Reject a descriptor with no runner and no explicit decline reason.
- [ ] Adapt valid descriptors into existing `activeCheck` entries at run snapshot time.
- [ ] Preserve existing ledger identity and dispatch semantics while adding phase metadata.

**Verification:**

```bash
go test ./internal/scanner -run 'TestCheckRegistry|TestCatalogRegistryParity' -count=1
```

Expected: current catalog rows cannot be mistaken for runnable rows; missing/duplicate registry entries fail.

---

## Task 3: Port Shared Scanner Primitives Before Individual Checks

**Files:**
- Modify: `internal/bcheck/insertion.go`
- Modify: `internal/core/store.go`
- Modify: `internal/scanner/audit.go`
- Create: `internal/scanner/probes.go`
- Test: `internal/bcheck/insertion_parity_test.go`, `internal/scanner/probes_test.go`

- [ ] Implement URL filename and folder insertion points.
- [ ] Implement parameter-name, whole-body, synthetic-header, and body/query relocation points.
- [ ] Implement bounded nested JSON/base64/XML point expansion with correct re-encoding.
- [ ] Add stored-exchange lookup by stable message ID without copying raw bytes.
- [ ] Add a `CheckContext` that supplies original exchange, optional stored exchange, insertion point, sender, scan config, and finding builder.
- [ ] Make probe construction correct for URL encoding, JSON escaping, header values, multipart refusal, and Content-Length.
- [ ] Add per-probe request budgets and cancellation propagation.

**Verification:**

```bash
go test ./internal/bcheck ./internal/core ./internal/scanner -run 'Insertion|Probe|Stored' -count=1
```

Expected: fixtures cover every insertion family needed by at least one Java inventory row.

---

## Task 4: Port High-Confidence Native Check Families

**Files:**
- Create: `internal/scanner/checks_injection.go`
- Create: `internal/scanner/checks_reflection.go`
- Create: `internal/scanner/checks_auth.go`
- Modify: existing `sql*.go`, `jwt_weak.go`, `dom*.go`, and `js_vulns.go` only where behavior is extended
- Test: matching `*_parity_test.go` files

Port in this order:

1. SQL injection and parser-discrepancy variants.
2. Reflected/stored XSS and HTML/DOM reflection variants.
3. Path traversal and URL/path normalization variants.
4. JWT weak-secret and weak-signature variants.
5. Header/cookie/session security checks.
6. File upload and content-type confusion checks.
7. Cache deception and URL parsing/mapping discrepancy checks.

For each family:

- [ ] Write a fixture containing the baseline request, probe payloads, expected response signal, issue TypeIndex, and finding detail.
- [ ] Port the smallest evaluator that reproduces the observed Java behavior; do not reproduce obfuscated helper structure.
- [ ] Add negative fixtures that differ only in the required signal.
- [ ] Add scope/phase tests proving the check runs at the declared unit and does not run again at a broader/narrower unit.
- [ ] Add dedup tests where Java uses special handling, especially JWT secret-value merging.
- [ ] Register every resulting TypeIndex with its exact metadata.

**Verification:**

```bash
go test ./internal/scanner -run 'Test.*Parity|Test.*Injection|Test.*Reflection|Test.*JWT|Test.*Traversal|Test.*Cache' -count=1
```

Expected: every completed family has positive, negative, scope, cancellation, and finding-shape coverage.

---

## Task 5: Add Stored, JavaScript, Collaborator, and Tool-Dependent Runnables

**Files:**
- Modify: `internal/scanner/audit.go`, `audit_engine.go`
- Create: `internal/scanner/checks_stored.go`
- Create: `internal/scanner/checks_javascript.go`
- Modify: existing tool-runner and collaborator integration files
- Test: `stored_parity_test.go`, `javascript_parity_test.go`, `oob_parity_test.go`, `tool_parity_test.go`

- [ ] Make A4 stored-per-insertion-point dispatch reachable with original + stored exchange context.
- [ ] Implement S2/S3 result handling and explicit OOB prerequisite outcomes.
- [ ] Add browser/CDP-backed or static JavaScript analysis according to the selected architecture; browser-dependent checks must expose bounded worker limits.
- [ ] Port external-tool checks through the existing allowlist runner and count unavailable tools as unsupported.
- [ ] Preserve finding provenance: source exchange, stored exchange, browser event, or tool output.
- [ ] Ensure no Collaborator/OOB-dependent check is reported as clean when no interaction server is configured.

**Verification:**

```bash
go test ./internal/scanner -run 'Test.*Stored|Test.*Javascript|Test.*Collaborator|Test.*Tool' -count=1
```

Expected: unavailable prerequisites produce explicit skipped/unsupported outcomes and never clean results.

---

## Task 6: Complete Registry Mapping for All 183 Issue Types

**Files:**
- Modify: `internal/scanner/check_registry.go`
- Create: `internal/scanner/check_registry_generated.go`
- Test: `internal/scanner/check_registry_test.go`
- Modify: `internal/scanner/tools/java_check_inventory.json`

- [ ] Map every TypeIndex to native, BCheck, tool, or declined status.
- [ ] For one evaluator serving multiple issue types, include a tested output discriminator for each TypeIndex.
- [ ] Map special Java exemptions: cross-domain POST, serialized object, JWT weak secret, input retrieval reflected, and stored XSS phases.
- [ ] Map all seven Java dispatch scopes and all applicable phases.
- [ ] Require a decline reason for Java behaviors not supported by the chosen Go architecture.
- [ ] Generate the registry from checked-in catalog/inventory data to prevent hand-edited omissions.
- [ ] Fail CI when catalog count, registry count, or inventory count changes unexpectedly.

**Verification:**

```bash
go test ./internal/scanner -run 'TestRegistryHasEveryCatalogType|TestNoDuplicateTypeIndex|TestJavaInventoryMapping' -count=1
```

Expected: 183 catalog rows, 183 registry rows, and zero silent metadata-only rows.

---

## Task 7: Build Differential Fixtures and Coverage Accounting

**Files:**
- Create: `internal/scanner/check_coverage.go`
- Create: `internal/scanner/coverage_report_test.go`
- Create: `internal/scanner/fixtures/manifest.json`
- Modify: `internal/web/api_scanner_coverage.go`
- Modify: `internal/web/ui/src/pages/scanner.tsx`
- Create: `docs/SCANNER-COVERAGE.md`

Coverage categories:

```text
catalogued
native_implemented
bcheck_implemented
tool_dependent
executed
passed_without_finding
finding_produced
skipped_with_reason
unsupported
explicitly_declined
metadata_only
```

- [ ] Emit one row per TypeIndex with implementation, phase, scope, fixture IDs, and latest outcome.
- [ ] Track coverage by request family: host, path, request, response, insertion point, stored, JavaScript, and tool-dependent.
- [ ] Track lifecycle outcomes separately from finding outcomes.
- [ ] Add fixtures for every supported phase/scope and every insertion family.
- [ ] Add regression fixtures for the 65 Java concrete implementation families, grouping only where behavior is proven equivalent.
- [ ] Expose JSON and human-readable reports through CLI and `/api/scanner/coverage`.
- [ ] Render unsupported/declined/skipped counts in React without inflating pass percentages.

**Verification:**

```bash
go test ./internal/scanner ./internal/web -run 'Test.*Coverage|Test.*Fixture' -count=1
go run ./cmd/conform /root/.cache/BChecks
```

Expected: 264/264 BChecks still parse; scanner coverage report names every unsupported or unexecuted TypeIndex.

---

## Task 8: Integrate Scanner Phases, Lifecycle, Deduplication, and Task Controls

**Files:**
- Modify: `internal/scanner/audit.go`, `audit_engine.go`
- Modify: `internal/scanner/dedup.go` or create it if absent
- Modify: `internal/dash/tasks.go`
- Modify: `internal/web/api_scanner.go`, `api_scanner_coverage.go`
- Modify: React scanner/dashboard pages
- Test: scanner integration and API tests

- [ ] Add 15 audit-item lifecycle states and stable persistence indices.
- [ ] Add follow-up passes and task count/percentage pause thresholds.
- [ ] Add typed deduplication before persistence, including JWT secret-value identity and CRC signatures.
- [ ] Add named task kinds and crawl/audit progress normalization.
- [ ] Ensure cancellation, resume, partial failure, and unsupported checks remain visible in API/UI state.
- [ ] Verify stored and JavaScript phases do not bypass scope or task budgets.

**Verification:**

```bash
QUICK=1 ./verify.sh
go test ./internal/scanner ./internal/web ./internal/dash -count=1
```

Expected: zero warnings, all existing tests pass, and scanner task state remains honest under partial coverage.

---

## Task 9: Full Gate and Release Evidence

**Files:**
- Modify: `burpsy-go/docs/SCANNER-COVERAGE.md`
- Modify: `burpsy-go/ROADMAP.md` or the active planning artifact

- [ ] Run `gofmt -l .` and require empty output.
- [ ] Run `go build ./...` with zero warnings/errors.
- [ ] Run `go vet ./...`.
- [ ] Run `go test ./...`.
- [ ] Run `QUICK=1 ./verify.sh`.
- [ ] Run the full `./verify.sh` including scanner/crawler E2E suites.
- [ ] Archive the generated coverage report with the release/CI artifact.
- [ ] Update issue #29 with native implementation count, TypeIndex coverage, executed fixture count, and explicit decline list.

Expected release evidence:

- Native Java-family coverage is reported separately from BCheck coverage.
- Every TypeIndex has a non-silent status.
- No unsupported check is counted as passed.
- Existing proxy, crawler, BCheck, and UI behavior remains green.

---

## Execution Order and Dependencies

```text
Task 1 inventory
   ↓
Task 2 registry contract
   ↓
Task 3 shared primitives
   ↓
Task 4 native check families ─────┐
Task 5 stored/JS/OOB/tool checks ─┤
                                  ↓
                         Task 6 complete TypeIndex mapping
                                  ↓
                         Task 7 coverage harness
                                  ↓
                         Task 8 integration/state/task controls
                                  ↓
                         Task 9 full verification
```

Tasks 4 and 5 can run in parallel only after Task 3 defines the shared `CheckContext` and probe contract. Task 6 must wait for both family ports because it is the completeness gate. Task 7 can begin with fixture scaffolding after Task 2 but its final gate waits for Task 6. Task 8 must wait for the registry and coverage shape so lifecycle state cannot hide missing implementations.

## Definition of Done

- 65 concrete Java scanner implementation families have a reviewed mapping.
- All 183 catalog TypeIndex values have executable, BCheck/tool-backed, or explicit declined status.
- Native Go check count is no longer a hard-coded five-entry table.
- Stored/second-order, insertion-point, JavaScript, deduplication, lifecycle, and task-progress semantics are represented or explicitly declined.
- Coverage reports distinguish catalog, implementation, execution, skip, unsupported, decline, and finding outcomes.
- Full `verify.sh` passes with zero warnings and no hidden scanner skips.
