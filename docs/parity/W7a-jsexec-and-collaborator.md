# W7a — closing NOT-DETERMINED items 10 and 7

Baseline: `51dea16` (worktree `tsk_FciAmg-`, path
`/root/burpsy-react-ui/.orchestry/workspaces/tsk_FciAmg-/burpsy-go`).

---

## Item 10 — jsexec wired-vs-unwired contradiction

**Original wording (§8.10):** "Whether wiring `jsexec`'s prototype-pollution check is
blocked by anything beyond scheduling. `infra_coverage.go:269-274` implies the browser
blocker it cites is already retired by `domexec`, which suggests it is not blocked — but
that was not verified end to end."

**CLOSED. Verdict: not a scheduling question — the table's attribution is simply wrong.
`jsexec` contributes nothing to the wired check; a different primitive (`domexec`) does
all the work, and `jsexec` is dead code.**

### Evidence

1. `internal/scanner/infra_coverage.go:273-281` — the `js-execution-tier` primitive row:
   ```go
   {
       Name: "js-execution-tier",
       File: "internal/jsexec/jsexec.go",
       // No stale phrase of its own: the prototype-pollution row's reason cites the
       // browser blocker, which the dom-execution-harness entry already retires. ...
       StaleReasonPhrases: nil,
       UnblockedIssues:    nil,
       WiredIssues:        []string{"Client-side prototype pollution"},
   }
   ```
   `WiredIssues` is documented at `infra_coverage.go:46-49` as: "rows this primitive's
   machinery now actually detects — they have a native evaluator and are no longer
   declined." So the table asserts that `internal/jsexec/jsexec.go` is the machinery
   behind the "Client-side prototype pollution" check being wired.

2. That assertion is false. `internal/scanner/checks_dom_extra.go:23-41` is the actual
   registered evaluator:
   ```go
   func checkClientSidePrototypePollution(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
       ...
       obs, err := observeDOM(ctx, cc, []domexec.SourceKind{...})
       ...
       hits := domexec.ObservationsForSink(obs, domexec.SinkPrototypePollution)
       ...
   }
   ```
   registered at `checks_dom_extra.go:148`:
   ```go
   nativeDescriptor("Client-side prototype pollution", DispatchScopePerUrl, domChecksEnabled, checkClientSidePrototypePollution),
   ```
   It imports and calls only `internal/domexec` (`checks_dom_extra.go:19`). It never
   imports or calls `internal/jsexec`.

3. `internal/jsexec` has **zero non-test callers anywhere in the module**:
   ```
   $ grep -rln '"github.com/burpsy-go/burpsy/internal/jsexec"' --include="*.go" .
   (no output)
   $ grep -rn "jsexec\." --include="*.go" . | grep -v _test.go | grep -v jsexec/jsexec.go
   internal/scanner/infra_coverage.go:274:  File: "internal/jsexec/jsexec.go"   # a string literal, not a call
   ```
   `jsexec.TestPrototypePollution` (`jsexec.go:153`) is invoked only from its own test
   file, `internal/jsexec/jsexec_test.go:40,57,86`. This matches and confirms W5's
   earlier headline count of "1 STATE2 package: jsexec."

4. The check itself **is** live and reachable, just not through jsexec: it is registered
   in the same `nativeDescriptor` table as every other DOM check, gated only by
   `domChecksEnabled` (`checks_dom.go:32`: `func domChecksEnabled(c *ScanConfig) bool {
   return c != nil && c.CheckDOM }`) — the identical, ordinary config gate every sibling
   DOM check uses, not a special blocker.

### What this means, precisely

- **"Client-side prototype pollution" is WIRED** (STATE 4) via `domexec` — confirmed, not
  merely inferred, by reading the registered evaluator and its dispatch gate.
- **`internal/jsexec` is UNWIRED** (STATE 2, dead code) — it is not "blocked by anything,"
  scheduled or otherwise; it is simply never called in production. There is no pending
  work item to "unblock" it, because nothing in the live check path depends on it.
- **The contradiction is in the ledger, not the product.** `infra_coverage.go` credits
  `jsexec.go` with wiring a check that `domexec` actually wires. The design intent
  documented at `checks_dom_extra.go:6-8` ("confirmed in two tiers (goja and a real
  browser)") describes a two-tier check that was never built that way — only the browser
  tier (`domexec`) exists in the registered evaluator. The goja tier (`jsexec`) was
  written, tested in isolation, and never connected.
- Practically: deleting `internal/jsexec` today would not regress any scanner behaviour —
  `go build ./...` would still produce a binary that detects "Client-side prototype
  pollution" exactly as it does now, because nothing calls it.
- Recommended fix for the ledger (not applied — out of scope for this verification task):
  either (a) wire `jsexec.TestPrototypePollution` as a genuine second tier inside
  `checkClientSidePrototypePollution`, matching the comment's stated intent, or (b) remove
  `File: "internal/jsexec/jsexec.go"` from the `js-execution-tier` row and attribute
  `WiredIssues: ["Client-side prototype pollution"]` to the `dom-execution-harness` row
  (`infra_coverage.go:233-237`) where the real evaluator lives, and mark `jsexec` as an
  explicit STATE 2 orphan in the coverage doc.

---

## Item 7 — Collaborator mint-payload fix

**Original wording (§8.7):** "The Collaborator mint-payload fix is recorded as verified in
a surviving summary, but the summary was truncated before its evidence. The claim stands
unproven here." (Source of the truncated claim: `R1-salvage.md:72`, "Collaborator's
mint-payload defect is verified fixed (summary truncated mid-sentence here; the claim is
recorded but its evidence is lost).")

**CLOSED. Verdict: the underlying claim is TRUE, but "fix" is the wrong word — there was
never a bug in mint *logic* to patch. The defect was reachability: the OOB provider that
mint payloads depend on had zero callers before commit `997f459`, so every mint request
would have failed end to end. That commit is the "fix," and it is the only commit that has
ever touched this file.**

### Evidence

1. `internal/web/api_collaborator.go` has exactly one commit in its history:
   ```
   $ git log --oneline --follow -- internal/web/api_collaborator.go
   997f459 collaborator: the out-of-band channel becomes a surface — /api/collaborator over internal/oob
   ```
   There is no later "fix" commit to this file — so any "fix" the summary meant must be
   `997f459` itself (creation = the fix), not a subsequent patch.

2. `997f459`'s own commit message and the file's header comment
   (`api_collaborator.go:1-10`) state the defect it closed directly:
   > "`internal/oob` drives ProjectDiscovery's `interactsh-client` as a real OOB channel,
   > and `internal/scanner/oob_channel.go` wraps it in an `OOBProvider`... Neither was
   > reachable: `NewLazyOOBProvider` had zero callers in the whole tree, so
   > `ActiveScanner.oob` was nil in every running burpsy, and every out-of-band row
   > refused with 'no collaborator channel is configured for this scan'... This file and
   > the `-collaborator-server` flag are the two halves of making it reachable."

3. Verified this wiring is real at HEAD, not just asserted in a comment:
   ```
   $ grep -n "NewLazyOOBProvider" -r . --include="*.go"
   cmd/burpsy/main.go:85:   # comment describing the prior zero-caller state
   cmd/burpsy/main.go:357:  oobProvider = scanner.NewLazyOOBProvider(oob.Options{...})
   internal/scanner/oob_channel.go:98: func NewLazyOOBProvider(opts oob.Options) OOBProvider {...}
   ```
   `NewLazyOOBProvider` now has exactly one production caller, `cmd/burpsy/main.go:357`,
   reached when the `-collaborator-server` flag (`main.go:97`) is set — matching the
   commit message's "two halves" claim.

4. The mint handler itself, `handleCollaboratorPayload`
   (`api_collaborator.go:501-551`), reads that same provider through
   `s.scanner.OOBRegistration()` / `s.scanner.OOBChannel(...)` and refuses cleanly (409)
   when unconfigured, or mints `marker + "." + channel.Domain()` when it is. This logic
   has not changed since `997f459` (single-commit history, point 1).

5. Frontend reachability, confirmed independently (not assumed from W3):
   - `internal/web/ui/src/lib/data.collab.ts:83-89` defines `useMintPayload`, a
     `useMutation` that POSTs to `/api/collaborator/payload`.
   - `internal/web/ui/src/pages/collaborator.tsx:39,70-77` calls `mint.mutate(...)` from
     a button disabled only by `!s.configured`, matching the backend's own state model
     (`collabNotConfigured`/`collabReady`/etc., `api_collaborator.go:57-67`).
   - `internal/web/route_manifest_test.go:164` asserts `/api/collaborator/payload` is in
     the route manifest and UI-referenced — this is a route-reachability test, not a
     behavioural one (it does not invoke the handler).

### Caveat — what remains genuinely unverified

There is **no Go test that behaviourally exercises `handleCollaboratorPayload`** — no
`internal/web/api_collaborator_test.go` exists at all (confirmed by `find . -iname
"*collaborator*test*"` returning nothing under `internal/web`). This is structurally
unsurprising: minting a real payload requires a live `interactsh-client` subprocess making
a public DNS registration, which is exactly the kind of external dependency this
project's test suite avoids elsewhere (see `oob_channel_test.go`'s `fakeChannel`, built
for the same reason). So:

- **Reachability is proven**: the provider is wired, the route is registered, the UI
  calls it, and the handler's refusal/success branches read consistently from the
  now-non-nil provider.
- **Full behavioural correctness under a live channel remains an ungated, manual-only
  claim** — consistent with `verified_ci_gates`'s standing finding that this repo's CI
  gates only `gofmt`/`build`/`vet`/`go test`, and there is no e2e run of Collaborator in
  CI. Anyone re-citing this item should say "wired and reachable, unit-untested by
  design," not "tested."

### Bottom line

The R1-salvage claim survives verification: there *was* a real defect (an unreachable OOB
provider, not a mint-logic bug), and it *is* fixed at `997f459`, which is the same and
only commit that created this surface — confirmed independently via `NewLazyOOBProvider`'s
caller graph and the frontend's mutation wiring, filling the evidence gap the truncated
summary left open.
