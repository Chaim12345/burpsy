# Design: the 0vzb.46 second-identity seam (integrator lane)

Status: design, 2026-10-25. Implementation AFTER the W1 wave-2 merge (the types live on W1's
branch; building against it now would collide with slices 2-3 in the same package).

## W1's pin (accepted)

scanner.SecondIdentity{CookieHeader, AuthorizationHeader, APIKeyHeader, APIKeyValue};
ScanConfig.SecondIdentity tagged json:"-" (excluded from persistence BY CONSTRUCTION, pinned by
TestSecondIdentityCredentialsNeverPersist); switches CheckIDORTwoIdentity / CheckBFLA /
CheckMassAssignment / CheckAPIWrites are plain persisted bools. Credentials enter only threaded
in memory at scan start.

## How the checks actually read it (verified on W1's branch at d86f1e3b)

idorProber reads idorSecondIdentity(cc.Config) — cc.Config is the check context's *ScanConfig,
populated in NewCheckContext from scanner.config, the scanner's GLOBAL config. Per-run values in
this engine already have a carrier precedent: runConfigFrom(ctx) / lightAuditFrom(ctx) —
newAuditRun puts run state on the context and newCheckContextForRun overrides cc fields from it.

## The seam

1. scanner package (post-merge, integrator): AuditConfig gains a Go-only
   `SecondIdentity *SecondIdentity` — no JSON tag, so no config document can carry it.
   newAuditRun stashes it on the run context (the runConfigFrom pattern); newCheckContextForRun,
   when present, swaps cc.Config for a COPY of the scanner-global snapshot with SecondIdentity
   set (and, per W1's semantics, nothing else changed). A copy, never the shared pointer: two
   concurrent runs carrying different B identities must not see each other's credentials, and a
   run must never mutate the global. Slices 2-3 (BFLA, mass assignment) read the same cc.Config
   path, so the one carrier serves all three techniques.
2. web (integrator): scannerAuditReq gains `second_identity` — a web-local struct with the four
   string fields and real json tags (scanner's own type is json:"-" by pin, so the request type
   cannot be reused; the mapping is field-by-field and explicit). Both single-exchange handlers
   and the audit-items path map it onto cfg.SecondIdentity. Empty second_identity (all fields
   blank) is a 400 — a credential carrying nothing is a config error, not an inert run. The
   switches stay where W1 put them: /api/scanner/config PUT + the saved-config library, no
   second-identity key accepted there (json:"-" already makes a planted key unmarshal to zero).
3. W2 (after the web seam lands): the Second Identity form on the scan launch dialog, posting
   second_identity with the start request. Fields: cookie header, authorization header, API key
   header + value. The form must make the in-memory-only lifetime visible ("held for this run,
   never saved") — the operator types credentials into it.

## Refused alternatives

- Setting SecondIdentity on the GLOBAL config around a run: leaks B's credentials into every
  concurrent run and into ConfigSnapshot reads; race-prone. Never.
- Accepting second_identity on /api/scanner/config PUT: that document round-trips through the
  saved-config library on disk; W1's pin exists precisely to keep credentials out of it.

## Gate

- scanner: carrier tests — a run carrying SecondIdentity dispatches checks with cc.Config
  showing it; a run without sees the zero value; two runs with different identities do not
  cross; the global snapshot is unchanged after a run. Negative controls per the repo bar.
- web: second_identity threads to the run (asserted via a declining check's recorded reason,
  or a stubbed scanner); empty second_identity 400; a {"SecondIdentity":...} key planted in a
  PUT body still unmarshals to zero (W1's pin test covers the type; the web test covers the
  route's own decode).
- ui: form posts the pinned shape; check + components green; dist rebuilt.
