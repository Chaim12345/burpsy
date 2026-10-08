# Risk Assessment

## S.U.P.E.R Architecture Health Summary

| Principle | Status | Key Finding |
|:----------|:-------|:------------|
| S Single Purpose | 🟡 | Some UI pages bundle multiple concerns |
| U Unidirectional | 🟢 | Clean server → JSON → React flow |
| P Ports | 🟡 | Some wire shapes undocumented |
| E Env-Agnostic | 🟢 | No hardcoded env assumptions |
| R Replaceable | 🟡 | Session + web modules have mild coupling |

**Overall**: Core sound; violations at UI-shell edges. Priority P (wire shapes) and S (split multi-concern pages).

## Top Risks

| Risk | Impact | Mitigation |
|:-----|:-------|:-----------|
| Scope auth bug (cj7x) | High | Fix first Phase 1 |
| 15 sequencer tests missing | Medium | Phase 3 |
| 39 UI shell gaps | Medium | Phase 6 |
| Test coverage gaps | Medium | Tests-by-default rule |
| Beads close_reason missing commit hash | Low | Require commit in every closure |

## Testing Risks
- Go tests exist but some new features lack coverage
- React tests only in ui/src/lib/, not per-page
- Mitigation: every task adds Go *_test.go and/or React *.test.ts

## Governance Risks
- .beads/issues.jsonl canonical but close_reason lacks machine-readable commits on prior closures
- Mitigation: this run requires commit hash in every close_reason
