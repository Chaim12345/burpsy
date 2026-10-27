# Scanner switch wiring: descriptor + BOTH dispatch gates

Found by W1 during 0vzb.46 slice 2 (2026-10-25): `brokenAccessControlWithAuthLogic` and
`withSessionManagement` call their inner wrapper chain only under a UNION of downstream
switches. A switch admitted by the descriptor predicate but missing from either gate
no-ops silently - a CheckBFLA-only audit skipped every BAC check while reporting as
admitted. Both gates now include bflaEnabled.

RULE: any new switch riding the BAC descriptor must be added in three places or it
silently no-ops:
1. the descriptor predicate (admission),
2. `brokenAccessControlWithAuthLogic`'s union gate,
3. `withSessionManagement`'s union gate.
