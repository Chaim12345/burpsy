# Mutation testing

The wave rule (2026-10-25): no bead closes on green tests alone if a mutation pass was offered
and not run. Accepted survivors are documented with the reasoning (redundant defences,
byte-equivalent implementation detail, etc.) - see capped-run.sh m3 and W6's slice-alias
survivor for the shape of a good acceptance.

## Gotchas
- Python: stale .pyc caches fake results on same-second same-size rewrites. Mutate with
  PYTHONDONTWRITEBYTECODE=1 (W5, 2026-10-25, parity.py).
- Bash: INT cannot be trapped in background jobs; an INT-vs-TERM mutant can be masked by KILL
  escalation (W5, capped-run.sh m7 - killed via a HUP test instead).
- Verify production files pristine after every mutant (W6's pass did this per-mutant).
