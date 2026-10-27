# Swarm wiki

Integrator-owned tribal knowledge for the bead swarm on backlog-b9. Workers read-only.
History, not the present: every claim is dated and, where it concerns code, cites the commit
it was true at. New facts supersede old ones by addition, never by rewrite.

## Environment
- [sandbox.md](sandbox.md) - what the agent sandboxes can and cannot do, and what breaks on rebuild

## Method
- [gates.md](gates.md) - the wave gate: what runs where, what is excluded and why
- [mutation-testing.md](mutation-testing.md) - the mutation bar and its gotchas

## Decisions
- Rulings live in the bead close_reasons and the commit history of .beads/issues.jsonl; this wiki
  does not duplicate them. Cross-cutting rulings that no single bead owns get a page here.
- Switch wiring: a new BAC-descriptor switch must be added to the descriptor predicate AND both dispatch gates or it silently no-ops - see switch-wiring.md (W1 discovery, 0vzb.46 slice 2, 2026-10-25).
