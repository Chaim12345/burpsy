// The Intruder "Interactions" column (burpsy-react-ui-nib6): Burp's "Interactions - The number of
// interactions made with the Collaborator server". Each attempt of a Collaborator-payload attack
// names the addresses it sent (Attempt.collaborator_payloads), and the Collaborator interaction log
// attributes every callback to the minted address it carries (row.payload). Joining the two here
// means a callback that arrives minutes after the attack still lands on the row that provoked it.

import type { CollaboratorInteractionRow } from "./data.collab";
import type { Attempt } from "./types.tools";

/** True when any attempt carried a Collaborator address, i.e. the column means something. */
export function hasCollaboratorAttempts(attempts: readonly Attempt[]): boolean {
  return attempts.some((attempt) => (attempt.collaborator_payloads?.length ?? 0) > 0);
}

/**
 * Each attempt's interactions, by ordinal, one per observable event. A repeat of the same callback
 * (same protocol, query type and client — one lookup's fan-out, oob.Deduplicate's key) is collapsed
 * WITHIN the attempt. The log's own `collapsed` flag is not used: the server computes it across the
 * whole log, so the same resolver calling back for two different payloads would count for only the
 * first attempt. Address comparison ignores case; the server attributes case-insensitively too.
 */
export function interactionsByAttempt(
  attempts: readonly Attempt[],
  rows: readonly CollaboratorInteractionRow[],
): Map<number, CollaboratorInteractionRow[]> {
  const byAddress = new Map<string, CollaboratorInteractionRow[]>();
  for (const row of rows) {
    if (!row.payload) continue;
    const key = row.payload.toLowerCase();
    const list = byAddress.get(key);
    if (list) list.push(row);
    else byAddress.set(key, [row]);
  }
  const out = new Map<number, CollaboratorInteractionRow[]>();
  for (const attempt of attempts) {
    const addresses = attempt.collaborator_payloads;
    if (!addresses?.length) continue;
    const events = new Set<string>();
    const hits: CollaboratorInteractionRow[] = [];
    const ordered = [...new Set(addresses.map((address) => address.toLowerCase()))]
      .flatMap((address) => byAddress.get(address) ?? [])
      .sort((a, b) => a.at_ms - b.at_ms || a.id - b.id);
    for (const row of ordered) {
      const event = `${row.type}|${row.q_type ?? ""}|${row.client_ip}`;
      if (events.has(event)) continue;
      events.add(event);
      hits.push(row);
    }
    out.set(attempt.ordinal, hits);
  }
  return out;
}
