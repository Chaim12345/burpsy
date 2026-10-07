/**
 * When a finding was found, as one compact cell (burpsy-react-ui-exiu).
 *
 * Exported separately because the formatting has one rule that matters more than the format: a
 * finding with no timestamp renders as an em dash, never as a date. Zero means the store has no time
 * for it, and `new Date(0)` is a perfectly good date — which is exactly the problem. A
 * plausible-looking 1 Jan 1970 in a column an operator sorts by is worse than an obvious gap,
 * because it is believed.
 *
 * Relative time rather than a date, because the question the column answers is "is this new?" — and
 * because an issue list spanning days is unreadable as absolute timestamps.
 */

/** A compact "3m ago" / "2h ago" / "Sep 4" — recent enough to read as recency, old enough to date. */
export function formatFoundAt(timestampUnixMs?: number): string {
 if (!timestampUnixMs) return "—";
 const at = new Date(timestampUnixMs);
 // A timestamp in the future is a clock skew or a bad write, not a finding from next week. Saying
 // "in 3m" would be a lie with a number attached.
 const ageMs = Date.now() - at.getTime();
 if (ageMs < 0) return at.toLocaleDateString();
 const minutes = Math.floor(ageMs / 60_000);
 if (minutes < 1) return "just now";
 if (minutes < 60) return `${minutes}m ago`;
 const hours = Math.floor(minutes / 60);
 if (hours < 24) return `${hours}h ago`;
 const days = Math.floor(hours / 24);
 if (days < 7) return `${days}d ago`;
 return at.toLocaleDateString();
}

/** The full timestamp, for the row's title attribute — the exact value behind the compact form. */
export function foundAtTitle(timestampUnixMs?: number): string | undefined {
 if (!timestampUnixMs) return undefined;
 return `First raised ${new Date(timestampUnixMs).toLocaleString()}`;
}
