/**
 * The listener filter (burpsy-react-ui-80tg).
 *
 * Burp's http-history/filter-settings.html:109-116 offers "Filter by listener - You can show items
 * received on a specific listener port. This can be useful when testing access controls." The
 * Listener port column rendered and could not be filtered, and a column that cannot be filtered
 * forces the operator to reconstruct the predicate as DSL.
 *
 * The parsing rule is extracted here because it is the part that can go quietly wrong: a
 * non-numeric segment coerced to 0 would match every row that came from a producer with no listener,
 * which is the exact opposite of what the operator typed and looks like the filter working.
 */
export function parseListenerPorts(raw: string): Set<number> {
 return new Set(
  raw
   .split(",")
   .map((v) => v.trim())
   .filter((v) => v !== "" && /^\d+$/.test(v))
   .map((v) => Number(v)),
 );
}
