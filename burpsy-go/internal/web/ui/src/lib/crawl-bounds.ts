/**
 * One optional crawl bound, as the console collects it and the server applies it.
 *
 * burpsy-react-ui-qzzy. This is the whole reason it exists as a named function rather than an
 * inline `Number(x) || undefined`:
 *
 *   - a BLANK field means "I did not choose", and is omitted from the request entirely so the
 *     engine's documented default applies;
 *   - a typed 0 means "none", and is sent as 0.
 *
 * Those are different requests, and `||` answers both with undefined — so asking for a crawl that
 * admits no locations at all started a 300-location crawl while the form showed a 0. The server
 * reads the difference off pointer-typed fields; this produces it.
 */

/** The wire field for one bound, given the raw text of its form field. */
export function crawlBound(key: string, raw: string): Record<string, number> {
  if (raw.trim() === "") return {};
  const n = Number(raw);
  // Non-numeric and negative values are omitted rather than sent. The server refuses a negative
  // bound with a 400 that names the field and says what a bound is, and pre-empting that with a
  // client-side guess about what the operator meant would replace a real error with a silent
  // default — the same confusion this module exists to remove, one layer up.
  if (!Number.isFinite(n) || n < 0) return {};
  return { [key]: n };
}
