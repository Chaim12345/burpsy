/**
 * Query hooks for the browsable issue-definition catalogue (Target › Issue definitions).
 *
 * Built on the same `useResource` the rest of the console uses. The keys live here rather than in
 * `data.ts`'s shared `keys` registry for the reason `attackKeys` does the same in `data.attack.ts`:
 * these resources are read by one area, and nothing in the event stream's INVALIDATION map needs to
 * reach them — the catalogue is embedded at build time and cannot change while the process runs.
 * A cache entry the server can never invalidate belongs next to its consumer.
 */
import { query } from "./api";
import { useResource } from "./data";
import type { Advisory, AdvisoryCatalogue } from "./types.advisory";

export const advisoryKeys = {
  /**
   * Keyed on both filters because the filtering happens server-side, so each combination is a
   * different response. The catalogue itself is static, so these entries stay warm for the session
   * and going back to a previous filter is instant.
   */
  catalogue: (q: string, severity: string) => ["advisories", q, severity] as const,
  definition: (typeIndex: string) => ["advisories", "definition", typeIndex] as const,
};

/**
 * The catalogue index, filtered server-side.
 *
 * Server-side rather than in the browser because the search covers the description, and the
 * description is the expensive half: filtering here would mean shipping all 183 definitions' prose to
 * run a `.includes()` over it. It also means the search runs over the same plain-text paragraphs the
 * reader renders, instead of over the raw HTML fragment where "p" and "href" are matchable words that
 * appear nowhere on screen.
 *
 * Callers pass a debounced term — this is one request per settled keystroke, not per keystroke.
 */
export const useAdvisories = (q: string, severity: string) =>
  useResource<AdvisoryCatalogue>(
    advisoryKeys.catalogue(q, severity),
    `/api/advisories${query({ q, severity: severity === "all" ? "" : severity })}`,
  );

/**
 * One definition in full.
 *
 * Disabled until a row is selected, so opening the screen fetches the index and nothing else. The
 * response is the same `Advisory` shape a finding carries, which is what lets one component render
 * both.
 */
export const useAdvisory = (typeIndex: string | null) =>
  useResource<Advisory>(
    advisoryKeys.definition(typeIndex ?? ""),
    `/api/advisories/${typeIndex ?? ""}`,
    typeIndex !== null && typeIndex !== "",
  );
