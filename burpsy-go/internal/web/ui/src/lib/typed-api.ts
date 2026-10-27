/**
 * The console's typed API client (burpsy-react-ui-pg5a): openapi-fetch over the generated
 * api-schema.d.ts, which openapi-typescript renders from the server's own OpenAPI document. Paths,
 * verbs, query parameters, request bodies, and declared response shapes are all checked by tsc;
 * `bun run check:api-types` fails if the schema is stale, so this client cannot drift from the server.
 *
 * Two honesty notes:
 *
 * - A route with no declared response type (x-burpsy-declared: false in the document) types its 200
 *   as unknown here, not as a guessed shape. The declared set grows in internal/web/route_schemas.go.
 * - Confirm-gated mutations mint through the same gatedFetch every console call uses: a mutating
 *   verb on a gated route mints a token bound to the exact call before anything is sent, and the
 *   operator-approval flow (`options.approve`) is available via typedApiWith. The confirmation
 *   preview and re-mint-on-drift rules are gatedFetch's, unchanged.
 */
import createClient from "openapi-fetch";
import type { paths } from "./api-schema";
import { type GatedOptions, gatedFetch } from "./api";

export type { operations, paths } from "./api-schema";

/**
 * Build a typed client. `options` is passed to gatedFetch, so a caller that wants the operator to
 * preview a gated call passes `approve` exactly as it would to api().
 */
// openapi-fetch builds a Request, which needs an absolute URL; the console is same-origin, so the
// base is the page's own origin (the invalid host is only a non-browser fallback, for tests).
const baseUrl = typeof location !== "undefined" ? location.origin : "http://console.invalid";

export function typedApiWith(options: GatedOptions = {}) {
 return createClient<paths>({
  baseUrl,
  fetch: async (request: Request) => {
   // openapi-fetch hands over a Request whose body is a stream; the confirmation mint binds to the
   // exact bytes, so the body is read back to text here — JSON request bodies are short by design.
   const body = request.body === null ? undefined : await request.text();
   return gatedFetch(request.url, { method: request.method, headers: request.headers, body }, options);
  },
 });
}

/** The shared client for calls with no operator-preview needs (reads, and mutations a click armed). */
export const typedApi = typedApiWith();
