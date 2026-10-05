/**
 * The session-rule editor's pre-request script action (burpsy-react-ui-ydmj): the reference shown
 * beside the editor, and reading which action a save refusal names.
 */

/**
 * What a run_script action's script can see and call — internal/session's sandbox, stated where the
 * operator types. Kept as data so the card renders a list rather than a paragraph to parse.
 */
export const SCRIPT_REFERENCE: readonly { name: string; detail: string }[] = [
 { name: "request", detail: "{ method, url, headers (object), body } — the request as the actions before this one left it. Mutable: what you assign is what is sent." },
 { name: "response", detail: "{ status, headers, body } — the last response this rule observed. Read-only, and null before the first one." },
 { name: "store.get(k) / store.set(k, v) / store.delete(k)", detail: "Per-rule values kept across requests — where a captured token lives." },
 { name: "log(...)", detail: "Writes a line to the session trace." },
 {
  name: "burpsy.*",
  detail: "hmacSha256Hex(key, msg), hmacSha256Base64(key, msg), sha256Hex(s), base64Encode(s), base64UrlEncode(s), base64Decode(s), randomHex(n).",
 },
];

export const SCRIPT_LIMITS =
 "Strict mode, no network and no filesystem, 500 ms per run. A script that throws (or runs out of time) leaves the request unchanged, and the session trace says why.";

/**
 * The action a ValidateActions refusal names, e.g. "action 2" or "action 1 → else 2", or "" when the
 * message names none. The server's path is the editor's own numbering (1-based, then/else branches),
 * so the card whose path equals it is the one the refusal belongs to.
 */
export function refusedActionPath(message: string): string {
 const match = /(action \d+(?: → (?:then|else) \d+)*) \(/.exec(message);
 return match?.[1] ?? "";
}

/** The path a card is at, in the server's numbering. */
export function actionPath(parent: string, index: number, branch?: "then" | "else"): string {
 return parent === "" ? `action ${index + 1}` : `${parent} → ${branch ?? "then"} ${index + 1}`;
}
