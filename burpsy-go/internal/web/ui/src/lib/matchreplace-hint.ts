import type { MatchReplaceCategory, MatchReplaceTarget } from "./types.policy";

/**
 * The placeholder for a match & replace rule's Match field.
 *
 * A blank match has a meaning on exactly two targets — a request or response header rule adds its
 * replacement as a new header line (Burp's documented behaviour, internal/matchreplace
 * checkEmptyMatch). Every other target refuses a blank match at save time, so advertising "empty =
 * add this header" there invited the operator to write a rule the server then rejects
 * (burpsy-react-ui-p5zu).
 */
export function matchPlaceholder(target: MatchReplaceTarget, category: MatchReplaceCategory): string {
  if (target === "request_header" || target === "response_header") return "empty = add this header";
  return category === "regex" ? "regex to match" : "text to match";
}
