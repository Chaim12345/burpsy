/**
 * The tagged arms of a scope rule (burpsy-react-ui-c09): a host named by a regular expression or by
 * an IP range, and a path named by a regular expression, beside the wildcard host and literal path
 * prefix the table has always had.
 *
 * Burp states the same two arms — "Specify a regular expression to match each URL component" and
 * "Host or IP range" — as one field each whose content decides how it is read. burpsy carries them
 * the same way: the arm rides *inside* the pattern and path strings, prefixed with `regex:` or
 * `range:`. That is not a display convention, it is the wire and the stored form, because those two
 * strings are also the rule's identity on remove, toggle and edit (see core/scope.go's arm-tag
 * comment for why a parallel field would have to land in four places at once, and what a rule would
 * mean in the meantime).
 *
 * So the page needs exactly two operations — put an arm into a string, take it back out — and the
 * mode selector is the honest way to present a field that is read three ways. They live here rather
 * than in the page because they come in pairs that must agree: an encode the decode cannot read is a
 * rule the operator can create and never edit.
 *
 * # What the validation here is, and is not
 *
 * The server is the authority: core.NewScopeRuleFrom compiles the expression with Go's regexp (RE2)
 * and parses the range with net/netip, and the endpoint answers 400 with the reason. These checks
 * exist to catch the ordinary typo at the keystroke instead of after a round trip, and they are
 * deliberately *narrower* than the server's — a JavaScript RegExp is not RE2, so anything this
 * accepts may still be refused, and nothing this refuses would have been accepted. They never widen:
 * the page cannot talk the server into storing an arm it would not have stored.
 */

/** How a rule's host string is read. `wildcard` is the historical glob arm. */
export type HostArmMode = "wildcard" | "regex" | "range";

/** How a rule's path string is read. `prefix` is the historical literal-prefix arm. */
export type PathArmMode = "prefix" | "regex";

/** The tags, matching core.ScopeRegexArm and core.ScopeRangeArm exactly. */
export const REGEX_ARM_TAG = "regex:";
export const RANGE_ARM_TAG = "range:";

export interface HostArm {
 mode: HostArmMode;
 /** The arm's body: the glob, the expression or the range — never the tag. */
 value: string;
}

export interface PathArm {
 mode: PathArmMode;
 value: string;
}

/** Reads a stored host pattern into the mode and body a form can show. */
export function decodeHostArm(pattern: string): HostArm {
 if (pattern.startsWith(REGEX_ARM_TAG)) return { mode: "regex", value: pattern.slice(REGEX_ARM_TAG.length) };
 if (pattern.startsWith(RANGE_ARM_TAG)) return { mode: "range", value: pattern.slice(RANGE_ARM_TAG.length) };
 return { mode: "wildcard", value: pattern };
}

/** Writes a mode and body back into the single string the wire carries. */
export function encodeHostArm(mode: HostArmMode, value: string): string {
 const body = value.trim();
 if (mode === "regex") return REGEX_ARM_TAG + body;
 if (mode === "range") return RANGE_ARM_TAG + body;
 return body;
}

/** Reads a stored path arm. A rule with no path arm (null) decodes as an empty prefix. */
export function decodePathArm(path: string | null | undefined): PathArm {
 if (!path) return { mode: "prefix", value: "" };
 if (path.startsWith(REGEX_ARM_TAG)) return { mode: "regex", value: path.slice(REGEX_ARM_TAG.length) };
 return { mode: "prefix", value: path };
}

/** Writes a path arm back. An empty body is no path arm at all, which is what "the whole host" is. */
export function encodePathArm(mode: PathArmMode, value: string): string {
 const body = value.trim();
 if (body === "") return "";
 return mode === "regex" ? REGEX_ARM_TAG + body : body;
}

/** Whether a regular expression compiles at all. RegExp, not RE2 — see this file's header. */
function expressionProblem(what: string, body: string): string | null {
 if (body.trim() === "") {
  return `A ${what} regular expression cannot be blank. Blank means "match anything", and a rule that matches anything is not a rule — leave the field's mode on its literal setting instead.`;
 }
 try {
  new RegExp(body);
 } catch (problem) {
  return `That ${what} regular expression does not compile: ${problem instanceof Error ? problem.message : String(problem)}`;
 }
 return null;
}

/**
 * Whether an IP range reads as one. Dotted-quad CIDR and bare IPv4 are checked properly, including
 * the host bits the server refuses; anything with a colon is IPv6 and is left to the server, which
 * has a parser and this file would only have half of one.
 */
function rangeProblem(body: string): string | null {
 const trimmed = body.trim();
 if (trimmed === "") return "An IP range cannot be blank. Write a CIDR block such as 10.0.0.0/8, or a single address.";
 if (trimmed.includes(":")) return null;
 const [address = "", width, ...rest] = trimmed.split("/");
 if (rest.length > 0) return `"${trimmed}" has more than one /; a range is an address, optionally followed by one prefix length.`;
 const octets = address.split(".");
 if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
  return `"${address}" is not an IPv4 address.`;
 }
 if (width === undefined) return null;
 if (!/^\d{1,2}$/.test(width) || Number(width) > 32) return `"/${width}" is not a prefix length between 0 and 32.`;
 const bits = Number(width);
 const value = octets.reduce((sum, part) => sum * 256 + Number(part), 0);
 // Host bits set means the operator wrote either a network or one address and the two readings are
 // orders of magnitude apart, so the server refuses rather than masking. Say which two they meant.
 const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
 if ((value & mask) >>> 0 !== value) {
  const masked = (value & mask) >>> 0;
  const network = [masked >>> 24, (masked >>> 16) & 255, (masked >>> 8) & 255, masked & 255].join(".");
  return `"${trimmed}" has host bits set: write ${network}/${bits} for the network, or ${address} for that one address.`;
 }
 return null;
}

/**
 * Why this host arm cannot be sent, or null when it can.
 *
 * Every mode refuses a body that itself begins with a tag, because that is the one way the page could
 * send an arm the operator did not choose. Wildcard is the obvious case — typing `regex:^a$` into the
 * host field while the mode says Wildcard would store a regex rule from a form that showed a glob —
 * and the tagged modes are the same mistake one step subtler: `regex:^api\.example\.com$` pasted from
 * the table (which shows the tag) into a field whose mode is already Regular expression becomes
 * `regex:regex:^api\.example\.com$`, a pattern that *does* compile — `regex:` is a valid prefix to
 * match literally — so the rule saves, renders as armed, and can never match a real host. The
 * comparison happens on the trimmed body, so leading whitespace does not smuggle one past.
 */
export function hostArmProblem(mode: HostArmMode, value: string): string | null {
 const body = value.trim();
 if (mode === "wildcard") {
  if (body === "") return "A host pattern is required.";
  if (body.startsWith(REGEX_ARM_TAG)) return `"${REGEX_ARM_TAG}" is how a rule says its host is a regular expression. Choose the Regular expression mode instead of typing the prefix.`;
  if (body.startsWith(RANGE_ARM_TAG)) return `"${RANGE_ARM_TAG}" is how a rule says its host is an IP range. Choose the IP range mode instead of typing the prefix.`;
  return null;
 }
 if (mode === "regex") {
  if (body.startsWith(REGEX_ARM_TAG)) {
   return `The expression starts with "${REGEX_ARM_TAG}", which this mode adds itself — the table shows it because that is what gets stored. Write the expression without it (${body.slice(REGEX_ARM_TAG.length)}), or switch the mode to Wildcard if this really is a host that begins with those characters.`;
  }
  return expressionProblem("host", body);
 }
 if (body.startsWith(RANGE_ARM_TAG)) {
  return `The range starts with "${RANGE_ARM_TAG}", which this mode adds itself — the table shows it because that is what gets stored. Write the block without it (${body.slice(RANGE_ARM_TAG.length)}).`;
 }
 return rangeProblem(body);
}

/** Why this path arm cannot be sent, or null when it can. An empty prefix is "the whole host". */
export function pathArmProblem(mode: PathArmMode, value: string): string | null {
 const body = value.trim();
 if (mode === "prefix") {
  if (body === "") return null;
  if (body.startsWith(REGEX_ARM_TAG)) return `"${REGEX_ARM_TAG}" is how a rule says its path is a regular expression. Choose the Regular expression mode instead of typing the prefix.`;
  if (!body.startsWith("/")) return "A path prefix must start with /, so it can match a request path.";
  return null;
 }
 if (body === "") return null;
 // Same trap as the host side: a pasted `regex:/v1/.*` under a mode that adds the tag would store
 // `regex:regex:/v1/.*`, which compiles and matches nothing a request path can look like.
 if (body.startsWith(REGEX_ARM_TAG)) {
  return `The expression starts with "${REGEX_ARM_TAG}", which this mode adds itself — the table shows it because that is what gets stored. Write the expression without it (${body.slice(REGEX_ARM_TAG.length)}), or switch the mode to Prefix if the path really begins with those characters.`;
 }
 return expressionProblem("path", body);
}

/** How an arm is labelled in the rules table: the mode, so a regex rule cannot be read as a glob. */
export function hostArmLabel(mode: HostArmMode): string {
 return mode === "regex" ? "regex" : mode === "range" ? "IP range" : "wildcard";
}
