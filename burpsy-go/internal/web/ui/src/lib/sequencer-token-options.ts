/**
 * Token-location picker options (6t8), parsed from a response the operator actually has —
 * usually the one that arrived with a Send to Sequencer hand-off. Burp's "Token location
 * within response" offers Cookie / Form field / Custom location as pickers over the response;
 * presenting what is actually present, for the operator to choose from, is still a declaration —
 * the operator picks. Nothing here auto-selects, so the declared-not-guessed disclosure on the
 * capture form stays true.
 *
 * Parsed, not regexed, so the names are exact: Set-Cookie pairs are split at the first
 * semicolon the way the server's cookie extractor reads them, header names keep their wire
 * case, and form fields are the value-bearing input/select/textarea controls.
 */

export interface TokenOption {
 /** The name the operator's location refers to — a cookie or header name, a form-field name. */
 name: string;
 /** A short value excerpt, so two same-named cookies are distinguishable on sight. */
 excerpt: string;
}

/** The first value bytes, enough to recognise the token — the capture pulls the whole value. */
function excerpt(value: string): string {
 const trimmed = value.trim();
 return trimmed.length > 24 ? trimmed.slice(0, 23) + "…" : trimmed;
}

/** Set-Cookie values, one per header; the name is the pair's left side. */
export function cookieOptions(response: string): TokenOption[] {
 const out = new Map<string, TokenOption>();
 for (const line of headerLines(response)) {
  if (!/^set-cookie:/i.test(line)) continue;
  const pair = line.slice(line.indexOf(":") + 1);
  const nameValue = pair.split(";")[0] ?? "";
  const eq = nameValue.indexOf("=");
  if (eq <= 0) continue;
  const name = nameValue.slice(0, eq).trim();
  const value = nameValue.slice(eq + 1).trim();
  if (!out.has(name.toLowerCase())) {
   out.set(name.toLowerCase(), { name, excerpt: excerpt(value) });
  }
 }
 return [...out.values()];
}

/** Every response header except Set-Cookie, which cookieOptions already covers. */
export function headerOptions(response: string): TokenOption[] {
 const out = new Map<string, TokenOption>();
 for (const line of headerLines(response)) {
  if (/^set-cookie:/i.test(line)) continue;
  const colon = line.indexOf(":");
  if (colon <= 0) continue;
  const name = line.slice(0, colon).trim();
  const value = line.slice(colon + 1).trim();
  if (!out.has(name.toLowerCase())) {
   out.set(name.toLowerCase(), { name, excerpt: excerpt(value) });
  }
 }
 return [...out.values()];
}

/** Value-bearing form controls, input/select/textarea — where anti-CSRF tokens travel. */
export function formFieldOptions(response: string): TokenOption[] {
 const out = new Map<string, TokenOption>();
 const body = response.split(/\r?\n\r?\n/, 2)[1] ?? "";
 const tag = /<(?:input|select|textarea)((?:[^>"']|"[^"]*"|'[^']*')*)>/gi;
 const attr = /name\s*=\s*("([^"]*)"|'([^']*)')/i;
 const valueAttr = /value\s*=\s*("([^"]*)"|'([^']*)')/i;
 for (const m of body.matchAll(tag)) {
  const attrs = m[1] ?? "";
  const nameMatch = attrs.match(attr);
  if (!nameMatch) continue;
  const name = (nameMatch[2] ?? nameMatch[3] ?? "").trim();
  if (!name) continue;
  const valueMatch = attrs.match(valueAttr);
  const value = valueMatch ? (valueMatch[2] ?? valueMatch[3] ?? "") : "";
  if (!out.has(name.toLowerCase())) {
   out.set(name.toLowerCase(), { name, excerpt: excerpt(value) });
  }
 }
 return [...out.values()];
}

/** The header block's lines: everything before the first blank line, tolerating bare-LF. */
function headerLines(response: string): string[] {
 const head = response.split(/\r?\n\r?\n/, 1)[0] ?? "";
 return head.split(/\r?\n/);
}
