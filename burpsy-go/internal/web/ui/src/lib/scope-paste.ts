/**
 * Paste URL and Load from file for the scope table (dao): many entries, one box.
 *
 * Burp offers both, side by side, on every scope-entry surface — "Add a new item by
 * pasting a URL", "Paste URL", "Load ..." (map_root.tsv class burp.Zry2,
 * configPanelTargetScope; the same pair appears in burp.Zh5w, burp.Zrda and burp.Zhw_).
 * The value is the decomposition: a URL becomes the arms the Add form already has, so
 * scoping a 40-host engagement stops being 40 manual host/port/path/scheme entries.
 *
 * Both halves live here because both halves are the same decision. "Load from file"
 * fills the same box this parses, so there is no second format to invent (which is the
 * question the issue parked) — the file format *is* one entry per line.
 *
 * One entry per line, and a line is either a URL (`scheme://host[:port][/path]`) or a
 * bare host pattern (`host[:port]`, `*` allowed) — the syntax the form's own Host field
 * accepts. Refusing the bare form here would make the paste box the one place an
 * operator cannot write what the form takes; accepting a bare host with a path would be
 * guessing at a scheme, so that is refused with the URL to paste instead.
 *
 * Nothing is silently dropped or coerced. A line this cannot read comes back by number
 * with a reason, and a line whose rule is already in scope comes back as a duplicate
 * rather than being added twice: a bulk entry that quietly loses a host is a scan that
 * touches something the operator did not authorise, or fails to touch something they
 * did, and neither is visible afterwards. The caller reports both counts.
 */

/** The arms of a scope rule, in the shape the Add form and POST /api/scope both speak. */
export interface ScopeRuleArms {
  pattern: string;
  port?: number;
  path?: string;
  protocol?: "http" | "https";
}

/** One input line that produced no rule, with the reason it did not. */
export interface ScopePasteLine {
  /** 1-based, as the operator sees it in the box. */
  line: number;
  /** The trimmed entry, so the message can quote what it refused. */
  text: string;
  reason: string;
}

export interface ScopePasteResult {
  rules: ScopeRuleArms[];
  /** Lines that are not a URL or a host pattern this can read. */
  refused: ScopePasteLine[];
  /** Lines that are readable, whose rule is already in scope — including earlier in this same box. */
  duplicates: ScopePasteLine[];
}

/** A rule's identity, for "is this already in scope". JSON so no separator can appear in a value. */
function tupleKey(rule: ScopeRuleArms): string {
  return JSON.stringify([rule.protocol ?? "", rule.pattern, rule.port ?? 0, rule.path ?? ""]);
}

/**
 * How a rule is described in a message: the URL form when the scheme is known, otherwise the
 * pattern form the Host field takes.
 *
 * Written as a URL rather than as its arms concatenated, because that is what the operator pasted:
 * `https://a.test:9443/x` is recognisable next to the line they sent, while the arms run together
 * (`https` + `a.test` = "httpsa.test") name a host that does not exist. A rule with no scheme arm
 * genuinely has no scheme, so it prints as a pattern.
 */
export function describeScopeRule(rule: ScopeRuleArms): string {
  const scheme = rule.protocol !== undefined ? `${rule.protocol}://` : "";
  const port = rule.port !== undefined ? `:${rule.port}` : "";
  return `${scheme}${rule.pattern}${port}${rule.path ?? ""}`;
}

/**
 * parseScopePaste reads a box of entries into scope-rule arms.
 *
 * `existing` is what is already in scope, so a re-pasted list does not double every
 * rule. It is optional because the parser is also the place the *within-box* duplicate
 * rule lives, and a caller with no list still gets that half.
 */
export function parseScopePaste(text: string, existing: ScopeRuleArms[] = []): ScopePasteResult {
  const rules: ScopeRuleArms[] = [];
  const refused: ScopePasteLine[] = [];
  const duplicates: ScopePasteLine[] = [];
  const seen = new Set(existing.map(tupleKey));

  text.split(/\r?\n/).forEach((rawLine, index) => {
    const line = index + 1;
    const entry = rawLine.trim();
    // Blank and comment lines are not entries. A scope list pasted out of a brief is
    // ordinarily annotated, and a `#` line reported as "unreadable" would train the
    // operator to ignore the refusal count — which is the count that matters.
    if (entry === "" || entry.startsWith("#")) return;

    const parsed = parseScopeEntry(entry);
    if ("reason" in parsed) {
      refused.push({ line, text: entry, reason: parsed.reason });
      return;
    }
    const key = tupleKey(parsed);
    if (seen.has(key)) {
      duplicates.push({ line, text: entry, reason: `already in scope as ${describeScopeRule(parsed)}` });
      return;
    }
    seen.add(key);
    rules.push(parsed);
  });

  return { rules, refused, duplicates };
}

/** One entry: the rule it names, or the reason it names none. */
function parseScopeEntry(entry: string): ScopeRuleArms | { reason: string } {
  if (entry.includes("://")) return parseUrlEntry(entry);
  return parseHostPatternEntry(entry);
}

function parseUrlEntry(entry: string): ScopeRuleArms | { reason: string } {
  // `new URL("http:///path")` answers with hostname "path" — the authority is empty and
  // the first path segment is read as the host. A scope rule built from that would cover
  // a host nobody named, so the empty-authority form is refused before it is parsed.
  const authority = entry.slice(entry.indexOf("://") + 3);
  if (authority === "" || authority.startsWith("/")) {
    return { reason: "has no host — the scheme is followed straight by a path, so there is nothing to scope" };
  }

  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    // The common causes are a port outside 1..65535 and a bracketed IPv6 literal that is
    // not closed; both are properties of the entry, not of the parser, so neither is
    // guessed at here.
    return { reason: "is not a URL this can read — check the host and the port" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return {
      reason: `${url.protocol} is not a scheme a scope rule can carry — only http and https, since anything else would build a rule that matches nothing`,
    };
  }

  const rule: ScopeRuleArms = {
    pattern: url.hostname,
    protocol: url.protocol === "https:" ? "https" : "http",
  };
  // URL drops a default port (`http://host:80/` reports ""), which is the right answer:
  // a rule with no port arm already covers 80.
  if (url.port !== "") rule.port = Number(url.port);
  // "/" is the whole host, which is what a rule with no path arm already covers; using
  // it as a path prefix would restrict every rule to paths beginning with "/", i.e. none.
  if (url.pathname !== "" && url.pathname !== "/") rule.path = url.pathname;
  return rule;
}

function parseHostPatternEntry(entry: string): ScopeRuleArms | { reason: string } {
  if (entry.includes("/")) {
    return { reason: "has a path but no scheme — paste the whole URL, for example https://host/path" };
  }
  if (/\s/.test(entry)) {
    return { reason: "contains a space — one entry per line" };
  }

  let host = entry;
  let port: number | undefined;
  const colon = entry.lastIndexOf(":");
  // A bracketed IPv6 literal carries colons of its own, so only a colon *after* the
  // closing bracket can be a port separator. `[::1]` has none; `[::1]:8443` does.
  if (colon > 0 && !entry.slice(colon + 1).includes("]")) {
    const tail = entry.slice(colon + 1);
    if (!/^\d+$/.test(tail)) {
      return { reason: `has a port that is not a number (${tail})` };
    }
    port = Number(tail);
    if (port < 1 || port > 65535) {
      return { reason: `has a port outside 1..65535 (${tail})` };
    }
    host = entry.slice(0, colon);
  }

  if (host === "") return { reason: "has no host" };
  // A bracketed literal is checked on its own terms rather than through the pattern check
  // below, because its colons are part of the address. Half a bracket is refused: it is
  // the shape `[::1` takes when a line is truncated, and reading it as a host named
  // "[::1" would put a rule in the table that nothing can ever match.
  if (host.startsWith("[")) {
    if (!/^\[[0-9A-Fa-f:.]*\]$/.test(host)) {
      return { reason: "is not a bracketed address — an IPv6 literal in brackets holds only hex digits, colons and dots, and both brackets" };
    }
    return port === undefined ? { pattern: host } : { pattern: host, port };
  }
  // A comma is refused with the same weight as a path or a space rather than being split
  // on: the crawl box separates on commas, this one does not (Burp's Paste URL takes one
  // URL and its Load takes one per line), and a parser that quietly accepted both would
  // be inventing a third format for the one input where a misread host is a scan the
  // operator did not authorise.
  if (/[\s/?#@:,]/.test(host)) {
    return { reason: "is not a host pattern — hosts are a name or a glob, with no scheme, path, query or comma" };
  }
  // Deliberately permissive beyond that (a `*` glob, an underscore, a bracket): the
  // server takes any non-empty pattern, and a parser stricter than the API would refuse
  // input the Add form next to it accepts.
  return port === undefined ? { pattern: host } : { pattern: host, port };
}
