import { CalendarClock, FileSearch2, FileCode2, Gauge, Radar } from "lucide-react";
import type { MenuAction, MenuGroup } from "../ui/menu";

/**
 * Burp's "Engagement tools" context-menu group (burpsy-react-ui-gupj).
 *
 * Burp hangs eight entries off this submenu: the six in
 * tools/engagement-tools/index.html (Find references, Discover content, Schedule task,
 * Target analyzer, Generate CSRF PoC, Manual simulator) plus the two site-map searches in
 * tools/search.html (Find comments, Find scripts). burpsy had one of them flat on the row
 * menu and pages for several others with no context-menu route to them.
 *
 * The rule every row below is built to is the one the Intruder menu landed on (yinb): an item
 * either does its job or is present-and-disabled saying why — never a row that looks live and
 * does nothing. Two of Burp's eight are handled by *absence* rather than by greying, and both
 * are argued at their definition below, because a greyed row implies the feature is a setting
 * away and neither of these is.
 *
 * The group is built here, as data, rather than inline in the page, so the dispositions can be
 * asserted without mounting a tree: the tests pin that every disabled row carries a reason, that
 * Manual simulator is absent, and that a seed from a branch node searches what the hint claims.
 */

/** Which of the three searches /api/engagement/{kind} can run. */
export type EngagementSearchKind = "comments" | "scripts" | "references";

/**
 * What the site map knew about the thing that was right-clicked.
 *
 * One shape for both menus the site map owns: a tree node (a host, or a path branch under one)
 * and an exchange row under a node. `path` is empty for a host node, which is the difference
 * between "this host" and "this branch".
 */
export interface EngagementSeed {
 host: string;
 /** The node's path, or the exchange's path. "" means the whole host. */
 path: string;
 /**
  * The origin's port and whether it was reached over TLS.
  *
  * Both are carried rather than assumed because the rows that hand a target to another page hand
  * it an *origin*, and guessing one is how a content-discovery sweep gets pointed somewhere the
  * operator never captured. Site-map nodes carry both (`sitemapNodeView`), so there is nothing to
  * guess; they stay optional only for callers that genuinely have neither, and `seedUrl` then
  * falls back to https with no port — a guess, which is why every caller in this repo passes them.
  */
 port?: number;
 tls?: boolean;
}

/** A search as the endpoint takes it: GET /api/engagement/{kind}?q=&host=. */
export interface EngagementSearch {
 kind: EngagementSearchKind;
 /** The literal the server looks for. Empty for comments and scripts, which take no term. */
 q: string;
 /** Restricts which stored responses are read. Empty means every captured host. */
 host: string;
}

/**
 * The term "Find references" should look for, given what was right-clicked.
 *
 * This is the part of the wiring that is easy to get wrong in a way that reads as success.
 * `/api/engagement/references` collects href/src/action/formaction attributes and then keeps a
 * match only when `q` is a **substring of the attribute text it found** (api_engagement.go). So
 * seeding the row's absolute URL — the obvious choice — finds nothing at all on any page that
 * writes its links relatively, which is most pages: `href="/checkout"` does not contain
 * "https://shop.test/checkout". The operator would read an empty table as "nothing links here"
 * when the truth is "the wrong thing was searched for".
 *
 * The path is the form that matches both ways round, because an absolute href to the same item
 * contains the path too. For a host node there is no path, and the host itself is the term —
 * which is also what Burp does with a host selection: "if you select a host, you will find all
 * references to that host" (tools/search.html).
 */
export function referenceTerm(seed: EngagementSeed): string {
 return seed.path === "" ? seed.host : seed.path;
}

/**
 * The searches this seed produces, in Burp's submenu order.
 *
 * Note the asymmetry in `host`, which is deliberate and is Burp's:
 *
 *  - Find references searches **everywhere** ("search all of Burp's tools for HTTP responses
 *    that link to a particular item"). Restricting it to the seed's own host would hide the
 *    interesting answer — another host linking in.
 *  - Find comments and Find scripts are scoped to the selection, so they carry the host.
 */
export function engagementSearchFor(kind: EngagementSearchKind, seed: EngagementSeed): EngagementSearch {
 if (kind === "references") return { kind, q: referenceTerm(seed), host: "" };
 return { kind, q: "", host: seed.host };
}

/**
 * Where Burp scopes a branch and burpsy can only scope a host.
 *
 * Burp runs Find comments / Find scripts over "part or all of the Target site map", selected
 * branch included. `/api/engagement/{kind}` takes `host` and no path filter, so a right-click on
 * a branch searches that branch's whole host. The row stays enabled — it really does search, and
 * the result is a superset of what was asked for, not a wrong one — but the hint says so, because
 * an operator who believes the results are branch-scoped will read hits from a sibling branch as
 * hits in theirs.
 */
function scopeNote(seed: EngagementSeed): string {
 return seed.path === ""
  ? `Searches the captured responses from ${seed.host}.`
  : `Searches the captured responses from ${seed.host} — burpsy scopes this search by host, not by branch, so results may come from outside ${seed.path}.`;
}

/** What the page has to be able to do for the group's live rows. */
export interface EngagementHandlers {
 /** Show the seeded search and run it. */
 runSearch: (search: EngagementSearch) => void;
 /** Open Content discovery with this URL as the sweep target. */
 discoverContent: (target: string) => void;
 /** Open Settings › Scheduled tasks, carrying this URL as far as burpsy can take it. */
 scheduleTask: (target: string) => void;
 /** Show the Target analyzer for this host or branch. */
 analyzeTarget: (seed: EngagementSeed) => void;
}

/**
 * The seed's URL, used by the two rows that hand a target to another page.
 *
 * This was live-verified into existence: the first version assumed https and no port, and the
 * Discover content row on a site-map node then read "Opens Content discovery with
 * https://127.0.0.1/checkout" for traffic actually captured on http://127.0.0.1:19222. A sweep
 * launched from that would have been aimed at an origin the operator never visited, and the hint
 * stated the wrong URL confidently enough to be believed.
 *
 * Callers holding a real exchange still pass its `exchangeUrl` through `url`, which wins outright.
 */
export function seedUrl(seed: EngagementSeed, url?: string): string {
 if (url) return url;
 const scheme = seed.tls === false ? "http" : "https";
 const defaultPort = scheme === "https" ? 443 : 80;
 const authority = seed.port === undefined || seed.port === defaultPort ? seed.host : `${seed.host}:${seed.port}`;
 return `${scheme}://${authority}${seed.path}`;
}

/**
 * Burp's Engagement tools submenu for one seed.
 *
 * Returns a single-action group whose action is the submenu trigger, so a caller splices it into
 * an existing menu with one `extra` entry.
 */
export function engagementToolsGroup(seed: EngagementSeed, handlers: EngagementHandlers, url?: string): MenuGroup {
 const target = seedUrl(seed, url);
 const note = scopeNote(seed);
 const term = referenceTerm(seed);

 const actions: MenuAction[] = [
  {
   id: "find-references",
   label: "Find references",
   icon: FileSearch2,
   hint: `Responses anywhere in the capture whose href/src/action attributes mention ${term}. Searched as text, so a relative link to this item counts.`,
   onSelect: () => handlers.runSearch(engagementSearchFor("references", seed)),
  },
  {
   id: "find-comments",
   label: "Find comments",
   icon: FileSearch2,
   hint: `HTML comments in the captured responses. ${note}`,
   onSelect: () => handlers.runSearch(engagementSearchFor("comments", seed)),
  },
  {
   id: "find-scripts",
   label: "Find scripts",
   icon: FileCode2,
   hint: `Script sources referenced by the captured responses. ${note}`,
   onSelect: () => handlers.runSearch(engagementSearchFor("scripts", seed)),
  },
  {
   id: "discover-content",
   label: "Discover content",
   icon: Radar,
   hint: `Opens Content discovery with ${target} as the sweep target. A wordlist is still required, and the target is scope-checked before the sweep starts.`,
   onSelect: () => handlers.discoverContent(target),
  },
  {
   id: "schedule-task",
   label: "Schedule task",
   icon: CalendarClock,
   // Enabled, and honest about how far the seeding goes. burpsy's schedules really can run a
   // crawl against this URL (api_schedules.go registers a "crawl" kind taking a crawl request),
   // but the form that creates one lives in the Settings page and does not read a seed, so this
   // row opens that section and puts the URL on the clipboard to paste in. That is a real
   // action with a named limit, which is why it is not greyed: greying it would claim burpsy
   // cannot schedule work against this URL, and it can.
   hint: `Opens Settings › Scheduled tasks and copies ${target} to the clipboard. burpsy's schedule form is not seeded from the site map, so the URL has to be pasted into the new schedule's crawl seeds.`,
   onSelect: () => handlers.scheduleTask(target),
  },
  {
   id: "target-analyzer",
   label: "Target analyzer",
   icon: Gauge,
   // Burp's Target analyzer (burpsy-react-ui-dnvi), over what the site map holds for this node.
   hint: `Counts the dynamic and static URLs, parameters and unique parameter names captured under ${seed.path === "" ? seed.host : `${seed.host}${seed.path}`}, with a saved HTML report.`,
   onSelect: () => handlers.analyzeTarget(seed),
  },
 ];

 // Absent, not greyed, and each for its own reason:
 //
 //   Manual simulator — Burp generates synthetic traffic resembling a manual test. burpsy has no
 //     traffic generator of that shape and one is not wanted here: it is request volume aimed at a
 //     target for its own sake, which is the class of feature this console does not build. A greyed
 //     row would advertise it as pending.
 //
 //   Generate CSRF PoC — burpsy already has it, and it is already on this menu: lib/actions.ts
 //     carries it flat in the "engage" group beside "Record an issue". Repeating it inside the
 //     submenu would put two rows with one label on one menu. Moving the existing row in here is a
 //     one-line change in actions.ts, which this slice does not own (see the report).

 return {
  id: "engagement-tools",
  actions: [
   {
    id: "engagement",
    label: "Engagement tools",
    icon: Radar,
    hint: "Burp's engagement tools, seeded from this row.",
    submenu: [{ id: "engagement-items", title: "Engagement tools", actions }],
    onSelect: () => undefined,
   },
  ],
 };
}
