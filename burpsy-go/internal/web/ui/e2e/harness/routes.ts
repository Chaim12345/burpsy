// Every routable view, mirrored from src/nav.ts.
//
// It is a copy rather than an import because src/nav.ts imports every page component, and through
// them React, CodeMirror and Radix — pulling that into the runner process to read a list of strings
// would make a browser suite depend on a bundler. The copy is kept honest by two checks that both
// run against the live app rather than against this file:
//
//   * routes.spec.ts asserts the command palette's "Go to" group lists exactly these ids, so a leaf
//     added to nav.ts and not to this list fails.
//   * The h1 text below is asserted per route, so a page renamed on either side fails.
//
// `h1` is the PageHeader title, which is NOT always the nav label — "Logger" renders "Tool log",
// "WebSockets history" renders "WebSocket traffic", "Match & Replace" renders "Match / replace".
// The divergence is recorded here deliberately: if it should be fixed, this is where it shows.

export interface Route {
  /** URL hash and the routing key. */
  id: string;
  /** Label on the tool tab or sub-tab. Uppercased by CSS — never compare textContent to it. */
  label: string;
  /** Exact text of the page's <h1>. */
  h1: string;
  /** The tool tab this leaf sits under, and its alt+N hotkey when it has one. */
  tool: string;
  hotkey?: string;
}

export const ROUTES: Route[] = [
  { id: "dashboard", label: "Dashboard", h1: "Dashboard", tool: "dashboard", hotkey: "1" },
  { id: "sitemap", label: "Site map", h1: "Site map", tool: "target", hotkey: "2" },
  { id: "scanner", label: "Issues", h1: "Issues", tool: "target" },
  { id: "scope", label: "Scope", h1: "Scope", tool: "target" },
  { id: "intercept", label: "Intercept", h1: "Intercept", tool: "proxy", hotkey: "3" },
  { id: "history", label: "HTTP history", h1: "HTTP history", tool: "proxy" },
  { id: "wshistory", label: "WebSockets history", h1: "WebSocket traffic", tool: "proxy" },
  { id: "matchreplace", label: "Match & Replace", h1: "Match / replace", tool: "proxy" },
  { id: "intruder", label: "Intruder", h1: "Intruder", tool: "intruder", hotkey: "4" },
  { id: "repeater", label: "Repeater", h1: "Repeater", tool: "repeater", hotkey: "5" },
  { id: "sequencer", label: "Sequencer", h1: "Sequencer", tool: "sequencer", hotkey: "6" },
  { id: "decoder", label: "Decoder", h1: "Decoder", tool: "decoder", hotkey: "7" },
  { id: "comparer", label: "Comparer", h1: "Comparer", tool: "comparer", hotkey: "8" },
  { id: "logger", label: "Logger", h1: "Tool log", tool: "logger", hotkey: "9" },
  { id: "organizer", label: "Organizer", h1: "Organizer", tool: "organizer", hotkey: "0" },
  { id: "session", label: "Session", h1: "Session", tool: "session" },
  { id: "discover", label: "Discover", h1: "Discover", tool: "discover" },
  { id: "settings", label: "Settings", h1: "Settings", tool: "settings" },
];

/** The alt+N bindings, in nav order. Session and Settings have none — browsers ran out of digits. */
export const HOTKEY_ROUTES = ROUTES.filter((route) => route.hotkey);
