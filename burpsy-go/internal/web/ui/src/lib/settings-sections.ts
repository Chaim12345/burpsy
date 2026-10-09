/**
 * The Settings page's own table of contents (burpsy-react-ui-f6a).
 *
 * Burp's Settings is a dialog with a left-hand tree, a Search box and All/User/Project
 * filters; burpsy's was seventeen cards on one uninterrupted scroll with no way to jump,
 * filter or find anything, and `tools/command-palette.html` names "find and open Burp's
 * settings" as one of the palette's core jobs — which burpsy's single "Settings" navigate
 * action could not do. This module is the one list that fixes both: the page renders from
 * it, the page's section rail renders from it, and the command palette builds one entry
 * per section from it. A hand-written second list is the thing that drifts, so there is
 * exactly one.
 *
 * **A flat list, not a tree.** Burp's is a tree because its categories have children
 * (Settings > Network > Connections). burpsy's seventeen cards have none — each is a leaf
 * — so inventing a level of depth here would mean grouping the cards into categories that
 * exist nowhere else in this console, and the grouping would be this file's opinion rather
 * than the page's structure. When a section grows children, this is where they go.
 *
 * **Sub-headings inside a card are not destinations.** Two cards carry a second
 * `SectionHeading` ("Negotiation probe" under Protocols, "What each tool honours" under
 * Resource pools). They are parts of their card's state, not separate settings panels —
 * the probe reads the protocol report above it, the support table is the pool list's
 * explanation — so they are reachable by scrolling to their card and are deliberately not
 * separate rows. Splitting them would put two nav entries on one card's state.
 *
 * **What `keywords` is for.** The search matches a section's rendered text as well as this
 * metadata (see `filterSettingsSections`), so field labels do not need copying here and
 * cannot go stale. `keywords` carries only what the card does *not* say on screen: Burp's
 * own name for the panel, and the words an operator arrives with ("proxy pac", "ntlm")
 * that the card never prints.
 */

/** One card on the Settings page. `title` must be the exact `<h2>` its card renders. */
export interface SettingsSection {
  /** Stable, URL-safe, and the suffix of the card's DOM id. Renaming one breaks a bookmark, not a build. */
  readonly id: string;
  /** The card's `<h2>`. The nav, the palette entry and the card heading are all this string. */
  readonly title: string;
  /** One line for the palette hint and the search haystack — the card's own `detail`, trimmed. */
  readonly summary: string;
  /** Search terms the card does not print: Burp's name for it, and the operator's word for it. */
  readonly keywords: string;
}

/**
 * Every section the Settings page renders, in render order.
 *
 * The order is the page's order, deliberately unchanged by this work: an operator who knew
 * where something was must still find it there. `SettingsPage` maps this array, so this is
 * the render order rather than a description of it.
 */
export const SETTINGS_SECTIONS = [
  {
    id: "proxy",
    title: "Proxy",
    summary: "What the server has captured so far, and where its listeners are bound.",
    keywords: "listener bind port capture interception startup",
  },
  {
    id: "suite",
    title: "Suite",
    summary: "Startup behaviour, where burpsy keeps its state on disk, and the suite-level settings Burp exposes.",
    keywords: "suite performance startup shutdown temporary files updates early adopter close confirm interception at startup ca directory",
  },
  {
    id: "rest-api",
    title: "REST API",
    summary: "Every HTTP route this console exposes, classified by what it can do, and where the console is bound. Read-only.",
    keywords: "api routes endpoints surface exposure risk gated classification bind address network json",
  },
  {
    id: "resource-pools",
    title: "Resource pools",
    summary: "Saved limits every tool can reference by name, instead of each run re-specifying its own.",
    keywords: "concurrency throttle rate limit configResourcePools",
  },
  {
    id: "scheduled-tasks",
    title: "Scheduled tasks",
    summary: "Start a crawl or an audit at a wall-clock time, or on an interval. The schedule survives a restart.",
    keywords: "cron timer recurring automation",
  },
  {
    id: "protocols",
    title: "Protocols",
    summary: "How this tool's own senders reached their targets, and a probe that asks an authority directly.",
    keywords: "http2 h2 alpn negotiation probe",
  },
  {
    id: "network",
    title: "Network",
    summary: "Hostname resolution, DNS lookup, timeouts, redirections and open-ended responses.",
    keywords: "dns timeout redirect streaming connections",
  },
  {
    id: "scanner",
    title: "Scanner",
    summary: "Shipped audit configurations and their concrete settings. Read-only.",
    keywords: "audit crawl configuration library preset",
  },
  {
    id: "llm-triage",
    title: "LLM triage",
    summary: "The post-scan second look: an operator-supplied OpenAI-compatible endpoint that advises on gated findings. Advice only — a triage note never moves a finding's severity or confidence.",
    keywords: "llm ai triage second look endpoint model openai",
  },
  {
    id: "skills",
    title: "Skills",
    summary: "The skill library loaded with -skills DIR: packaged prompt techniques an MCP client invokes, the tools each one calls, and which this project turns off.",
    keywords: "skills prompts mcp agent techniques library disable",
  },
  {
    id: "browser-engine",
    title: "Browser engine",
    summary: "Which headless browser runs the DOM-based checks. Changing it takes a restart.",
    keywords: "chromium headless dom embedded browser",
  },
  {
    id: "browser",
    title: "Browser",
    summary: "The browser Open browser launches: its data folder, sandbox and GPU, and clearing its data.",
    keywords: "open browser chromium profile data folder sandbox gpu clear cookies proxy",
  },
  {
    id: "upstream-proxy",
    title: "Upstream proxy and SOCKS",
    summary: "Where this tool's traffic goes on its way out. Ordered rules, first match wins.",
    keywords: "socks5 chain corporate pac",
  },
  {
    id: "platform-auth",
    title: "Platform authentication",
    summary: "Credentials burpsy presents to a host that demands them, first host match wins.",
    keywords: "basic digest ntlm kerberos negotiate 401 credentials",
  },
  {
    id: "client-certificates",
    title: "Client TLS certificates",
    summary: "PKCS#12 identities presented when a host asks for a client certificate.",
    keywords: "p12 pfx mutual mtls smartcard",
  },
  {
    id: "server-certificates",
    title: "Server TLS certificates",
    summary: "Information only: every X.509 certificate a target server presented to this tool.",
    keywords: "x509 tls ssl certificate chain fingerprint sha256 issuer subject san",
  },
  {
    id: "logging",
    title: "Logging",
    summary: "Per-tool request and response log files, written as traffic happens.",
    keywords: "log file disk requests responses proxy scanner repeater intruder all tools",
  },
  {
    id: "appearance",
    title: "Appearance",
    summary: "Stored in this browser; it does not travel with the capture.",
    keywords: "theme dark light font size density user interface display",
  },
  {
    id: "hotkeys",
    title: "Hotkeys",
    summary: "mod is ⌘ on macOS and Ctrl elsewhere. Stored in this browser.",
    keywords: "keyboard shortcut chord rebind",
  },
  {
    id: "certificate",
    title: "Certificate",
    summary: "A client that does not trust this CA cannot be intercepted on HTTPS at all.",
    keywords: "ca root download install trust https",
  },
  {
    id: "ca-import",
    title: "Use your own CA",
    summary: "Sign with a CA you already have, instead of the one this server generated.",
    keywords: "import pem key signing certificate authority",
  },
  {
    id: "message-editor",
    title: "Message editor",
    summary: "Which headers the eye button hides in Pretty, and which reading (Original / Edited / Auto-modified) a history row opens on. Stored in this browser.",
    keywords: "hide headers eye pretty uninteresting request response default display message reading original edited auto-modified",
  },
  {
    id: "uninteresting-headers",
    title: "Comparer: uninteresting headers",
    summary: "Headers whose differences are dimmed when comparing messages. Nothing is hidden here.",
    keywords: "comparer diff ignore noise date dimmed",
  },
  {
    id: "project-backup",
    title: "Project backup",
    summary: "A consistent snapshot of the project database, taken with SQLite's own VACUUM INTO.",
    keywords: "save copy snapshot retention sqlite restore",
  },
  {
    id: "diagnostics",
    title: "Diagnostics",
    summary: "What the store holds, and whether the live event stream is actually delivering.",
    keywords: "event stream health store size troubleshooting",
  },
] as const satisfies readonly SettingsSection[];

/**
 * The id of a section that exists. `SettingsPage`'s component map is keyed by this, so a
 * section added to the array above without a component on the page fails the typecheck —
 * which is the invariant this whole module is for, enforced at build time rather than by
 * a test that has to be remembered.
 */
export type SettingsSectionId = (typeof SETTINGS_SECTIONS)[number]["id"];

/** The DOM id of a section's card. Prefixed, because `network` alone is not this page's to own. */
export function settingsSectionAnchor(id: string): string {
  return `settings-${id}`;
}

/**
 * Does this section match what was typed?
 *
 * `body` is the section card's rendered text, which is where the actual settings are: every
 * field label, every hint, every table header the card printed. Passing it in rather than
 * reading the DOM here keeps the predicate pure and testable, and means the page can decide
 * what "rendered" means (it reads `textContent`, so a card still loading matches on less
 * text until its data arrives — a search run in the first moments of the page can miss a
 * label that has not been fetched yet).
 *
 * Every whitespace-separated word must match somewhere, rather than the whole phrase
 * matching as a substring: "tls timeout" should find Network, where nothing on this page
 * contains that phrase literally.
 */
export function settingsSectionMatches(section: SettingsSection, body: string, term: string): boolean {
  return matchesAllWords(`${section.title} ${section.summary} ${section.keywords} ${body}`, term);
}

/**
 * Does this text contain every word of the term?
 *
 * Exported because the page runs the same rule twice at two scales: once over a section to
 * decide whether to show it, and once *inside* the surviving section to find which control
 * actually matched — a search that only scrolls to a card heading has not found the setting,
 * it has found the card. Both must agree on what "matches" means, or the page would highlight
 * something the filter did not keep.
 */
export function matchesAllWords(text: string, term: string): boolean {
  const words = term.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = text.toLowerCase();
  return words.every((word) => haystack.includes(word));
}

/**
 * The sections still visible for a search term, in render order.
 *
 * `body` is asked for per section rather than handed in as a map so the page can read the
 * live DOM lazily — an empty term skips reading it entirely, which is the common case.
 */
export function filterSettingsSections(
  term: string,
  body: (section: SettingsSection) => string,
  sections: readonly SettingsSection[] = SETTINGS_SECTIONS,
): SettingsSection[] {
  if (!term.trim()) return [...sections];
  return sections.filter((section) => settingsSectionMatches(section, body(section), term));
}

/**
 * A section the palette has been asked to open, held until the Settings page can act on it.
 *
 * The palette can fire from any route, so "navigate to Settings and scroll to Network" is
 * two events with a mount in between: the module variable survives that gap, and the event
 * covers the other case — the palette fired while Settings was already on screen, where
 * nothing mounts and an effect would never run.
 *
 * Not in the zustand store on purpose: `useApp` is persisted, and a scroll target that
 * outlives the tab would scroll a fresh session to wherever the last one was looking.
 */
const SECTION_REQUEST = "burpsy:settings-section";
let pendingSection: string | null = null;

/**
 * Is there a real DOM to post the request to?
 *
 * Feature-tested rather than `typeof window !== "undefined"`, because that is not the same
 * question: other tests in this suite install a partial `window` stub, and a global that
 * exists without `dispatchEvent` would throw here — in a module whose whole job is to be
 * safe to call from anywhere. The pending id below does not need a DOM at all, so a host
 * without one still gets the part that works.
 */
function canPostEvents(): boolean {
  return typeof window !== "undefined" && typeof window.dispatchEvent === "function" && typeof CustomEvent === "function";
}

/** Ask the Settings page to show a section. Navigate first; this only says where to land. */
export function requestSettingsSection(id: SettingsSectionId): void {
  pendingSection = id;
  if (canPostEvents()) {
    window.dispatchEvent(new CustomEvent(SECTION_REQUEST, { detail: id }));
  }
}

/** Read and clear the pending request. Clearing is the point: it must fire once, not on every render. */
export function takePendingSettingsSection(): string | null {
  const id = pendingSection;
  pendingSection = null;
  return id;
}

/** Subscribe to requests made while the page is already mounted. Returns the unsubscribe. */
export function onSettingsSectionRequest(handler: (id: string) => void): () => void {
  if (!canPostEvents() || typeof window.addEventListener !== "function") return () => undefined;
  const listener = (event: Event) => {
    const id = (event as CustomEvent<string>).detail;
    if (typeof id === "string") handler(id);
  };
  window.addEventListener(SECTION_REQUEST, listener);
  return () => window.removeEventListener(SECTION_REQUEST, listener);
}

/** What `ui/palette.tsx` consumes: the shape of a `PaletteAction`, built here so the list cannot drift. */
export interface SettingsPaletteAction {
  id: string;
  label: string;
  group: string;
  hint: string;
  keywords: string;
  run: () => void;
}

/**
 * One palette action per section — Burp's palette opens a *setting*, not a settings page.
 *
 * The label repeats the group word ("Settings › Network" under a "Settings" heading) because
 * the palette's recency ordering lifts a row away from its heading, and a row reading only
 * "Network" beside "Proxy › HTTP history" would look like a tool rather than a settings
 * panel. `navigate` is injected rather than imported so this stays testable without a store.
 */
export function settingsPaletteActions(navigate: (route: string) => void): SettingsPaletteAction[] {
  return SETTINGS_SECTIONS.map((section) => ({
    id: `settings:${section.id}`,
    label: `Settings › ${section.title}`,
    group: "Settings",
    hint: section.summary,
    keywords: `settings ${section.keywords}`,
    run: () => {
      navigate("settings");
      requestSettingsSection(section.id);
    },
  }));
}
