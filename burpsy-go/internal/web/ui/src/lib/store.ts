import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { RepeaterSendOptions } from "./types";
import type { AttackMode, PayloadRuleSpec, PayloadSourceType, PointView, RunView } from "./types.tools";
import type { ManualSpanView } from "./intruder-marks";
import { DEFAULT_HIDE_REQUEST_HEADERS, DEFAULT_HIDE_RESPONSE_HEADERS, requestBodyChanged } from "./message";
import type { ImportedTheme } from "./theme-import";
import type { MessageVariant } from "../ui/variant-picker";

export type Theme = "light" | "dark" | "system";
export type Density = "comfortable" | "compact";

/**
 * The two independent text scales (burpsy-react-ui-7bd), mirroring Burp's separate
 * UI-hierarchy and Code/Monospace sizes: `uiScale` multiplies every text token, and
 * `editorFont` sizes the message editor alone. Percent strings because both feed CSS
 * custom properties; "100%" and the editor's historical 12px are the defaults, so a
 * visitor who never opens Appearance sees exactly what the hardcoded build showed.
 */
export type EditorFont = "12px" | "13px" | "14px" | "16px" | "18px";
export type UiScale = "100%" | "110%" | "125%" | "150%";

/**
 * The message editor's font *family* (burpsy-react-ui-mqrn), the companion knob to `editorFont`'s
 * size — together they are Burp's http_message_display.font_name + font_size. "default" keeps the
 * stylesheet's own --font-mono stack (Penpot-canonical, IBM Plex Mono first); the rest are common
 * monospace families an operator may have installed locally, each named explicitly so it is picked
 * if present and falling back to the browser's generic monospace if not. Like editorFont and uiScale
 * this is a browser-side appearance preference — persisted here, applied as --editor-font-family.
 */
export type EditorFontFamily =
 | "default"
 | "ibm-plex-mono"
 | "cascadia-code"
 | "jetbrains-mono"
 | "sf-mono"
 | "consolas"
 | "menlo"
 | "courier-new";

/**
 * The CSS font-family stack for a stored family, or "" for "default" — the empty string means
 * "leave --editor-font-family unset so the editor falls back to the stylesheet's --font-mono". Each
 * named family ends in the generic `monospace` keyword, so a machine without that face still renders
 * the HTTP bytes in a monospace font rather than the body sans. Anything unrecognised is treated as
 * "default", so a corrupted preference reads in the canonical stack rather than an empty family.
 */
export function editorFontStack(family: string): string {
 switch (family) {
  case "ibm-plex-mono":
   return '"IBM Plex Mono", monospace';
  case "cascadia-code":
   return '"Cascadia Code", monospace';
  case "jetbrains-mono":
   return '"JetBrains Mono", monospace';
  case "sf-mono":
   return '"SF Mono", ui-monospace, monospace';
  case "consolas":
   return "Consolas, monospace";
  case "menlo":
   return "Menlo, monospace";
  case "courier-new":
   return '"Courier New", monospace';
  default:
   return "";
 }
}

/**
 * The CSS value of --ui-scale for a stored scale: a unitless factor ("1.1" for "110%"), because the
 * property multiplies px lengths and px × % is invalid CSS (burpsy-react-ui-9nlz). Anything
 * unparseable is 1, so a corrupted preference renders at the default size rather than in a fallback
 * font.
 */
export function uiScaleFactor(scale: string): string {
 const percent = Number.parseFloat(scale);
 return Number.isFinite(percent) && percent > 0 ? String(percent / 100) : "1";
}

/**
 * Per-operator triage state for Collaborator interactions (burpsy-react-ui-8o6): which
 * interaction ids have been opened (read), and the comment/highlight pairs written on
 * them. Held in this browser alongside the rest of the workspace state — like the
 * Inspector dock, it is a view over the operator's review progress, not part of the
 * interaction data the channel collects. Interaction ids are the log's positional ids,
 * stable within a channel's lifetime.
 */
export interface CollaboratorAnnotation {
  comment: string;
  highlight: string;
}

/** Which side of the editor pair the Inspector docks to — Burp's inspectorSettingsDock{Left,Right}. */
export type InspectorDock = "left" | "right";
/**
 * The state sections open in, Burp's `configPanelDefaultInspectorPanelState`.
 *
 * "auto" opens the sections that actually have rows, which is the useful default:
 * a request with no query string should not cost a line of screen to say so.
 * "collapsed" opens nothing, for an operator who wants to drive it from the
 * keyboard and expand only what they are looking for.
 */
export type InspectorPanelState = "auto" | "collapsed";

/**
 * The optional message-editor tabs an operator can add, remove and reorder
 * (burpsy-react-ui-t94i). Pretty/Raw/Hex are Burp's always-there core and stay outside this
 * model — Raw cannot be removed (it is the bytes themselves), and a model that could hide the
 * one view every message has would let an operator strand themselves.
 */
export type OptionalEditorTab = "render" | "graphql" | "jwt" | "params" | "protobuf" | "headers" | "queryparams" | "bodyparams" | "cookies" | "attributes";

/**
 * Tab order: the strip renders hidden-off, then in this order. The stored list need not name
 * every optional tab — any tab missing from it is shown in its default position (the array's
 * end, before nothing), which keeps a preference written by an older build loadable.
 */
export interface EditorTabPrefs {
 /** Which optional tabs are hidden. Absent = shown; Burp's default is every tab the message warrants. */
 hidden: OptionalEditorTab[];
 /** The order to render the optional tabs in. Tabs absent from this array follow their defaults. */
 order: OptionalEditorTab[];
}

export const defaultEditorTabPrefs: EditorTabPrefs = { hidden: [], order: [] };

/**
 * Move one tab one place, within the optional set. Returns the new order; callers persist it.
 * A tab not in the order array is appended first, so a reorder of a never-reordered strip
 * materialises the default order once and then moves within it.
 */
export function moveEditorTab(prefs: EditorTabPrefs, tab: OptionalEditorTab, direction: -1 | 1): EditorTabPrefs {
 const base = prefs.order.length
  ? prefs.order
  : (["render", "graphql", "jwt", "params", "protobuf", "headers", "queryparams", "bodyparams", "cookies", "attributes"] as OptionalEditorTab[]);
 const at = base.indexOf(tab);
 if (at < 0) return { ...prefs, order: base };
 const to = at + direction;
 if (to < 0 || to >= base.length) return { ...prefs, order: base };
 const order = [...base];
 const [moved] = order.splice(at, 1);
 if (moved === undefined) return { ...prefs, order: base };
 order.splice(to, 0, moved);
 return { ...prefs, order };
}

export interface RepeaterTab {
 id: string;
 name: string;
 target: string;
 protocol: string;
 request: string;
 /**
  * The tab's kind (burpsy-react-ui-6ex): Burp's Repeater opens each new HTTP **or WebSocket**
  * message in a tab, and the two are first-class tab types ("Select either HTTP or WebSocket",
  * burp's managing-tabs.html). "ws" tabs carry a frame payload instead of an HTTP request, and
  * their Send dials a fresh WebSocket (one-shot, the same decision the send bead recorded).
  * Absent = "http", so every existing tab and every older persisted draft reads as HTTP.
  */
 kind?: "http" | "ws";
 /**
  * This tab's own colour (burpsy-react-ui-fkj). Burp colours a GROUP and its tabs take that
  * colour; an ungrouped tab had no way to be marked at all, which is the gap — an operator pointing
  * at the one request to attack next cannot colour a group to say so. A tab's own colour wins over
  * its group's when both are set; `tabColour` in lib/repeater-tabs.ts says why.
  *
  * Empty (the default) means "inherit the group's", which is what every tab written before this
  * field means, and it leaves an ungrouped tab uncoloured rather than inventing a colour for it.
  color?: string;
 /** The frame's payload for a "ws" tab — the bytes the editor shows and the send carries. */
 wsPayload?: string;
 /** The frame's opcode ("text" | "binary"). Absent = "text". */
 wsOpcode?: string;
 /**
  * Which way the frame goes (burpsy-react-ui-6ex): Burp's "send to server" / "send to client"
  * choice. Absent = "server", which is the half a fresh dial can actually do. "client" is
  * offered and then refused by the wire with the reason ("a fresh connection has no client to
  * send to … intercept the WebSocket first"), because a chooser that silently omits one of the
  * two directions misstates what the tool offers — and a refusal the operator never sees is the
  * same as no choice at all.
  */
 wsDirection?: "server" | "client";
 /** The exchange this tab was opened from, sent back as the resend's parent so lineage survives.
  *  Undefined for a tab the operator started by hand — there is no antecedent to record. */
 fromExchange?: number;
 /** Which RepeaterGroup this tab belongs to. Undefined = ungrouped; groups are cosmetic buckets,
  *  never a permission or a send target, so a dangling id after a group delete is harmless. */
 groupId?: string;
  /** Per-send overrides (Burp's config-override menu). Absent fields mean "the standing behaviour" —
  *  see internal/web/repeater_options.go for what each key does and what is deliberately absent. */
 options?: RepeaterSendOptions;
 /**
  * The request body's exact bytes, base64, when it is binary (a protobuf/gRPC body) — the faithful
  * source of truth the lossy `request` text cannot be (burpsy-react-ui-ytkk). Set when the tab is
  * opened from a binary-bodied exchange, and updated when the operator edits the body in the Protobuf
  * view. The send uses it (as request_base64) so the exact octets reach the target; the head is still
  * taken fresh from `request`, so editing headers works. Absent for an ordinary text request.
  */
 requestBodyBase64?: string;
 /**
  * Whether this tab uses the global send defaults rather than its own `options`
  * (burpsy-react-ui-aa0p). Burp lets a tab override the global settings wholesale, marks it while
  * it does, and offers "Restore global default". Absent or true = inheriting (the send ignores
  * `options`); false = overriding (the send applies `options`). Kept separate from `options` being
  * empty so a tab tuned last week and then restored to the default keeps its tuning for when the
  * operator overrides again, exactly as Burp's toggle does.
  */
 inheritsGlobal?: boolean;
}

/** A coloured collapsible bucket of Repeater tabs — Burp's tab groups. Cosmetic by design:
 *  grouping must never gate sending or scope, because an operator who mis-files a tab into
 *  the wrong bucket should lose nothing but tidiness. */
export interface RepeaterGroup {
 id: string;
 name: string;
 color: string;
 collapsed: boolean;
}

export interface IntruderSeed {
 msgId: number | null;
 target: string;
 label: string;
}

/** A request handed to the Sequencer's live capture (fhp): the raw bytes and the authority, so
 *  the capture starts without the operator retyping either. Mirrors IntruderSeed. The response
 *  rides along when one exists (6t8): the token-location picker populates from it — cookies,
 *  headers and form fields actually present — while staying session-only like the rest. */
interface SequencerSeed {
 request: string;
 target: string;
 label: string;
 response: string | null;
}

/** How a grep pattern was typed: a literal to be quoted, or a regex sent as written. */
export type GrepMatchMode = "simple" | "regex";

/**
 * A whole Intruder attack configuration.
 *
 * It lives here rather than in the page's `useState` because only one page is mounted at a time
 * (app.tsx renders a single `<ActivePage />`), so component-local state meant that clicking any
 * other nav entry destroyed the base request, the positions, all seven payload forms, the
 * processing rules and the finished report — with no warning and no way back, since the
 * configuration that would let the attack be re-run went with it (burpsy-react-ui-rby).
 *
 * Burp treats an attack as a durable object: each one opens in its own window and can be saved into
 * the project file. This is the smaller version of that promise — one attack, but one that survives
 * navigation and reload the way Repeater's drafts already do.
 */
export interface IntruderConfig {
 msgId: string;
 target: string;
 label: string;
 mode: AttackMode;
 allPoints: boolean;
 points: PointView[];
 selected: number[];
 /** Hand-marked payload positions (Burp's Add §), with the text they cover. */
 manualSpans: ManualSpanView[];
 payloadTexts: string[];
 payloadTypes: PayloadSourceType[];
 payloadNumbers: { from: string; to: string; step: string }[];
 payloadFiles: string[];
 payloadBrute: { charset: string; min_len: string; max_len: string }[];
 payloadDates: { from: string; to: string; step: string; format: string }[];
 payloadCustom: { positions: string; separator: string }[];
 payloadNulls: string[];
 rules: PayloadRuleSpec[];
 grepMatch: string;
 grepMatchMode: GrepMatchMode;
 grepExtract: string;
 /** Grep - Match as a list (irt): one expression per line. Empty means the legacy single
  *  grepMatch field decides, so a stored config never silently stops matching. */
 grepMatchList: string[];
 /** Burp's "Case sensitive match" — simple-string entries stop being case-folded. */
 grepMatchCaseSensitive: boolean;
 /** Burp's "Exclude HTTP headers" — the list searches the response body only. */
 grepMatchExcludeHeaders: boolean;
 /** Burp's auto-pause (2cvk). `autoPauseEnabled` is the switch: when it is off the whole block is
  *  omitted from the launch body, so "did not choose" and "chose an empty expression list" stay
  *  two different requests rather than one request that means both. */
 autoPauseEnabled: boolean;
 autoPauseMode: "appears" | "missing";
 autoPauseExpressions: string[];
 autoPauseSimple: boolean;
 autoPauseCaseSensitive: boolean;
 /** Empty means the inline limits below apply; a name binds the attack to a saved pool. */
 poolName: string;
 maxRequests: number;
 maxInFlight: number;
 rps: string;
 /** Burp's resource-pool "With random variations" (nn0n), as a percentage of the interval `rps`
  *  implies. Empty or "0" is the flat delay every attack had before. */
 delayJitterPct: string;
 /** Burp's throttleIncrementMillis (nn0n): every gap is this many ms longer than the one before.
  *  Empty or "0" means a delay that does not ramp. */
 delayIncrementMS: string;
 /** Burp's "Number of retries on network failure" (n39). Empty = the server's default (Burp's 3). */
 retries: string;
 /** Burp's "Pause before retry" in ms (n39). Empty = the server's default (Burp's 2000). */
 retryDelayMS: string;
 /** Burp's "Make unmodified baseline request" (v34): the template as item 0. */
 baseline: boolean;
 /**
  * Burp's other two attack settings (burpsy-react-ui-fmxv): "Set Connection header"
  * (add or update Connection: close on every request) and "Store full payloads" (keep the
  * full payload values on each result row, so a report can name its own payloads).
  *
  * Both false by default, which is what every attack sent before this setting existed did; the
  * engine implemented both in 29a7ee3 with no way for a request to reach them.
  */
 setConnectionClose: boolean;
 storePayloads: boolean;
}

/**
 * What the browser knew about the payload sets at the moment an attack was launched.
 *
 * Kept beside the report so an attempt row's ordinal can be decoded into payload text after the
 * fact. Snapshotted rather than read live because editing the payload forms after a run must not
 * silently relabel the rows of a report those forms did not produce.
 *
 * `sets[i]` is null when the browser cannot name that set's payloads — a server-side file, or any
 * set whose server-reported count disagrees with the browser's list, which is what a payload
 * processing rule that skipped an item looks like from here.
 */
export interface IntruderPayloadSnapshot {
 mode: AttackMode;
 points: number;
 sets: (string[] | null)[];
}

/**
 * A one-shot instruction from the menubar to the Intruder page.
 *
 * The menubar cannot launch an attack itself: `onRun` in pages/intruder.tsx owns the whole launch —
 * the pre-launch snapshot of running attacks that lets the page identify its own task id, the
 * payload snapshot the report is read through, the payload-source encoding, and the error handling.
 * A second copy of that in app.tsx would be a second attack launcher that drifts from the first.
 * So the menu states an intention and the page performs it, exactly as History's "Send to Intruder"
 * states an intention through `intruderSeed`.
 *
 * `nonce` exists because "start" twice in a row is two instructions, not one: a bare string would
 * be equal to itself and the page's effect would not re-fire.
 */
export interface IntruderCommand {
  kind: "start" | "stop";
  nonce: number;
}

/**
 * What the Intruder page currently permits, published for the menubar to read.
 *
 * Only the mounted page knows whether an attack is in flight (the run mutation and the located task
 * id are its state), so it says so here and the menu greys its items accordingly. `null` means the
 * page is not mounted — the menu then falls back to `intruderLaunchBlocker`, which needs nothing
 * but the stored configuration.
 */
export interface IntruderStatus {
  /**
   * Why the page would refuse to launch right now, or null when it would launch.
   *
   * A reason rather than a boolean: the menubar has to explain a greyed "Start attack", and the
   * page is the only place that knows whether the obstacle is a missing message id, an unselected
   * position or an empty payload set.
   */
  refusal: string | null;
  /** True while an attack launched from this page is still running. */
  running: boolean;
  /** True once the running attack's task id has been located, i.e. once Stop can name its target. */
  controllable: boolean;
}

/**
 * Why the stored configuration cannot be launched, or null when nothing here stands in the way.
 *
 * Deliberately a NECESSARY condition, not a sufficient one — payload-set sizing needs the page's
 * arithmetic over seven payload forms, and duplicating that here is how two launch guards start
 * disagreeing. The menu uses this to grey an item it can be certain about; the page remains the
 * authority and refuses with its own reason if it finds something this cannot see.
 */
export function intruderLaunchBlocker(config: IntruderConfig): string | null {
  const id = config.msgId.trim();
  if (id === "") return "Choose a stored message id on the Intruder page first.";
  if (!Number.isInteger(Number(id)) || Number(id) < 0) return `"${config.msgId}" is not a stored message id.`;
  if (config.target.trim() === "") return "The attack has no target authority yet.";
  if (config.selected.length === 0) return "No insertion points are selected — discover and choose some first.";
  return null;
}

/** A finished attack: the report, and enough context to read it. */
export interface IntruderRun {
 view: RunView | null;
 /** An older server's flat per-attempt array. Kept as-is; the page renders it as JSON. */
 legacy: unknown;
 snapshot: IntruderPayloadSnapshot | null;
}

export const DEFAULT_PAYLOADS = "admin\nroot\ntest\n' OR 1=1--\n../../etc/passwd";

export function emptyIntruderConfig(): IntruderConfig {
 return {
  msgId: "",
  target: "",
  label: "",
  mode: "sniper",
  allPoints: false,
  points: [],
  selected: [],
  manualSpans: [],
  payloadTexts: [DEFAULT_PAYLOADS],
  payloadTypes: ["list"],
  payloadNumbers: [{ from: "1", to: "100", step: "1" }],
  payloadFiles: [""],
  payloadBrute: [{ charset: "abc", min_len: "1", max_len: "3" }],
  payloadDates: [{ from: "2024-01-01", to: "2024-12-31", step: "1", format: "yyyy-MM-dd" }],
  payloadCustom: [{ positions: "a,b\nc,d", separator: "" }],
  payloadNulls: ["10"],
  rules: [],
  grepMatch: "",
  grepMatchMode: "simple",
  grepExtract: "",
  grepMatchList: [],
  grepMatchCaseSensitive: false,
  grepMatchExcludeHeaders: false,
 autoPauseEnabled: false,
 autoPauseMode: "appears",
 autoPauseExpressions: [],
 autoPauseSimple: true,
 autoPauseCaseSensitive: false,
  poolName: "",
  maxRequests: 1000,
  maxInFlight: 8,
  rps: "",
  delayJitterPct: "",
  delayIncrementMS: "",
  retries: "",
  retryDelayMS: "",
  baseline: false,
  setConnectionClose: false,
  storePayloads: false,
 };
}

let sequence = 0;
function nextId(): string {
 sequence += 1;
 return `t${Date.now().toString(36)}${sequence}`;
}

/** How many Repeater tabs stay open at once, and how deep the reopen stack goes. */
const REPEATER_TAB_CAP = 12;
const REPEATER_REOPEN_CAP = 12;

/**
 * Enforce the open-tab ceiling without destroying work.
 *
 * `openRepeaterTab` and `duplicateRepeaterTab` used to end in a bare `.slice(-12)`. Opening a
 * thirteenth tab therefore dropped the oldest one on the floor: no toast, no confirmation, and
 * — the part that made it a data-loss bug rather than a UI wart — no entry on the reopen stack
 * that exists precisely to protect request drafts. An operator with twelve tabs of hand-built
 * requests lost the first by opening a thirteenth, and found out later.
 *
 * Every *close* path in this store already does the right thing: the removed tab goes onto
 * `closedRepeaterTabs` so `reopenClosedRepeaterTab` can bring it back with its draft intact.
 * A tab pushed out by the cap is a tab being closed, so it takes the same route. That keeps
 * one rule for "a tab left the strip" instead of two that disagree.
 *
 * The cap stays. Removing it would trade a recoverable eviction for unbounded state, and the
 * ceiling is not the defect — the silence was.
 */
function capRepeaterTabs(
 tabs: RepeaterTab[],
 closed: RepeaterTab[],
): { repeaterTabs: RepeaterTab[]; closedRepeaterTabs: RepeaterTab[] } {
 if (tabs.length <= REPEATER_TAB_CAP) {
  return { repeaterTabs: tabs, closedRepeaterTabs: closed };
 }
 // Oldest-first, matching the left→right order the bulk closes push in, so reopen walks them
 // back in the same direction regardless of how they left.
 const evicted = tabs.slice(0, tabs.length - REPEATER_TAB_CAP);
 return {
  repeaterTabs: tabs.slice(tabs.length - REPEATER_TAB_CAP),
  closedRepeaterTabs: [...closed, ...evicted].slice(-REPEATER_REOPEN_CAP),
 };
}

/** One item in a Comparer side's list (burpsy-react-ui-yy2). */
export interface ComparerItem {
 /** Stable per-session identity for React keys and per-item remove. */
 id: number;
 /** Where it came from — "Exchange #3", "Repeater draft", "pasted". The item tables' visible
  * column; picking pairs out of a set is done by provenance, not by reading bytes. */
 label: string;
 /** The bytes themselves. */
 value: string;
}

let comparerItemSeq = 0;
/** Mint one item's identity. Monotonic per session, so a remove-then-add can never alias. */
export function newComparerItem(label: string, value: string): ComparerItem {
 comparerItemSeq += 1;
 return { id: comparerItemSeq, label, value };
}

interface AppState {
 route: string;
 theme: Theme;
 density: Density;
 /** Whether to ask before the console tab is closed or reloaded (burpsy-react-ui-fyua), Burp's
  *  suppress_confirm_on_close inverted to a positive opt-in. Off by default — a proxy console is
  *  not a document with unsaved edits, so the prompt is a preference, not a safety default. */
 confirmOnClose: boolean;
 /** Message-editor font size (burpsy-react-ui-7bd); drives the editor theme via --editor-font-size. */
 collaboratorRead: number[];
 collaboratorAnnotations: Record<number, CollaboratorAnnotation>;
 editorFont: EditorFont;
 /** Message-editor font family (burpsy-react-ui-mqrn); drives the editor theme via
  *  --editor-font-family. "default" keeps the stylesheet's --font-mono. */
 editorFontFamily: EditorFontFamily;
 /**
  * An imported JSON theme (burpsy-react-ui-fpew), or null for the Penpot defaults. Overlays only the
  * ui.text/ui.background/ui.editor.message token slots the file named; app.tsx applies it as inline
  * custom properties on <html> and clears the rest. Browser-side appearance state, like the theme
  * and the editor font — it does not travel with the capture.
  */
 customTheme: ImportedTheme | null;
 /**
  * A theme being previewed but not yet kept (burpsy-react-ui-fpew). Deliberately NOT persisted: a
  * preview that made the console unreadable (dark text on dark paper) must be escapable by a reload,
  * and a kept theme — customTheme — is the only one that survives one. app.tsx applies
  * themePreview ?? customTheme, so a live preview overlays the kept theme without replacing it.
  */
 themePreview: ImportedTheme | null;
 /**
  * The loaded .proto (burpsy-react-ui-3pco), shared by every message editor so a schema loaded once
  * names fields in History, Repeater, Intercept and the rest alike. Persisted: it is the operator's
  * description of the target's API, which outlives a reload. null = schemaless view.
  */
 protoSchema: { name: string; text: string } | null;
 /**
  * The message type each direction is read as, when the operator chose one. Empty = automatic: the
  * gRPC call path's rpc signature, or the schema's only message. Per direction because a request and
  * its response are different messages.
  */
 protoMessages: { request?: string; response?: string };
 /** URL-encode as you type (burpsy-react-ui-js1) — Burp's editor toggle: special characters
  * typed into a request are encoded automatically. Persisted: a typing preference is a
  * layout-class choice, the same one editorFont is. */
 urlEncodeAsYouType: boolean;
 setUrlEncodeAsYouType: (on: boolean) => void;
 /** UI text scale (burpsy-react-ui-7bd); sets --ui-scale on <html>. */
 uiScale: UiScale;
 paletteOpen: boolean;
 shortcutsOpen: boolean;
 inspectorDock: InspectorDock;
 inspectorPanelState: InspectorPanelState;
 /**
  * Message-editor tab preferences (burpsy-react-ui-t94i): which of the optional tabs are
  * shown, and in what order — Burp's settings/ui/message-editor "Show" checkboxes plus
  * Up/Down reordering. Persisted, because an operator who has curated the strip has made a
  * layout choice, the same class of fact as inspectorDock.
  */
 editorTabs: EditorTabPrefs;
 setEditorTabs: (prefs: EditorTabPrefs) => void;
 /**
  * Burp's Hide request/response headers lists (burpsy-react-ui-whr): the names the message
  * editor's eye button removes from a Pretty view. Burp keeps these as user options
  * (`user_options.misc.uninteresting_headers` / `user_options.misc.uninteresting_response_headers`);
  * here they are per-browser, because only this browser's render consults them — the server
  * never reads them, and nothing about a capture changes when they do. The list *contents* are
  * burpsy's own (see message.ts), not a recovered Burp default.
  */
 hideRequestHeaders: string[];
 hideResponseHeaders: string[];
 /** Burp's `hide_uninteresting_headers_by_default`: whether a newly opened Pretty view starts
  *  with the eye already on. Off by default, so a reader who never asked for it sees every
  *  header. */
 hideHeadersByDefault: boolean;
 /**
  * Burp's `user_options.proxy.default_display_message` (ngcj): which reading the history
  * message editors show a newly selected row by default — Original, Edited, or
  * Auto-modified. Burp's own out-of-box default is ORIGINAL (recovered from the obfuscated
  * jar: burp.Zblz initialises both its request and response config values to Zpg8.ORIGINAL),
  * and a migrated operator's habits expect exactly that. Per-direction would be Burp's
  * `.request`/`.response` split; one setting serves burpsy's picker, which an operator sets
  * per pane anyway — the default is only the starting point, never a forced reading.
  */
 defaultMessageVariant: MessageVariant;
 /** Replace the default reading. */
 setDefaultMessageVariant: (variant: MessageVariant) => void;
 /** Replace one direction's list. Names are normalised by `parseHeaderNames` — the same
  *  function the settings textarea uses — so the stored list and the text the operator typed
  *  cannot disagree about folding or duplicates. */
 setHideHeaders: (kind: "request" | "response", names: string[]) => void;
 setHideHeadersByDefault: (on: boolean) => void;

 repeaterTabs: RepeaterTab[];
 activeRepeaterTab: string | null;
 /** Reopen-closed stack, most recent last. Session-only by design (see partialize). */
 closedRepeaterTabs: RepeaterTab[];
 repeaterGroups: RepeaterGroup[];
 intruderSeed: IntruderSeed | null;
 /** The live-capture request handed over by a Send to Sequencer action, consumed once by the
  *  page on mount (fhp). Session-only: a seed from yesterday is a request from yesterday. */
 sequencerSeed: SequencerSeed | null;
 /** The one live Intruder attack configuration. Persisted — see IntruderConfig. */
 intruder: IntruderConfig;
 /** The last finished attack, or null when none has run. Persisted alongside its configuration:
  *  a report that outlives the form is the half of burpsy-react-ui-rby that actually hurt. */
 intruderRun: IntruderRun | null;
 /** Which Intruder sub-tab is open, so returning to the page lands where it was left. */
 intruderTab: string;
 /** A pending menubar instruction for the Intruder page (burpsy-react-ui-yinb). Session-only and
  *  cleared on arrival: it is a one-shot command, not a setting, and a stale one replayed after a
  *  reload would launch an attack nobody asked for. */
 intruderCommand: IntruderCommand | null;
 /** What the mounted Intruder page permits, or null when no page is mounted. The menu reads it to
  *  decide what to disable AND why — only the page can size the attack, so only the page can say
  *  whether Start is possible. A menu item that cannot act must say the reason, never no-op. */
 intruderStatus: IntruderStatus | null;
 /** One Comparer item (burpsy-react-ui-yy2): a label naming where it came from and the bytes.
  * The label is what the two item tables show, because "which exchange is this" is the question
  * an operator picking pairs out of a set is asking. */
 comparerItems: { a: ComparerItem[]; b: ComparerItem[] };
 /** The pending one-shot hand-off, kept: senders still hand over raw bytes + a label, the
  * Comparer consumes them into its list on arrival. Same consume-once shape as before, so
  * every sender's call is unchanged. */
 comparerSlots: { a: string; b: string };
 /** Set when another page hands the Decoder an input to transform. Session-only, like
  *  intruderSeed: a stale payload surviving a reload would masquerade as current work. */
 decoderSeed: { label: string; input: string } | null;
 /** Set when another page asks History to focus one exchange. */
 historyFocus: number | null;
 /** Set when another page pushes a filter expression into History. */
 historyQuery: string;
 /** The rows ticked in HTTP history, by exchange id.
  *
  *  It lives here rather than in history.tsx because a second surface acts on it: the New scan
  *  dialog's "Audit selected items" (Burp's third scan kind) audits the current selection, and the
  *  dialog is on the dashboard while the ticks are in the table. Burp's selection is one notion
  *  shared by the table and the wizard for the same reason — "the selected items" has to mean the
  *  same thing wherever it is read.
  *
  *  Session-only, like historyFocus: a selection restored from a reload would name rows that may be
  *  gone, and the operator would be launching a scan of items they chose in a different session. */
 checkedExchanges: number[];
 /** Set when another page asks the Issues page to select one finding (its id). Session-only,
  * like historyFocus: a stale one would masquerade as current work after a reload. */
 issueFocus: number | null;

 setRoute: (route: string) => void;
 setTheme: (theme: Theme) => void;
 setDensity: (density: Density) => void;
 setConfirmOnClose: (confirmOnClose: boolean) => void;
 markCollaboratorRead: (id: number) => void;
 setCollaboratorAnnotation: (id: number, annotation: CollaboratorAnnotation) => void;
 setEditorFont: (font: EditorFont) => void;
 setEditorFontFamily: (family: EditorFontFamily) => void;
 /** Keep an imported theme, or null to revert to the Penpot defaults (burpsy-react-ui-fpew). */
 setCustomTheme: (theme: ImportedTheme | null) => void;
 /** Preview a theme live without keeping it; null ends the preview (burpsy-react-ui-fpew). */
 setThemePreview: (theme: ImportedTheme | null) => void;
 setProtoSchema: (schema: { name: string; text: string } | null) => void;
 setProtoMessage: (direction: "request" | "response", message: string) => void;
 setUiScale: (scale: UiScale) => void;
 setPaletteOpen: (open: boolean) => void;
 setShortcutsOpen: (open: boolean) => void;
 setInspectorDock: (dock: InspectorDock) => void;
 setInspectorPanelState: (state: InspectorPanelState) => void;

 openRepeaterTab: (tab: { name: string; target: string; protocol?: string; request: string; requestBodyBase64?: string; fromExchange?: number; kind?: "http" | "ws"; wsPayload?: string; wsOpcode?: string; wsDirection?: "server" | "client" }) => string;
 updateRepeaterTab: (id: string, patch: Partial<Omit<RepeaterTab, "id">>) => void;
 closeRepeaterTab: (id: string) => void;
 closeOtherRepeaterTabs: (id: string) => void;
 closeRepeaterTabsLeftOf: (id: string) => void;
 closeRepeaterTabsRightOf: (id: string) => void;
 duplicateRepeaterTab: (id: string) => void;
 reopenClosedRepeaterTab: () => void;
 setActiveRepeaterTab: (id: string) => void;

 createRepeaterGroup: () => string;
 renameRepeaterGroup: (id: string, name: string) => void;
 deleteRepeaterGroup: (id: string) => void;
 toggleRepeaterGroup: (id: string) => void;
 setRepeaterTabGroup: (tabId: string, groupId: string | null) => void;
  /** Move one tab to `index` in the strip (fkj). A pure reorder: membership, colour and content
   *  are untouched, so a drag cannot change which group a request belongs to by accident. */
  moveRepeaterTab: (tabId: string, index: number) => void;
  /** Set or clear one tab's own colour. Empty clears it, which sends the tab back to its group's
   *  colour rather than to "no colour" — the same reading the model documents. */
  setRepeaterTabColor: (tabId: string, color: string) => void;
 setRepeaterTabOptions: (tabId: string, options: RepeaterSendOptions) => void;

 setIntruderSeed: (seed: IntruderSeed | null) => void;
 setSequencerSeed: (seed: SequencerSeed | null) => void;
 /** Patch the attack configuration. Takes an updater so the page's field setters compose. */
 setIntruder: (next: IntruderConfig | ((current: IntruderConfig) => IntruderConfig)) => void;
 setIntruderRun: (run: IntruderRun | null) => void;
 setIntruderTab: (tab: string) => void;
 /** Ask the Intruder page to start or stop its attack (burpsy-react-ui-yinb). The PAGE decides
  *  whether it can — the menubar cannot size an attack, so it asks rather than asserts. */
 requestIntruderCommand: (kind: IntruderCommand["kind"]) => void;
 clearIntruderCommand: () => void;
 setIntruderStatus: (status: IntruderStatus | null) => void;
 setDecoderSeed: (seed: { label: string; input: string } | null) => void;
 setComparerSlot: (slot: "a" | "b", value: string) => void;
 /** Append one item to a side's list (yy2): send-to adds; the comparison runs on the selected
  * item from each list, so sending no longer discards what was there. */
 addComparerItem: (slot: "a" | "b", item: ComparerItem) => void;
 /** Remove one item from a side by id (Burp's Remove — "Delete the highlighted item"). */
 removeComparerItem: (slot: "a" | "b", id: number) => void;
 /** Clear one side's whole list (Burp's Clear — "Delete all items in the list"). */
 clearComparerItems: (slot: "a" | "b") => void;
 focusExchange: (id: number | null) => void;
 setHistoryQuery: (value: string) => void;
 setCheckedExchanges: (ids: number[]) => void;
 focusIssue: (id: number | null) => void;
}

/**
 * What survives a reload.
 *
 * Transient coordination flags must not: a stale one masquerades as current work. Layout
 * preferences and drafted work should. A named export rather than an inline lambda so the rule can
 * be asserted in a test — zustand's `persist` API is unreachable in an environment with no
 * localStorage, which is every unit-test run.
 */
export function persistedWorkspace(state: AppState) {
 return {
  theme: state.theme,
  density: state.density,
  confirmOnClose: state.confirmOnClose,
  collaboratorRead: state.collaboratorRead,
  collaboratorAnnotations: state.collaboratorAnnotations,
  editorFont: state.editorFont,
  editorFontFamily: state.editorFontFamily,
  customTheme: state.customTheme,
  protoSchema: state.protoSchema,
  protoMessages: state.protoMessages,
  urlEncodeAsYouType: state.urlEncodeAsYouType,
  uiScale: state.uiScale,
  // Where the Inspector sits and how much of it is open are layout choices an
  // operator makes once. Persisted here rather than under a `burpsy.*` key of
  // their own so there is exactly one place per-browser UI state lives.
  inspectorDock: state.inspectorDock,
  inspectorPanelState: state.inspectorPanelState,
  // The tab strip's show/hide and order (t94i): layout the operator curates once.
  editorTabs: state.editorTabs,
  // The message editor's hide-headers lists (whr) and their default toggle: the same class of
  // layout choice as the tab strip — an operator curates them once and expects the eye to
  // behave the same next session.
  hideRequestHeaders: state.hideRequestHeaders,
  hideResponseHeaders: state.hideResponseHeaders,
  hideHeadersByDefault: state.hideHeadersByDefault,
  // The default message reading (ngcj): same class of once-curated layout choice as the
  // hide-headers lists above, and Burp persists it too (user_options.proxy.*).
  defaultMessageVariant: state.defaultMessageVariant,
  repeaterTabs: state.repeaterTabs,
  activeRepeaterTab: state.activeRepeaterTab,
  // Groups are layout the operator curates — same persistence class as tab drafts.
  repeaterGroups: state.repeaterGroups,
  // An Intruder attack is work, not a transient form: the configuration and the report it
  // produced both survive navigation and reload. The report is bounded by the server's
  // detail_limit (500 attempt rows), so this is tens of kilobytes, not unbounded growth.
  intruder: state.intruder,
  intruderRun: state.intruderRun,
  intruderTab: state.intruderTab,
  // Deliberately absent: closedRepeaterTabs, and every *Seed / focus / query flag. A reopen stack
  // that survived a reload would resurrect drafts the operator closed days ago, and a persisted
  // intruderSeed would re-seed Intruder on every load, overwriting the attack above.
  //
  // intruderCommand and intruderStatus are out for the same reason and a sharper one
  // (burpsy-react-ui-yinb): a persisted "start" would fire an attack against a live target on every
  // page load, with no click behind it, and a persisted status would tell the menubar an attack is
  // running when nothing is.
 };
}

export const useApp = create<AppState>()(
 persist(
  (set, get) => ({
   route: "dashboard",
   theme: "dark",
   density: "compact",
   collaboratorRead: [],
   collaboratorAnnotations: {},
   editorFont: "12px",
   editorFontFamily: "default",
   customTheme: null,
   themePreview: null,
   protoSchema: null,
   protoMessages: {},
  urlEncodeAsYouType: false,
   uiScale: "100%",
   paletteOpen: false,
   shortcutsOpen: false,
   inspectorDock: "right",
   inspectorPanelState: "auto",
  editorTabs: defaultEditorTabPrefs,
  setEditorTabs: (prefs) => set({ editorTabs: prefs }),
  hideRequestHeaders: [...DEFAULT_HIDE_REQUEST_HEADERS],
  hideResponseHeaders: [...DEFAULT_HIDE_RESPONSE_HEADERS],
  hideHeadersByDefault: false,
  defaultMessageVariant: "original",
  setDefaultMessageVariant: (defaultMessageVariant) => set({ defaultMessageVariant }),
  setHideHeaders: (kind, names) =>
   set(kind === "request" ? { hideRequestHeaders: names } : { hideResponseHeaders: names }),
  setHideHeadersByDefault: (hideHeadersByDefault) => set({ hideHeadersByDefault }),
   repeaterTabs: [],
   activeRepeaterTab: null,
   closedRepeaterTabs: [],
   repeaterGroups: [],
   intruderSeed: null,
  sequencerSeed: null,
   intruder: emptyIntruderConfig(),
   intruderRun: null,
   intruderTab: "positions",
 intruderCommand: null,
 intruderStatus: null,
   decoderSeed: null,
   comparerSlots: { a: "", b: "" },
 comparerItems: { a: [], b: [] },
   historyFocus: null,
   historyQuery: "",
   checkedExchanges: [],
   issueFocus: null,

   setRoute: (route) => set({ route, paletteOpen: false }),
   setTheme: (theme) => set({ theme }),
   setDensity: (density) => set({ density }),
   confirmOnClose: false,
   setConfirmOnClose: (confirmOnClose) => set({ confirmOnClose }),
   markCollaboratorRead: (id) =>
    set((state) => (state.collaboratorRead.includes(id) ? state : { collaboratorRead: [...state.collaboratorRead, id] })),
   setCollaboratorAnnotation: (id, annotation) =>
    set((state) => ({ collaboratorAnnotations: { ...state.collaboratorAnnotations, [id]: annotation } })),
   setEditorFont: (editorFont) => set({ editorFont }),
   setEditorFontFamily: (editorFontFamily) => set({ editorFontFamily }),
   setCustomTheme: (customTheme) => set({ customTheme }),
   setThemePreview: (themePreview) => set({ themePreview }),
   // A new schema clears the per-direction choices: they named messages of the old one.
   setProtoSchema: (protoSchema) => set({ protoSchema, protoMessages: {} }),
   setProtoMessage: (direction, message) =>
    set((state) => ({ protoMessages: { ...state.protoMessages, [direction]: message || undefined } })),
  setUrlEncodeAsYouType: (urlEncodeAsYouType) => set({ urlEncodeAsYouType }),
   setUiScale: (uiScale) => set({ uiScale }),
   setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
   setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
   setInspectorDock: (inspectorDock) => set({ inspectorDock }),
   setInspectorPanelState: (inspectorPanelState) => set({ inspectorPanelState }),

   openRepeaterTab: ({ name, target, protocol = "https", request, requestBodyBase64, fromExchange, kind, wsPayload, wsOpcode, wsDirection }) => {
    const id = nextId();
    set((state) => ({
     ...capRepeaterTabs(
      [
       // The EXISTING tabs, then the new one. Without the spread this call receives a
       // one-element list on every open, so capRepeaterTabs keeps the newest tab and evicts
       // everything else — the strip was replaced rather than appended to, and every Repeater tab
       // except the last vanished on the next open. Measured as 7/7 failing in
       // repeater-tab-cap.test.ts before this line and 7/7 passing after (uaq0).
       ...state.repeaterTabs,
       {
        id,
        name,
        target,
        protocol,
        request,
        ...(requestBodyBase64 ? { requestBodyBase64 } : {}),
        fromExchange,
        // The ws half (6ex) rides the same spread: a tab that was opened as a frame must keep
        // its kind and payload, or the strip shows a WS tab whose pane is an HTTP request editor
        // — which is exactly what happened before this line existed.
        ...(kind ? { kind } : {}),
        ...(wsPayload !== undefined ? { wsPayload } : {}),
        ...(wsOpcode ? { wsOpcode } : {}),
        ...(wsDirection ? { wsDirection } : {}),
       },
      ],
      state.closedRepeaterTabs,
     ),
     activeRepeaterTab: id,
    }));
    return id;
   },
   updateRepeaterTab: (id, patch) =>
    set((state) => ({
     repeaterTabs: state.repeaterTabs.map((tab) => {
      if (tab.id !== id) return tab;
      const next = { ...tab, ...patch };
      // Drop a now-stale faithful binary body (burpsy-react-ui-ytkk). Every path that rewrites the
      // request text funnels through here — the raw editor, a body-encoding transform, loading a
      // different request — so this is the one place that can tell a body edit from a header edit.
      // If the body changed and the caller did not itself set requestBodyBase64, the stored base64
      // no longer matches what the operator sees, and resending it would silently discard their
      // edit; clearing it falls the send back to the (now authoritative) request text. A header-only
      // edit keeps it, so editing headers around a binary body still resends the exact bytes. The
      // Protobuf view's Apply sets request first (clears) then requestBodyBase64 (restores), so its
      // order matters — see editor.tsx.
      if (
       patch.request !== undefined &&
       !("requestBodyBase64" in patch) &&
       tab.requestBodyBase64 !== undefined &&
       requestBodyChanged(tab.request, next.request)
      ) {
       next.requestBodyBase64 = undefined;
      }
      return next;
     }),
    })),
   closeRepeaterTab: (id) =>
    set((state) => {
     const closing = state.repeaterTabs.find((tab) => tab.id === id);
     const remaining = state.repeaterTabs.filter((tab) => tab.id !== id);
     const wasActive = state.activeRepeaterTab === id;
     return {
      repeaterTabs: remaining,
      activeRepeaterTab: wasActive ? (remaining.at(-1)?.id ?? null) : state.activeRepeaterTab,
      // Reopen-closed needs the whole tab back — request draft included, because "reopen"
      // that loses the request is just close with extra steps. Bounded so a long session
      // cannot grow it without limit.
      closedRepeaterTabs: closing ? [...state.closedRepeaterTabs, closing].slice(-12) : state.closedRepeaterTabs,
     };
    }),
   // The bulk closes funnel through one helper: every removed tab lands on the reopen stack
   // in visual order (left→right), so reopen walks them back right-to-left like Burp does.
   closeOtherRepeaterTabs: (id) =>
    set((state) => {
     const closing = state.repeaterTabs.filter((tab) => tab.id !== id);
     const kept = state.repeaterTabs.filter((tab) => tab.id === id);
     return {
      repeaterTabs: kept,
      closedRepeaterTabs: [...state.closedRepeaterTabs, ...closing].slice(-12),
      activeRepeaterTab: id,
     };
    }),
   closeRepeaterTabsLeftOf: (id) =>
    set((state) => {
     const index = state.repeaterTabs.findIndex((tab) => tab.id === id);
     if (index <= 0) return {};
     const closing = state.repeaterTabs.slice(0, index);
     return {
      repeaterTabs: state.repeaterTabs.slice(index),
      closedRepeaterTabs: [...state.closedRepeaterTabs, ...closing].slice(-12),
      activeRepeaterTab: id,
     };
    }),
   closeRepeaterTabsRightOf: (id) =>
    set((state) => {
     const index = state.repeaterTabs.findIndex((tab) => tab.id === id);
     if (index < 0 || index === state.repeaterTabs.length - 1) return {};
     const closing = state.repeaterTabs.slice(index + 1);
     return {
      repeaterTabs: state.repeaterTabs.slice(0, index + 1),
      closedRepeaterTabs: [...state.closedRepeaterTabs, ...closing].slice(-12),
      activeRepeaterTab: id,
     };
    }),
   duplicateRepeaterTab: (id) =>
    set((state) => {
     const source = state.repeaterTabs.find((tab) => tab.id === id);
     if (!source) return {};
     const copy: RepeaterTab = { ...source, id: nextId(), name: `${source.name} copy` };
     const index = state.repeaterTabs.findIndex((tab) => tab.id === id);
     const next = [...state.repeaterTabs];
     next.splice(index + 1, 0, copy);
     return { ...capRepeaterTabs(next, state.closedRepeaterTabs), activeRepeaterTab: copy.id };
    }),
   reopenClosedRepeaterTab: () =>
    set((state) => {
     const last = state.closedRepeaterTabs.at(-1);
     if (!last) return {};
     return {
      repeaterTabs: [...state.repeaterTabs, last],
      closedRepeaterTabs: state.closedRepeaterTabs.slice(0, -1),
      activeRepeaterTab: last.id,
     };
    }),
   setActiveRepeaterTab: (activeRepeaterTab) => set({ activeRepeaterTab }),

   createRepeaterGroup: () => {
    // Palette order is stable, so group colours cycle predictably rather than looking random.
    const palette = ["#e5484d", "#f5a623", "#3b82f6", "#22c55e", "#a855f7", "#14b8a6"];
    const count = get().repeaterGroups.length;
    const id = `g${Date.now().toString(36)}${count}`;
    set((state) => ({
     repeaterGroups: [
      ...state.repeaterGroups,
      {
       id,
       name: `Group ${state.repeaterGroups.length + 1}`,
       color: palette[state.repeaterGroups.length % palette.length] ?? "#3b82f6",
       collapsed: false,
      },
     ],
    }));
    return id;
   },
   renameRepeaterGroup: (id, name) =>
    set((state) => ({
     repeaterGroups: state.repeaterGroups.map((group) => (group.id === id ? { ...group, name } : group)),
    })),
   deleteRepeaterGroup: (id) =>
    set((state) => ({
     // Members fall out as ungrouped tabs, never deleted with their bucket: a group is a
     // view over tabs, and destroying the view must not destroy the work inside it.
     repeaterGroups: state.repeaterGroups.filter((group) => group.id !== id),
     repeaterTabs: state.repeaterTabs.map((tab) =>
      tab.groupId === id ? { ...tab, groupId: undefined } : tab,
     ),
    })),
   toggleRepeaterGroup: (id) =>
    set((state) => ({
     repeaterGroups: state.repeaterGroups.map((group) =>
      group.id === id ? { ...group, collapsed: !group.collapsed } : group,
     ),
    })),
   setRepeaterTabGroup: (tabId, groupId) =>
    set((state) => ({
     repeaterTabs: state.repeaterTabs.map((tab) => (tab.id === tabId ? { ...tab, groupId: groupId ?? undefined } : tab)),
    })),
   // Reorder and colour (fkj). The move takes the tab out and puts it back at `index`, which is what
   // makes "drag the first tab to the end" move one tab rather than landing on its neighbour: the
   // target index is computed against the list AFTER the removal, so a drop past the old position
   // does not shift by one. Clamped, because a drop beyond the end is "last", not "lost".
   moveRepeaterTab: (tabId, index) =>
    set((state) => {
     const from = state.repeaterTabs.findIndex((tab) => tab.id === tabId);
     if (from < 0) return state;
     const target = Math.max(0, Math.min(index, state.repeaterTabs.length - 1));
     if (target === from) return state;
     const next = [...state.repeaterTabs];
     const [moved] = next.splice(from, 1);
     if (moved === undefined) return state;
     next.splice(target, 0, moved);
     return { repeaterTabs: next };
    }),
   setRepeaterTabColor: (tabId, color) =>
    set((state) => ({
     repeaterTabs: state.repeaterTabs.map((tab) =>
      tab.id === tabId ? { ...tab, color: color === "" ? undefined : color } : tab,
     ),
    })),
   setRepeaterTabOptions: (tabId, options) =>
    set((state) => ({
     repeaterTabs: state.repeaterTabs.map((tab) => (tab.id === tabId ? { ...tab, options } : tab)),
    })),

   setIntruderSeed: (intruderSeed) => set({ intruderSeed }),
   setSequencerSeed: (sequencerSeed) => set({ sequencerSeed }),
   setIntruder: (next) =>
    set((state) => ({ intruder: typeof next === "function" ? next(state.intruder) : next })),
   setIntruderRun: (intruderRun) => set({ intruderRun }),
   setIntruderTab: (intruderTab) => set({ intruderTab }),
   // The nonce counts instructions, so two identical clicks are two commands rather than one
   // ignored repeat. Reusing the existing `sequence` counter keeps one source of monotonic ids.
   requestIntruderCommand: (kind) => set({ intruderCommand: { kind, nonce: ++sequence } }),
   clearIntruderCommand: () => set({ intruderCommand: null }),
   setIntruderStatus: (intruderStatus) => set({ intruderStatus }),
   setDecoderSeed: (decoderSeed) => set({ decoderSeed }),
   setComparerSlot: (slot, value) => set({ comparerSlots: { ...get().comparerSlots, [slot]: value } }),
 addComparerItem: (slot, item) =>
  set({
   comparerItems: {
    ...get().comparerItems,
    [slot]: [...get().comparerItems[slot], item],
   },
  }),
 removeComparerItem: (slot, id) =>
  set({
   comparerItems: {
    ...get().comparerItems,
    [slot]: get().comparerItems[slot].filter((entry) => entry.id !== id),
   },
  }),
 clearComparerItems: (slot) => set({ comparerItems: { ...get().comparerItems, [slot]: [] } }),
   focusExchange: (historyFocus) => set({ historyFocus }),
   setHistoryQuery: (historyQuery) => set({ historyQuery }),
   setCheckedExchanges: (checkedExchanges) => set({ checkedExchanges }),
   focusIssue: (issueFocus) => set({ issueFocus }),
  }),
  { name: "burpsy.workspace", partialize: persistedWorkspace },
 ),
);
  /** Move one tab to `index` in the strip (fkj). A pure reorder: membership, colour and content
/** Resolve "system" against the OS preference so callers only deal with light/dark. */
export function resolveTheme(theme: Theme): "light" | "dark" {
 if (theme !== "system") return theme;
 return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
