import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { RepeaterSendOptions } from "./types";
import type { AttackMode, PayloadRuleSpec, PayloadSourceType, PointView, RunView } from "./types.tools";
import type { ManualSpanView } from "./intruder-marks";

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

export interface RepeaterTab {
 id: string;
 name: string;
 target: string;
 protocol: string;
 request: string;
 /** The exchange this tab was opened from, sent back as the resend's parent so lineage survives.
  *  Undefined for a tab the operator started by hand — there is no antecedent to record. */
 fromExchange?: number;
 /** Which RepeaterGroup this tab belongs to. Undefined = ungrouped; groups are cosmetic buckets,
  *  never a permission or a send target, so a dangling id after a group delete is harmless. */
 groupId?: string;
 /** Per-send overrides (Burp's config-override menu). Absent fields mean "the standing behaviour" —
  *  see internal/web/repeater_options.go for what each key does and what is deliberately absent. */
 options?: RepeaterSendOptions;
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
 *  the capture starts without the operator retyping either. Mirrors IntruderSeed. */
interface SequencerSeed {
 request: string;
 target: string;
 label: string;
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
 /** Empty means the inline limits below apply; a name binds the attack to a saved pool. */
 poolName: string;
 maxRequests: number;
 maxInFlight: number;
 rps: string;
 /** Burp's "Number of retries on network failure" (n39). Empty = the server's default (Burp's 3). */
 retries: string;
 /** Burp's "Pause before retry" in ms (n39). Empty = the server's default (Burp's 2000). */
 retryDelayMS: string;
 /** Burp's "Make unmodified baseline request" (v34): the template as item 0. */
 baseline: boolean;
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
  poolName: "",
  maxRequests: 1000,
  maxInFlight: 8,
  rps: "",
  retries: "",
  retryDelayMS: "",
  baseline: false,
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

interface AppState {
 route: string;
 theme: Theme;
 density: Density;
 /** Message-editor font size (burpsy-react-ui-7bd); drives the editor theme via --editor-font-size. */
 collaboratorRead: number[];
 collaboratorAnnotations: Record<number, CollaboratorAnnotation>;
 editorFont: EditorFont;
 /** UI text scale (burpsy-react-ui-7bd); sets --ui-scale on <html>. */
 uiScale: UiScale;
 paletteOpen: boolean;
 shortcutsOpen: boolean;
 inspectorDock: InspectorDock;
 inspectorPanelState: InspectorPanelState;

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
 comparerSlots: { a: string; b: string };
 /** Set when another page hands the Decoder an input to transform. Session-only, like
  *  intruderSeed: a stale payload surviving a reload would masquerade as current work. */
 decoderSeed: { label: string; input: string } | null;
 /** Set when another page asks History to focus one exchange. */
 historyFocus: number | null;
 /** Set when another page pushes a filter expression into History. */
 historyQuery: string;
 /** Set when another page asks the Issues page to select one finding (its id). Session-only,
  * like historyFocus: a stale one would masquerade as current work after a reload. */
 issueFocus: number | null;

 setRoute: (route: string) => void;
 setTheme: (theme: Theme) => void;
 setDensity: (density: Density) => void;
 markCollaboratorRead: (id: number) => void;
 setCollaboratorAnnotation: (id: number, annotation: CollaboratorAnnotation) => void;
 setEditorFont: (font: EditorFont) => void;
 setUiScale: (scale: UiScale) => void;
 setPaletteOpen: (open: boolean) => void;
 setShortcutsOpen: (open: boolean) => void;
 setInspectorDock: (dock: InspectorDock) => void;
 setInspectorPanelState: (state: InspectorPanelState) => void;

 openRepeaterTab: (tab: { name: string; target: string; protocol?: string; request: string; fromExchange?: number }) => string;
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
 setRepeaterTabOptions: (tabId: string, options: RepeaterSendOptions) => void;

 setIntruderSeed: (seed: IntruderSeed | null) => void;
 setSequencerSeed: (seed: SequencerSeed | null) => void;
 /** Patch the attack configuration. Takes an updater so the page's field setters compose. */
 setIntruder: (next: IntruderConfig | ((current: IntruderConfig) => IntruderConfig)) => void;
 setIntruderRun: (run: IntruderRun | null) => void;
 setIntruderTab: (tab: string) => void;
 setDecoderSeed: (seed: { label: string; input: string } | null) => void;
 setComparerSlot: (slot: "a" | "b", value: string) => void;
 focusExchange: (id: number | null) => void;
 setHistoryQuery: (value: string) => void;
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
  collaboratorRead: state.collaboratorRead,
  collaboratorAnnotations: state.collaboratorAnnotations,
  editorFont: state.editorFont,
  uiScale: state.uiScale,
  // Where the Inspector sits and how much of it is open are layout choices an
  // operator makes once. Persisted here rather than under a `burpsy.*` key of
  // their own so there is exactly one place per-browser UI state lives.
  inspectorDock: state.inspectorDock,
  inspectorPanelState: state.inspectorPanelState,
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
   uiScale: "100%",
   paletteOpen: false,
   shortcutsOpen: false,
   inspectorDock: "right",
   inspectorPanelState: "auto",
   repeaterTabs: [],
   activeRepeaterTab: null,
   closedRepeaterTabs: [],
   repeaterGroups: [],
   intruderSeed: null,
  sequencerSeed: null,
   intruder: emptyIntruderConfig(),
   intruderRun: null,
   intruderTab: "positions",
   decoderSeed: null,
   comparerSlots: { a: "", b: "" },
   historyFocus: null,
   historyQuery: "",
   issueFocus: null,

   setRoute: (route) => set({ route, paletteOpen: false }),
   setTheme: (theme) => set({ theme }),
   setDensity: (density) => set({ density }),
   markCollaboratorRead: (id) =>
    set((state) => (state.collaboratorRead.includes(id) ? state : { collaboratorRead: [...state.collaboratorRead, id] })),
   setCollaboratorAnnotation: (id, annotation) =>
    set((state) => ({ collaboratorAnnotations: { ...state.collaboratorAnnotations, [id]: annotation } })),
   setEditorFont: (editorFont) => set({ editorFont }),
   setUiScale: (uiScale) => set({ uiScale }),
   setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
   setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
   setInspectorDock: (inspectorDock) => set({ inspectorDock }),
   setInspectorPanelState: (inspectorPanelState) => set({ inspectorPanelState }),

   openRepeaterTab: ({ name, target, protocol = "https", request, fromExchange }) => {
    const id = nextId();
    set((state) => ({
     ...capRepeaterTabs(
      [...state.repeaterTabs, { id, name, target, protocol, request, fromExchange }],
      state.closedRepeaterTabs,
     ),
     activeRepeaterTab: id,
    }));
    return id;
   },
   updateRepeaterTab: (id, patch) =>
    set((state) => ({
     repeaterTabs: state.repeaterTabs.map((tab) => (tab.id === id ? { ...tab, ...patch } : tab)),
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
   setDecoderSeed: (decoderSeed) => set({ decoderSeed }),
   setComparerSlot: (slot, value) => set({ comparerSlots: { ...get().comparerSlots, [slot]: value } }),
   focusExchange: (historyFocus) => set({ historyFocus }),
   setHistoryQuery: (historyQuery) => set({ historyQuery }),
   focusIssue: (issueFocus) => set({ issueFocus }),
  }),
  { name: "burpsy.workspace", partialize: persistedWorkspace },
 ),
);

/** Resolve "system" against the OS preference so callers only deal with light/dark. */
export function resolveTheme(theme: Theme): "light" | "dark" {
 if (theme !== "system") return theme;
 return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
