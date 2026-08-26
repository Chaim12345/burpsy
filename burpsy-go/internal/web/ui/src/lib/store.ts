import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { RepeaterSendOptions } from "./types";

export type Theme = "light" | "dark" | "system";
export type Density = "comfortable" | "compact";

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

let sequence = 0;
function nextId(): string {
  sequence += 1;
  return `t${Date.now().toString(36)}${sequence}`;
}

interface AppState {
  route: string;
  theme: Theme;
  density: Density;
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
  comparerSlots: { a: string; b: string };
  /** Set when another page hands the Decoder an input to transform. Session-only, like
   *  intruderSeed: a stale payload surviving a reload would masquerade as current work. */
  decoderSeed: { label: string; input: string } | null;
  /** Set when another page asks History to focus one exchange. */
  historyFocus: number | null;
  /** Set when another page pushes a filter expression into History. */
  historyQuery: string;

  setRoute: (route: string) => void;
  setTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
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
  setDecoderSeed: (seed: { label: string; input: string } | null) => void;
  setComparerSlot: (slot: "a" | "b", value: string) => void;
  focusExchange: (id: number | null) => void;
  setHistoryQuery: (value: string) => void;
}

export const useApp = create<AppState>()(
  persist(
    (set, get) => ({
      route: "dashboard",
      theme: "dark",
      density: "compact",
      paletteOpen: false,
      shortcutsOpen: false,
      inspectorDock: "right",
      inspectorPanelState: "auto",
      repeaterTabs: [],
      activeRepeaterTab: null,
      closedRepeaterTabs: [],
      repeaterGroups: [],
      intruderSeed: null,
      decoderSeed: null,
      comparerSlots: { a: "", b: "" },
      historyFocus: null,
      historyQuery: "",

      setRoute: (route) => set({ route, paletteOpen: false }),
      setTheme: (theme) => set({ theme }),
      setDensity: (density) => set({ density }),
      setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
      setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
      setInspectorDock: (inspectorDock) => set({ inspectorDock }),
      setInspectorPanelState: (inspectorPanelState) => set({ inspectorPanelState }),

      openRepeaterTab: ({ name, target, protocol = "https", request, fromExchange }) => {
        const id = nextId();
        set((state) => ({
          repeaterTabs: [...state.repeaterTabs, { id, name, target, protocol, request, fromExchange }].slice(-12),
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
          return { repeaterTabs: next.slice(-12), activeRepeaterTab: copy.id };
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
      setDecoderSeed: (decoderSeed) => set({ decoderSeed }),
      setComparerSlot: (slot, value) => set({ comparerSlots: { ...get().comparerSlots, [slot]: value } }),
      focusExchange: (historyFocus) => set({ historyFocus }),
      setHistoryQuery: (historyQuery) => set({ historyQuery }),
    }),
    {
      name: "burpsy.workspace",
      // Transient coordination flags must not survive a reload; layout preferences and
      // Repeater drafts should.
      partialize: (state) => ({
        theme: state.theme,
        density: state.density,
        // Where the Inspector sits and how much of it is open are layout choices an
        // operator makes once. Persisted here rather than under a `burpsy.*` key of
        // their own so there is exactly one place per-browser UI state lives.
        inspectorDock: state.inspectorDock,
        inspectorPanelState: state.inspectorPanelState,
        repeaterTabs: state.repeaterTabs,
        activeRepeaterTab: state.activeRepeaterTab,
        // Groups are layout the operator curates — same persistence class as tab drafts.
        repeaterGroups: state.repeaterGroups,
        // Deliberately absent: closedRepeaterTabs. A reopen stack that survives a reload would
        // resurrect drafts the operator chose to close days ago, which reads as a bug, not a feature.
      }),
    },
  ),
);

/** Resolve "system" against the OS preference so callers only deal with light/dark. */
export function resolveTheme(theme: Theme): "light" | "dark" {
  if (theme !== "system") return theme;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
