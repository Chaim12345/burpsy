import { create } from "zustand";
import { persist } from "zustand/middleware";

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
  intruderSeed: IntruderSeed | null;
  comparerSlots: { a: string; b: string };
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
  setActiveRepeaterTab: (id: string) => void;

  setIntruderSeed: (seed: IntruderSeed | null) => void;
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
      intruderSeed: null,
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
          const remaining = state.repeaterTabs.filter((tab) => tab.id !== id);
          const wasActive = state.activeRepeaterTab === id;
          return {
            repeaterTabs: remaining,
            activeRepeaterTab: wasActive ? (remaining.at(-1)?.id ?? null) : state.activeRepeaterTab,
          };
        }),
      setActiveRepeaterTab: (activeRepeaterTab) => set({ activeRepeaterTab }),

      setIntruderSeed: (intruderSeed) => set({ intruderSeed }),
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
      }),
    },
  ),
);

/** Resolve "system" against the OS preference so callers only deal with light/dark. */
export function resolveTheme(theme: Theme): "light" | "dark" {
  if (theme !== "system") return theme;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
