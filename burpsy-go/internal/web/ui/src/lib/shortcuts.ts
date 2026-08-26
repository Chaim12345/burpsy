/**
 * The keyboard-shortcut registry: one source of truth for the shortcuts modal, the
 * Settings page's Hotkeys section, and the bindings app.tsx actually installs.
 *
 * # Why some of these are rebindable and most are not
 *
 * Burp's hotkeys are user data — `user_options.misc.hotkeys`, behind a searchable table
 * with duplicate detection and a per-action edit dialog — and its own settings copy says
 * every hotkey must use the Command or Control key. So a *named global action* is the unit
 * a hotkey registry can address.
 *
 * Most rows here are not that. `right-click` is not a chord. The table's arrow, page and
 * Home/End keys are what a listbox does and rebinding them would break the widget rather
 * than configure it. The message-editor codec keys are bound inside a CodeMirror keymap
 * against the current selection, and `Enter` on a focused row is the table's own activate.
 * Those stay fixed, and each says why — a table that offered an Edit button on a row it
 * could not actually rebind would be the defect this project is built against.
 *
 * `rebindable: true` rows are dispatched from one place (app.tsx or a page's useHotkeys)
 * against this registry, so changing one here changes what is installed.
 */

/** A chord in react-hotkeys-hook's vocabulary: lowercase, `+`-joined, `mod` for ctrl/cmd. */
export type Chord = string;

export interface ShortcutAction {
  /** Stable key. Persisted in the keymap, so renaming one resets that binding. */
  id: string;
  group: string;
  label: string;
  /** The shipped binding. `null` means the action exists with no default, as Burp's palette does. */
  defaultChord: Chord | null;
  /** Display override for rows whose keys are not a literal chord (`↑ ↓`, `right-click`). */
  display?: string[];
  /** False when the action cannot honestly be rebound; `note` then says why. */
  rebindable: boolean;
  /** Why this differs from Burp, or why it is fixed. Rendered beside the row. */
  note?: string;
}

export const SHORTCUT_ACTIONS: ShortcutAction[] = [
  // ---- Send to ---------------------------------------------------------------------
  { id: "send.repeater", group: "Send to", label: "Send the selected exchange to Repeater", defaultChord: "mod+r", rebindable: true },
  { id: "send.intruder", group: "Send to", label: "Send the selected exchange to Intruder", defaultChord: "mod+i", rebindable: true },
  {
    id: "send.organizer", group: "Send to", label: "Send the selected exchange to Organizer",
    defaultChord: "mod+o", rebindable: true,
    note: "Burp binds Ctrl+O here too",
  },
  {
    id: "send.rowEnter", group: "Send to", label: "Send the focused row to Repeater",
    defaultChord: null, display: ["Enter"], rebindable: false,
    note: "The table's own activate key — rebinding it would break row activation, not configure it",
  },
  {
    id: "send.contextMenu", group: "Send to", label: "All send-to and copy actions for a row",
    defaultChord: null, display: ["right-click"], rebindable: false,
    note: "Not a chord",
  },

  // ---- Proxy -----------------------------------------------------------------------
  { id: "proxy.forward", group: "Proxy", label: "Forward the held message", defaultChord: "mod+f", rebindable: true },
  {
    id: "proxy.toggleIntercept", group: "Proxy", label: "Toggle interception",
    defaultChord: "alt+t", rebindable: true,
    note: "Burp uses mod+T; browsers reserve it for a new tab. Rebindable, so pick your own",
  },

  // ---- Message editor --------------------------------------------------------------
  // All fixed: these live in a CodeMirror keymap and act on the current selection, not on a
  // globally dispatched action. See ui/editor.tsx's PAIRS.
  { id: "editor.urlEncode", group: "Message editor", label: "URL-encode the selection", defaultChord: null, display: ["mod", "U"], rebindable: false, note: "Editor keymap" },
  { id: "editor.urlDecode", group: "Message editor", label: "URL-decode the selection", defaultChord: null, display: ["mod", "shift", "U"], rebindable: false, note: "Editor keymap" },
  { id: "editor.htmlEncode", group: "Message editor", label: "HTML-encode the selection", defaultChord: null, display: ["mod", "H"], rebindable: false, note: "Editor keymap" },
  { id: "editor.htmlDecode", group: "Message editor", label: "HTML-decode the selection", defaultChord: null, display: ["mod", "shift", "H"], rebindable: false, note: "Editor keymap" },
  { id: "editor.b64Encode", group: "Message editor", label: "Base64-encode the selection", defaultChord: null, display: ["mod", "B"], rebindable: false, note: "Editor keymap" },
  { id: "editor.b64Decode", group: "Message editor", label: "Base64-decode the selection", defaultChord: null, display: ["mod", "shift", "B"], rebindable: false, note: "Editor keymap" },
  { id: "editor.search", group: "Message editor", label: "Search in the editor", defaultChord: null, display: ["mod", "S"], rebindable: false, note: "Editor keymap" },
  { id: "repeater.send", group: "Message editor", label: "Send the request in Repeater", defaultChord: "mod+enter", rebindable: true, note: "Burp also binds Ctrl+Space" },

  // ---- Navigation ------------------------------------------------------------------
  { id: "nav.palette", group: "Navigation", label: "Command palette", defaultChord: "mod+k", rebindable: true, note: "Burp ships its palette with no default binding at all" },
  { id: "nav.nextTool", group: "Navigation", label: "Next tool tab", defaultChord: "mod+alt+right", rebindable: true },
  { id: "nav.prevTool", group: "Navigation", label: "Previous tool tab", defaultChord: "mod+alt+left", rebindable: true },
  {
    id: "nav.tools", group: "Navigation", label: "Switch to a tool by number",
    defaultChord: null, display: ["alt", "1…0"], rebindable: false,
    note: "Ten bindings driven by nav.ts's own hotkey field; Burp uses mod+shift+letter, which browsers reserve",
  },
  { id: "nav.tableMove", group: "Navigation", label: "Move through the table", defaultChord: null, display: ["↑", "↓"], rebindable: false, note: "Listbox keys" },
  { id: "nav.tablePage", group: "Navigation", label: "Move a page through the table", defaultChord: null, display: ["PgUp", "PgDn"], rebindable: false, note: "Listbox keys" },
  { id: "nav.tableEnds", group: "Navigation", label: "First or last row", defaultChord: null, display: ["Home", "End"], rebindable: false, note: "Listbox keys" },

  // ---- Appearance and help ---------------------------------------------------------
  { id: "view.toggleTheme", group: "Appearance and help", label: "Toggle light and dark theme", defaultChord: "mod+shift+l", rebindable: true },
  { id: "help.shortcuts", group: "Appearance and help", label: "Show the shortcut list", defaultChord: "shift+slash", display: ["?"], rebindable: true },
];

/** The persisted override map: action id -> chord, or null for "unbound by the operator". */
export type Keymap = Record<string, Chord | null>;

/**
 * Where the operator's overrides live.
 *
 * localStorage rather than the Zustand workspace store, matching `burpsy.split.*` and
 * `burpsy.logger.columns`: this is a per-browser preference, and keeping it out of the
 * store also keeps U21 off a file another unit is editing.
 */
export const KEYMAP_STORAGE_KEY = "burpsy.hotkeys";

export const REBINDABLE = SHORTCUT_ACTIONS.filter((a) => a.rebindable);

const byId = new Map(SHORTCUT_ACTIONS.map((a) => [a.id, a]));

/** The action a chord is currently assigned to, or null. Used for duplicate detection. */
export function actionForChord(keymap: Keymap, chord: Chord, exceptId?: string): ShortcutAction | null {
  for (const action of REBINDABLE) {
    if (action.id === exceptId) continue;
    if (chordFor(keymap, action.id) === chord) return action;
  }
  return null;
}

/** The chord in force for an action: the operator's override if set, else the default. */
export function chordFor(keymap: Keymap, id: string): Chord | null {
  if (Object.prototype.hasOwnProperty.call(keymap, id)) return keymap[id] ?? null;
  return byId.get(id)?.defaultChord ?? null;
}

/**
 * Whether a chord is one this build will accept.
 *
 * Burp's own rule, quoted in its settings copy: a hotkey must use the Command key on macOS
 * or the Control key on Windows, and may add other modifiers. `mod` is that key. `alt`-only
 * is allowed here as the documented exception — alt+T and alt+1…0 exist precisely because
 * browsers reserve the mod+ combinations Burp uses, so refusing alt would refuse the
 * bindings this build already ships.
 */
export function validateChord(raw: string): { chord: Chord } | { error: string } {
  const chord = raw.trim().toLowerCase();
  if (chord === "") return { error: "Press a key combination" };
  const parts = chord.split("+").filter((p) => p !== "");
  const mods = parts.filter((p) => p === "mod" || p === "shift" || p === "alt");
  const keys = parts.filter((p) => !["mod", "shift", "alt"].includes(p));
  if (keys.length === 0) return { error: "A modifier on its own is not a shortcut — add a key" };
  if (keys.length > 1) return { error: `Only one non-modifier key: got ${keys.join(" and ")}` };
  if (!mods.includes("mod") && !mods.includes("alt")) {
    return { error: "Must include mod (Ctrl/Cmd) or alt — a bare key would fire while typing" };
  }
  // Canonical modifier order, typed as the literal union so the array is not widened to string[]
  // — that widening is what let this line typecheck-fail once typescript was actually available.
  const ORDER = ["mod", "alt", "shift"] as const;
  const ordered = ORDER.filter((m) => mods.includes(m));
  return { chord: [...ordered, keys[0]!].join("+") };
}

/** A chord rendered as the key caps the modal and the table show. */
export function chordKeys(action: ShortcutAction, keymap: Keymap): string[] {
  if (action.display) return action.display;
  const chord = chordFor(keymap, action.id);
  if (chord === null) return ["unbound"];
  return chord.split("+").map((part) => (part === "shift+slash" ? "?" : part === "slash" ? "?" : part));
}

/** Grouped for rendering, preserving declaration order within each group. */
export function shortcutGroups(): { title: string; rows: ShortcutAction[] }[] {
  const order: string[] = [];
  const groups = new Map<string, ShortcutAction[]>();
  for (const action of SHORTCUT_ACTIONS) {
    if (!groups.has(action.group)) {
      groups.set(action.group, []);
      order.push(action.group);
    }
    groups.get(action.group)!.push(action);
  }
  return order.map((title) => ({ title, rows: groups.get(title)! }));
}
