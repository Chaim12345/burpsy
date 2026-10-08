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
  /**
   * The binding under the desktop shell (cmd/desktop, Wails), where no browser reserves keys. Set
   * only on rows whose web default is a browser-forced alternative to Burp's own chord; the desktop
   * then gets Burp's chord (2czi).
   */
  desktopChord?: Chord;
  /** Display override for rows whose keys are not a literal chord (`↑ ↓`, `right-click`). */
  display?: string[];
  /** False when the action cannot honestly be rebound; `note` then says why. */
  rebindable: boolean;
  /** Why this differs from Burp, or why it is fixed. Rendered beside the row. */
  note?: string;
  /**
   * Burp's own action name (Zipf.java's enum, or the UserDefaults.json hotkey id) when this row is
   * Burp's action. Shown in Settings so an operator can find "REPEATER_HISTORY_GO_BACK" by name.
   */
  burp?: string;
  /**
   * Offered in the command palette as a generated row (lib/palette-commands.ts catalogueCommands).
   * The palette runs it through lib/commands.ts, so it is runnable exactly when some mounted
   * component has registered a handler — and `where` is the reason shown when none has.
   */
  palette?: boolean;
  /** Where the action can run, for the palette's "not available here" reason: "Repeater" etc. */
  where?: string;
}

export const SHORTCUT_ACTIONS: ShortcutAction[] = [
  // ---- Send to ---------------------------------------------------------------------
  { id: "send.repeater", group: "Send to", label: "Send the selected exchange to Repeater", defaultChord: "mod+r", rebindable: true, burp: "SEND_TO_REPEATER" },
  { id: "send.intruder", group: "Send to", label: "Send the selected exchange to Intruder", defaultChord: "mod+i", rebindable: true, burp: "SEND_TO_INTRUDER" },
  {
    id: "send.organizer", group: "Send to", label: "Send the selected exchange to Organizer",
    defaultChord: "mod+o", rebindable: true, burp: "SEND_TO_ORGANISER",
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
  { id: "proxy.forward", group: "Proxy", label: "Forward the held message", defaultChord: "mod+f", rebindable: true, burp: "FORWARD_PROXY_MESSAGE" },
  {
    id: "proxy.toggleIntercept", group: "Proxy", label: "Toggle interception",
    defaultChord: "alt+t", desktopChord: "mod+t", rebindable: true, burp: "TOGGLE_PROXY_INTERCEPTION",
    note: "Burp uses mod+T; browsers reserve it for a new tab. The desktop shell uses Burp's chord",
  },
  { id: "proxy.forwardAll", group: "Proxy", label: "Forward all held messages", defaultChord: null, rebindable: true, burp: "FORWARD_ALL_PROXY_MESSAGES", palette: true, where: "Proxy › Intercept" },
  {
    id: "proxy.dropAll", group: "Proxy", label: "Drop all held messages", defaultChord: null, rebindable: true, burp: "DROP_ALL_PROXY_MESSAGES", palette: true, where: "Proxy › Intercept",
    note: "Asks first, exactly as the toolbar button does — a chord never skips the confirmation",
  },
  {
    id: "proxy.interceptResponse", group: "Proxy", label: "Forward the held request and intercept its response", defaultChord: null, rebindable: true,
    burp: "FORWARD_PROXY_MESSAGE_AND_INTERCEPT_RESPONSE", palette: true, where: "Proxy › Intercept, with a held request selected",
  },

  // ---- Repeater --------------------------------------------------------------------
  {
    id: "repeater.send", group: "Repeater", label: "Send the request in Repeater", defaultChord: "ctrl+space", desktopChord: "ctrl+space", rebindable: true, burp: "ISSUE_REPEATER_REQUEST",
    note: "Burp's Ctrl+Space, as a literal Ctrl on every platform: ⌘+Space is Spotlight on macOS",
  },
  { id: "repeater.sendEnter", group: "Repeater", label: "Send the request in Repeater (second binding)", defaultChord: "mod+enter", rebindable: true, note: "burpsy's own; kept beside Burp's Ctrl+Space" },
  { id: "repeater.historyBack", group: "Repeater", label: "Go back in this tab's request history", defaultChord: null, rebindable: true, burp: "REPEATER_HISTORY_GO_BACK", palette: true, where: "Repeater" },
  { id: "repeater.historyForward", group: "Repeater", label: "Go forward in this tab's request history", defaultChord: null, rebindable: true, burp: "REPEATER_HISTORY_GO_FORWARDS", palette: true, where: "Repeater" },
  { id: "tab.close", group: "Repeater", label: "Close the current tab", defaultChord: null, rebindable: true, burp: "CLOSE_TAB", palette: true, where: "Repeater" },
  { id: "tab.reopen", group: "Repeater", label: "Reopen the last closed tab", defaultChord: null, rebindable: true, burp: "REOPEN_CLOSED_TAB", palette: true, where: "Repeater" },
  { id: "tab.duplicate", group: "Repeater", label: "Duplicate the current tab", defaultChord: null, rebindable: true, burp: "DUPLICATE_TAB", palette: true, where: "Repeater" },
  { id: "tab.next", group: "Repeater", label: "Next tab", defaultChord: null, rebindable: true, burp: "GO_TO_NEXT_TAB", palette: true, where: "Repeater" },
  { id: "tab.prev", group: "Repeater", label: "Previous tab", defaultChord: null, rebindable: true, burp: "GO_TO_PREV_TAB", palette: true, where: "Repeater" },
  { id: "tab.rename", group: "Repeater", label: "Rename the current tab", defaultChord: null, rebindable: true, burp: "RENAME_TAB", palette: true, where: "Repeater" },

  // ---- Intruder --------------------------------------------------------------------
  {
    id: "intruder.startAttack", group: "Intruder", label: "Start the attack", defaultChord: null, rebindable: true, burp: "INTRUDER_START_ATTACK", palette: true, where: "anywhere",
    note: "The Intruder menu's own launch path: the same blockers apply, and it opens Intruder",
  },

  // ---- Message editor --------------------------------------------------------------
  // The codec and search rows are fixed: they live in a CodeMirror keymap and act on the current
  // selection, not on a globally dispatched action. See ui/editor.tsx's burpEditorKeys.
  { id: "editor.urlEncode", group: "Message editor", label: "URL-encode the selection", defaultChord: null, display: ["mod", "U"], rebindable: false, note: "Editor keymap", burp: "EDITOR_URL_ENCODE_KEY_CHARS" },
  { id: "editor.urlDecode", group: "Message editor", label: "URL-decode the selection", defaultChord: null, display: ["mod", "shift", "U"], rebindable: false, note: "Editor keymap", burp: "EDITOR_URL_DECODE" },
  { id: "editor.htmlEncode", group: "Message editor", label: "HTML-encode the selection", defaultChord: null, display: ["mod", "H"], rebindable: false, note: "Editor keymap", burp: "EDITOR_HTML_ENCODE_KEY_CHARS" },
  { id: "editor.htmlDecode", group: "Message editor", label: "HTML-decode the selection", defaultChord: null, display: ["mod", "shift", "H"], rebindable: false, note: "Editor keymap", burp: "EDITOR_HTML_DECODE" },
  { id: "editor.b64Encode", group: "Message editor", label: "Base64-encode the selection", defaultChord: null, display: ["mod", "B"], rebindable: false, note: "Editor keymap", burp: "EDITOR_B64_ENCODE" },
  { id: "editor.b64Decode", group: "Message editor", label: "Base64-decode the selection", defaultChord: null, display: ["mod", "shift", "B"], rebindable: false, note: "Editor keymap", burp: "EDITOR_B64_DECODE" },
  { id: "editor.search", group: "Message editor", label: "Search in the editor", defaultChord: null, display: ["mod", "S"], rebindable: false, note: "Editor keymap", burp: "EDITOR_SEARCH" },
  { id: "editor.prevMatch", group: "Message editor", label: "Previous search match", defaultChord: null, display: ["mod", "comma"], rebindable: false, note: "Editor keymap (CodeMirror findPrevious)", burp: "EDITOR_PREV_MATCH" },
  { id: "editor.nextMatch", group: "Message editor", label: "Next search match", defaultChord: null, display: ["mod", "period"], rebindable: false, note: "Editor keymap (CodeMirror findNext)", burp: "EDITOR_NEXT_MATCH" },
  { id: "editor.copyPrettified", group: "Message editor", label: "Copy prettified", defaultChord: null, display: ["mod", "alt", "C"], rebindable: false, note: "Editor keymap", burp: "EDITOR_COPY_PRETTIFIED" },
  {
    id: "editor.deleteLine", group: "Message editor", label: "Delete the current line", defaultChord: null, display: ["mod", "D"], rebindable: false, burp: "EDITOR_DELETE_LINE",
    note: "Editor keymap, editable editors only. Outside an editor Ctrl+D stays the browser's bookmark key",
  },
  { id: "editor.paragraphUp", group: "Message editor", label: "Previous paragraph (shift extends)", defaultChord: null, display: ["mod", "up"], rebindable: false, note: "Editor keymap; a paragraph ends at a blank line, so headers and body are two", burp: "EDITOR_PREV_PARA" },
  { id: "editor.paragraphDown", group: "Message editor", label: "Next paragraph (shift extends)", defaultChord: null, display: ["mod", "down"], rebindable: false, note: "Editor keymap; a paragraph ends at a blank line, so headers and body are two", burp: "EDITOR_NEXT_PARA" },
  { id: "editor.togglePretty", group: "Message editor", label: "Toggle Pretty and Raw", defaultChord: null, rebindable: true, burp: "EDITOR_TOGGLE_PRETTIFY", palette: true, where: "a message editor (click into one first)" },
  { id: "editor.toggleWrap", group: "Message editor", label: "Toggle line wrap", defaultChord: null, rebindable: true, burp: "EDITOR_TOGGLE_LINE_WRAP", palette: true, where: "a message editor (click into one first)" },
  { id: "editor.toggleNonPrinting", group: "Message editor", label: "Toggle non-printing characters", defaultChord: null, rebindable: true, burp: "EDITOR_TOGGLE_DISPLAY_NON_PRINTABLE_CHARS", palette: true, where: "a message editor (click into one first)" },
  { id: "editor.toggleHideHeaders", group: "Message editor", label: "Toggle hiding uninteresting headers", defaultChord: null, rebindable: true, burp: "EDITOR_TOGGLE_HIDE_UNINTERESTING_HEADERS", palette: true, where: "a message editor (click into one first)" },
  { id: "editor.insertCollaborator", group: "Message editor", label: "Insert a Collaborator payload", defaultChord: null, rebindable: true, burp: "EDITOR_INSERT_COLLABORATOR_PAYLOAD", palette: true, where: "an editable message editor (click into one first)" },
  { id: "editor.toggleSidebar", group: "Message editor", label: "Toggle the Inspector sidebar", defaultChord: null, rebindable: true, burp: "EDITOR_TOGGLE_SIDEBAR", palette: true, where: "anywhere" },
  { id: "editor.cycleLayout", group: "Message editor", label: "Cycle the request/response layout", defaultChord: null, rebindable: true, burp: "EDITOR_CYCLE_REQUEST_RESPONSE_LAYOUT", palette: true, where: "Proxy › HTTP history" },

  // ---- Navigation ------------------------------------------------------------------
  { id: "nav.palette", group: "Navigation", label: "Command palette", defaultChord: "mod+k", rebindable: true, burp: "SHOW_COMMAND_PALETTE", note: "Burp's documented default is also Ctrl+K, so this matches Burp exactly" },
  { id: "nav.switchDashboard", group: "Navigation", label: "Switch to Dashboard", defaultChord: "mod+shift+d", rebindable: true, burp: "SHOW_DASHBOARD" },
  { id: "nav.switchProxy", group: "Navigation", label: "Switch to Proxy", defaultChord: "mod+shift+p", rebindable: true, burp: "SHOW_PROXY", note: "Firefox reserves this chord for a private window; alt+3 works everywhere" },
  { id: "nav.switchRepeater", group: "Navigation", label: "Switch to Repeater", defaultChord: "mod+shift+r", rebindable: true, burp: "SHOW_REPEATER", note: "Claimed from the browser's hard reload; F5 still reloads" },
  { id: "nav.switchLogger", group: "Navigation", label: "Switch to Logger", defaultChord: "mod+shift+l", rebindable: true, burp: "SHOW_LOGGER" },
  { id: "nav.switchOrganizer", group: "Navigation", label: "Switch to Organizer", defaultChord: "mod+shift+o", rebindable: true, burp: "SHOW_ORGANIZER" },
  {
    id: "nav.switchTarget", group: "Navigation", label: "Switch to Target", defaultChord: null, desktopChord: "mod+shift+t", rebindable: true, burp: "SHOW_TARGET",
    note: "Burp uses mod+shift+T, which browsers reserve to reopen a closed tab — alt+2 is the browser binding. The desktop shell uses Burp's chord",
  },
  {
    id: "nav.switchIntruder", group: "Navigation", label: "Switch to Intruder", defaultChord: null, desktopChord: "mod+shift+i", rebindable: true, burp: "SHOW_INTRUDER",
    note: "Burp uses mod+shift+I, which opens the browser's developer tools; claiming it would take DevTools away — alt+4 is the browser binding. The desktop shell uses Burp's chord",
  },
  {
    id: "nav.nextTool", group: "Navigation", label: "Next tool tab", defaultChord: "mod+alt+right", desktopChord: "mod+equal", rebindable: true, burp: "GO_TO_NEXT_TAB",
    note: "Burp uses mod+= — the browser's zoom in. Claiming it would take away text resize (WCAG 1.4.4)",
  },
  {
    id: "nav.prevTool", group: "Navigation", label: "Previous tool tab", defaultChord: "mod+alt+left", desktopChord: "mod+minus", rebindable: true, burp: "GO_TO_PREV_TAB",
    note: "Burp uses mod+- — the browser's zoom out. Claiming it would take away text resize (WCAG 1.4.4)",
  },
  {
    id: "nav.tools", group: "Navigation", label: "Switch to a tool by number",
    defaultChord: null, display: ["alt", "1…0"], rebindable: false,
    note: "Ten bindings driven by nav.ts's own hotkey field",
  },
  { id: "nav.search", group: "Navigation", label: "Search across tools", defaultChord: null, rebindable: true, burp: "OPEN_SEARCH", palette: true, where: "anywhere" },
  { id: "nav.settings", group: "Navigation", label: "Show settings", defaultChord: null, rebindable: true, burp: "SHOW_SETTINGS", palette: true, where: "anywhere" },
  { id: "tasks.toggle", group: "Navigation", label: "Pause or resume task execution", defaultChord: null, rebindable: true, burp: "TOGGLE_TASK_EXECUTION", palette: true, where: "anywhere" },
  { id: "nav.tableMove", group: "Navigation", label: "Move through the table (shift extends the selection)", defaultChord: null, display: ["↑", "↓"], rebindable: false, note: "Listbox keys" },
  { id: "nav.tablePage", group: "Navigation", label: "Move a page through the table", defaultChord: null, display: ["PgUp", "PgDn"], rebindable: false, note: "Listbox keys" },
  { id: "nav.tableEnds", group: "Navigation", label: "First or last row", defaultChord: null, display: ["Home", "End"], rebindable: false, note: "Listbox keys; Burp's TABLE_GO_TO_TOP and TABLE_GO_TO_BOTTOM" },
  { id: "nav.tableSelectAll", group: "Navigation", label: "Select every row in the table", defaultChord: null, display: ["mod", "A"], rebindable: false, note: "With the table focused; inside a field it selects the field's text" },

  // ---- Appearance and help ---------------------------------------------------------
  {
    id: "view.toggleTheme", group: "Appearance and help", label: "Toggle light and dark theme", defaultChord: null, rebindable: true,
    note: "Unbound by default: mod+shift+L is Burp's Switch to Logger, and Burp ships no theme chord. Still in the palette",
  },
  { id: "help.shortcuts", group: "Appearance and help", label: "Show the shortcut list", defaultChord: "shift+slash", display: ["?"], rebindable: true },
];

/** Which shell the console runs in: the browser, or the Wails desktop shell (no reserved keys). */
export type Platform = "web" | "desktop";

/** Read once: the shell does not change under a running page. */
const PLATFORM: Platform = typeof window !== "undefined" && (window as unknown as { runtime?: unknown }).runtime ? "desktop" : "web";

/** The shipped binding for an action on a platform. */
export function defaultChordFor(action: ShortcutAction, platform: Platform = PLATFORM): Chord | null {
  return platform === "desktop" && action.desktopChord !== undefined ? action.desktopChord : action.defaultChord;
}

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
export function actionForChord(keymap: Keymap, chord: Chord, exceptId?: string, platform: Platform = PLATFORM): ShortcutAction | null {
  for (const action of REBINDABLE) {
    if (action.id === exceptId) continue;
    if (chordFor(keymap, action.id, platform) === chord) return action;
  }
  return null;
}

/** The chord in force for an action: the operator's override if set, else the default. */
export function chordFor(keymap: Keymap, id: string, platform: Platform = PLATFORM): Chord | null {
  if (Object.prototype.hasOwnProperty.call(keymap, id)) return keymap[id] ?? null;
  const action = byId.get(id);
  return action ? defaultChordFor(action, platform) : null;
}

/** The registry row for an id. */
export function shortcutAction(id: string): ShortcutAction | undefined {
  return byId.get(id);
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
  // `ctrl` is the literal Control key on every platform, where `mod` is ⌘ on macOS. It exists for
  // Burp's Ctrl+Space, whose ⌘ form is Spotlight.
  const mods = parts.filter((p) => p === "mod" || p === "ctrl" || p === "shift" || p === "alt");
  const keys = parts.filter((p) => !["mod", "ctrl", "shift", "alt"].includes(p));
  if (keys.length === 0) return { error: "A modifier on its own is not a shortcut — add a key" };
  if (keys.length > 1) return { error: `Only one non-modifier key: got ${keys.join(" and ")}` };
  if (!mods.includes("mod") && !mods.includes("ctrl") && !mods.includes("alt")) {
    return { error: "Must include mod (Ctrl/Cmd) or alt — a bare key would fire while typing" };
  }
  // Canonical modifier order, typed as the literal union so the array is not widened to string[]
  // — that widening is what let this line typecheck-fail once typescript was actually available.
  const ORDER = ["mod", "ctrl", "alt", "shift"] as const;
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
