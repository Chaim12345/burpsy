/**
 * The keyboard-shortcut registry: one source of truth for the shortcuts modal
 * and the Settings page's Hotkeys section. Burp's bindings, kept where a browser
 * allows it — the exceptions are called out rather than silently changed, because
 * a Burp user's muscle memory is the point.
 */
export interface ShortcutRow {
  keys: string[];
  label: string;
  /** Set when the binding differs from Burp's, so the reason is visible. */
  note?: string;
}

export const SHORTCUT_GROUPS: { title: string; rows: ShortcutRow[] }[] = [
  {
    title: "Send to",
    rows: [
      { keys: ["mod", "R"], label: "Send the selected exchange to Repeater" },
      { keys: ["mod", "I"], label: "Send the selected exchange to Intruder" },
      { keys: ["Enter"], label: "Send the focused row to Repeater" },
      { keys: ["right-click"], label: "All send-to and copy actions for a row" },
    ],
  },
  {
    title: "Proxy",
    rows: [
      { keys: ["mod", "F"], label: "Forward the held message" },
      { keys: ["alt", "T"], label: "Toggle interception", note: "Burp uses mod+T; browsers reserve it for a new tab" },
    ],
  },
  {
    title: "Message editor",
    rows: [
      { keys: ["mod", "U"], label: "URL-encode the selection" },
      { keys: ["mod", "shift", "U"], label: "URL-decode the selection" },
      { keys: ["mod", "H"], label: "HTML-encode the selection" },
      { keys: ["mod", "shift", "H"], label: "HTML-decode the selection" },
      { keys: ["mod", "B"], label: "Base64-encode the selection" },
      { keys: ["mod", "shift", "B"], label: "Base64-decode the selection" },
      { keys: ["mod", "S"], label: "Search in the editor" },
      { keys: ["mod", "Enter"], label: "Send the request in Repeater" },
    ],
  },
  {
    title: "Navigation",
    rows: [
      { keys: ["mod", "K"], label: "Command palette" },
      {
        keys: ["alt", "1…0"],
        label: "Switch tool",
        note: "Burp uses mod+shift+letter; browsers reserve most of those",
      },
      { keys: ["↑", "↓"], label: "Move through the table" },
      { keys: ["PgUp", "PgDn"], label: "Move a page through the table" },
      { keys: ["Home", "End"], label: "First or last row" },
    ],
  },
  {
    title: "Appearance and help",
    rows: [
      { keys: ["mod", "shift", "L"], label: "Toggle light and dark theme" },
      { keys: ["?"], label: "Show this list" },
    ],
  },
];
