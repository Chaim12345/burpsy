/**
 * Burp's shipped hotkey table, row by row, and what burpsy does with each (2czi).
 *
 * Source: Preferences/UserDefaults.json in the Burp 2026.7 jar (user_options.misc.hotkeys, 50 rows:
 * /root/burp-re/in/extract/resources/Preferences/UserDefaults.json). That is the 47 rows an installed
 * Burp persists in UserConfigPro.json plus the three Burp AI rows. Every other action in Burp's
 * catalogue (Zipf.java, ~190) ships with no chord and is reachable from the palette, as it is here.
 *
 * Each row has exactly one disposition:
 *   - "same": burpsy binds Burp's chord. `chord` is that chord in burpsy's vocabulary.
 *   - "alternative": the browser forces a different chord (or claiming Burp's would cost something
 *     worse — DevTools, text zoom). `chord` is the one burpsy binds, `reason` says why, and the
 *     desktop shell (no browser in the way) binds Burp's own via the registry's `desktopChord`.
 *   - "declined": burpsy does not have the feature. No chord.
 *
 * Browser tiers are stated per row in `reason`, and the Chromium ones are MEASURED: real X key
 * events (xdotool over XTEST) into headed Chromium under Xvfb, 2026-10-08, with a probe page that
 * preventDefaults every keydown. Of the 24 chords probed, only Ctrl+T never reached the page (a new
 * tab opened). Ctrl+Shift+T reached it too, but only because no closed tab existed to reopen; it is
 * Chromium's reopen-closed-tab command and is not relied on. Ctrl+Minus/Equals and Ctrl+Shift+I
 * reached the page and were preventable — declining them is policy (text zoom, DevTools), not
 * feasibility. CDP-dispatched keys (Playwright's keyboard.press) skip the browser's accelerator
 * layer entirely, which is why the probe used X events. Firefox was not measured with real keys:
 * its window never mapped under Xvfb with the available build. Its rows cite Firefox's own
 * reserved-key list instead and say so.
 */
import type { Chord } from "./shortcuts";

export type Disposition = "same" | "alternative" | "declined";

export interface BurpHotkey {
 /** Burp's id, as UserDefaults.json spells it. */
 action: string;
 /** Burp's chord, as UserDefaults.json spells it. */
 burpChord: string;
 disposition: Disposition;
 /**
  * The burpsy registry row that implements it (lib/shortcuts.ts), or "native" when CodeMirror or
  * the browser already does it inside the message editor, or null when declined.
  */
 burpsyId: string | "native" | null;
 /** The chord burpsy binds, in its own vocabulary. Null only when declined. */
 chord: Chord | null;
 reason: string;
}

const CM = "CodeMirror's standard keymap, inside the message editor (on macOS the platform's own ⌘/⌥ forms)";

export const BURP_HOTKEYS: BurpHotkey[] = [
 {
  action: "send_to_repeater",
  burpChord: "Ctrl+R",
  disposition: "same",
  burpsyId: "send.repeater",
  chord: "mod+r",
  reason: "Claimed with preventDefault on every table page; reload is not a reserved browser key, and F5 still reloads",
 },
 {
  action: "send_to_intruder",
  burpChord: "Ctrl+I",
  disposition: "same",
  burpsyId: "send.intruder",
  chord: "mod+i",
  reason: "Claimed on every table page",
 },
 {
  action: "send_to_organizer",
  burpChord: "Ctrl+O",
  disposition: "same",
  burpsyId: "send.organizer",
  chord: "mod+o",
  reason: "Claimed on every table page; the browser's Open file is not reserved",
 },
 {
  action: "forward_intercepted_proxy_message",
  burpChord: "Ctrl+F",
  disposition: "same",
  burpsyId: "proxy.forward",
  chord: "mod+f",
  reason: "Claimed on Proxy › Intercept while a message is held; find-in-page works everywhere else",
 },
 {
  action: "toggle_proxy_interception",
  burpChord: "Ctrl+T",
  disposition: "alternative",
  burpsyId: "proxy.toggleIntercept",
  chord: "alt+t",
  reason:
   "Ctrl+T is reserved by the browser: measured in Chromium with real key events, a new tab opened and the page never received the key. The desktop shell binds Ctrl+T",
 },
 {
  action: "issue_repeater_request",
  burpChord: "Ctrl+Space",
  disposition: "same",
  burpsyId: "repeater.send",
  chord: "ctrl+space",
  reason: "A literal Ctrl on every platform — ⌘+Space is Spotlight on macOS. mod+Enter stays as a second binding",
 },
 {
  action: "switch_to_dashboard",
  burpChord: "Ctrl+Shift+D",
  disposition: "same",
  burpsyId: "nav.switchDashboard",
  chord: "mod+shift+d",
  reason: "Claimed from the browser's bookmark-all-tabs, which is not reserved",
 },
 {
  action: "switch_to_target",
  burpChord: "Ctrl+Shift+T",
  disposition: "alternative",
  burpsyId: "nav.tools",
  chord: "alt+2",
  reason:
   "Ctrl+Shift+T is the browser's reopen-closed-tab command. Chromium let the probe page have it only because no closed tab existed, so it is not relied on. alt+2 switches to Target; the desktop shell binds Ctrl+Shift+T",
 },
 {
  action: "switch_to_proxy",
  burpChord: "Ctrl+Shift+P",
  disposition: "same",
  burpsyId: "nav.switchProxy",
  chord: "mod+shift+p",
  reason:
   "Measured claimable in Chromium. Firefox's reserved-key list includes it (private window; not measured here), so Firefox users have alt+3",
 },
 {
  action: "switch_to_intruder",
  burpChord: "Ctrl+Shift+I",
  disposition: "alternative",
  burpsyId: "nav.tools",
  chord: "alt+4",
  reason:
   "Measured claimable in Chromium, but it is the developer-tools key and claiming it would take DevTools away. alt+4 switches to Intruder; the desktop shell binds Ctrl+Shift+I",
 },
 {
  action: "switch_to_repeater",
  burpChord: "Ctrl+Shift+R",
  disposition: "same",
  burpsyId: "nav.switchRepeater",
  chord: "mod+shift+r",
  reason: "Claimed from the browser's hard reload, which is not reserved",
 },
 {
  action: "switch_to_logger",
  burpChord: "Ctrl+Shift+L",
  disposition: "same",
  burpsyId: "nav.switchLogger",
  chord: "mod+shift+l",
  reason: "Was burpsy's theme toggle; the theme moved to the palette, since Burp ships no theme chord",
 },
 {
  action: "switch_to_organizer",
  burpChord: "Ctrl+Shift+O",
  disposition: "same",
  burpsyId: "nav.switchOrganizer",
  chord: "mod+shift+o",
  reason: "Claimed from the browser's bookmark manager, which is not reserved",
 },
 {
  action: "go_to_previous_tab",
  burpChord: "Ctrl+Minus",
  disposition: "alternative",
  burpsyId: "nav.prevTool",
  chord: "mod+alt+left",
  reason:
   "Measured claimable in Chromium, but it is the browser's zoom out and claiming it would take away text resize (WCAG 1.4.4). The desktop shell binds Ctrl+Minus",
 },
 {
  action: "go_to_next_tab",
  burpChord: "Ctrl+Equals",
  disposition: "alternative",
  burpsyId: "nav.nextTool",
  chord: "mod+alt+right",
  reason:
   "Measured claimable in Chromium, but it is the browser's zoom in and claiming it would take away text resize (WCAG 1.4.4). The desktop shell binds Ctrl+Equals",
 },
 {
  action: "open_command_palette",
  burpChord: "Ctrl+K",
  disposition: "same",
  burpsyId: "nav.palette",
  chord: "mod+k",
  reason: "Claimed everywhere, including inside the editor",
 },
 { action: "editor_cut", burpChord: "Ctrl+X", disposition: "same", burpsyId: "native", chord: "mod+x", reason: CM },
 { action: "editor_copy", burpChord: "Ctrl+C", disposition: "same", burpsyId: "native", chord: "mod+c", reason: CM },
 {
  action: "editor_copy_prettified",
  burpChord: "Ctrl+Alt+C",
  disposition: "same",
  burpsyId: "editor.copyPrettified",
  chord: "mod+alt+c",
  reason: "Editor keymap: the selection as shown, or the whole message prettified",
 },
 { action: "editor_paste", burpChord: "Ctrl+V", disposition: "same", burpsyId: "native", chord: "mod+v", reason: CM },
 { action: "editor_undo", burpChord: "Ctrl+Z", disposition: "same", burpsyId: "native", chord: "mod+z", reason: CM },
 { action: "editor_redo", burpChord: "Ctrl+Y", disposition: "same", burpsyId: "native", chord: "mod+y", reason: CM },
 { action: "editor_select_all", burpChord: "Ctrl+A", disposition: "same", burpsyId: "native", chord: "mod+a", reason: CM },
 {
  action: "editor_search",
  burpChord: "Ctrl+S",
  disposition: "same",
  burpsyId: "editor.search",
  chord: "mod+s",
  reason: "Editor keymap; opens the search panel instead of the browser's Save page",
 },
 {
  action: "editor_go_to_previous_search_match",
  burpChord: "Ctrl+Comma",
  disposition: "same",
  burpsyId: "editor.prevMatch",
  chord: "mod+comma",
  reason: "Editor keymap (CodeMirror findPrevious); opens search when there is none yet",
 },
 {
  action: "editor_go_to_next_search_match",
  burpChord: "Ctrl+Period",
  disposition: "same",
  burpsyId: "editor.nextMatch",
  chord: "mod+period",
  reason: "Editor keymap (CodeMirror findNext); opens search when there is none yet",
 },
 {
  action: "editor_url_decode",
  burpChord: "Ctrl+Shift+U",
  disposition: "same",
  burpsyId: "editor.urlDecode",
  chord: "mod+shift+u",
  reason: "Editor keymap, on the selection",
 },
 {
  action: "editor_url_encode_key_characters",
  burpChord: "Ctrl+U",
  disposition: "same",
  burpsyId: "editor.urlEncode",
  chord: "mod+u",
  reason: "Editor keymap, on the selection; view-source keeps the key outside the editor",
 },
 {
  action: "editor_html_decode",
  burpChord: "Ctrl+Shift+H",
  disposition: "same",
  burpsyId: "editor.htmlDecode",
  chord: "mod+shift+h",
  reason: "Editor keymap, on the selection",
 },
 {
  action: "editor_html_encode_key_characters",
  burpChord: "Ctrl+H",
  disposition: "same",
  burpsyId: "editor.htmlEncode",
  chord: "mod+h",
  reason: "Editor keymap, on the selection",
 },
 {
  action: "editor_base64_decode",
  burpChord: "Ctrl+Shift+B",
  disposition: "same",
  burpsyId: "editor.b64Decode",
  chord: "mod+shift+b",
  reason: "Editor keymap, on the selection",
 },
 {
  action: "editor_base64_encode",
  burpChord: "Ctrl+B",
  disposition: "same",
  burpsyId: "editor.b64Encode",
  chord: "mod+b",
  reason: "Editor keymap, on the selection",
 },
 {
  action: "editor_backspace_word",
  burpChord: "Ctrl+Backspace",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+backspace",
  reason: CM,
 },
 { action: "editor_delete_word", burpChord: "Ctrl+Delete", disposition: "same", burpsyId: "native", chord: "mod+delete", reason: CM },
 {
  action: "editor_delete_line",
  burpChord: "Ctrl+D",
  disposition: "same",
  burpsyId: "editor.deleteLine",
  chord: "mod+d",
  reason:
   "Editor keymap, editable editors only; it displaces CodeMirror's select-next-occurrence there. Outside an editor Ctrl+D stays the browser's bookmark key",
 },
 { action: "editor_go_to_previous_word", burpChord: "Ctrl+Left", disposition: "same", burpsyId: "native", chord: "mod+left", reason: CM },
 {
  action: "editor_go_to_previous_word_extend_selection",
  burpChord: "Ctrl+Shift+Left",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+shift+left",
  reason: CM,
 },
 { action: "editor_go_to_next_word", burpChord: "Ctrl+Right", disposition: "same", burpsyId: "native", chord: "mod+right", reason: CM },
 {
  action: "editor_go_to_next_word_extend_selection",
  burpChord: "Ctrl+Shift+Right",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+shift+right",
  reason: CM,
 },
 {
  action: "editor_go_to_previous_paragraph",
  burpChord: "Ctrl+Up",
  disposition: "same",
  burpsyId: "editor.paragraphUp",
  chord: "mod+up",
  reason: "Editor keymap; a paragraph ends at a blank line",
 },
 {
  action: "editor_go_to_previous_paragraph_extend_selection",
  burpChord: "Ctrl+Shift+Up",
  disposition: "same",
  burpsyId: "editor.paragraphUp",
  chord: "mod+shift+up",
  reason: "Editor keymap; Shift extends the selection",
 },
 {
  action: "editor_go_to_next_paragraph",
  burpChord: "Ctrl+Down",
  disposition: "same",
  burpsyId: "editor.paragraphDown",
  chord: "mod+down",
  reason: "Editor keymap; a paragraph ends at a blank line",
 },
 {
  action: "editor_go_to_next_paragraph_extend_selection",
  burpChord: "Ctrl+Shift+Down",
  disposition: "same",
  burpsyId: "editor.paragraphDown",
  chord: "mod+shift+down",
  reason: "Editor keymap; Shift extends the selection",
 },
 {
  action: "editor_go_to_start_of_document",
  burpChord: "Ctrl+Home",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+home",
  reason: CM,
 },
 {
  action: "editor_go_to_start_of_document_extend_selection",
  burpChord: "Ctrl+Shift+Home",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+shift+home",
  reason: CM,
 },
 { action: "editor_go_to_end_of_document", burpChord: "Ctrl+End", disposition: "same", burpsyId: "native", chord: "mod+end", reason: CM },
 {
  action: "editor_go_to_end_of_document_extend_selection",
  burpChord: "Ctrl+Shift+End",
  disposition: "same",
  burpsyId: "native",
  chord: "mod+shift+end",
  reason: CM,
 },
 {
  action: "explain_this",
  burpChord: "Ctrl+E",
  disposition: "declined",
  burpsyId: null,
  chord: null,
  reason: "Burp AI. burpsy has no Burp AI and no PortSwigger account (declined in gaps.md, burpsy-react-ui-9g5y)",
 },
 {
  action: "send_to_burp_at",
  burpChord: "Ctrl+G",
  disposition: "declined",
  burpsyId: null,
  chord: null,
  reason: "Burp AI. burpsy has no Burp AI and no PortSwigger account (declined in gaps.md, burpsy-react-ui-9g5y)",
 },
 {
  action: "open_burp_at",
  burpChord: "Ctrl+Shift+G",
  disposition: "declined",
  burpsyId: null,
  chord: null,
  reason: "Burp AI. burpsy has no Burp AI and no PortSwigger account (declined in gaps.md, burpsy-react-ui-9g5y)",
 },
];

/** Burp's chord in burpsy's vocabulary: "Ctrl+Shift+D" → "mod+shift+d", "Ctrl+Equals" → "mod+equal". */
export function burpChordToChord(burpChord: string): Chord {
 const names: Record<string, string> = { ctrl: "mod", equals: "equal", backspace: "backspace", delete: "delete" };
 return burpChord
  .split("+")
  .map((part) => {
   const lower = part.trim().toLowerCase();
   return names[lower] ?? lower;
  })
  .join("+");
}

/** Whether two chords name the same keys. `ctrl` and `mod` are the same key off macOS, which is
 *  Burp's own platform reading of its Ctrl chords. */
export function sameChord(a: Chord, b: Chord): boolean {
 const norm = (chord: Chord) =>
  chord
   .split("+")
   .map((part) => (part === "ctrl" ? "mod" : part))
   .sort()
   .join("+");
 return norm(a) === norm(b);
}
