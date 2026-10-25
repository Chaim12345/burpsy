/**
 * Multi-row table selection as a pure reducer (burpsy-react-ui-fe16).
 *
 * Burp's tables are Swing JTables with the default multiple-interval selection model: click
 * selects one row, Ctrl/Cmd-click toggles one, Shift-click selects the range from the anchor,
 * Shift+arrow extends it, Ctrl+A selects everything. Its context menus then branch on the
 * selection size — Zr2s.java builds "Delete selected items", "Copy URLs" and a multi-item
 * "Send to Comparer" when `var1.size() > 1`.
 *
 * Every operation here takes `order`: the row ids as DISPLAYED, after sort and filter. A range is
 * a range on screen, so computing it over the data array instead would select rows the operator
 * never saw between the two they clicked, the moment a column is sorted.
 *
 * `focus` is the row the keyboard is on and the one the detail pane shows (VirtualTable's
 * `selectedId`); `anchor` is where a Shift range starts. Both are ids, not indexes, so a re-sort
 * or a poll that inserts rows above them does not silently move them.
 */

export interface SelectionState {
 /** Selected row ids, in the displayed order at the time of the last operation. */
 ids: string[];
 anchor: string | null;
 focus: string | null;
}

export const EMPTY_SELECTION: SelectionState = { ids: [], anchor: null, focus: null };

export type SelectionAction =
 /** Plain click, or plain arrow movement: exactly this row. */
 | { type: "only"; id: string }
 /** Ctrl/Cmd-click: add or remove this row, leaving the rest. The anchor moves here. */
 | { type: "toggle"; id: string }
 /** Shift-click: anchor..id inclusive, replacing the selection. The anchor stays. */
 | { type: "range"; id: string }
 /** Shift+arrow / Shift+Page / Shift+Home/End: move focus and select anchor..focus. */
 | { type: "extend"; delta: number | "start" | "end" }
 /** Plain arrow / Page / Home / End: move focus and select only it. */
 | { type: "move"; delta: number | "start" | "end" }
 /** Ctrl+A. */
 | { type: "all" }
 /** The displayed rows changed (filter, poll, delete): drop ids no longer shown. */
 | { type: "prune" }
 /** Replace from outside (a store write, "select none"). */
 | { type: "set"; ids: string[]; focus?: string | null };

/** Keep `ids` in displayed order and drop any not displayed. */
function inOrder(ids: Iterable<string>, order: readonly string[]): string[] {
 const wanted = new Set(ids);
 return order.filter((id) => wanted.has(id));
}

function stepIndex(order: readonly string[], from: string | null, delta: number | "start" | "end"): number {
 if (order.length === 0) return -1;
 if (delta === "start") return 0;
 if (delta === "end") return order.length - 1;
 const at = from === null ? -1 : order.indexOf(from);
 // No focus yet: the first step down lands on the first row, the first step up on the last —
 // the same thing VirtualTable's single-selection `move` did.
 if (at < 0) return delta > 0 ? 0 : order.length - 1;
 return Math.min(order.length - 1, Math.max(0, at + delta));
}

function rangeIds(order: readonly string[], anchor: string | null, to: string): string[] {
 const end = order.indexOf(to);
 if (end < 0) return [];
 const start = anchor === null ? -1 : order.indexOf(anchor);
 // An anchor that is no longer displayed (filtered away) degrades to a single-row range rather
 // than reaching back to a row the operator cannot see.
 if (start < 0) return [to];
 const [lo, hi] = start <= end ? [start, end] : [end, start];
 return order.slice(lo, hi + 1);
}

export function reduceSelection(state: SelectionState, action: SelectionAction, order: readonly string[]): SelectionState {
 switch (action.type) {
  case "only":
   if (!order.includes(action.id)) return state;
   return { ids: [action.id], anchor: action.id, focus: action.id };
  case "toggle": {
   if (!order.includes(action.id)) return state;
   const has = state.ids.includes(action.id);
   const ids = has ? state.ids.filter((id) => id !== action.id) : inOrder([...state.ids, action.id], order);
   return { ids, anchor: action.id, focus: action.id };
  }
  case "range": {
   if (!order.includes(action.id)) return state;
   const anchor = state.anchor ?? state.focus;
   return {
    ids: rangeIds(order, anchor, action.id),
    anchor: anchor !== null && order.includes(anchor) ? anchor : action.id,
    focus: action.id,
   };
  }
  case "extend": {
   const at = stepIndex(order, state.focus, action.delta);
   if (at < 0) return state;
   const focus = order[at]!;
   const anchor = state.anchor !== null && order.includes(state.anchor) ? state.anchor : (state.focus ?? focus);
   return { ids: rangeIds(order, anchor, focus), anchor, focus };
  }
  case "move": {
   const at = stepIndex(order, state.focus, action.delta);
   if (at < 0) return state;
   const focus = order[at]!;
   return { ids: [focus], anchor: focus, focus };
  }
  case "all":
   return { ids: [...order], anchor: state.anchor ?? order[0] ?? null, focus: state.focus ?? order[0] ?? null };
  case "prune": {
   const ids = inOrder(state.ids, order);
   const keep = (id: string | null) => (id !== null && order.includes(id) ? id : null);
   return { ids, anchor: keep(state.anchor), focus: keep(state.focus) };
  }
  case "set": {
   const ids = inOrder(action.ids, order);
   const focus = action.focus === undefined ? state.focus : action.focus;
   return { ids, anchor: focus, focus };
  }
  default:
   return state;
 }
}

/** Which action a click with these modifiers means. `mod` is Ctrl on Windows/Linux, Cmd on macOS. */
export function clickAction(id: string, modifiers: { shift: boolean; mod: boolean }): SelectionAction {
 if (modifiers.shift) return { type: "range", id };
 if (modifiers.mod) return { type: "toggle", id };
 return { type: "only", id };
}

/**
 * Whether a right-click on `id` should keep the current selection. Burp (and every desktop table)
 * keeps a multi-selection when the click lands inside it, so the N-row menu is reachable at all;
 * a right-click outside it selects just that row, so the menu acts on what was clicked.
 */
export function contextKeepsSelection(state: SelectionState, id: string): boolean {
 return state.ids.length > 1 && state.ids.includes(id);
}

/** Two selections with the same ids in the same order. Lets callers skip no-op store writes. */
export function sameIds(a: readonly string[], b: readonly string[]): boolean {
 return a.length === b.length && a.every((id, index) => id === b[index]);
}
