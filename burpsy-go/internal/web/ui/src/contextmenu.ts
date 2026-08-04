// One right-click menu, shared by every pane that has rows. Before this existed the send-to-Repeater
// / send-to-Intruder / send-to-Comparer hand-offs were reachable only from buttons rendered inside
// History's row — an operator who never clicked into a row never learnt they existed, which is the
// complaint this module answers. The plumbing (`emit`/`on`, the EVT_SEND_TO_* events) was already
// there; only the way in was missing.
//
// Two deliberate choices:
//
//  * The menu is attached to a *container* and matches rows by selector, not to the rows themselves.
//    Every pane here re-renders its table by assigning `innerHTML`, which would throw away per-row
//    listeners on the next Refresh; a delegated listener on the container survives that, so a pane
//    wires the menu exactly once in its init().
//
//  * `items()` returning an empty list means "not mine": the native browser menu is left alone.
//    preventDefault() is called only once we know we are drawing something, so right-clicking a
//    table header, a hint line or a <pre> still gets Copy/Inspect/Save-as like any other page.

/** One row of the menu. A separator ignores every other field. */
export interface MenuItem {
  label?: string;
  /** Right-aligned keyboard hint, e.g. "Ctrl+R". Display only — the binding lives in shortcuts.ts. */
  hint?: string;
  separator?: boolean;
  /** Drawn dimmed and unselectable. Use with `label` saying *why*, never as a silent no-op. */
  disabled?: boolean;
  run?: () => void | Promise<void>;
}

const MENU_ID = "ctx-menu";
/** Keeps the menu clear of the viewport edge it is being flipped away from. */
const EDGE_MARGIN = 4;

let openMenu: HTMLElement | null = null;

/** True while a menu is on screen. shortcuts.ts consults this so a global binding cannot fire
 * underneath an open menu — arrow keys and Enter belong to the menu while it is up. */
export function isContextMenuOpen(): boolean {
  return openMenu !== null;
}

function closeContextMenu(): void {
  if (!openMenu) return;
  openMenu.remove();
  openMenu = null;
  document.removeEventListener("pointerdown", onOutsidePointer, true);
  document.removeEventListener("keydown", onMenuKey, true);
  // Capture on scroll: scrolling happens on whichever element is under the pointer, and a menu
  // anchored to fixed viewport coordinates would otherwise slide away from the row it belongs to.
  window.removeEventListener("scroll", closeContextMenu, true);
  window.removeEventListener("resize", closeContextMenu);
  window.removeEventListener("blur", closeContextMenu);
}

/** Opens a menu at viewport coordinates. Any menu already open is replaced. */
function showContextMenu(x: number, y: number, items: MenuItem[], heading?: string): void {
  closeContextMenu();
  const drawable = items.filter((i) => i.separator || i.label);
  if (drawable.length === 0) return;

  const el = document.createElement("div");
  el.id = MENU_ID;
  el.setAttribute("role", "menu");
  el.tabIndex = -1;
  if (heading) {
    const h = document.createElement("div");
    h.className = "ctx-head";
    h.textContent = heading;
    el.appendChild(h);
  }
  for (const item of drawable) {
    if (item.separator) {
      const sep = document.createElement("div");
      sep.className = "ctx-sep";
      el.appendChild(sep);
      continue;
    }
    // A <button> rather than a styled <div>: Enter and Space activate it natively once focused, so
    // keyboard operation is the browser's job rather than a re-implementation that can drift.
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ctx-item";
    btn.setAttribute("role", "menuitem");
    btn.disabled = item.disabled === true;
    btn.tabIndex = -1;
    const label = document.createElement("span");
    label.textContent = item.label ?? "";
    btn.appendChild(label);
    if (item.hint) {
      const hint = document.createElement("span");
      hint.className = "ctx-hint";
      hint.textContent = item.hint;
      btn.appendChild(hint);
    }
    // Hover moves focus so the keyboard's notion of "current item" and the mouse's agree; a menu
    // where arrow-down resumes from somewhere the pointer has since left is its own small bug.
    btn.addEventListener("mouseenter", () => btn.focus());
    btn.addEventListener("click", () => {
      // Close first: the action may switch tabs or raise a toast, and both read better against a
      // screen the menu is no longer covering.
      const run = item.run;
      closeContextMenu();
      if (run) void run();
    });
    el.appendChild(btn);
  }

  // Right-clicking the menu itself is swallowed. Without this the browser's own menu opens on top of
  // ours, which is both ugly and a way to end up with two menus fighting over the same click.
  el.addEventListener("contextmenu", (e) => e.preventDefault());
  // Off-screen at first paint so the measurement below cannot flash the menu at the wrong corner.
  el.style.left = "-9999px";
  el.style.top = "0";
  document.body.appendChild(el);
  position(el, x, y);
  openMenu = el;

  document.addEventListener("pointerdown", onOutsidePointer, true);
  document.addEventListener("keydown", onMenuKey, true);
  window.addEventListener("scroll", closeContextMenu, true);
  window.addEventListener("resize", closeContextMenu);
  window.addEventListener("blur", closeContextMenu);

  // Focus the menu itself, not its first item: opening on the first entry invites an accidental
  // Enter on whatever happens to be at the top. Arrow-down is the deliberate first step.
  el.focus({ preventScroll: true });
}

/** Places the menu at (x, y), flipping it back over the anchor when it would leave the viewport. */
function position(el: HTMLElement, x: number, y: number): void {
  const r = el.getBoundingClientRect();
  const maxX = window.innerWidth - EDGE_MARGIN;
  const maxY = window.innerHeight - EDGE_MARGIN;
  let left = x;
  let top = y;
  if (left + r.width > maxX) left = x - r.width;
  if (top + r.height > maxY) top = y - r.height;
  // A menu taller or wider than the viewport cannot be flipped into it; clamp to the near edge and
  // let the CSS max-height scroll it rather than pushing it off the top-left.
  el.style.left = `${Math.max(EDGE_MARGIN, left)}px`;
  el.style.top = `${Math.max(EDGE_MARGIN, top)}px`;
}

function itemsOf(menu: HTMLElement): HTMLButtonElement[] {
  return Array.from(menu.querySelectorAll<HTMLButtonElement>(".ctx-item:not(:disabled)"));
}

function onOutsidePointer(e: PointerEvent): void {
  if (openMenu && !openMenu.contains(e.target as Node)) closeContextMenu();
}

/** Arrow/Home/End/Escape while the menu is up. Registered in the capture phase and stopping
 * propagation, so the global shortcut handler never sees these keys. */
function onMenuKey(e: KeyboardEvent): void {
  const menu = openMenu;
  if (!menu) return;
  if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    closeContextMenu();
    return;
  }
  if (e.key === "Tab") {
    // Tabbing out of a context menu means dismissing it, not walking the page behind it.
    e.preventDefault();
    e.stopPropagation();
    closeContextMenu();
    return;
  }
  const keys = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keys.includes(e.key)) return;
  const entries = itemsOf(menu);
  if (entries.length === 0) return;
  e.preventDefault();
  e.stopPropagation();
  const current = entries.findIndex((b) => b === document.activeElement);
  let next: number;
  switch (e.key) {
    case "Home":
      next = 0;
      break;
    case "End":
      next = entries.length - 1;
      break;
    case "ArrowUp":
      next = current <= 0 ? entries.length - 1 : current - 1;
      break;
    default:
      next = current === -1 || current === entries.length - 1 ? 0 : current + 1;
  }
  entries[next]?.focus();
}

export interface RowContextMenuOptions<T> {
  /** Selector for the element the rows live in, or the element itself. */
  container: string | HTMLElement;
  /** Selector a right-click target must be inside of to count as a row, e.g. `tr[data-id]`. */
  rowSelector: string;
  /** The model this row stands for, or null when the row is not one we can act on (a "no rows yet"
   * placeholder, a spanning error cell) — the native menu is then left alone. */
  resolve: (row: HTMLElement) => T | null;
  /** The menu for that row. Return an empty array to fall through to the native menu. */
  items: (model: T, row: HTMLElement) => MenuItem[];
  /** Optional heading drawn above the items, e.g. "exchange #42". */
  heading?: (model: T, row: HTMLElement) => string;
  /** Called before the menu opens. Panes use this to select the row, the way a table normally
   * behaves — right-clicking something and then acting on a *different* selection is a trap. */
  select?: (model: T, row: HTMLElement) => void;
}

/** Wires one delegated right-click menu over a pane's rows. Call once from the pane's init(). */
export function attachRowContextMenu<T>(opts: RowContextMenuOptions<T>): void {
  const container =
    typeof opts.container === "string" ? document.querySelector<HTMLElement>(opts.container) : opts.container;
  if (!container) return;
  container.addEventListener("contextmenu", (e: MouseEvent) => {
    const row = (e.target as HTMLElement | null)?.closest<HTMLElement>(opts.rowSelector);
    if (!row || !container.contains(row)) return;
    const model = opts.resolve(row);
    if (model === null) return;
    const items = opts.items(model, row);
    if (items.length === 0) return;
    e.preventDefault();
    opts.select?.(model, row);
    showContextMenu(e.clientX, e.clientY, items, opts.heading?.(model, row));
  });
}
