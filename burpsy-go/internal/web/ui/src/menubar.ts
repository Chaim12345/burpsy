// Top-level menu bar: File / Project / Help dropdowns. Each menu pops open on click and closes on
// outside-click, Escape, or item activation. Keyboard arrow-key navigation moves between items
// within an open menu and between top-level triggers.

import { $, $all, toast } from "./common";
import { toggleSheet } from "./shortcuts";

let openMenu: string | null = null;

function closeAll(): void {
  $all<HTMLDivElement>(".menu-pop").forEach((p) => {
    p.hidden = true;
    const trigger = $<HTMLButtonElement>(`.menu-trigger[data-menu="${p.dataset["menuPop"]}"]`);
    if (trigger) trigger.setAttribute("aria-expanded", "false");
  });
  openMenu = null;
}

function openPop(name: string): void {
  closeAll();
  const pop = $<HTMLDivElement>(`.menu-pop[data-menu-pop="${name}"]`);
  const trigger = $<HTMLButtonElement>(`.menu-trigger[data-menu="${name}"]`);
  if (!pop || !trigger) return;
  pop.hidden = false;
  trigger.setAttribute("aria-expanded", "true");
  openMenu = name;
  // Focus the first item
  const first = $<HTMLButtonElement>(".menu-entry", pop);
  if (first) first.focus();
}

function handleTriggerClick(e: MouseEvent): void {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(".menu-trigger");
  if (!btn) return;
  const name = btn.dataset["menu"];
  if (!name) return;
  if (openMenu === name) {
    closeAll();
  } else {
    openPop(name);
  }
}

function handleEntryClick(e: MouseEvent): void {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(".menu-entry");
  if (!btn) return;
  const action = btn.dataset["action"];
  closeAll();
  if (action) runAction(action);
}

function runAction(action: string): void {
  switch (action) {
    case "reload":
      location.reload();
      break;
    case "new-window":
      window.open(location.href, "_blank");
      break;
    case "shortcuts":
      toggleSheet();
      break;
    case "about":
      toast("burpsy — a memory-frugal HTTP testing proxy");
      break;
    default:
      toast(`${action}: not yet implemented`);
      break;
  }
}

function onKey(e: KeyboardEvent): void {
  if (!openMenu) return;
  const pop = $<HTMLDivElement>(`.menu-pop[data-menu-pop="${openMenu}"]`);
  if (!pop) return;
  const items = $all<HTMLButtonElement>(".menu-entry", pop);
  const idx = items.indexOf(document.activeElement as HTMLButtonElement);

  if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    closeAll();
    return;
  }
  if (e.key === "ArrowDown") {
    e.preventDefault();
    const next = (idx + 1) % items.length;
    items[next]?.focus();
    return;
  }
  if (e.key === "ArrowUp") {
    e.preventDefault();
    const prev = (idx - 1 + items.length) % items.length;
    items[prev]?.focus();
    return;
  }
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    (document.activeElement as HTMLButtonElement)?.click();
    return;
  }
}

function onBodyClick(e: MouseEvent): void {
  const target = e.target as HTMLElement;
  // Click on a trigger is handled by handleTriggerClick
  if (target.closest(".menu-trigger")) return;
  // Click inside a popup is handled by handleEntryClick
  if (target.closest(".menu-pop")) return;
  // Anything else closes
  if (openMenu) closeAll();
}

export function initMenubar(): void {
  const bar = $(".menubar");
  if (!bar) return;
  bar.addEventListener("click", handleTriggerClick);
  bar.addEventListener("click", handleEntryClick);
  document.addEventListener("click", onBodyClick, true);
  document.addEventListener("keydown", onKey, true);
}
