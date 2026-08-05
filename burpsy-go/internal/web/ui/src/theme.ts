import { $, $all } from "./common";

type Theme = "obsidian" | "graphite" | "midnight" | "paper";
type Accent = "amber" | "cyan" | "lime" | "rose" | "violet";

const THEMES = new Set<Theme>(["obsidian", "graphite", "midnight", "paper"]);
const ACCENTS = new Set<Accent>(["amber", "cyan", "lime", "rose", "violet"]);

function stored<T extends string>(key: string, allowed: Set<T>, fallback: T): T {
  try {
    const value = localStorage.getItem(key) as T | null;
    return value && allowed.has(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

function remember(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Appearance remains usable for the current page when storage is unavailable.
  }
}

function applyTheme(theme: Theme): void {
  document.documentElement.dataset["theme"] = theme;
  document.documentElement.style.colorScheme = theme === "paper" ? "light" : "dark";
  remember("burpsy-theme", theme);
  $all<HTMLButtonElement>("[data-theme-choice]").forEach((button) => {
    const selected = button.dataset["themeChoice"] === theme;
    button.classList.toggle("on", selected);
    button.setAttribute("aria-checked", String(selected));
  });
}

function applyAccent(accent: Accent): void {
  document.documentElement.dataset["accent"] = accent;
  remember("burpsy-accent", accent);
  $all<HTMLButtonElement>("[data-accent-choice]").forEach((button) => {
    const selected = button.dataset["accentChoice"] === accent;
    button.classList.toggle("on", selected);
    button.setAttribute("aria-checked", String(selected));
  });
}

function closeMenu(): void {
  const menu = $<HTMLElement>("#theme-menu");
  const toggle = $("#theme-toggle");
  if (menu) menu.hidden = true;
  toggle?.setAttribute("aria-expanded", "false");
}

export function initTheme(): void {
  const theme = stored("burpsy-theme", THEMES, "obsidian");
  const accent = stored("burpsy-accent", ACCENTS, "amber");
  applyTheme(theme);
  applyAccent(accent);

  const menu = $<HTMLElement>("#theme-menu");
  const toggle = $("#theme-toggle");
  toggle?.addEventListener("click", (event) => {
    event.stopPropagation();
    if (!menu) return;
    menu.hidden = !menu.hidden;
    toggle.setAttribute("aria-expanded", String(!menu.hidden));
  });
  menu?.addEventListener("click", (event) => event.stopPropagation());
  $all<HTMLButtonElement>("[data-theme-choice]").forEach((button) => {
    button.addEventListener("click", () => applyTheme(button.dataset["themeChoice"] as Theme));
  });
  $all<HTMLButtonElement>("[data-accent-choice]").forEach((button) => {
    button.addEventListener("click", () => applyAccent(button.dataset["accentChoice"] as Accent));
  });
  document.addEventListener("click", closeMenu);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeMenu();
  });
}
