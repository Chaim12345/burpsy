import { QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  ClipboardPaste,
  Command,
  Database,
  FileDown,
  FileUp,	Gauge,
	Keyboard,
	Moon,
  Network,
  Plus,
  Repeat2,
  RotateCcw,
  Rows3,
  Search,
  Settings,
  ShieldCheck,
  Sun,
  Unplug,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { useHotkeys } from "react-hotkeys-hook";
import { Toaster, toast } from "sonner";
import { api, downloadText, formatBytes, formatCount, historyToCSV, relativeTime, requestFromUrl, templateRequest } from "./lib/api";
import { queryClient, useConnection, useEventStream, useIntercept, useScope, useStats } from "./lib/data";
import { attentionFor, attentionSignals } from "./lib/attention";
import { useCaCert } from "./lib/data.policy";
import { onDesktopEvent } from "./lib/runtime";
import { settingsPaletteActions } from "./lib/settings-sections";
import { resolveTheme, useApp } from "./lib/store";
import type { Exchange } from "./lib/types";
import { chordKeys, shortcutGroups, type ShortcutAction } from "./lib/shortcuts";
import { useChord, useKeymap } from "./lib/keymap";
import { clearHiddenToolTabs, readHiddenToolTabs, writeHiddenToolTabs } from "./lib/tool-tabs";
import { NAV_LEAVES, TOOLS, entryLeaf, findLeaf, toolOf } from "./nav";
import { ErrorBoundary } from "./ui/layout";
import { ContextMenu, DropdownMenu, type MenuGroup } from "./ui/menu";
import { CommandPalette, type PaletteAction } from "./ui/palette";
import { SearchDialog } from "./ui/search-dialog";
import { Badge, IconButton, Kbd, Modal } from "./ui/primitives";


function ShortcutHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  const keymap = useKeymap();
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="mod is ⌘ on macOS and Ctrl elsewhere.">
      <div className="shortcut-table">
        {shortcutGroups().map((group) => (
          <div key={group.title}>
            <div className="shortcut-group">{group.title}</div>
            {group.rows.map((entry: ShortcutAction) => (
              <div className="shortcut-row" key={entry.id}>
                <div>
                  {chordKeys(entry, keymap).map((key, i) => (
                    <span key={key}>{i > 0 ? "+" : null}<Kbd>{key}</Kbd></span>
                  ))}
                </div>
                <span>
                  {entry.label}
                  {entry.note ? <small className="shortcut-note">{entry.note}</small> : null}
                </span>
              </div>
            ))}
          </div>
        ))}
      </div>
    </Modal>
  );
}

function useThemeEffect(): void {
  const theme = useApp((state) => state.theme);
  const uiScale = useApp((state) => state.uiScale);
  const editorFont = useApp((state) => state.editorFont);
  useEffect(() => {
    const apply = () => document.documentElement.setAttribute("data-theme", resolveTheme(theme));
    apply();
    if (theme !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  // The two text scales (burpsy-react-ui-7bd) ride the same attribute pattern as the
  // theme: one place on <html>, everything downstream reads the custom property.
  useEffect(() => {
    document.documentElement.style.setProperty("--ui-scale", uiScale);
  }, [uiScale]);
  useEffect(() => {
    document.documentElement.style.setProperty("--editor-font-size", editorFont);
  }, [editorFont]);
}

/**
 * Name the browser tab after the tool on screen.
 *
 * Burp users navigate by tool name, and this console is a single-page app whose tab
 * said only "burpsy" no matter where you were — so two windows open on two different
 * tools were indistinguishable in the taskbar, and the browser's own history read as
 * a column of identical entries. The tool comes first because that is the part a
 * truncated tab label keeps.
 *
 * Deliberately not paired with a meta description. An audit rule asked for one, but
 * that rule exists to control how a search engine renders a result snippet, and this
 * page is served by a proxy on localhost that no crawler can reach and no operator
 * would want indexed. A description tag here would be decoration that implies a
 * search presence this tool does not have.
 */
function useDocumentTitle(): void {
  const route = useApp((state) => state.route);
  useEffect(() => {
    const leaf = findLeaf(route);
    const tool = toolOf(route);
    // Sub-views repeat their tool name ("Proxy · HTTP history"); a tool that owns one
    // view would otherwise say the same word twice.
    const name = tool.leaves.length > 1 ? `${tool.label} · ${leaf.label}` : leaf.label;
    document.title = `${name} — burpsy`;
  }, [route]);
}

/** Keep the URL hash and the store's route in sync in both directions. */
function useHashRoute(): void {
  const route = useApp((state) => state.route);
  const setRoute = useApp((state) => state.setRoute);

  useEffect(() => {
    const fromHash = location.hash.slice(1);
    if (fromHash && NAV_LEAVES.some((leaf) => leaf.id === fromHash)) setRoute(fromHash);
    const onHashChange = () => {
      const next = location.hash.slice(1);
      if (next && NAV_LEAVES.some((leaf) => leaf.id === next)) setRoute(next);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [setRoute]);

  useEffect(() => {
    if (location.hash.slice(1) !== route) history.replaceState(null, "", `#${route}`);
  }, [route]);
}

function App(): JSX.Element {
  const route = useApp((state) => state.route);
  const setRoute = useApp((state) => state.setRoute);
  const theme = useApp((state) => state.theme);
  const setTheme = useApp((state) => state.setTheme);
  const density = useApp((state) => state.density);
  const setDensity = useApp((state) => state.setDensity);
  const paletteOpen = useApp((state) => state.paletteOpen);
  const setPaletteOpen = useApp((state) => state.setPaletteOpen);
  const shortcutsOpen = useApp((state) => state.shortcutsOpen);
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const repeaterTabCount = useApp((state) => state.repeaterTabs.length);
  const setShortcutsOpen = useApp((state) => state.setShortcutsOpen);
  // Burp puts Search on the tab bar, and it is shell state rather than a page's: it crosses tools,
  // so no single tool owns it. Local rather than in the store because nothing outside the shell
  // opens it — the command palette and the menu item are both built here.
  const [searchOpen, setSearchOpen] = useState(false);
  // Which top-level tabs the operator has hidden (burpsy-react-ui-lje3). Burp's View menu is where
  // this lives; the tab keeps working when hidden — hotkeys, the palette and links into its routes
  // all still reach it — so hiding is a statement about chrome, never about capability.
  const [hiddenTools, setHiddenTools] = useState<string[]>(() => readHiddenToolTabs());
  const setToolHidden = (id: string, hidden: boolean) => {
    const next = hidden ? [...new Set([...hiddenTools, id])] : hiddenTools.filter((entry) => entry !== id);
    setHiddenTools(next);
    writeHiddenToolTabs(next);
  };

  useThemeEffect();
  useDocumentTitle();
  useHashRoute();
  useEventStream();

  const stats = useStats();
  const scope = useScope();
  // Whether there is a CA to hand out at all. TLS interception is off unless burpsy was started with
  // -intercept-tls, and /ca.crt answers 404 in that case — so the status bar, the menu and the
  // palette all used to offer a download that lands on an error page. Settings already gated on this
  // hook; the shell now does too, and says why instead of failing.
  const caCert = useCaCert();
  const caAvailable = caCert.data?.available ?? false;
  const live = useConnection((state) => state.live);
  const lastEventAt = useConnection((state) => state.lastEventAt);
  const eventCount = useConnection((state) => state.eventCount);

  // Tool attention (burpsy-react-ui-xvo). Burp's shell owns this per tool rather than letting each
  // tool surface it on its own page, and the reason is the Proxy case below: interception holding a
  // request makes the operator's browser hang, and the page that would explain it is the one they
  // are not looking at.
  //
  // `useIntercept` polls, which makes the shell the second place in the console that does — so it is
  // worth saying why. Held messages are the one thing that has to appear while an operator is
  // waiting on it, and the poll is what guarantees the count arrives even if the event stream is
  // down; the `intercept` event kind invalidates the same key, so the steady state is event-driven
  // and the 1.5s poll is the floor under it. On a crawl or an audit the shell's own polling is one
  // small GET every 1.5s against a stream already coalescing hundreds of exchanges a second.
  const interceptQuery = useIntercept();
  const attention = attentionSignals({ intercept: interceptQuery.data });

  const leaf = findLeaf(route);
  const tool = toolOf(route);
  const ActivePage = leaf.page;

  const navigate = useCallback(
    (id: string) => {
      setRoute(id);
      document.getElementById("main-content")?.focus();
    },
    [setRoute],
  );

  const toggleTheme = useCallback(() => {
    const next = resolveTheme(theme) === "dark" ? "light" : "dark";
    setTheme(next);
  }, [theme, setTheme]);

  // File > Export History from the desktop shell exports the full capture (the
  // History page's button exports the loaded, filtered view). Index rows only —
  // never bodies — so the CSV cannot leak payloads.
  const exportHistoryCSV = useCallback(async () => {
    try {
      const rows = await api<Exchange[]>("/api/history?limit=100000");
      if (rows.length === 0) {
        toast.error("No history rows to export");
        return;
      }
      downloadText("history.csv", historyToCSV(rows), "text/csv");
      toast.success(`Exported ${rows.length} exchanges to CSV`);
    } catch {
      toast.error("History export failed");
    }
  }, []);

  // Desktop menu bridge: cmd/desktop's buildMenu emits burpsy:navigate (Tools
  // items) and burpsy:menu (File/View/Help items) as Wails events. The shell
  // subscribes here; in web mode onDesktopEvent returns null and this effect is
  // a no-op — every action stays reachable through the hotkeys and the palette,
  // so a menu click and a keyboard shortcut drive the identical handler.
  useEffect(() => {
    const offNavigate = onDesktopEvent("burpsy:navigate", (route) => {
      if (typeof route === "string") navigate(route);
    });
    const offMenu = onDesktopEvent("burpsy:menu", (action) => {
      switch (action) {
        case "toggle-theme":
          toggleTheme();
          break;
        case "command-palette":
          setPaletteOpen(true);
          break;
        case "shortcuts":
          setShortcutsOpen(true);
          break;
        case "export-history":
          void exportHistoryCSV();
          break;
        default:
          break;
      }
    });
    return () => {
      offNavigate?.();
      offMenu?.();
    };
  }, [navigate, toggleTheme, exportHistoryCSV, setPaletteOpen, setShortcutsOpen]);

  const paletteChord = useChord("nav.palette");
  const shortcutsChord = useChord("help.shortcuts");
  const themeChord = useChord("view.toggleTheme");
  const nextToolChord = useChord("nav.nextTool");
  const prevToolChord = useChord("nav.prevTool");

  // Burp's Ctrl+Alt+Left / Ctrl+Alt+Right. Cycling is a separate action from alt+1…0 because
  // there are thirteen tools and ten digits: four tabs are reachable only this way.
  const cycleTool = useCallback(
    (delta: number) => {
      const tools = TOOLS;
      const currentTool = toolOf(route);
      const at = tools.findIndex((entry) => entry.id === currentTool.id);
      if (at === -1) return;
      // Wraps, because a cycle that stops at the ends makes the last tab unreachable from the
      // first without counting.
      const next = tools[(at + delta + tools.length) % tools.length]!;
      navigate(entryLeaf(next));
    },
    [route, navigate],
  );
  useHotkeys(nextToolChord, (event) => { event.preventDefault(); cycleTool(1); },
    { enableOnFormTags: true }, [nextToolChord, cycleTool]);
  useHotkeys(prevToolChord, (event) => { event.preventDefault(); cycleTool(-1); },
    { enableOnFormTags: true }, [prevToolChord, cycleTool]);

  // Bound from the keymap, not a literal: the Settings table edits these, and a literal here
  // would mean an operator's rebind changed the row the modal displays and nothing else.
  useHotkeys(
    paletteChord,
    (event) => {
      event.preventDefault();
      setPaletteOpen(true);
    },
    { enableOnFormTags: true },
    [paletteChord, setPaletteOpen],
  );

  useHotkeys(shortcutsChord, () => setShortcutsOpen(true), { enableOnFormTags: false }, [shortcutsChord]);
  useHotkeys(
    themeChord,
    (event) => {
      event.preventDefault();
      toggleTheme();
    },
    { enableOnFormTags: true },
    [themeChord, toggleTheme],
  );

  const [importResult, setImportResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const importInputRef = useRef<HTMLInputElement>(null);

  const exportConfiguration = useCallback(() => {
    // A blob download rather than window.open: an operator wants a file to carry between
    // engagements, not a browser tab rendering JSON.
    void fetch("/api/config/export")
      .then((res) => {
        if (!res.ok) throw new Error(`export failed (${res.status})`);
        return res.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "burpsy-config.json";
        link.click();
        URL.revokeObjectURL(url);
      })
      .catch((err) => setImportResult({ ok: false, detail: String(err) }));
  }, []);

  const importConfiguration = useCallback(async (file: File) => {
    const text = await file.text();
    try {
      const res = await fetch("/api/config/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: text,
      });
      const body: unknown = await res.json().catch(() => null);
      if (!res.ok || !body || typeof body !== "object" || !("status" in body)) {
        const detail =
          body && typeof body === "object" && "error" in body ? String((body as { error: unknown }).error) : res.statusText;
        setImportResult({ ok: false, detail });
        return;
      }
      const counts = body as { scope_rules?: number; intercept_dirs?: number; session_rules?: number };
      // Every surface the bundle touched just changed underneath the open pages.
      void queryClient.invalidateQueries();
      setImportResult({
        ok: true,
        detail: `${counts.scope_rules ?? 0} scope rule(s), ${counts.intercept_dirs ?? 0} intercept list(s), ${counts.session_rules ?? 0} session rule(s) applied.`,
      });
    } catch (err) {
      setImportResult({ ok: false, detail: String(err) });
    }
  }, []);

  const hotkeyTools = useMemo(() => TOOLS.filter((entry) => entry.hotkey), []);
  useHotkeys(
    hotkeyTools.map((entry) => `alt+${entry.hotkey}`).join(","),
    (event, handler) => {
      const pressed = handler.keys?.[0];
      const target = hotkeyTools.find((entry) => entry.hotkey === pressed);
      if (target) {
        event.preventDefault();
        navigate(entryLeaf(target));
      }
    },
    { enableOnFormTags: true },
    [hotkeyTools, navigate],
  );

  const paletteActions = useMemo<PaletteAction[]>(() => {
    const navigation: PaletteAction[] = TOOLS.flatMap((entry) =>
      entry.leaves.map((child) => ({
        id: `go:${child.id}`,
        label: entry.leaves.length > 1 ? `${entry.label} › ${child.label}` : child.label,
        group: "Go to",
        hint: child.description,
        shortcut: entry.hotkey && entryLeaf(entry) === child.id ? `alt+${entry.hotkey}` : undefined,
        keywords: child.description,
        icon: entry.icon,
        run: () => navigate(child.id),
      })),
    );

    const commands: PaletteAction[] = [
      {
        id: "cmd:theme",
        label: `Switch to ${resolveTheme(theme) === "dark" ? "light" : "dark"} theme`,
        group: "Appearance",
        shortcut: "mod+shift+L",
        icon: resolveTheme(theme) === "dark" ? Sun : Moon,
        run: toggleTheme,
      },
      {
        id: "cmd:density",
        label: `Use ${density === "compact" ? "comfortable" : "compact"} table rows`,
        group: "Appearance",
        keywords: "density rows spacing",
        run: () => {
          setDensity(density === "compact" ? "comfortable" : "compact");
          toast.success(`Table rows set to ${density === "compact" ? "comfortable" : "compact"}`);
        },
      },
      {
        id: "cmd:search",
        // The menu bar is hidden on narrow viewports and this dialog lives on it, so the palette
        // has to reach the same action or Search would simply be unavailable on a small screen.
        label: "Search across tools…",
        // Its own group rather than "Go to": the Go-to heading is built by flat-mapping the tools
        // over their leaves, so a facility filed under it would read as a route that is not one.
        group: "Search",
        keywords: "find grep suite-wide proxy repeater organizer",
        icon: Search,
        run: () => setSearchOpen(true),
      },
      {
        id: "cmd:shortcuts",
        label: "Show keyboard shortcuts",
        group: "Help",
        shortcut: "?",
        icon: Keyboard,
        run: () => setShortcutsOpen(true),
      },
      {
        id: "cmd:ca",
        // The label states the outcome rather than offering an action that cannot happen. Kept in the
        // list either way so searching "certificate" explains the situation instead of finding nothing.
        label: caAvailable ? "Download the CA certificate" : "CA certificate unavailable — TLS interception is off",
        group: "Help",
        keywords: "certificate https tls install",
        icon: ShieldCheck,
        run: () =>
          caAvailable
            ? window.open("/ca.crt", "_blank")
            : toast.info(caCert.data?.detail ?? "TLS interception is not enabled, so there is no CA to trust."),
      },
      {
        id: "cmd:report",
        label: "Export the findings report (HTML)",
        group: "Help",
        keywords: "html findings issues export",
        run: () => window.open("/api/report/html", "_blank"),
      },
    ];

    // One entry per Settings section, built from the same list the page and its section rail
    // render from (lib/settings-sections.ts). Burp's palette opens a *setting*, not a settings
    // page — "find and open Burp's settings" is one of the jobs tools/command-palette.html gives
    // it — and a second list written out here is exactly the thing that would drift the first
    // time a section was added.
    return [...navigation, ...settingsPaletteActions(navigate), ...commands];
  }, [navigate, theme, toggleTheme, density, setDensity, setShortcutsOpen]);

  const hasSubTabs = tool.leaves.length > 1;

  /**
   * Burp's menu bar, adapted rather than copied. Its Project menu is built around
   * project files, and its Intruder menu around attack-config state that only the
   * Intruder page holds — neither has a global equivalent here, so those items are
   * dropped instead of shipped as decoration. Every entry below does something.
   */
  const MENUS: { label: string; groups: MenuGroup[] }[] = [
    {
      label: "burpsy",
      groups: [
        {
          id: "app",
          actions: [
            { id: "settings", label: "Settings", icon: Settings, onSelect: () => navigate("settings") },
            { id: "palette", label: "Command palette", shortcut: "mod+K", icon: Command, onSelect: () => setPaletteOpen(true) },
            { id: "search", label: "Search across tools…", icon: Search, onSelect: () => setSearchOpen(true) },
            { id: "keys", label: "Keyboard shortcuts", shortcut: "?", icon: Keyboard, onSelect: () => setShortcutsOpen(true) },
          ],
        },
        {
          id: "state",
          actions: [
            { id: "dashboard", label: "Dashboard", icon: Gauge, onSelect: () => navigate("dashboard") },
          ],
        },
      ],
    },
    {
      label: "File",
      groups: [
        {
          id: "report",
          actions: [
            { id: "html", label: "Export report (HTML)", icon: FileDown, onSelect: () => window.open("/api/report/html", "_blank") },
            { id: "json", label: "Export report (JSON)", icon: FileDown, onSelect: () => window.open("/api/report/json", "_blank") },
            { id: "sarif", label: "Export report (SARIF)", icon: FileDown, onSelect: () => window.open("/api/report/sarif", "_blank") },
          ],
        },
        {
          id: "config",
          actions: [
            { id: "export-config", label: "Export configuration", icon: FileDown, onSelect: () => exportConfiguration() },
            { id: "import-config", label: "Import configuration…", icon: FileUp, onSelect: () => importInputRef.current?.click() },
          ],
        },
        {
          id: "certificate",
          actions: [
            {
              id: "ca",
              label: caAvailable ? "Download CA certificate" : "CA certificate unavailable",
              icon: ShieldCheck,
              disabled: !caAvailable,
              onSelect: () => window.open("/ca.crt", "_blank"),
            },
          ],
        },
      ],
    },
    {
      label: "Repeater",
      groups: [
        {
          id: "repeater",
          actions: [
            {
              id: "new",
              label: "New request tab",
              icon: Plus,
              onSelect: () => {
                openRepeaterTab({
                  name: `Request ${repeaterTabCount + 1}`,
                  target: "https://example.com:443",
                  protocol: "https",
                  request: templateRequest("example.com"),
                });
                navigate("repeater");
              },
            },
            {
              id: "paste-url",
              label: "Paste host / URL as request",
              icon: ClipboardPaste,
              onSelect: () => {
                // window.prompt rather than a modal, for the reason lib/actions.ts's addComment
                // records: this menu is built by a plain factory on every open, so a modal would
                // need state threaded through the menubar to reach it.
                //
                // The clipboard is not read directly. navigator.clipboard.readText needs a
                // permission the operator has to grant, and a menu item that silently does
                // nothing on refusal is worse than one that shows them what it is about to use.
                const pasted = window.prompt("Paste host or URL", "");
                if (pasted === null) return;
                const built = requestFromUrl(pasted);
                if (!built) {
                  toast.error(`Not a host or URL burpsy can send to: ${pasted.trim() || "(empty)"}`);
                  return;
                }
                openRepeaterTab({
                  name: pasted.trim().slice(0, 42),
                  target: built.target,
                  protocol: built.protocol,
                  request: built.request,
                });
                navigate("repeater");
                toast.success(`New Repeater tab for ${built.target}`);
              },
            },
            { id: "go", label: "Go to Repeater", shortcut: "alt+5", icon: Repeat2, onSelect: () => navigate("repeater") },
          ],
        },
      ],
    },
    {
      label: "View",
      groups: [
        {
          id: "tabs",
          // Burp's View menu: one checkable entry per top-level tab, checked when the tab is
          // showing, plus a way back to the default layout. This is the tab list — the menu that
          // used to hold it was a burpsy invention, and Burp's own affordance is a show/hide, not
          // a navigate: a hidden tab is still reachable by hotkey and by the command palette.
          title: "Top-level tabs",
          actions: [
            ...TOOLS.map((entry) => ({
              id: `tab-${entry.id}`,
              label: entry.label,
              checked: !hiddenTools.includes(entry.id),
              shortcut: entry.hotkey ? `alt+${entry.hotkey}` : undefined,
              onSelect: () => setToolHidden(entry.id, !hiddenTools.includes(entry.id)),
            })),
            {
              id: "restore-tabs",
              label: "Restore default tab layout",
              icon: RotateCcw,
              disabled: hiddenTools.length === 0,
              onSelect: () => {
                clearHiddenToolTabs();
                setHiddenTools([]);
                toast.success("Showing every top-level tab");
              },
            },
          ],
        },
        {
          id: "theme",
          actions: [
            {
              id: "theme-toggle",
              label: `${resolveTheme(theme) === "dark" ? "Light" : "Dark"} theme`,
              shortcut: "mod+shift+L",
              icon: resolveTheme(theme) === "dark" ? Sun : Moon,
              onSelect: toggleTheme,
            },
            {
              id: "theme-system",
              label: "Follow the system theme",
              disabled: theme === "system",
              onSelect: () => setTheme("system"),
            },
          ],
        },
        {
          id: "density",
          actions: [
            {
              id: "density-toggle",
              label: `${density === "compact" ? "Comfortable" : "Compact"} table rows`,
              icon: Rows3,
              onSelect: () => setDensity(density === "compact" ? "comfortable" : "compact"),
            },
          ],
        },
        {
          id: "layout",
          actions: [
            {
              id: "reset-layout",
              label: "Reset panel layout",
              icon: RotateCcw,
              onSelect: () => {
                for (let i = localStorage.length - 1; i >= 0; i--) {
                  const key = localStorage.key(i);
                  if (key?.startsWith("burpsy.split.")) localStorage.removeItem(key);
                }
                window.location.reload();
              },
            },
          ],
        },
      ],
    },
    {
      label: "Help",
      groups: [
        {
          id: "help",
          actions: [
            { id: "keys", label: "Keyboard shortcuts", shortcut: "?", icon: Keyboard, onSelect: () => setShortcutsOpen(true) },
            { id: "palette", label: "Command palette", shortcut: "mod+K", icon: Command, onSelect: () => setPaletteOpen(true) },
          ],
        },
      ],
    },
  ];

  return (
    <Tooltip.Provider delayDuration={420} skipDelayDuration={200}>
      <a className="skip-link" href="#main-content">
        Skip to workspace
      </a>
      <div className={hasSubTabs ? "app-shell has-subtabs" : "app-shell"}>
        {/* Menu bar, above the tool tabs as in Burp. Hidden on narrow viewports,
            where the command palette reaches the same actions. */}
        <div className="menu-bar">
          {MENUS.map((menu) => (
            <DropdownMenu
              key={menu.label}
              groups={menu.groups}
              align="start"
              trigger={
                <button type="button" className="menu-trigger">
                  {menu.label}
                </button>
              }
            />
          ))}
        </div>

        {/* Primary tool row. */}
        <header className="toolbar-row">
          <div className="brand">
            <span className="brand-symbol">b/</span>
            <span className="brand-name">burpsy</span>
          </div>
          <nav className="tool-tabs" aria-label="Tools">
            {TOOLS.filter((entry) => !hiddenTools.includes(entry.id)).map((entry) => {
              const Icon = entry.icon;
              const current = entry.id === tool.id;
              const signal = attentionFor(attention, entry.id);
              return (
                // Burp puts exactly three things on a tool tab's context menu: detach, reattach and
                // hide. Detach is honoured as the browser's own answer to it — the route opened in a
                // new window — and reattach is deliberately absent, because there is no window this
                // page created and can close; the operator's browser window is their own. Hide
                // writes the same preference the View menu's checkboxes do, so the two affordances
                // cannot disagree about what is showing.
                <ContextMenu
                  key={entry.id}
                  groups={[
                    {
                      id: "tab",
                      actions: [
                        {
                          id: "tab-detach",
                          label: "Detach tab",
                          onSelect: () => {
                            window.open(`#${entryLeaf(entry)}`, "_blank", "noopener,noreferrer");
                          },
                        },
                        { id: "tab-hide", label: "Hide tab", onSelect: () => setToolHidden(entry.id, true) },
                      ],
                    },
                  ]}
                >
                <button
                  type="button"
                  className={current ? "tool-tab tool-tab-active" : "tool-tab"}
                  aria-current={current ? "page" : undefined}
                  // The count is in the tab before the tooltip is read, because a tooltip is not a
                  // signal: it needs a hover, and the operator is on another page with a stalled
                  // browser. The tooltip carries the sentence that explains it.
                  title={
                    signal ? `${signal.label}` : entry.hotkey ? `${entry.label} (alt+${entry.hotkey})` : entry.label
                  }
                  onClick={() => navigate(entryLeaf(entry))}
                >
                  <Icon size={14} />
                  <span>{entry.label}</span>
                  {signal ? (
                    <>
                      {/* The bare number is for the eye, so it is hidden from the accessible name
                          and the sentence carries it instead — the same split inspector.tsx uses,
                          and for the same reason: aria-label cannot name a <span>, which maps to
                          the generic role, so the label would simply be dropped. */}
                      <Badge tone="warn" className="tool-tab-attention" aria-hidden="true">
                        {signal.count}
                      </Badge>
                      <span className="sr-only">{signal.label}</span>
                    </>
                  ) : null}
                </button>
                </ContextMenu>
              );
            })}
          </nav>
          <div className="toolbar-right">
            <Badge tone={live ? "good" : "warn"}>
              {live ? <Activity size={11} /> : <Unplug size={11} />}
              {live ? "live" : "offline"}
            </Badge>
            <IconButton label="Command palette (mod+K)" onClick={() => setPaletteOpen(true)}>
              <Command size={15} />
            </IconButton>
            {/* Burp's Search lives on the tab bar, and it is here rather than on a page because it
                crosses tools — a page-local button would imply a page-local search. */}
            <IconButton label="Search across tools" onClick={() => setSearchOpen(true)}>
              <Search size={15} />
            </IconButton>
            <IconButton label="Keyboard shortcuts (?)" onClick={() => setShortcutsOpen(true)}>
              <Keyboard size={15} />
            </IconButton>
            <IconButton label="Settings" onClick={() => navigate("settings")}>
              <Settings size={15} />
            </IconButton>
            <IconButton
              label={resolveTheme(theme) === "dark" ? "Use light theme" : "Use dark theme"}
              onClick={toggleTheme}
            >
              {resolveTheme(theme) === "dark" ? <Sun size={15} /> : <Moon size={15} />}
            </IconButton>
          </div>
        </header>

        {/* Secondary row, only for tools that own more than one view. */}
        {hasSubTabs ? (
          <nav className="sub-tabs" aria-label={`${tool.label} views`}>
            {tool.leaves.map((child) => {
              const current = child.id === route;
              return (
                <button
                  key={child.id}
                  type="button"
                  className={current ? "sub-tab sub-tab-active" : "sub-tab"}
                  aria-current={current ? "page" : undefined}
                  title={child.description}
                  onClick={() => navigate(child.id)}
                >
                  {child.label}
                </button>
              );
            })}
          </nav>
        ) : null}

        <main id="main-content" tabIndex={-1}>
          <ErrorBoundary resetKey={route}>
            <ActivePage />
          </ErrorBoundary>
        </main>

        <div className="statusbar">
          <span>
            <span className={live ? "status-dot live" : "status-dot stale"} />
            {live ? "event stream connected" : "event stream offline"}
          </span>
          <span>
            <Database size={11} />
            {stats.data ? formatBytes(stats.data.stored_bytes) : "—"} stored
          </span>
          <span title="The proxy listener every client points at (the -proxy address)">
            <Network size={11} />
            {stats.data?.proxy_bind ?? "proxy: —"}
          </span>
          <span>
            <Network size={11} />
            {formatCount(stats.data?.exchanges)} exchanges
          </span>
          <span>{formatCount(stats.data?.messages)} messages</span>
          <span>{scope.data?.allow_all ? "scope: everything" : `scope: ${scope.data?.rules.length ?? 0} rules`}</span>
          {caAvailable ? (
            <a className="status-link" href="/ca.crt" download>
              <ShieldCheck size={11} />
              CA certificate
            </a>
          ) : (
            <span title={caCert.data?.detail ?? "Checking whether a CA is available…"}>
              <ShieldCheck size={11} />
              no CA
            </span>
          )}
          <span className="status-push">
            {eventCount > 0 && lastEventAt ? `last event ${relativeTime(lastEventAt)}` : "no events yet"}
          </span>
        </div>
      </div>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} actions={paletteActions} />
      <SearchDialog open={searchOpen} onOpenChange={setSearchOpen} />
      <ShortcutHelp open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      {/* Hidden on purpose: the File menu item is the affordance; the input only has to accept the
          chosen file. Cleared after every change so picking the same file twice still fires. */}
      <input
        ref={importInputRef}
        type="file"
        accept="application/json,.json"
        style={{ display: "none" }}
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void importConfiguration(file);
          event.target.value = "";
        }}
      />
      <Modal
        open={importResult !== null}
        onOpenChange={(open) => {
          if (!open) setImportResult(null);
        }}
        title={importResult?.ok ? "Configuration imported" : "Import failed"}
        description={importResult?.detail}
      >
        <p>Scope, intercept rules and session handling rules are affected.</p>
      </Modal>
      <Toaster position="bottom-right" theme={resolveTheme(theme)} closeButton duration={3800} />
    </Tooltip.Provider>
  );
}

const root = document.getElementById("root");
if (!root) throw new Error("missing React root");
createRoot(root).render(
  <QueryClientProvider client={queryClient}>
    <App />
  </QueryClientProvider>,
);
