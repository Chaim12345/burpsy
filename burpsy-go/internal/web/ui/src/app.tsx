import { QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  Command,
  Database,
  FileDown,
  Gauge,
  Keyboard,
  Moon,
  Network,
  Plus,
  Repeat2,
  Rows3,
  Settings,
  ShieldCheck,
  Sun,
  Unplug,
} from "lucide-react";
import { useCallback, useEffect, useMemo } from "react";
import { createRoot } from "react-dom/client";
import { useHotkeys } from "react-hotkeys-hook";
import { Toaster, toast } from "sonner";
import { formatBytes, formatCount, relativeTime, templateRequest } from "./lib/api";
import { queryClient, useConnection, useEventStream, useScope, useStats } from "./lib/data";
import { useCaCert } from "./lib/data.policy";
import { resolveTheme, useApp } from "./lib/store";
import { NAV_LEAVES, TOOLS, entryLeaf, findLeaf, toolOf } from "./nav";
import { ErrorBoundary } from "./ui/layout";
import { DropdownMenu, type MenuGroup } from "./ui/menu";
import { CommandPalette, type PaletteAction } from "./ui/palette";
import { Badge, IconButton, Kbd, Modal } from "./ui/primitives";

interface ShortcutRow {
  keys: string[];
  label: string;
  /** Set when the binding differs from Burp's, so the reason is visible. */
  note?: string;
}

/**
 * Burp's bindings, kept where a browser allows it. The exceptions are called out
 * rather than silently changed, because a Burp user's muscle memory is the point.
 */
const SHORTCUT_GROUPS: { title: string; rows: ShortcutRow[] }[] = [
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

function ShortcutHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="mod is ⌘ on macOS and Ctrl elsewhere.">
      <div className="shortcut-table">
        {SHORTCUT_GROUPS.map((group) => (
          <div key={group.title}>
            <div className="shortcut-group">{group.title}</div>
            {group.rows.map((entry) => (
              <div className="shortcut-row" key={entry.label}>
                <div>
                  {entry.keys.map((key) => (
                    <Kbd key={key}>{key}</Kbd>
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
  useEffect(() => {
    const apply = () => document.documentElement.setAttribute("data-theme", resolveTheme(theme));
    apply();
    if (theme !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
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

  useThemeEffect();
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

  useHotkeys(
    "mod+k",
    (event) => {
      event.preventDefault();
      setPaletteOpen(true);
    },
    { enableOnFormTags: true },
  );

  useHotkeys("shift+slash", () => setShortcutsOpen(true));
  useHotkeys(
    "mod+shift+l",
    (event) => {
      event.preventDefault();
      toggleTheme();
    },
    { enableOnFormTags: true },
    [toggleTheme],
  );

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

    return [...navigation, ...commands];
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
      label: "Project",
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
            { id: "go", label: "Go to Repeater", shortcut: "alt+5", icon: Repeat2, onSelect: () => navigate("repeater") },
          ],
        },
      ],
    },
    {
      label: "View",
      groups: [
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
            {TOOLS.map((entry) => {
              const Icon = entry.icon;
              const current = entry.id === tool.id;
              return (
                <button
                  key={entry.id}
                  type="button"
                  className={current ? "tool-tab tool-tab-active" : "tool-tab"}
                  aria-current={current ? "page" : undefined}
                  title={entry.hotkey ? `${entry.label} (alt+${entry.hotkey})` : entry.label}
                  onClick={() => navigate(entryLeaf(entry))}
                >
                  <Icon size={14} />
                  <span>{entry.label}</span>
                </button>
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
            <IconButton label="Keyboard shortcuts (?)" onClick={() => setShortcutsOpen(true)}>
              <Keyboard size={15} />
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
      <ShortcutHelp open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
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
