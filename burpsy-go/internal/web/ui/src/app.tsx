import { cn } from "./lib/cn";
import { QueryClientProvider } from "@tanstack/react-query";
import { PlatformAuthPrompt } from "./ui/platform-auth-prompt";
import { scopeAllowsEverything } from "./lib/scope-state";
import { appliedSectionLabels, readBundleCoverage } from "./lib/config-coverage";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
 Activity,
 ClipboardPaste,
 Command,
 Copy,
 Crosshair,
 Database,
 FileDown,
 FileUp,
 FolderOpen,
 Gauge,
 Keyboard,
 ListChecks,
 Moon,
 Network,
 PencilLine,
 Plus,
 Radar,
 Repeat2,
 RotateCcw,
 Rows3,
 Save,
 ScanSearch,
 Search,
 Settings,
 ShieldCheck,
 Square,
 Sun,
 MousePointerClick,
 Unplug,
 Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { createRoot } from "react-dom/client";
import { useHotkeys } from "react-hotkeys-hook";
import { Toaster, toast } from "sonner";
import { api, copyToClipboard, gatedFetch, json, downloadText, formatBytes, formatCount, historyToCSV, relativeTime, requestFromUrl, templateRequest } from "./lib/api";
import { queryClient, useConnection, useEventStream, useIntercept, useProject, useProjectEpoch, useRenameProject, useScope, useStats } from "./lib/data";
import { useScannerLive } from "./lib/data.attack";
import { useCrawls } from "./lib/data.observe";
import { attentionFor, attentionSignals } from "./lib/attention";
import { useCaCert } from "./lib/data.policy";
import {
 attackConfigFilename,
 parseAttackConfig,
 serializeAttackConfig,
} from "./lib/intruder-config-file";
import { onDesktopEvent } from "./lib/runtime";
import { requestSettingsSection, settingsPaletteActions } from "./lib/settings-sections";
import { helpMenuGroups } from "./lib/help-menu";
import { editorFontStack, emptyIntruderConfig, intruderLaunchBlocker, resolveTheme, uiScaleFactor, useApp } from "./lib/store";
import { THEME_SLOTS, themeTokenVars } from "./lib/theme-import";
import type { Exchange, MessageView } from "./lib/types";
import { chordKeys, SHORTCUT_ACTIONS, shortcutGroups, type ShortcutAction } from "./lib/shortcuts";
import { useChord, useCommandChord, useKeymap } from "./lib/keymap";
import { commandsVersion, hasCommand, runCommand, subscribeCommands, unavailableReason, useCommandHandler } from "./lib/commands";
import { catalogueCommands } from "./lib/palette-commands";
import { usePluginHotkeys } from "./lib/plugin-hotkeys";
import { clearHiddenToolTabs, clearToolTabOrder, moveToolTab, orderToolTabs, readHiddenToolTabs, readToolTabOrder, writeHiddenToolTabs, writeToolTabOrder } from "./lib/tool-tabs";
import { NAV_LEAVES, TOOLS, entryLeaf, findLeaf, toolOf } from "./nav";
import { ErrorBoundary } from "./ui/layout";
import { BottomDock } from "./ui/bottom-dock";
import { ContextMenu, DropdownMenu, type MenuGroup } from "./ui/menu";
import { CommandPalette, type PaletteAction } from "./ui/palette";
import { ProjectSwitcher } from "./ui/project-switcher";
import { DialogHost } from "./ui/dialog-host";
import { promptDialog } from "./lib/dialogs";
import { SearchDialog } from "./ui/search-dialog";
import { HiddenInputsDialog } from "./ui/hidden-inputs-dialog";
import { CsrfPocDialog } from "./ui/csrf-poc-dialog";
import { ClickbanditDialog } from "./ui/clickbandit-dialog";
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
 const editorFontFamily = useApp((state) => state.editorFontFamily);
 const customTheme = useApp((state) => state.customTheme);
 const themePreview = useApp((state) => state.themePreview);
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
  document.documentElement.style.setProperty("--ui-scale", uiScaleFactor(uiScale));
 }, [uiScale]);
 useEffect(() => {
  document.documentElement.style.setProperty("--editor-font-size", editorFont);
 }, [editorFont]);
 // The editor font family (burpsy-react-ui-mqrn): a non-default choice sets --editor-font-family,
 // which the editor's CodeMirror theme reads; "default" removes the property so the editor falls
 // back to the stylesheet's --font-mono. Family and size are separate custom properties so one can
 // change without disturbing the other.
 useEffect(() => {
  const stack = editorFontStack(editorFontFamily);
  if (stack) document.documentElement.style.setProperty("--editor-font-family", stack);
  else document.documentElement.style.removeProperty("--editor-font-family");
 }, [editorFontFamily]);
 // The imported theme (burpsy-react-ui-fpew): set an inline override on <html> for every slot the
 // theme names (an inline property beats semantic.css's :root rule), and remove every other slot the
 // theme could have named so a reverted or narrowed theme falls back to the Penpot default instead of
 // keeping a stale override. Walking THEME_SLOTS rather than a remembered key set means the cleanup is
 // correct even across a reload where the previous overrides were never in this document's inline style.
 useEffect(() => {
  const style = document.documentElement.style;
  // A live preview overlays the kept theme (themePreview ?? customTheme): previewing shows the file
  // before it is kept, and a preview that read badly is escaped by a reload because themePreview is
  // not persisted. themeTokenVars tolerates a corrupted persisted theme (an object without tokens)
  // rather than letting Object.entries throw and take the whole app down on load.
  const active = themePreview ?? customTheme;
  const vars = active ? themeTokenVars(active) : {};
  for (const slot of THEME_SLOTS) {
   const prop = `--${slot}`;
   const value = vars[prop];
   if (value !== undefined) style.setProperty(prop, value);
   else style.removeProperty(prop);
  }
 }, [customTheme, themePreview]);
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

/**
 * Ask before the console tab closes or reloads, when the operator opted in (burpsy-react-ui-fyua).
 * A beforeunload handler with a non-empty returnValue is the only prompt a browser still honours, and
 * only while it is installed — so the listener is added exactly when the preference is on, and the
 * browser shows its own generic confirmation. Off by default, so nothing changes for an operator who
 * never visits the setting.
 */
function useConfirmOnClose(): void {
 const confirmOnClose = useApp((state) => state.confirmOnClose);
 useEffect(() => {
  if (!confirmOnClose) return;
  const onBeforeUnload = (event: BeforeUnloadEvent) => {
   event.preventDefault();
   event.returnValue = "";
  };
  window.addEventListener("beforeunload", onBeforeUnload);
  return () => window.removeEventListener("beforeunload", onBeforeUnload);
 }, [confirmOnClose]);
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

/**
 * Every catalogue chord, bound once (2czi). Each is a literal so keymap-installed.test.ts can see
 * the wire; each runs whichever component registered the action (lib/commands.ts) and leaves the
 * key to the browser when none has.
 */
function CatalogueHotkeys(): null {
 useCommandChord("nav.switchDashboard");
 useCommandChord("nav.switchTarget");
 useCommandChord("nav.switchProxy");
 useCommandChord("nav.switchIntruder");
 useCommandChord("nav.switchRepeater");
 useCommandChord("nav.switchLogger");
 useCommandChord("nav.switchOrganizer");
 useCommandChord("nav.search");
 useCommandChord("nav.settings");
 useCommandChord("tasks.toggle");
 useCommandChord("intruder.startAttack");
 useCommandChord("proxy.forwardAll");
 useCommandChord("proxy.dropAll");
 useCommandChord("proxy.interceptResponse");
 useCommandChord("repeater.historyBack");
 useCommandChord("repeater.historyForward");
 useCommandChord("tab.close");
 useCommandChord("tab.reopen");
 useCommandChord("tab.duplicate");
 useCommandChord("tab.next");
 useCommandChord("tab.prev");
 useCommandChord("tab.rename");
 useCommandChord("editor.togglePretty");
 useCommandChord("editor.toggleWrap");
 useCommandChord("editor.toggleNonPrinting");
 useCommandChord("editor.toggleHideHeaders");
 useCommandChord("editor.insertCollaborator");
 useCommandChord("editor.toggleSidebar");
 useCommandChord("editor.cycleLayout");
 useCommandChord("table.goToEntry");
 return null;
}

/**
 * The command palette plus Burp's action catalogue (2czi): every registry row flagged `palette`,
 * runnable when a mounted component has registered it and otherwise listed with its owner's
 * reason or where it lives. "Search across tools" is one of these (nav.search) — the menu bar is
 * hidden on narrow viewports, so the palette still has to reach it.
 *
 * Its own component so that only it subscribes to the command bridge. The bridge changes on every
 * page mount and every editor focus; subscribed from App, each change re-rendered the whole
 * console, which measured as a palette jump to Logger taking roughly twice as long.
 */
function CataloguePalette({
 open,
 onOpenChange,
 actions,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 actions: PaletteAction[];
}): JSX.Element {
 const keymap = useKeymap();
 const tick = useSyncExternalStore(subscribeCommands, commandsVersion, commandsVersion);
 const all = useMemo(
  () => [...actions, ...catalogueCommands(SHORTCUT_ACTIONS, keymap, hasCommand, (id) => void runCommand(id), unavailableReason)],
  // `tick` is the dependency that matters: it changes when availability does.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  [actions, keymap, tick],
 );
 return <CommandPalette open={open} onOpenChange={onOpenChange} actions={all} />;
}

function App(): JSX.Element {
 const route = useApp((state) => state.route);
 const setRoute = useApp((state) => state.setRoute);
 const theme = useApp((state) => state.theme);
 const setTheme = useApp((state) => state.setTheme);
 const density = useApp((state) => state.density);
 const setDensity = useApp((state) => state.setDensity);
 const tableStripes = useApp((state) => state.tableStripes);
 const setTableStripes = useApp((state) => state.setTableStripes);
 const paletteOpen = useApp((state) => state.paletteOpen);
 const setPaletteOpen = useApp((state) => state.setPaletteOpen);
 const shortcutsOpen = useApp((state) => state.shortcutsOpen);
 const openRepeaterTab = useApp((state) => state.openRepeaterTab);
 const repeaterTabCount = useApp((state) => state.repeaterTabs.length);
 const setShortcutsOpen = useApp((state) => state.setShortcutsOpen);
 // Burp's top-level Clickbandit (burpsy-react-ui-g67w).
 const [clickbanditOpen, setClickbanditOpen] = useState(false);
 // Burp puts Search on the tab bar, and it is shell state rather than a page's: it crosses tools,
 // so no single tool owns it. Local rather than in the store because nothing outside the shell
 // opens it — the command palette and the menu item are both built here.
 const [searchOpen, setSearchOpen] = useState(false);
 // The project switcher (dlw2). Shell state because both the Project menu and the palette open it.
 const [projectsOpen, setProjectsOpen] = useState(false);
 // Bumped by every completed project switch; keying the routed page on it remounts the page, so no
 // component-local selection from the project that was left survives into the one that was opened.
 const projectEpoch = useProjectEpoch((state) => state.epoch);
 // Which top-level tabs the operator has hidden (burpsy-react-ui-lje3). Burp's View menu is where
 // this lives; the tab keeps working when hidden — hotkeys, the palette and links into its routes
 // all still reach it — so hiding is a statement about chrome, never about capability.
 const [hiddenTools, setHiddenTools] = useState<string[]>(() => readHiddenToolTabs());
 // The operator's tab order (sk29): dragging a tab along the strip, remembered across reloads.
 const [toolOrder, setToolOrder] = useState<string[]>(() => readToolTabOrder());
 const [draggedTool, setDraggedTool] = useState<string | null>(null);
 const [dragOverTool, setDragOverTool] = useState<string | null>(null);
 const orderedTools = orderToolTabs(TOOLS, toolOrder);
 const dropTool = (onto: string) => {
  if (draggedTool && draggedTool !== onto) {
   const next = moveToolTab(
    orderedTools.map((entry) => entry.id),
    draggedTool,
    onto,
   );
   setToolOrder(next);
   writeToolTabOrder(next);
  }
  setDraggedTool(null);
  setDragOverTool(null);
 };
 const setToolHidden = (id: string, hidden: boolean) => {
  const next = hidden ? [...new Set([...hiddenTools, id])] : hiddenTools.filter((entry) => entry !== id);
  setHiddenTools(next);
  writeHiddenToolTabs(next);
 };

 useThemeEffect();
 useConfirmOnClose();
 useDocumentTitle();
 useHashRoute();
 useEventStream();
 // A loaded plugin's declared hotkeys are installed here, at the shell, because a hotkey is
 // suite-wide by construction (wsu4): the keydown has to reach it from every tool, which no
 // single page can promise, and the palette-equivalent action it runs is the shell's too.
 usePluginHotkeys();

 const stats = useStats();
 const scope = useScope();
 // Whether there is a CA to hand out at all. TLS interception is off unless burpsy was started with
 // -intercept-tls, and /ca.crt answers 404 in that case — so the status bar, the menu and the
 // palette all used to offer a download that lands on an error page. Settings already gated on this
 // hook; the shell now does too, and says why instead of failing.
 const caCert = useCaCert();
 const caAvailable = caCert.data?.available ?? false;
 // The Project menu's readout (je3y): which project this instance is. It is a plain read, not a
 // poll — the name and the -db path change only when this process restarts or the operator
 // renames from the menu itself, and the rename invalidates the query by key.
 const project = useProject();
 const renameProject = useRenameProject();
 // Save copy is the backup route, and the backup route is riskDestructive (it prunes old
 // snapshots past the retention count), so it answers 428 until a one-time confirm is minted.
 // The mint here is explicit, from a menu click, with the dialog the browser shows — the same
 // shape every other gated console action takes — never an automatic retry that would turn the
 // gate into a speed bump.
 const saveProjectCopy = useCallback(() => {
  if (!project.data?.backupable) {
   toast.info("A copy needs a project database, and this instance persists nothing.");
   return;
  }
  // api() mints the gate's confirmation for /api/backup on this click (p1uz).
  void api<{ path: string; bytes: number; pruned: number; kept: number; warning?: string }>("/api/backup", { method: "POST" })
   .then((r) =>
    toast.success(
     r.warning
      ? `Project copy written to ${r.path} (${formatBytes(r.bytes)}) — ${r.warning}`
      : `Project copy written to ${r.path} (${formatBytes(r.bytes)}; kept ${r.kept})`,
    ),
   )
   .catch((error) => toast.error(`Save copy failed: ${String(error)}`));
 }, [project.data?.backupable]);
 // Rename, from the Project menu and from the palette: one handler, through the shell's themed
 // prompt (bea3). A blank name cannot be submitted — the dialog says so under the field — which
 // replaces the old pair of checks (silent return in one caller, a toast in the other).
 const renameProjectViaDialog = useCallback(() => {
  if (!project.data?.persisted) {
   toast.info("A project name lives in the database file, and this instance has none — start burpsy with -db.");
   return;
  }
  const current = project.data?.name ?? "";
  void promptDialog({
   title: "Rename project",
   description: "The name is stored in the project database, so it survives a restart.",
   label: "Project name",
   initial: current === "Unnamed" ? "" : current,
   confirmLabel: "Rename",
  }).then((name) => {
   if (name === null || name.trim() === "") return;
   renameProject.mutate(name.trim(), {
    onSuccess: (confirmed) => toast.success(`Project renamed to ${confirmed.name}`),
    onError: (error) => toast.error(`Rename refused: ${String(error)}`),
   });
  });
 }, [project.data?.persisted, project.data?.name, renameProject]);
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
 // The other two attention sources (ve2q). Both are queries the shell already has to keep warm
 // for its own chrome: the live-audit state is what the Scanner tab's own summary reads, and the
 // crawl list is what the dashboard's task tiles are made of. Neither is fetched for the badge —
 // a badge that costs a poll the console was not already making is a badge that turns itself off
 // under load, which is the opposite of what an attention indicator is for.
 const liveAuditQuery = useScannerLive(4_000);
 const crawlsQuery = useCrawls();
 const attention = attentionSignals({
  intercept: interceptQuery.data,
  liveAudit: liveAuditQuery.data,
  crawls: crawlsQuery.data?.crawls,
 });

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
  // enableOnContentEditable, because the palette's "Convert selection" group (burpsy-react-ui-1wrb)
  // acts on the selection in a message editor, and a CodeMirror editor is a contenteditable — so
  // without this the one chord that reaches those commands was dead in the exact place an operator
  // uses them, having just selected the text they want encoded. They still worked from a blurred
  // editor, which made the group look intermittent rather than unreachable: the same keystroke did
  // nothing or opened the palette depending on where the caret happened to be. Nothing is taken
  // from the editor by claiming it — editor.tsx's own chords are s/u/h/b, and the handler
  // preventDefaults so no browser default fires either.
  { enableOnFormTags: true, enableOnContentEditable: true },
  [paletteChord, setPaletteOpen],
 );

 useHotkeys(shortcutsChord, () => setShortcutsOpen(true), { enableOnFormTags: false }, [shortcutsChord]);

 // Burp's action catalogue (2czi). The shell owns the actions that need no page: switching tools,
 // search, settings, the task pause, the Inspector sidebar and Intruder's Start (through the
 // Intruder menu's own launch path below). Pages register their own (lib/commands.ts); every
 // chord is bound once, in CatalogueHotkeys, whichever component handles it.
 const switchTo = useCallback(
  (toolId: string) => {
   const target = TOOLS.find((entry) => entry.id === toolId);
   if (target) navigate(entryLeaf(target));
  },
  [navigate],
 );
 useCommandHandler("nav.switchDashboard", () => switchTo("dashboard"));
 useCommandHandler("nav.switchTarget", () => switchTo("target"));
 useCommandHandler("nav.switchProxy", () => switchTo("proxy"));
 useCommandHandler("nav.switchIntruder", () => switchTo("intruder"));
 useCommandHandler("nav.switchRepeater", () => switchTo("repeater"));
 useCommandHandler("nav.switchLogger", () => switchTo("logger"));
 useCommandHandler("nav.switchOrganizer", () => switchTo("organizer"));
 useCommandHandler("nav.search", () => setSearchOpen(true));
 useCommandHandler("nav.settings", () => navigate("settings"));
 const setInspectorPanelState = useApp((state) => state.setInspectorPanelState);
 const inspectorPanelState = useApp((state) => state.inspectorPanelState);
 useCommandHandler("editor.toggleSidebar", () => {
  const next = inspectorPanelState === "collapsed" ? "auto" : "collapsed";
  setInspectorPanelState(next);
  toast.info(next === "collapsed" ? "Inspector collapsed" : "Inspector shown");
 });
 // Burp's TOGGLE_TASK_EXECUTION: the dashboard's Pause all tasks / Resume, read fresh from the
 // server each time so a chord pressed after another client paused does the right thing.
 useCommandHandler("tasks.toggle", () => {
  void api<{ paused?: boolean }>("/api/dashboard")
   .then((board) => api<{ paused: boolean; running: number }>(`/api/tasks/${board.paused ? "resume" : "pause"}`, json("POST", {})))
   .then((result) => {
    toast.success(result.paused ? `Tasks paused (${result.running} running)` : "Tasks resumed");
    void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
   })
   .catch((failure: unknown) => toast.error(`Could not toggle task execution: ${failure instanceof Error ? failure.message : String(failure)}`));
 });
 useHotkeys(
  themeChord,
  (event) => {
   event.preventDefault();
   toggleTheme();
  },
  { enableOnFormTags: true },
  [themeChord, toggleTheme],
 );

 /**
  * What the import actually did, and — the part that was missing — what the imported bundle said
  * it could not carry.
  *
  * The coverage lives in the FILE, not in the import response, and that split is deliberate on the
  * server: a bundle's own account of what it carries is evidence about the bundle, not an
  * instruction to the importer (configBundle.Coverage's doc). So the console reads it out of the
  * document the operator chose, and the server's response is used only for what it genuinely
  * knows — which surfaces this import applied.
  *
  * Omitted stays undefined when the file carries no coverage block at all, which is what an older
  * or hand-written bundle looks like. That is reported as "unknown", never as "nothing was
  * omitted": a bundle that says nothing about its coverage has not been shown to be complete.
  */
 const [importResult, setImportResult] = useState<{
  ok: boolean;
  detail: string;
  /** The sections this import applied, named from what the server reported. */
  applied: string[];
  /** The bundle's own account of what it did not carry, or undefined if it made none. */
  omitted?: string[];
  /** True only when the file itself declares itself partial. */
  partial: boolean;
 } | null>(null);
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
   .catch((err) => setImportResult({ ok: false, detail: String(err), applied: [], partial: false }));
 }, []);

 const importConfiguration = useCallback(async (file: File) => {
  const text = await file.text();
  try {
   // gatedFetch: /api/config/import is riskDestructive, and this is the operator's file pick (p1uz).
   const res = await gatedFetch("/api/config/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: text,
   });
   const body: unknown = await res.json().catch(() => null);
   if (!res.ok || !body || typeof body !== "object" || !("status" in body)) {
    const detail =
     body && typeof body === "object" && "error" in body ? String((body as { error: unknown }).error) : res.statusText;
    // Nothing was applied, and the file's coverage was never read — `omitted` stays undefined so
    // the modal reports an absence of information rather than a partial transfer it knows nothing
    // about. Collapsing those two is the bug this bead exists to fix, in a new place.
    setImportResult({ ok: false, detail, applied: [], partial: false });
    return;
   }
   // Narrowed, not cast: these are fields off a parsed JSON response and an operator-supplied
   // file, and an unchecked assertion here would trust a shape nothing has checked. A missing
   // field reads as absent, which is what it is.
   const scopeRules = "scope_rules" in body && typeof body.scope_rules === "number" ? body.scope_rules : 0;
   const interceptDirs = "intercept_dirs" in body && typeof body.intercept_dirs === "number" ? body.intercept_dirs : 0;
   const sessionRules = "session_rules" in body && typeof body.session_rules === "number" ? body.session_rules : 0;
   // Counted for the detail line; the section NAMES come from appliedSectionLabels below, which
   // narrows the same fields itself rather than trusting a cast here.
   // The bundle's own coverage, read from the document rather than from the response. The server
   // deliberately ignores it on import (a bundle's account of itself is evidence, not instruction),
   // so an older or hand-written file may not carry one at all — which readBundleCoverage reports as
   // undefined, not as "nothing was omitted".
   const coverage = readBundleCoverage(text);
   // Named from what the server reports applying, not from a hand-written sentence. The old one said
   // "Scope, intercept rules and session handling rules are affected" — which omitted
   // uninteresting_headers even though it IS carried, and had already drifted from the server.
   // `body` is `object` narrowed to carry "status"; the reader takes the fields it needs as unknown
   // and narrows them itself, so nothing here asserts a shape the response has not been shown to have.
   const applied = appliedSectionLabels(body as Record<string, unknown>);
   // Every surface the bundle touched just changed underneath the open pages.
   void queryClient.invalidateQueries();
   setImportResult({
    ok: true,
    detail: `${scopeRules} scope rule(s), ${interceptDirs} intercept list(s), ${sessionRules} session rule(s) applied.`,
    applied,
    omitted: coverage?.omitted,
    partial: coverage?.partial ?? false,
   });
  } catch (err) {
   setImportResult({ ok: false, detail: String(err), applied: [], partial: false });
  }
 }, []);

 // ---- Burp's Intruder menu ---------------------------------------------------------------------
 //
 // burp.Zcur's mainIntruderMenu, adapted. The rule for every row below is the repo's: a control
 // that cannot be honoured is present-but-disabled saying why, or absent — never a no-op. The
 // rows that act do so through state the Intruder page already owns; the page stays the single
 // authority on launching, because a second copy of its `onRun` in this file would be a second
 // attack launcher, and the two would drift.
 //
 // Absent rather than greyed, because they name a concept burpsy does not have at all:
 // "Copy configuration from first tab", "Copy configuration from last tab" and "New tab behavior".
 // Burp opens each attack in its own tab; burpsy holds exactly one attack (see IntruderConfig), so
 // there is no other tab to copy from and no new-tab behaviour to configure. A greyed row for each
 // would imply a multi-attack feature is a setting away.
 const intruderConfig = useApp((state) => state.intruder);
 const setIntruderConfig = useApp((state) => state.setIntruder);
 const setIntruderRun = useApp((state) => state.setIntruderRun);
 const intruderStatus = useApp((state) => state.intruderStatus);
 const openIntruderTab = useApp((state) => state.openIntruderTab);
 const closeAllIntruderTabs = useApp((state) => state.closeAllIntruderTabs);
 const reopenIntruderTab = useApp((state) => state.reopenIntruderTab);
 const closedIntruderTabs = useApp((state) => state.closedIntruderTabs);
 const requestIntruderCommand = useApp((state) => state.requestIntruderCommand);
 const attackInputRef = useRef<HTMLInputElement>(null);
 const [attackLoadError, setAttackLoadError] = useState<string | null>(null);
 const [confirmAttackDefaults, setConfirmAttackDefaults] = useState(false);

 const saveAttackConfig = useCallback(() => {
  downloadText(attackConfigFilename(), serializeAttackConfig(intruderConfig), "application/json");
  toast.success("Attack configuration saved");
 }, [intruderConfig]);

 const loadAttackConfig = useCallback(
  async (file: File) => {
   const result = parseAttackConfig(await file.text());
   if (!result.ok) {
    // Named refusal, not a partial load: a configuration half-taken from the file and half left
    // over from the page is an attack nobody wrote, and the operator would find out by reading
    // a report produced by requests they did not intend.
    setAttackLoadError(result.reason);
    return;
   }
   setIntruderConfig(result.config);
   // The stored report was produced by the plan being replaced. Keeping it beside a different
   // configuration would label one attack's rows with another attack's payload sets.
   setIntruderRun(null);
   navigate("intruder");
   toast.success(`Attack configuration loaded from ${file.name}`);
  },
  [setIntruderConfig, setIntruderRun, navigate],
 );

 const copyAttackConfig = useCallback(
  (withPositions: boolean) => {
   // Burp's own submenu wording. "Without payload positions" is the portable form: the same
   // payload sets, processing rules and settings, with the base request's marked positions
   // dropped so the configuration can be pasted onto a different request.
   const config = withPositions ? intruderConfig : { ...intruderConfig, points: [], selected: [] };
   void copyToClipboard(serializeAttackConfig(config)).then(
    () => toast.success(withPositions ? "Attack config copied" : "Attack config copied without payload positions"),
    (error: unknown) => toast.error(`Could not copy: ${error instanceof Error ? error.message : String(error)}`),
   );
  },
  [intruderConfig],
 );

 const sendAttackBaseToRepeater = useCallback(async () => {
  const id = Number(intruderConfig.msgId);
  try {
   const message = await api<MessageView>(`/api/message/${id}`);
   if (message.truncated) {
    // Sending the prefix would put a request in Repeater that is not the one that was captured,
    // and every send from that tab would be a send of something nobody wrote.
    toast.error(
     `Stored message ${id} is truncated${typeof message.len === "number" ? ` (${formatBytes(message.len)} captured)` : ""}, so Repeater would receive a request that is not the one captured.`,
    );
    return;
   }
   const raw = message.text ?? "";
   if (raw === "") {
    toast.error(`Stored message ${id} has no bytes to send.`);
    return;
   }
   // The target is what the attack itself sends to, so Repeater inherits it verbatim rather than
   // re-deriving a host from the request's own Host header, which a proxied request may not have.
   const target = intruderConfig.target.trim();
   const protocol = target.toLowerCase().startsWith("http://") ? "http" : "https";
   openRepeaterTab({
    name: (intruderConfig.label || `Intruder base #${id}`).slice(0, 42),
    target,
    protocol,
    request: raw,
   });
   navigate("repeater");
   toast.success("Intruder's base request sent to Repeater");
  } catch (error) {
   toast.error(`Could not load message ${id}: ${error instanceof Error ? error.message : String(error)}`);
  }
 }, [intruderConfig, openRepeaterTab, navigate]);

 // Why "Start attack" is grey. The mounted page publishes its own reason (it alone can size the
 // payload sets); with the page unmounted the store's necessary-conditions check stands in, and
 // anything it cannot see the page refuses on arrival, by name, in a toast.
 const attackRunning = intruderStatus?.running ?? false;
 const startBlocker = attackRunning
  ? "An attack is already running."
  : intruderStatus
   ? intruderStatus.refusal
   : intruderLaunchBlocker(intruderConfig);
 const stopBlocker = !attackRunning
  ? "No attack is running."
  : intruderStatus?.controllable
   ? null
   : "The running attack has not been identified yet — its controls appear in the Intruder header once it is named.";

 const INTRUDER_MENU: MenuGroup[] = [
  {
   // Attack tabs (9bv2): Burp's managing-tabs actions, on the menu as well as the strip's own.
   id: "tabs",
   actions: [
    {
     id: "new-tab",
     label: "New attack tab",
     icon: Plus,
     hint: "Open an empty attack tab; the attacks in the other tabs are kept as they are.",
     onSelect: () => {
      openIntruderTab();
      navigate("intruder");
     },
    },
    {
     id: "close-all-tabs",
     label: "Close all tabs",
     disabled: attackRunning,
     hint: attackRunning ? "An attack is running; its report needs its tab to land in." : "Close every attack tab. Reopen closed tab brings them back one at a time.",
     onSelect: closeAllIntruderTabs,
    },
    {
     id: "reopen-tab",
     label: closedIntruderTabs.length ? `Reopen closed tab (${closedIntruderTabs.length})` : "Reopen closed tab",
     icon: RotateCcw,
     disabled: closedIntruderTabs.length === 0,
     hint: closedIntruderTabs.length ? "Bring back the most recently closed attack tab with its configuration and results." : "No attack tab has been closed this session.",
     onSelect: () => {
      reopenIntruderTab();
      navigate("intruder");
     },
    },
   ],
  },
  {
   id: "attack",
   actions: [
    {
     id: "start",
     label: "Start attack",
     icon: Zap,
     disabled: startBlocker !== null,
     hint: startBlocker ?? "Launch this attack from the Intruder page.",
     onSelect: () => {
      navigate("intruder");
      requestIntruderCommand("start");
     },
    },
    {
     // Burp keeps Stop on the attack window (burp.Zhwf), not on this menu, because each attack
     // has its own window. burpsy has one attack and no window to put it on, so a menu that
     // could start an attack and not stop it would be a one-way door.
     id: "stop",
     label: "Stop",
     icon: Square,
     disabled: stopBlocker !== null,
     hint: stopBlocker ?? "Stop the running attack; the report shows everything sent so far.",
     onSelect: () => {
      navigate("intruder");
      requestIntruderCommand("stop");
     },
    },
    {
     id: "open-saved",
     label: "Open saved attack",
     icon: FolderOpen,
     disabled: true,
     hint: "burpsy has no project file, so a finished attack and its results are not stored on disk to be reopened. Save attack config writes the configuration to a JSON file instead.",
     onSelect: () => undefined,
    },
   ],
  },
  {
   id: "config",
   actions: [
    {
     id: "save-config",
     label: "Save attack config",
     icon: Save,
     hint: "Write the whole attack — base message, target, positions, payload sets, processing rules, grep and limits — to a JSON file.",
     onSelect: saveAttackConfig,
    },
    {
     id: "load-config",
     label: "Load attack config",
     icon: FileUp,
     disabled: attackRunning,
     hint: attackRunning
      ? "An attack is running; loading a different configuration under it would misreport the attack in flight."
      : "Read an attack back from a saved JSON file. A file this burpsy cannot restore in full is refused naming the field.",
     onSelect: () => attackInputRef.current?.click(),
    },
    {
     id: "copy-config",
     label: "Copy attack config",
     icon: Copy,
     hint: "Copy the configuration to the clipboard in the same format Save writes.",
     onSelect: () => undefined,
     submenu: [
      {
       id: "copy-config-variants",
       actions: [
        {
         id: "copy-with-positions",
         label: "With payload positions",
         onSelect: () => copyAttackConfig(true),
        },
        {
         id: "copy-without-positions",
         label: "Without payload positions",
         hint: "The portable form: same payloads and settings, no marked positions, so it can be pasted onto a different request.",
         onSelect: () => copyAttackConfig(false),
        },
       ],
      },
     ],
    },
    {
     id: "defaults",
     label: "Use default attack configuration",
     icon: RotateCcw,
     disabled: attackRunning,
     hint: attackRunning
      ? "An attack is running; resetting its configuration under it would misreport the attack in flight."
      : "Restore the payload sets, processing rules, grep and limits to their defaults, keeping the base request, target and positions.",
     onSelect: () => setConfirmAttackDefaults(true),
    },
    {
     id: "payload-lists",
     label: "Configure predefined payload lists",
     icon: ListChecks,
     disabled: true,
     hint: "burpsy has no payload-list library. A payload set can read a server-side file by name on the Intruder page's Payloads tab, which is the closest thing that exists.",
     onSelect: () => undefined,
    },
   ],
  },
  {
   id: "scan",
   actions: [
    {
     id: "scan-points",
     label: "Scan defined insertion points",
     icon: ScanSearch,
     disabled: true,
     hint: "burpsy's audit (POST /api/audit/{exchange}) derives its own insertion points and has no field that accepts a chosen set, so the positions marked here could not be the ones scanned.",
     onSelect: () => undefined,
    },
    {
     id: "active-scan",
     label: "Do active scan",
     icon: Radar,
     disabled: true,
     hint: "The audit is keyed by exchange id; Intruder's base request is a stored message id, and a message carries no back-reference to the exchange it came from. Start an active audit from the History row instead.",
     onSelect: () => undefined,
    },
    {
     id: "passive-scan",
     label: "Do passive scan",
     icon: Crosshair,
     disabled: true,
     hint: "The only passive entry point (POST /api/scanner/passive-branch) sweeps a whole site-map branch, which is many exchanges rather than this one base request.",
     onSelect: () => undefined,
    },
    {
     id: "to-repeater",
     label: "Send to Repeater",
     icon: Repeat2,
     disabled: intruderConfig.msgId.trim() === "" || intruderConfig.target.trim() === "",
     hint:
      intruderConfig.msgId.trim() === "" || intruderConfig.target.trim() === ""
       ? "The attack has no base message and target yet, so there is nothing to send."
       : "Open the attack's base request, unmodified, in a new Repeater tab.",
     onSelect: () => void sendAttackBaseToRepeater(),
    },
   ],
  },
 ];

 // Burp's INTRUDER_START_ATTACK, through exactly the Intruder menu's Start entry: the same blocker
 // refuses it with the same words, and the launch itself is still the page's.
 useCommandHandler("intruder.startAttack", () => {
  if (startBlocker !== null) {
   toast.error(startBlocker);
   return;
  }
  navigate("intruder");
  requestIntruderCommand("start");
 });

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

 const requestRepeaterTabSearch = useApp((state) => state.requestRepeaterTabSearch);
 const repeaterTabSearchChord = useChord("repeater.tabSearch");
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
    shortcut: themeChord || undefined,
    icon: resolveTheme(theme) === "dark" ? Sun : Moon,
    run: toggleTheme,
   },
   {
    id: "cmd:stripes",
    label: tableStripes ? "Use plain table rows (no zebra stripe)" : "Use zebra-striped table rows",
    group: "Appearance",
    keywords: "zebra stripe striping rows table appearance",
    icon: Rows3,
    run: () => {
     setTableStripes(!tableStripes);
     toast.success(tableStripes ? "Table rows are plain" : "Table rows are zebra-striped");
    },
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
    // Burp's OPEN_TAB_SEARCH (qqcn): with forty named Repeater tabs, the palette is where an operator
    // already goes to find things. Navigates to Repeater and asks the page to open its search.
    id: "cmd:repeater-tab-search",
    label: "Open tab search (Repeater)",
    group: "Search",
    keywords: "repeater tabs find filter named",
    shortcut: repeaterTabSearchChord || undefined,
    icon: Search,
    run: () => {
     navigate("repeater");
     requestRepeaterTabSearch();
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
   {
    id: "cmd:project-rename",
    label: project.data?.persisted ? "Rename this project…" : "Rename project — no project file (start with -db)",
    group: "Help",
    keywords: "project name rename file db database",
    icon: PencilLine,
    run: renameProjectViaDialog,
   },
   {
    id: "cmd:project-open",
    label: "Open or create a project…",
    group: "Help",
    keywords: "project open switch new create file db database",
    icon: FolderOpen,
    run: () => setProjectsOpen(true),
   },
   {
    id: "cmd:project-save-copy",
    label: project.data?.backupable ? "Save a copy of this project" : "Save a project copy — no project file (start with -db)",
    group: "Help",
    keywords: "project copy backup snapshot db database",
    icon: Save,
    run: saveProjectCopy,
   },
  ];

  // One entry per Settings section, built from the same list the page and its section rail
  // render from (lib/settings-sections.ts). Burp's palette opens a *setting*, not a settings
  // page — "find and open Burp's settings" is one of the jobs tools/command-palette.html gives
  // it — and a second list written out here is exactly the thing that would drift the first
  // time a section was added.
  return [...navigation, ...settingsPaletteActions(navigate), ...commands];
 }, [themeChord, navigate, requestRepeaterTabSearch, repeaterTabSearchChord, theme, toggleTheme, density, setDensity, tableStripes, setTableStripes, setShortcutsOpen, project.data?.name, project.data?.persisted, project.data?.backupable, project.data?.database_note, renameProject, renameProjectViaDialog, saveProjectCopy, setProjectsOpen]);

 const hasSubTabs = tool.leaves.length > 1;
 // The Dashboard already shows both lists in full, so the dock would only repeat it there.
 const showDock = route !== "dashboard";

 /**
  * Burp's menu bar, adapted rather than copied. Its Project menu is built around project files;
  * burpsy's project file is the -db database, so the menu names it, renames it, copies it and
  * (dlw2) opens or creates another one — and declines the import Burp offers, with the reason.
  *
  * Intruder is here now (burpsy-react-ui-yinb). It was dropped on the grounds that its state lives
  * only on the Intruder page — true, and the wrong conclusion: the attack configuration moved into
  * the store (burpsy-react-ui-rby), so the menu can read it, and the page can be asked to act on it
  * without this file learning how to launch an attack. Every enabled entry below does something;
  * every disabled one says why it cannot, in its `hint`.
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
     id: "tools",
     actions: [
      // Burp's top-level "Burp Clickbandit" (burpsy-react-ui-g67w).
      { id: "clickbandit", label: "Clickbandit", icon: MousePointerClick, onSelect: () => setClickbanditOpen(true) },
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
   label: "Project",
   groups: [
    {
     id: "identity",
     title: "This instance",
     actions: [
      {
       // The readout, not a command: the whole point of the menu is that an operator can
       // see which project a running instance is. Disabled because clicking it should do
       // nothing, with the hint carrying what it names — the AC's "Project file" readout.
       id: "file",
       label: project.data?.persisted ? `Project file: ${project.data.database}` : "No project file",
       icon: Database,
       disabled: true,
       hint:
        project.data?.persisted
         ? `This instance's project is the database at ${project.data.database}.`
         : (project.data?.database_note ??
          "This instance was started without -db, so nothing it captures is persisted."),
       onSelect: () => undefined,
      },
      {
       id: "rename",
       label: "Rename project…",
       icon: PencilLine,
       disabled: !project.data?.persisted,
       hint: project.data?.persisted
        ? "Name the project; the name is stored in the database, so it survives a restart."
        : "A project name lives in the database file, and this instance has none.",
       onSelect: renameProjectViaDialog,
      },
     ],
    },
    {
     id: "copies",
     title: "Project file operations",
     actions: [
      {
       id: "save-copy",
       label: "Save copy",
       icon: Save,
       disabled: !project.data?.backupable,
       hint: project.data?.backupable
        ? "Write a complete snapshot of this project to a new database file (VACUUM INTO)."
        : "A copy needs a project database, and this instance persists nothing.",
       onSelect: saveProjectCopy,
      },
      {
       // Burp's open/new project (dlw2). The running process re-points its database and
       // re-runs the startup restore (api_project_open.go), so this is a real switch, not a
       // restart instruction. The dialog lists the .db files beside this one, takes a new
       // file name for a new project, and asks before anything is replaced.
       id: "open",
       label: "Open or create project…",
       icon: FolderOpen,
       hint: "Switch this instance to another project file, or create a new one. Everything on screen is replaced by that project's.",
       onSelect: () => setProjectsOpen(true),
      },
      {
       id: "import",
       label: "Import project file",
       icon: FileUp,
       disabled: true,
       hint: "Declined: burpsy has no separate project container to merge into — the -db file IS the project, so an import would have to merge another database into the one this process is running on. Use Open or create project… to switch to that file instead.",
       onSelect: () => undefined,
      },
     ],
    },
   ],
  },
  {
   label: "Intruder",
   groups: INTRUDER_MENU,
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
       onSelect: async () => {
        // The shell's themed prompt (lib/dialogs.ts, bea3): this menu is built by a plain
        // factory on every open, and promptDialog is how a factory asks for a string without
        // threading modal state through the menubar.
        //
        // The clipboard is not read directly. navigator.clipboard.readText needs a
        // permission the operator has to grant, and a menu item that silently does
        // nothing on refusal is worse than one that shows them what it is about to use.
        const pasted = await promptDialog({
         title: "Paste host or URL as request",
         description: "A host (example.com), host:port, or a full URL. Opens a new Repeater tab with a GET for it.",
         label: "Host or URL",
         placeholder: "https://example.com/path",
         confirmLabel: "Open in Repeater",
        });
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
      ...orderedTools.map((entry) => ({
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
       disabled: hiddenTools.length === 0 && toolOrder.length === 0,
       onSelect: () => {
        clearHiddenToolTabs();
        clearToolTabOrder();
        setHiddenTools([]);
        setToolOrder([]);
        toast.success("Showing every top-level tab in the default order");
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
       shortcut: themeChord || undefined,
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
       id: "stripes-toggle",
       label: "Zebra-striped table rows",
       checked: tableStripes,
       onSelect: () => setTableStripes(!tableStripes),
      },
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
   groups: helpMenuGroups({
    openShortcuts: () => setShortcutsOpen(true),
    openPalette: () => setPaletteOpen(true),
    openDocumentation: () => navigate("discover"),
    openDiagnostics: () => {
     requestSettingsSection("diagnostics");
     navigate("settings");
    },
   }),
  },
 ];

 return (
  <Tooltip.Provider delayDuration={420} skipDelayDuration={200}>
   <a className="skip-link" href="#main-content">
    Skip to workspace
   </a>
   <div className={`app-shell${hasSubTabs ? " has-subtabs" : ""}${showDock ? " has-dock" : ""}`}>
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
      {orderedTools.filter((entry) => !hiddenTools.includes(entry.id)).map((entry) => {
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
         // A tool tab's menu is Burp's detach/hide trio, which carries no documentation entry.
         docTopic={null}
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
          className={cn(current ? "tool-tab tool-tab-active" : "tool-tab", dragOverTool === entry.id && draggedTool !== entry.id && "tool-tab-dragover")}
          // Drag a tab along the strip to reorder it (sk29); the order is saved per browser.
          draggable
          onDragStart={(event) => {
           setDraggedTool(entry.id);
           event.dataTransfer.effectAllowed = "move";
           event.dataTransfer.setData("text/plain", entry.id);
          }}
          onDragOver={(event) => {
           if (!draggedTool) return;
           event.preventDefault();
           event.dataTransfer.dropEffect = "move";
           setDragOverTool(entry.id);
          }}
          onDragLeave={() => setDragOverTool((over) => (over === entry.id ? null : over))}
          onDrop={(event) => {
           event.preventDefault();
           dropTool(entry.id);
          }}
          onDragEnd={() => {
           setDraggedTool(null);
           setDragOverTool(null);
          }}
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
      {tool.leaves.filter((child) => !child.hidden).map((child) => {
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
     <ErrorBoundary resetKey={`${route}:${projectEpoch}`}>
      <ActivePage key={projectEpoch} />
     </ErrorBoundary>
    </main>

    {showDock ? <BottomDock /> : null}

    {/* The status bar as a landmark (burpsy-react-ui-4t8a): a <footer> gives
            screen-reader users a navigable contentinfo region, so the status text is
            reachable by landmark navigation rather than only by reading the whole page.
            The bare div before was axe's 'region' finding — not a WCAG A/AA failure (the
            tagged gate was green), but the text was unreachable by navigation, which is
            what the landmark exists to fix. */}
    <footer className="statusbar">
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
     <span>{scopeAllowsEverything(scope.data) ? `scope: everything${scope.data?.rules.length ? " not excluded" : ""}` : `scope: ${scope.data?.rules.length ?? 0} rules`}</span>
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
    </footer>
   </div>

   <CataloguePalette open={paletteOpen} onOpenChange={setPaletteOpen} actions={paletteActions} />
   <SearchDialog open={searchOpen} onOpenChange={setSearchOpen} />
   <HiddenInputsDialog />
   <CsrfPocDialog />
   <ClickbanditDialog open={clickbanditOpen} onOpenChange={setClickbanditOpen} />
   <ProjectSwitcher open={projectsOpen} onOpenChange={setProjectsOpen} />
   <ShortcutHelp open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
   {/* Every confirm/prompt in the console (lib/dialogs.ts, bea3). Mounted once, here. */}
   <DialogHost />
   <CatalogueHotkeys />
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
   {/* Load attack config's file picker. Separate from the configuration import above because the
          two accept different documents and must not be able to feed each other's reader. */}
   <input
    ref={attackInputRef}
    type="file"
    accept="application/json,.json"
    data-testid="attack-config-input"
    style={{ display: "none" }}
    onChange={(event) => {
     const file = event.target.files?.[0];
     if (file) void loadAttackConfig(file);
     event.target.value = "";
    }}
   />
   <Modal
    open={attackLoadError !== null}
    onOpenChange={(open) => {
     if (!open) setAttackLoadError(null);
    }}
    title="Attack configuration refused"
    description={attackLoadError ?? undefined}
   >
    <p>
     Nothing was loaded. The attack on the Intruder page is untouched — a configuration that
     cannot be restored in full is refused rather than applied in part.
    </p>
   </Modal>
   <Modal
    open={confirmAttackDefaults}
    onOpenChange={setConfirmAttackDefaults}
    title="Use the default attack configuration?"
    description="The payload sets, processing rules, grep expressions and limits go back to their defaults."
   >
    <p>
     The base message, target and marked insertion points are kept, so the attack still points at
     the same request. The last report is cleared: it was produced by the configuration being
     replaced.
    </p>
    <div className="toolbar">
     <button type="button" className="button" onClick={() => setConfirmAttackDefaults(false)}>
      Cancel
     </button>
     <button
      type="button"
      className="button button-primary"
      onClick={() => {
       const defaults = emptyIntruderConfig();
       setIntruderConfig((current) => ({
        ...defaults,
        msgId: current.msgId,
        target: current.target,
        label: current.label,
        mode: current.mode,
        allPoints: current.allPoints,
        points: current.points,
        selected: current.selected,
       }));
       setIntruderRun(null);
       setConfirmAttackDefaults(false);
       navigate("intruder");
       toast.success("Attack configuration reset to defaults");
      }}
     >
      Use defaults
     </button>
    </div>
   </Modal>
   <Modal
    open={importResult !== null}
    onOpenChange={(open) => {
     if (!open) setImportResult(null);
    }}
    title={importResult?.ok ? "Configuration imported" : "Import failed"}
    description={importResult?.detail}
   >
    {/*
    The point of this modal. It used to say one fixed sentence — "Scope, intercept rules and
    session handling rules are affected." — which named three of the four carried sections,
    omitted uninteresting_headers even though it IS in the bundle, and said nothing at all about
    the ten settings the export never carried. An operator migrating a project read that as a
    complete transfer.

    So: the applied sections come from what the server reported applying, and the omissions come
    from the bundle's own coverage block. That block is deliberately NOT read off the import
    response (configBundle.Coverage's doc — a bundle's account of itself is evidence about the
    file, not an instruction to the importer), which is why it is parsed out of the document here.
   */}
    {importResult?.ok ? (
     <>
      <p>
       {importResult.applied.length ? <>Applied: {importResult.applied.join(", ")}.</> : "No section carried any configuration to apply."}
      </p>
      {importResult.omitted === undefined ? (
       <p className="field-hint">
        <strong>This file does not say what it can carry.</strong> It carries no coverage block, so
        the settings it cannot carry are unknown: they were neither transferred nor reported
        missing. Treat this as a partial
        transfer unless you can see otherwise — a bundle that says nothing about its coverage has
        not been shown to be complete.
       </p>
      ) : importResult.omitted.length ? (
       <p className="field-hint">
        <strong>
         {importResult.partial ? "This is a partial transfer." : "This file reports omissions."}
        </strong>{" "}
        The following {importResult.omitted.length === 1 ? "setting is" : `${importResult.omitted.length} settings are`} not
        carried by this bundle and were not transferred: {importResult.omitted.join(", ")}.
       </p>
      ) : null}
     </>
    ) : null}
   </Modal>
   <Toaster position="bottom-right" theme={resolveTheme(theme)} closeButton duration={3800} />
   <PlatformAuthPrompt />
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
