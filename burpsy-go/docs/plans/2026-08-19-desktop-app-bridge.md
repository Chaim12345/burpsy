# Bridge Plan: Burpsy Desktop App + UI/UX Gap Closure

> **Created 2026-08-19.** Comprehensive plan to bridge the UI/UX gaps identified in
> `/root/burp-re/BURP_UI_UX_COMPARISON.md` and deliver a native desktop application.
>
> **Current state**: burpsy-go is a 33MB Go binary with an embedded React web UI
> (bun-bundled, `go:embed`), served via `net/http`. Accessible at `http://127.0.0.1:3080`.
>
> **Target state**: Native desktop application with full keyboard shortcuts, context menus,
> config UI, and system integration — while preserving the existing web UI for remote/headless use.

---

## Executive Summary

### The Three-Layer Bridge Strategy

1. **Desktop Shell (Wails v2)** — Wrap the existing React UI in a native WebView container
   with Go backend bindings. Adds system tray, native menus, file dialogs, keyboard shortcuts.
   
2. **UI/UX Feature Parity** — Implement the 15 critical gaps identified in the comparison:
   keyboard shortcuts, expanded context menus, config panels, drag-and-drop, etc.
   
3. **Hybrid Mode** — Keep the web server running alongside the desktop app, so users can
   choose: native desktop (Wails) OR remote web (current) OR both simultaneously.

### Why Wails (not Tauri / Electron / PWA)

| Framework | Backend | Frontend | Binary Size | Fit for burpsy |
|---|---|---|---|---|
| **Wails v2** | Go (native) | WebView (native) | ~15-20MB | ✅ Perfect — Go backend, React frontend, native feel |
| Tauri | Rust | WebView | ~5-10MB | ❌ Backend is Go, not Rust |
| Electron | Node.js | Chromium | ~150MB+ | ❌ Too heavy, doesn't leverage Go backend |
| PWA | Any | Browser | N/A | ⚠️ Limited system integration (no tray, limited shortcuts) |

**Wails v2** is the natural choice:
- Go backend bindings (call Go functions directly from JS)
- Native WebView (WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS)
- System tray, native menus, file dialogs, notifications
- Cross-platform (Linux/Windows/macOS)
- Small binary (~15-20MB vs current 33MB server-only)
- Active community, good docs

---

## Phase 1: Desktop Shell Foundation (Weeks 1-3)

### 1.1 Wails Integration

**Goal**: Wrap the existing React UI in a Wails desktop shell without breaking the current web UI.

**Architecture**:
```
┌─────────────────────────────────────────────────────┐
│ Wails Desktop App                                   │
│  ┌───────────────────────────────────────────────┐ │
│  │ Native WebView (WebKitGTK / WebView2 / WKWebView) │
│  │  ┌─────────────────────────────────────────┐  │ │
│  │  │ React UI (same codebase as web)         │  │ │
│  │  │ - app.tsx, pages/*, lib/*               │  │ │
│  │  │ - Wails bindings (window.wails.*)       │  │ │
│  │  └─────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────┐ │
│  │ Go Backend (wails.App)                        │ │
│  │ - cmd/desktop/main.go                         │ │
│  │ - Bindings to internal/* packages             │ │
│  │ - System tray, native menus, file dialogs     │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Implementation**:

1. **Add Wails dependency**:
   ```bash
   cd burpsy-go
   go get github.com/wailsapp/wails/v2@latest
   ```

2. **Create desktop entry point** (`cmd/desktop/main.go`):
   ```go
   package main
   
   import (
       "context"
       "embed"
       
       "github.com/wailsapp/wails/v2"
       "github.com/wailsapp/wails/v2/pkg/options"
       "github.com/wailsapp/wails/v2/pkg/options/assetserver"
       
       "github.com/burpsy-go/burpsy/internal/web"
       // ... other imports
   )
   
   //go:embed ui/dist/*
   var assets embed.FS
   
   type App struct {
       ctx     context.Context
       server  *web.Server
   }
   
   func NewApp() *App {
       return &App{}
   }
   
   func (a *App) startup(ctx context.Context) {
       a.ctx = ctx
       // Initialize burpsy server (reuse cmd/burpsy/main.go logic)
       a.server = web.NewServer(/* ... */)
   }
   
   // Expose Go functions to frontend
   func (a *App) SendToRepeater(reqID uint64) error { /* ... */ }
   func (a *App) ExportHistory(format string) (string, error) { /* ... */ }
   func (a *App) ShowSaveDialog(title string) (string, error) { /* ... */ }
   
   func main() {
       app := NewApp()
       
       err := wails.Run(&options.App{
           Title:  "burpsy",
           Width:  1400,
           Height: 900,
           AssetServer: &assetserver.Options{
               Assets: assets,
           },
           OnStartup: app.startup,
           Bind: []interface{}{
               app,
           },
       })
       
       if err != nil {
           log.Fatal(err)
       }
   }
   ```

3. **Detect runtime mode in React** (`src/lib/runtime.ts`):
   ```typescript
   export type RuntimeMode = 'desktop' | 'web';
   
   export function getRuntimeMode(): RuntimeMode {
       // Wails injects window.wails
       return (window as any).wails ? 'desktop' : 'web';
   }
   
   export async function sendToRepeater(reqID: number): Promise<void> {
       if (getRuntimeMode() === 'desktop') {
           // Call Go function directly
           return (window as any).wails.SendToRepeater(reqID);
       } else {
           // Fall back to HTTP API
           return fetch(`/api/repeater`, {
               method: 'POST',
               body: JSON.stringify({ reqID }),
           });
       }
   }
   ```

4. **Hybrid mode** — Run both Wails desktop app AND web server:
   ```go
   func (a *App) startup(ctx context.Context) {
       a.ctx = ctx
       a.server = web.NewServer(/* ... */)
       
       // Start web server in background (for remote access)
       go func() {
           a.server.ListenAndServe(":3080")
       }()
   }
   ```
   Now users can: use the desktop app locally OR access `http://127.0.0.1:3080` remotely.

**Deliverables**:
- `cmd/desktop/main.go` — Wails entry point
- `src/lib/runtime.ts` — Runtime detection + bindings
- Build script: `wails build` produces native binaries (Linux/Windows/macOS)
- Documentation: `docs/DESKTOP.md` — how to build, run, distribute

**Estimated effort**: 2-3 days (Wails setup + basic bindings)

---

### 1.2 System Tray + Native Menus

**Goal**: Add system tray icon and native menu bar (File, Edit, View, Tools, Help).

**Implementation**:

```go
import (
    "github.com/wailsapp/wails/v2/pkg/menu"
    "github.com/wailsapp/wails/v2/pkg/menu/keys"
)

func (a *App) startup(ctx context.Context) {
    // ... existing startup code ...
    
    // System tray
    wails.WindowSetSystemDefaultSize(ctx, 1400, 900)
    
    // Native menu bar
    appMenu := menu.NewMenu()
    
    fileMenu := appMenu.AddSubmenu("File")
    fileMenu.AddText("New Project", keys.CmdOrCtrl("n"), a.newProject)
    fileMenu.AddText("Open Project...", keys.CmdOrCtrl("o"), a.openProject)
    fileMenu.AddText("Save Project", keys.CmdOrCtrl("s"), a.saveProject)
    fileMenu.AddSeparator()
    fileMenu.AddText("Import History...", keys.Combo("i", keys.CmdOrCtrlKey, keys.ShiftKey), a.importHistory)
    fileMenu.AddText("Export History...", keys.Combo("e", keys.CmdOrCtrlKey, keys.ShiftKey), a.exportHistory)
    fileMenu.AddSeparator()
    fileMenu.AddText("Exit", keys.CmdOrCtrl("q"), a.exit)
    
    editMenu := appMenu.AddSubmenu("Edit")
    editMenu.AddText("Undo", keys.CmdOrCtrl("z"), a.undo)
    editMenu.AddText("Redo", keys.Combo("z", keys.CmdOrCtrlKey, keys.ShiftKey), a.redo)
    editMenu.AddSeparator()
    editMenu.AddText("Cut", keys.CmdOrCtrl("x"), a.cut)
    editMenu.AddText("Copy", keys.CmdOrCtrl("c"), a.copy)
    editMenu.AddText("Paste", keys.CmdOrCtrl("v"), a.paste)
    
    viewMenu := appMenu.AddSubmenu("View")
    viewMenu.AddText("Proxy", keys.CmdOrCtrl("1"), a.showProxy)
    viewMenu.AddText("Repeater", keys.CmdOrCtrl("2"), a.showRepeater)
    viewMenu.AddText("Scanner", keys.CmdOrCtrl("3"), a.showScanner)
    viewMenu.AddText("Intruder", keys.CmdOrCtrl("4"), a.showIntruder)
    viewMenu.AddText("Dashboard", keys.CmdOrCtrl("5"), a.showDashboard)
    viewMenu.AddSeparator()
    viewMenu.AddText("Toggle Intercept", keys.Combo("i", keys.CmdOrCtrlKey, keys.OptionOrAltKey), a.toggleIntercept)
    
    toolsMenu := appMenu.AddSubmenu("Tools")
    toolsMenu.AddText("Decoder", keys.Combo("d", keys.CmdOrCtrlKey, keys.ShiftKey), a.showDecoder)
    toolsMenu.AddText("Comparer", keys.Combo("c", keys.CmdOrCtrlKey, keys.ShiftKey), a.showComparer)
    toolsMenu.AddText("Sequencer", keys.Combo("s", keys.CmdOrCtrlKey, keys.ShiftKey), a.showSequencer)
    
    helpMenu := appMenu.AddSubmenu("Help")
    helpMenu.AddText("Documentation", nil, a.openDocs)
    helpMenu.AddText("About burpsy", nil, a.showAbout)
    
    wails.MenuSetApplicationMenu(ctx, appMenu)
}
```

**Deliverables**:
- System tray icon (burpsy logo)
- Native menu bar with keyboard shortcuts
- File dialogs (open/save project, import/export)

**Estimated effort**: 1 day

---

### 1.3 Build + Distribution

**Goal**: Produce distributable binaries for Linux, Windows, macOS.

**Build script** (`scripts/build-desktop.sh`):
```bash
#!/bin/bash
set -e

cd burpsy-go

# Build UI
cd internal/web/ui
bun run build
cd ../../..

# Build desktop app (Wails handles cross-compilation)
wails build -platform linux/amd64,linux/arm64,windows/amd64,darwin/amd64,darwin/arm64

# Output: build/bin/burpsy-{linux,linux-arm64,windows,darwin,darwin-arm64}
```

**Distribution**:
- **Linux**: AppImage + .deb + .rpm
- **Windows**: NSIS installer + portable .exe
- **macOS**: .dmg with code signing (requires Apple Developer account)

**Auto-updates**: Use Wails' built-in updater or integrate with GitHub Releases.

**Deliverables**:
- CI workflow (`.github/workflows/desktop-release.yml`)
- Signed binaries (Windows + macOS)
- Auto-update mechanism

**Estimated effort**: 2-3 days (CI setup + code signing)

---

## Phase 2: Keyboard Shortcuts (Weeks 4-5)

### 2.1 Global Shortcut System

**Goal**: Implement 50+ keyboard shortcuts (matching Burp's 118 KeyHandler classes).

**Implementation**:

1. **Shortcut registry** (`src/lib/shortcuts.ts`):
   ```typescript
   export interface Shortcut {
       key: string;           // e.g., "Ctrl+R"
       action: string;        // e.g., "sendToRepeater"
       description: string;   // e.g., "Send to Repeater"
       scope: 'global' | 'proxy' | 'repeater' | 'scanner' | 'intruder';
   }
   
   export const SHORTCUTS: Shortcut[] = [
       // Global
       { key: "Ctrl+1", action: "showProxy", description: "Show Proxy", scope: "global" },
       { key: "Ctrl+2", action: "showRepeater", description: "Show Repeater", scope: "global" },
       { key: "Ctrl+3", action: "showScanner", description: "Show Scanner", scope: "global" },
       { key: "Ctrl+4", action: "showIntruder", description: "Show Intruder", scope: "global" },
       { key: "Ctrl+5", action: "showDashboard", description: "Show Dashboard", scope: "global" },
       { key: "Ctrl+K", action: "commandPalette", description: "Command Palette", scope: "global" },
       { key: "Ctrl+Shift+P", action: "commandPalette", description: "Command Palette", scope: "global" },
       
       // Proxy
       { key: "Ctrl+Space", action: "toggleIntercept", description: "Toggle Intercept", scope: "proxy" },
       { key: "Ctrl+F", action: "forwardRequest", description: "Forward Request", scope: "proxy" },
       { key: "Ctrl+D", action: "dropRequest", description: "Drop Request", scope: "proxy" },
       
       // Repeater
       { key: "Ctrl+R", action: "sendRequest", description: "Send Request", scope: "repeater" },
       { key: "Ctrl+Shift+R", action: "sendAndFollowRedirects", description: "Send + Follow Redirects", scope: "repeater" },
       { key: "Ctrl+L", action: "updateContentLength", description: "Update Content-Length", scope: "repeater" },
       
       // Context menu actions
       { key: "Ctrl+Shift+R", action: "sendToRepeater", description: "Send to Repeater", scope: "global" },
       { key: "Ctrl+Shift+I", action: "sendToIntruder", description: "Send to Intruder", scope: "global" },
       { key: "Ctrl+Shift+S", action: "sendToScanner", description: "Send to Scanner", scope: "global" },
       { key: "Ctrl+Shift+C", action: "sendToComparer", description: "Send to Comparer", scope: "global" },
       
       // ... 50+ more
   ];
   ```

2. **Shortcut hook** (`src/lib/useShortcuts.ts`):
   ```typescript
   import { useEffect } from 'react';
   import { SHORTCUTS } from './shortcuts';
   
   export function useShortcuts(scope: string, actions: Record<string, () => void>) {
       useEffect(() => {
           const handler = (e: KeyboardEvent) => {
               const key = formatKeyEvent(e);
               const shortcut = SHORTCUTS.find(s => 
                   s.key === key && (s.scope === 'global' || s.scope === scope)
               );
               
               if (shortcut && actions[shortcut.action]) {
                   e.preventDefault();
                   actions[shortcut.action]();
               }
           };
           
           window.addEventListener('keydown', handler);
           return () => window.removeEventListener('keydown', handler);
       }, [scope, actions]);
   }
   
   function formatKeyEvent(e: KeyboardEvent): string {
       const parts: string[] = [];
       if (e.ctrlKey || e.metaKey) parts.push('Ctrl');
       if (e.shiftKey) parts.push('Shift');
       if (e.altKey) parts.push('Alt');
       parts.push(e.key.toUpperCase());
       return parts.join('+');
   }
   ```

3. **Usage in components**:
   ```typescript
   // In pages/repeater.tsx
   useShortcuts('repeater', {
       sendRequest: () => handleSend(),
       updateContentLength: () => handleUpdateCL(),
   });
   ```

**Deliverables**:
- 50+ keyboard shortcuts (matching Burp's most common)
- Shortcut cheatsheet overlay (`Ctrl+/` to toggle)
- Customizable shortcuts (user preferences)

**Estimated effort**: 3-4 days (implementation + testing)

---

### 2.2 Context Menu Expansion

**Goal**: Expand context menus from ~3-4 actions to 10+ actions per screen.

**Implementation**:

1. **Context menu registry** (`src/lib/contextMenus.ts`):
   ```typescript
   export interface ContextMenuItem {
       label: string;
       action: string;
       shortcut?: string;
       separator?: boolean;
   }
   
   export const HISTORY_CONTEXT_MENU: ContextMenuItem[] = [
       { label: "Send to Repeater", action: "sendToRepeater", shortcut: "Ctrl+Shift+R" },
       { label: "Send to Intruder", action: "sendToIntruder", shortcut: "Ctrl+Shift+I" },
       { label: "Send to Scanner", action: "sendToScanner", shortcut: "Ctrl+Shift+S" },
       { label: "Send to Comparer", action: "sendToComparer", shortcut: "Ctrl+Shift+C" },
       { separator: true },
       { label: "Copy URL", action: "copyURL" },
       { label: "Copy as cURL", action: "copyAsCurl" },
       { label: "Copy Request", action: "copyRequest" },
       { label: "Copy Response", action: "copyResponse" },
       { separator: true },
       { label: "Add to Scope", action: "addToScope" },
       { label: "Remove from Scope", action: "removeFromScope" },
       { separator: true },
       { label: "Comment...", action: "addComment" },
       { label: "Highlight", action: "highlight", submenu: ["Red", "Orange", "Yellow", "Green", "Blue"] },
       { separator: true },
       { label: "Delete", action: "delete" },
   ];
   
   export const REPEATER_CONTEXT_MENU: ContextMenuItem[] = [
       { label: "Send", action: "send", shortcut: "Ctrl+R" },
       { label: "Send + Follow Redirects", action: "sendFollow", shortcut: "Ctrl+Shift+R" },
       { separator: true },
       { label: "Send to Intruder", action: "sendToIntruder", shortcut: "Ctrl+Shift+I" },
       { label: "Send to Scanner", action: "sendToScanner", shortcut: "Ctrl+Shift+S" },
       { label: "Send to Comparer", action: "sendToComparer", shortcut: "Ctrl+Shift+C" },
       { separator: true },
       { label: "Copy Request", action: "copyRequest" },
       { label: "Copy Response", action: "copyResponse" },
       { separator: true },
       { label: "Save to Organizer", action: "saveToOrganizer" },
       { separator: true },
       { label: "Close Tab", action: "closeTab" },
       { label: "Close Other Tabs", action: "closeOtherTabs" },
   ];
   
   // ... similar for Scanner, Intruder, etc.
   ```

2. **Context menu component** (`src/components/ContextMenu.tsx`):
   ```typescript
   import * as RadixContextMenu from '@radix-ui/react-context-menu';
   
   export function ContextMenu({ items, children }: Props) {
       return (
           <RadixContextMenu.Root>
               <RadixContextMenu.Trigger asChild>
                   {children}
               </RadixContextMenu.Trigger>
               <RadixContextMenu.Portal>
                   <RadixContextMenu.Content className="context-menu">
                       {items.map((item, i) => 
                           item.separator ? (
                               <RadixContextMenu.Separator key={i} />
                           ) : (
                               <RadixContextMenu.Item
                                   key={i}
                                   onSelect={() => handleAction(item.action)}
                               >
                                   {item.label}
                                   {item.shortcut && (
                                       <span className="shortcut">{item.shortcut}</span>
                                   )}
                               </RadixContextMenu.Item>
                           )
                       )}
                   </RadixContextMenu.Content>
               </RadixContextMenu.Portal>
           </RadixContextMenu.Root>
       );
   }
   ```

**Deliverables**:
- Expanded context menus (10+ actions per screen)
- Shortcut hints in context menus
- Submenus (e.g., Highlight → color picker)

**Estimated effort**: 2-3 days

---

## Phase 3: Config UI Expansion (Weeks 6-8)

### 3.1 Settings Screen Overhaul

**Goal**: Expand from ~20-30 config panels to 80+ (matching Burp's 124).

**Implementation**:

1. **Settings structure** (`src/pages/settings.tsx`):
   ```typescript
   const SETTINGS_CATEGORIES = [
       {
           id: "proxy",
           label: "Proxy",
           panels: [
               "listeners",
               "request-handling",
               "response-handling",
               "match-replace",
               "tls-pass-through",
               "misc",
           ],
       },
       {
           id: "scanner",
           label: "Scanner",
           panels: [
               "scan-configuration",
               "insertion-points",
               "active-scanning",
               "passive-scanning",
               "crawl",
               "audit-optimization",
           ],
       },
       {
           id: "intruder",
           label: "Intruder",
           panels: [
               "payloads",
               "payload-processing",
               "grep-match",
               "resource-pools",
           ],
       },
       {
           id: "repeater",
           label: "Repeater",
           panels: [
               "connections",
               "redirects",
               "streaming-responses",
           ],
       },
       {
           id: "sequencer",
           label: "Sequencer",
           panels: [
               "token-analysis",
               "token-handling",
               "live-capture",
           ],
       },
       {
           id: "session",
           label: "Session",
           panels: [
               "session-handling-rules",
               "cookie-jar",
               "macros",
           ],
       },
       {
           id: "target",
           label: "Target",
           panels: [
               "scope",
               "site-map",
           ],
       },
       {
           id: "user-interface",
           label: "User Interface",
           panels: [
               "appearance",
               "hotkeys",
               "logging",
           ],
       },
       {
           id: "network",
           label: "Network",
           panels: [
               "timeouts",
               "upstream-proxy",
               "socks-proxy",
               "tls-negotiation",
           ],
       },
       {
           id: "tasks",
           label: "Tasks",
           panels: [
               "task-settings",
               "scheduled-tasks",
               "auto-start",
           ],
       },
   ];
   ```

2. **Settings panel components** (`src/pages/settings/panels/*.tsx`):
   - `ProxyListenersPanel.tsx` — Listener config (add/edit/delete listeners)
   - `ScannerConfigPanel.tsx` — Scan configuration (checks, insertion points)
   - `SessionRulesPanel.tsx` — Session handling rules
   - `MatchReplacePanel.tsx` — Match & replace rules
   - ... (80+ panels total)

**Deliverables**:
- 80+ settings panels (matching Burp's 124)
- Settings search (filter by name/description)
- Import/export settings (JSON)

**Estimated effort**: 2-3 weeks (largest phase)

---

### 3.2 Scan Configuration Wizard

**Goal**: Add a GUI wizard for configuring scans (currently JSON API only).

**Implementation**:

```typescript
// src/pages/scanner/ScanWizard.tsx
export function ScanWizard({ onComplete }: Props) {
    const [step, setStep] = useState(0);
    const [config, setConfig] = useState<ScanConfig>({});
    
    const steps = [
        {
            title: "Select Targets",
            component: <TargetSelector onChange={targets => setConfig({ ...config, targets })} />,
        },
        {
            title: "Choose Scan Type",
            component: (
                <div>
                    <RadioGroup value={config.scanType} onChange={type => setConfig({ ...config, scanType: type })}>
                        <Radio value="crawl">Crawl only</Radio>
                        <Radio value="audit">Audit only</Radio>
                        <Radio value="crawl-audit">Crawl + Audit</Radio>
                        <Radio value="live-audit">Live Audit (from Proxy)</Radio>
                    </RadioGroup>
                </div>
            ),
        },
        {
            title: "Scan Configuration",
            component: <ScanConfigEditor config={config} onChange={setConfig} />,
        },
        {
            title: "Review & Start",
            component: <ScanReview config={config} />,
        },
    ];
    
    return (
        <Dialog open onClose={() => onComplete(null)}>
            <h2>{steps[step].title}</h2>
            {steps[step].component}
            <div className="wizard-actions">
                {step > 0 && <Button onClick={() => setStep(step - 1)}>Back</Button>}
                {step < steps.length - 1 ? (
                    <Button onClick={() => setStep(step + 1)}>Next</Button>
                ) : (
                    <Button onClick={() => onComplete(config)}>Start Scan</Button>
                )}
            </div>
        </Dialog>
    );
}
```

**Deliverables**:
- 4-step scan wizard (targets → type → config → review)
- Scan preset selector (Fast / Deep / Custom)
- Insertion point configuration UI

**Estimated effort**: 3-4 days

---

## Phase 4: Missing Features (Weeks 9-12)

### 4.1 Drag-and-Drop

**Goal**: Add drag-and-drop for requests/responses (e.g., drag from History to Repeater).

**Implementation**: Use HTML5 drag-and-drop API + Radix UI primitives.

**Estimated effort**: 2 days

---

### 4.2 Import/Export

**Goal**: Add import/export for settings, history, scan results.

**Formats**:
- Settings: JSON
- History: CSV, JSON
- Scan results: HTML, JSON, SARIF (already supported), XML

**Implementation**:
- File dialogs (Wails native dialogs)
- Export endpoints in backend (`internal/web/api_export.go`)

**Estimated effort**: 3-4 days

---

### 4.3 Per-Tab Request History (Repeater)

**Goal**: Track request/response history per Repeater tab.

**Implementation**:
- Add `history` field to Repeater tab state
- Store each send/receive in history
- History viewer (table + detail)

**Estimated effort**: 2-3 days

---

### 4.4 Message Analyser (Repeater)

**Goal**: Add parameter table view (headers, query params, body params).

**Implementation**:
- Parse request/response into structured form
- Display as table (name, value, type)

**Estimated effort**: 2 days

---

### 4.5 Streaming Response Config

**Goal**: Add timeout configuration for streaming responses.

**Implementation**:
- Settings panel for streaming response timeout
- Backend: pass timeout to `internal/proxy`

**Estimated effort**: 1 day

---

### 4.6 Resource Pools (Intruder)

**Goal**: Add resource pool configuration for Intruder attacks.

**Implementation**:
- Resource pool settings panel
- Backend: `internal/intruder` resource pool support

**Estimated effort**: 2 days

---

## Phase 5: Plugin API (Weeks 13-16) — Optional

### 5.1 Extension System (Phase 8 from roadmap)

**Goal**: Implement a plugin API for third-party extensions.

**Options**:
1. **Go plugins** (`plugin` package) — Limited platform support, fragile
2. **gRPC-based extensions** — Language-agnostic, robust
3. **WebAssembly (WASM)** — Sandboxable, cross-language
4. **JavaScript extensions** (goja) — Already have goja in tree

**Recommendation**: **gRPC-based extensions** (language-agnostic, robust, sandboxable).

**Implementation**:
```go
// internal/extender/extender.go
package extender

import (
    "context"
    "net"
    
    "google.golang.org/grpc"
    
    pb "github.com/burpsy-go/burpsy/internal/extender/proto"
)

type ExtensionManager struct {
    extensions map[string]*Extension
    server     *grpc.Server
}

func NewExtensionManager() *ExtensionManager {
    return &ExtensionManager{
        extensions: make(map[string]*Extension),
        server:     grpc.NewServer(),
    }
}

func (m *ExtensionManager) Start(addr string) error {
    lis, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    
    pb.RegisterExtensionHostServer(m.server, m)
    return m.server.Serve(lis)
}

// Extension calls into burpsy
func (m *ExtensionManager) RegisterExtension(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
    // ...
}

// burpsy calls into extension
func (m *ExtensionManager) OnHTTPRequest(req *core.Request) (*core.Request, error) {
    for _, ext := range m.extensions {
        modified, err := ext.client.ProcessRequest(context.Background(), &pb.HTTPRequest{ /* ... */ })
        if err != nil {
            return nil, err
        }
        req = modified.ToCore()
    }
    return req, nil
}
```

**Deliverables**:
- gRPC extension host (`internal/extender`)
- Extension SDK (Python, JavaScript, Go)
- Extension settings UI
- Extension error log

**Estimated effort**: 3-4 weeks (major feature)

**Status**: Deliberately deferred (roadmap Phase 8). Implement only if there's user demand.

---

## Timeline + Milestones

| Phase | Weeks | Deliverables | Effort |
|---|---|---|---|
| **Phase 1**: Desktop Shell | 1-3 | Wails integration, system tray, native menus, build pipeline | 1-2 weeks |
| **Phase 2**: Keyboard Shortcuts | 4-5 | 50+ shortcuts, context menu expansion | 1 week |
| **Phase 3**: Config UI | 6-8 | 80+ settings panels, scan wizard | 2-3 weeks |
| **Phase 4**: Missing Features | 9-12 | Drag-drop, import/export, per-tab history, etc. | 2-3 weeks |
| **Phase 5**: Plugin API | 13-16 | gRPC extensions (optional) | 3-4 weeks |

**Total**: 12-16 weeks (3-4 months) for full feature parity, or 8-12 weeks (2-3 months) without plugin API.

---

## Risks + Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Wails WebView compatibility | Medium | Test on Linux/Windows/macOS early; fall back to Electron if needed |
| Performance (WebView vs native) | Low | WebView is fast enough for UI; heavy lifting stays in Go |
| Binary size increase | Low | Wails adds ~5-10MB; acceptable for desktop app |
| Maintaining two UIs (web + desktop) | Medium | Use same React codebase; detect runtime mode |
| Plugin API complexity | High | Defer Phase 5 until there's user demand |

---

## Success Criteria

1. **Desktop app runs on Linux/Windows/macOS** — Native binaries, system tray, native menus
2. **50+ keyboard shortcuts work** — Matching Burp's most common shortcuts
3. **80+ settings panels exposed** — Matching Burp's 124 config panels
4. **Context menus have 10+ actions** — Matching Burp's 324 MenuHandler classes
5. **Web UI still works** — Hybrid mode: desktop + web server simultaneously
6. **Binary size < 50MB** — Acceptable for desktop app

---

## Next Steps

1. **Start Phase 1** — Set up Wails, create `cmd/desktop/main.go`, build first desktop binary
2. **Document the plan** — Write `docs/plans/2026-08-19-desktop-app-bridge.md` (this document)
3. **Get user feedback** — Share plan with users, prioritize features based on demand
4. **Iterate** — Ship Phase 1, gather feedback, adjust Phase 2-5 priorities

---

## Sources

- `/root/burp-re/BURP_UI_UX_COMPARISON.md` — UI/UX gap analysis
- `/root/burpsy-react-ui/burpsy-go/cmd/burpsy/main.go` — Current entry point
- `/root/burpsy-react-ui/burpsy-go/internal/web/server.go` — Current HTTP server
- `/root/burpsy-react-ui/burpsy-go/internal/web/ui/` — React UI source
- Wails v2 docs: https://wails.io/docs/
