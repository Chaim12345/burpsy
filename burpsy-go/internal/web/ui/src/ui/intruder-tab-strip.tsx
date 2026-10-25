// The Intruder attack-tab strip (burpsy-react-ui-9bv2). Burp: "When you send a request to Burp
// Intruder, this creates a new attack tab", with Close, Close all tabs and Reopen closed tab
// (managing-tabs.html). The state rules live in lib/intruder-tabs.ts; this is only the strip.

import { useState } from "react";
import { Plus, RotateCcw, X } from "lucide-react";
import { useApp } from "../lib/store";
import { cn } from "../lib/cn";
import { ContextMenu, type MenuGroup } from "./menu";
import { IconButton, Input } from "./primitives";

export function IntruderTabStrip(): JSX.Element {
 const tabs = useApp((state) => state.intruderTabs);
 const activeId = useApp((state) => state.activeIntruderTabId);
 const closed = useApp((state) => state.closedIntruderTabs);
 const running = useApp((state) => state.intruderRunningTabs);
 const open = useApp((state) => state.openIntruderTab);
 const select = useApp((state) => state.switchIntruderTab);
 const close = useApp((state) => state.closeIntruderTab);
 const closeAll = useApp((state) => state.closeAllIntruderTabs);
 const reopen = useApp((state) => state.reopenIntruderTab);
 const rename = useApp((state) => state.renameIntruderTab);
 const [renaming, setRenaming] = useState<string | null>(null);
 const [draft, setDraft] = useState("");

 const reopenLabel = closed.length ? `Reopen closed tab (${closed.length})` : "Reopen closed tab";
 const menu = (id: string, name: string): MenuGroup[] => [
  {
   id: "tab",
   actions: [
    { id: "rename", label: "Rename", onSelect: () => (setRenaming(id), setDraft(name)) },
    { id: "new", label: "New attack tab", icon: Plus, onSelect: open },
   ],
  },
  {
   id: "lifecycle",
   actions: [
    // A running attack's report is written to its tab when it lands, so that tab stays open.
    { id: "close", label: "Close", danger: true, disabled: running.includes(id), onSelect: () => close(id) },
    { id: "close-all", label: "Close all tabs", danger: true, disabled: running.length > 0, onSelect: closeAll },
    { id: "reopen", label: reopenLabel, icon: RotateCcw, disabled: closed.length === 0, onSelect: reopen },
   ],
  },
 ];
 const commit = (id: string) => {
  rename(id, draft);
  setRenaming(null);
 };

 return (
  // A labelled group of toggle buttons rather than a tablist: each tab carries its own close button,
  // and a tablist may own nothing but tabs (axe aria-required-children).
  <div className="tabs-list" role="group" aria-label="Intruder attack tabs" style={{ marginBottom: 10 }}>
   {tabs.map((tab) => (
    <ContextMenu key={tab.id} groups={menu(tab.id, tab.name)} docTopic="intruder">
     <span style={{ display: "inline-flex", alignItems: "center" }}>
      <button
       type="button"
       aria-pressed={tab.id === activeId}
       className={cn("tabs-trigger")}
       data-state={tab.id === activeId ? "active" : undefined}
       title={running.includes(tab.id) ? `${tab.name} — attack running` : `${tab.name} — double-click to rename`}
       onClick={() => select(tab.id)}
       onDoubleClick={() => (setRenaming(tab.id), setDraft(tab.name))}
       style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
      >
       {renaming === tab.id ? null : <span>{tab.name}</span>}
       {running.includes(tab.id) ? (
        <span aria-hidden style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--accent)" }} />
       ) : null}
      </button>
      {renaming === tab.id ? (
       <Input
        value={draft}
        autoFocus
        aria-label="Attack tab name"
        onChange={(event) => setDraft(event.target.value)}
        onBlur={() => commit(tab.id)}
        onKeyDown={(event) => {
         if (event.key === "Enter") commit(tab.id);
         if (event.key === "Escape") setRenaming(null);
        }}
        style={{ maxWidth: "16ch", height: "1.4em", padding: "0 var(--s1)" }}
       />
      ) : null}
      <IconButton
       label={
        running.includes(tab.id) ? `Attack tab ${tab.name} is running; stop it or wait before closing` : `Close attack tab ${tab.name}`
       }
       size="small"
       disabled={running.includes(tab.id)}
       onClick={() => close(tab.id)}
      >
       <X size={11} />
      </IconButton>
     </span>
    </ContextMenu>
   ))}
   <IconButton label="New attack tab" size="small" onClick={open}>
    <Plus size={13} />
   </IconButton>
   <IconButton label={reopenLabel} size="small" onClick={reopen} disabled={closed.length === 0}>
    <RotateCcw size={13} />
   </IconButton>
  </div>
 );
}
