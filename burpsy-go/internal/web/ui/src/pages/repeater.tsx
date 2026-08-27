import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, Columns3, Copy, Crosshair, Plus, RotateCcw, Send, SlidersHorizontal, X } from "lucide-react";
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { api, formatDuration, json, statusTone, templateRequest } from "../lib/api";
import { SendCancelled, useRepeaterSend } from "../lib/data.tools";
import { useApp, type RepeaterTab } from "../lib/store";
import type { Exchange, RepeaterRedirects, RepeaterResult, RepeaterSendOptions } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Select, Tooltip } from "../ui/primitives";
import { ContextMenu, type MenuGroup } from "../ui/menu";
import { SimpleTable } from "../ui/table";

const DEFAULT_TARGET = "https://example.com:443";

/** The transport is read off the target URL rather than tracked separately. */
function schemeOf(target: string): "http" | "https" {
  return /^http:\/\//i.test(target.trim()) ? "http" : "https";
}

/**
 * Repeater keeps one tab per request under test. Tabs persist across reloads
 * (see the store's partialize), because losing a hand-crafted request to an
 * accidental refresh is the failure mode operators complain about most.
 */
export function RepeaterPage(): JSX.Element {
  const tabs = useApp((state) => state.repeaterTabs);
  const activeId = useApp((state) => state.activeRepeaterTab);
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const updateRepeaterTab = useApp((state) => state.updateRepeaterTab);
  const closeRepeaterTab = useApp((state) => state.closeRepeaterTab);
  const setActiveRepeaterTab = useApp((state) => state.setActiveRepeaterTab);
  const setIntruderSeed = useApp((state) => state.setIntruderSeed);
  const setRoute = useApp((state) => state.setRoute);

  // U19: groups + reopen stack. U20: per-tab send options. All actions are individual selectors
  // to match the house zustand style — no whole-store subscription that re-renders on any keypress
  // anywhere in the app.
  const closedTabs = useApp((state) => state.closedRepeaterTabs);
  const groups = useApp((state) => state.repeaterGroups);
  const closeOtherRepeaterTabs = useApp((state) => state.closeOtherRepeaterTabs);
  const closeRepeaterTabsLeftOf = useApp((state) => state.closeRepeaterTabsLeftOf);
  const closeRepeaterTabsRightOf = useApp((state) => state.closeRepeaterTabsRightOf);
  const duplicateRepeaterTab = useApp((state) => state.duplicateRepeaterTab);
  const reopenClosedRepeaterTab = useApp((state) => state.reopenClosedRepeaterTab);
  const createRepeaterGroup = useApp((state) => state.createRepeaterGroup);
  const renameRepeaterGroup = useApp((state) => state.renameRepeaterGroup);
  const deleteRepeaterGroup = useApp((state) => state.deleteRepeaterGroup);
  const toggleRepeaterGroup = useApp((state) => state.toggleRepeaterGroup);
  const setRepeaterTabGroup = useApp((state) => state.setRepeaterTabGroup);
  const setRepeaterTabOptions = useApp((state) => state.setRepeaterTabOptions);

  /**
   * Every response a tab has received, oldest first — not just the latest. Held in memory only;
   * the store persists the request draft across reloads, deliberately not the responses.
   *
   * Burp keeps a per-tab history because the whole method of the tool is "change one thing and
   * compare": overwriting the previous response destroys the half of the comparison you were about
   * to make. This kept exactly one response per tab and dropped the rest on every send.
   */
  const [history, setHistory] = useState<Record<string, RepeaterResult[]>>({});
  /** Which entry of the active tab's history is on screen. Null follows the newest. */
  const [viewing, setViewing] = useState<Record<string, number | null>>({});
  const [handingOff, setHandingOff] = useState(false);
  const [inspector, setInspector] = useState(true);
  /**
   * Which half of the exchange the Inspector is pointed at.
   *
   * The request half is editable — it is a draft, and that is the whole point of
   * the tool. The response half is not, and rather than render fields that
   * swallow keystrokes it says why (see `readOnlyNote` below). Offering only the
   * request would have been the easier answer, but an operator who wants to read
   * a Set-Cookie out of the response should not have to count bytes in Raw.
   */
  const [inspecting, setInspecting] = useState<"request" | "response">("request");
  const send = useRepeaterSend();

  // Bulk closes (close others / left / right) remove many tabs at once, so per-close cleanup in
  // the click handlers no longer covers it. One pruning effect owns the invariant instead: the
  // response history and the view position only ever hold keys for tabs that still exist.
  useEffect(() => {
    const alive = new Set(tabs.map((tab) => tab.id));
    setHistory((current) => Object.fromEntries(Object.entries(current).filter(([id]) => alive.has(id))));
    setViewing((current) => Object.fromEntries(Object.entries(current).filter(([id]) => alive.has(id))));
  }, [tabs]);

  const [renamingTab, setRenamingTab] = useState<string | null>(null);
  const [tabRenameValue, setTabRenameValue] = useState("");
  const [renamingGroup, setRenamingGroup] = useState<string | null>(null);
  const [groupRenameValue, setGroupRenameValue] = useState("");
  /** Whether the config-override panel (U20) is open for the active tab. */
  const [configOpen, setConfigOpen] = useState(false);

  const active = useMemo(() => tabs.find((tab) => tab.id === activeId) ?? tabs[0] ?? null, [tabs, activeId]);

  useEffect(() => {
    if (!active && tabs.length === 0) return;
    if (active && active.id !== activeId) setActiveRepeaterTab(active.id);
  }, [active, activeId, tabs.length, setActiveRepeaterTab]);

  const newTab = () => {
    openRepeaterTab({
      name: `Request ${tabs.length + 1}`,
      target: DEFAULT_TARGET,
      protocol: "https",
      request: templateRequest("example.com"),
    });
  };

  const submit = (tab: RepeaterTab) => {
    send.mutate(
      {
        target: tab.target,
        request: tab.request,
        protocol: schemeOf(tab.target),
        from_exchange: tab.fromExchange,
        // Absent options means "standing behaviour" — the backend validates and applies whatever
        // arrives, so an empty object is never sent when the operator set nothing.
        ...(tab.options ? { options: tab.options } : {}),
      },
      {
        onSuccess: (result) => {
          setHistory((current) => ({ ...current, [tab.id]: [...(current[tab.id] ?? []), result] }));
          // A new send always snaps the view forward: an operator who had paged back to compare is
          // still asking "what did this one do", and leaving them on an older entry would answer a
          // question they stopped asking.
          setViewing((current) => ({ ...current, [tab.id]: null }));
          toast.success(`${result.status} in ${formatDuration(result.duration_ms)}`);
        },
        onError: (error) => {
          // A cancellation is the operator getting what they asked for, so it is reported as
          // information rather than as a failure. It still says the request may have reached the
          // target: burpsy stopped waiting and told the sender to stop, but bytes already on the
          // wire are gone, and pretending otherwise is the one thing this button must not do.
          if (error instanceof SendCancelled) {
            toast.info("Send cancelled — anything already written to the target was still sent");
            return;
          }
          toast.error(error instanceof Error ? error.message : String(error));
        },
      },
    );
  };

  useHotkeys(
    "mod+enter",
    (event) => {
      event.preventDefault();
      if (active) submit(active);
    },
    { enableOnFormTags: true, enableOnContentEditable: true },
    [active],
  );

  /**
   * Intruder splices payloads into a *stored* message, so a Repeater draft has to
   * be sent once to exist in the store. Send it if needed, then resolve the
   * resulting exchange to the request message id Intruder needs.
   */
  const handOffToIntruder = async (tab: RepeaterTab) => {
    setHandingOff(true);
    try {
      const known = history[tab.id] ?? [];
      let exchangeId = known[known.length - 1]?.exchange_id;
      if (!exchangeId) {
        const sent = await api<RepeaterResult>(
          "/api/repeater/send",
          json("POST", {
            target: tab.target,
            request: tab.request,
            protocol: schemeOf(tab.target),
            ...(tab.options ? { options: tab.options } : {}),
          }),
        );
        setHistory((current) => ({ ...current, [tab.id]: [...(current[tab.id] ?? []), sent] }));
        exchangeId = sent.exchange_id;
      }
      if (!exchangeId) {
        toast.error("This request was not captured, so Intruder has no stored message to work from");
        return;
      }
      const exchange = await api<Exchange>(`/api/exchange/${exchangeId}`);
      setIntruderSeed({ msgId: exchange.request, target: tab.target, label: tab.name });
      setRoute("intruder");
      toast.success(`Message ${exchange.request} sent to Intruder`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    } finally {
      setHandingOff(false);
    }
  };

  if (!active) {
    return (
      <div className="page">
        <PageHeader title="Repeater" description="Craft one request and read its exact response." />
        <Empty
          title="No request open"
          detail="Start a blank request, or right-click any row in HTTP history and choose “Send to Repeater”."
          action={
            <Button onClick={newTab}>
              <Plus size={14} />
              New request
            </Button>
          }
        />
      </div>
    );
  }

  // The entry on screen: whichever the operator paged to, else the newest.
  const activeHistory = history[active.id] ?? [];
  const viewIndex = viewing[active.id] ?? activeHistory.length - 1;
  const result = activeHistory[viewIndex];
  /** How many overrides the active tab carries — shown on the Config trigger so a panel that is
   *  closed cannot silently narrow what Send will do. */
  const overrideCount = Object.keys(active.options ?? {}).length;

  /**
   * Merge a patch into the active tab's options, then drop every field whose value means
   * "standing behaviour" (empty string, false). Absence on the wire IS the default: sending an
   * explicit `false` would claim the operator chose something, when they merely unchecked it back.
   */
  const applyOptions = (patch: Partial<RepeaterSendOptions>) => {
    if (!active) return;
    const merged: RepeaterSendOptions = { ...(active.options ?? {}), ...patch };
    for (const key of Object.keys(merged) as (keyof RepeaterSendOptions)[]) {
      const value = merged[key];
      if (value === undefined || value === "" || value === false) delete merged[key];
    }
    setRepeaterTabOptions(active.id, merged);
  };

  /**
   * One tab trigger, wrapped in its own right-click menu. Built per tab rather than per strip so
   * each item closes over that tab's id and position; disabled states are computed here too,
   * because a menu that offers "close left" on the first tab is lying about the model.
   */
  const tabMenuGroups = (tab: RepeaterTab): MenuGroup[] => {
    const index = tabs.findIndex((t) => t.id === tab.id);
    return [
      {
        id: "edit",
        actions: [
          { id: "duplicate", label: "Duplicate tab", icon: Copy, onSelect: () => duplicateRepeaterTab(tab.id) },
          {
            id: "rename",
            label: "Rename",
            onSelect: () => {
              setRenamingTab(tab.id);
              setTabRenameValue(tab.name);
            },
          },
          ...groups.map((group) => ({
            id: `move-${group.id}`,
            label: `Move to ${group.name}`,
            onSelect: () => setRepeaterTabGroup(tab.id, group.id),
          })),
          ...(groups.length
            ? [{ id: "ungroup", label: "Remove from group", disabled: !tab.groupId, onSelect: () => setRepeaterTabGroup(tab.id, null) }]
            : []),
        ],
      },
      {
        id: "lifecycle",
        actions: [
          { id: "close", label: "Close", danger: true, onSelect: () => closeRepeaterTab(tab.id) },
          { id: "close-others", label: "Close other tabs", disabled: tabs.length < 2, onSelect: () => closeOtherRepeaterTabs(tab.id) },
          { id: "close-left", label: "Close tabs to the left", disabled: index <= 0, onSelect: () => closeRepeaterTabsLeftOf(tab.id) },
          {
            id: "close-right",
            label: "Close tabs to the right",
            disabled: index < 0 || index >= tabs.length - 1,
            onSelect: () => closeRepeaterTabsRightOf(tab.id),
          },
          {
            id: "reopen",
            label: closedTabs.length ? `Reopen closed tab (${closedTabs.length})` : "Reopen closed tab",
            icon: RotateCcw,
            disabled: closedTabs.length === 0,
            onSelect: reopenClosedRepeaterTab,
          },
          {
            id: "new-group",
            label: "New group with this tab",
            onSelect: () => setRepeaterTabGroup(tab.id, createRepeaterGroup()),
          },
        ],
      },
    ];
  };

  const renderTabTrigger = (tab: RepeaterTab): JSX.Element => (
    <ContextMenu groups={tabMenuGroups(tab)}>
      <div
        role="tab"
        aria-selected={tab.id === active.id}
        className="tabs-trigger"
        data-state={tab.id === active.id ? "active" : undefined}
        onClick={() => setActiveRepeaterTab(tab.id)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") setActiveRepeaterTab(tab.id);
        }}
        tabIndex={0}
        title={tab.name}
      >
        {renamingTab === tab.id ? (
          <Input
            value={tabRenameValue}
            autoFocus
            onChange={(event) => setTabRenameValue(event.target.value)}
            onBlur={() => commitTabRename(tab.id)}
            onKeyDown={(event) => {
              if (event.key === "Enter") commitTabRename(tab.id);
              if (event.key === "Escape") setRenamingTab(null);
            }}
            style={{ maxWidth: "14ch", height: "1.4em", padding: "0 var(--s1)" }}
            aria-label="Tab name"
          />
        ) : (
          <span>{tab.name}</span>
        )}
        <button
          type="button"
          className="tab-close"
          aria-label={`Close ${tab.name}`}
          onClick={(event) => {
            event.stopPropagation();
            closeRepeaterTab(tab.id);
          }}
        >
          <X size={11} />
        </button>
      </div>
    </ContextMenu>
  );

  /** Bulk closes can orphan response history keys; the pruning effect above owns cleanup. */
  const commitTabRename = (id: string) => {
    updateRepeaterTab(id, { name: tabRenameValue.trim() || `Request ${tabs.length + 1}` });
    setRenamingTab(null);
  };

  const ungrouped = tabs.filter((tab) => !tab.groupId || !groups.some((group) => group.id === tab.groupId));
  const commitGroupRename = (groupId: string) => {
    renameRepeaterGroup(groupId, groupRenameValue.trim() || "Group");
    setRenamingGroup(null);
  };

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Repeater"
          actions={
            <>
              <Badge tone={schemeOf(active.target) === "https" ? "good" : "warn"}>{schemeOf(active.target)}</Badge>
              {result ? (
                <>
                  <Badge tone={statusTone(result.status)}>{result.status}</Badge>
                  <Badge>{formatDuration(result.duration_ms)}</Badge>
                  {result.exchange_id ? <Badge>#{result.exchange_id}</Badge> : null}
                </>
              ) : null}
              {activeHistory.length > 1 ? (
                <span className="repeater-history" role="group" aria-label="Response history">
                  <IconButton
                    label="Previous response"
                    size="small"
                    disabled={viewIndex <= 0}
                    onClick={() => setViewing((c) => ({ ...c, [active.id]: Math.max(0, viewIndex - 1) }))}
                  >
                    <ChevronLeft size={13} />
                  </IconButton>
                  {/* Counts from 1 because it is a position an operator reads aloud, not an index. */}
                  <span className="cell-num" aria-live="polite">
                    {viewIndex + 1}/{activeHistory.length}
                  </span>
                  <IconButton
                    label="Next response"
                    size="small"
                    disabled={viewIndex >= activeHistory.length - 1}
                    onClick={() =>
                      setViewing((c) => {
                        const next = Math.min(activeHistory.length - 1, viewIndex + 1);
                        // Landing back on the newest returns the tab to following new sends, rather
                        // than pinning it to what is currently the last index and silently going
                        // stale the next time one lands.
                        return { ...c, [active.id]: next === activeHistory.length - 1 ? null : next };
                      })
                    }
                  >
                    <ChevronRight size={13} />
                  </IconButton>
                </span>
              ) : null}
              <IconButton
                label={inspector ? "Hide Inspector" : "Show Inspector"}
                size="small"
                aria-pressed={inspector}
                onClick={() => setInspector((current) => !current)}
              >
                <Columns3 size={13} />
              </IconButton>
              <Tooltip content="Per-send overrides for this tab">
                <Button variant="outline" aria-pressed={configOpen} onClick={() => setConfigOpen((open) => !open)}>
                  <SlidersHorizontal size={14} />
                  Config{overrideCount ? ` (${overrideCount})` : ""}
                </Button>
              </Tooltip>
              {/* Burp pairs Send with Cancel because a request to a wedged host otherwise leaves the
                  tab stuck with no way back except closing it. Shown only while a send is in flight:
                  a Cancel that is always present but usually inert invites a click that does nothing
                  and teaches the operator the control is unreliable. */}
              {send.isPending ? (
                <Tooltip content="Stop waiting and tell the sender to abandon this request">
                  <button type="button" className="button button-outline" onClick={send.cancel}>
                    <X size={14} />
                    Cancel
                  </button>
                </Tooltip>
              ) : null}
              <Tooltip content="Send the current request (mod+Enter)">
                <button type="button" className="button button-primary" onClick={() => submit(active)} disabled={send.isPending}>
                  <Send size={14} />
                  {send.isPending ? "Sending…" : "Send"}
                </button>
              </Tooltip>
            </>
          }
        />

        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10 }}>
          <div className="tabs-list" role="tablist" aria-label="Ungrouped Repeater requests">
            {ungrouped.map(renderTabTrigger)}
            <IconButton label="New request" size="small" onClick={newTab}>
              <Plus size={13} />
            </IconButton>
          </div>
          {groups.map((group) => {
            const members = tabs.filter((tab) => tab.groupId === group.id);
            return (
              <div key={group.id} style={{ border: `1px solid ${group.color}`, borderRadius: 8, padding: 4 }}>
                <div className="toolbar" style={{ gap: 6, padding: "2px 6px", alignItems: "center" }}>
                  <IconButton
                    label={group.collapsed ? `Expand ${group.name}` : `Collapse ${group.name}`}
                    size="small"
                    onClick={() => toggleRepeaterGroup(group.id)}
                  >
                    {group.collapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
                  </IconButton>
                  <span aria-hidden style={{ width: 9, height: 9, borderRadius: "50%", background: group.color, flexShrink: 0 }} />
                  {renamingGroup === group.id ? (
                    <Input
                      value={groupRenameValue}
                      autoFocus
                      onChange={(event) => setGroupRenameValue(event.target.value)}
                      onBlur={() => commitGroupRename(group.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") commitGroupRename(group.id);
                        if (event.key === "Escape") setRenamingGroup(null);
                      }}
                      style={{ maxWidth: "16ch", height: "1.4em", padding: "0 var(--s1)" }}
                      aria-label="Group name"
                    />
                  ) : (
                    // Double-click to rename, matching how the tab name field behaves elsewhere —
                    // and keeping a single click free for collapse, which is the common action.
                    <span
                      title="Double-click to rename"
                      style={{ cursor: "text" }}
                      onDoubleClick={() => {
                        setRenamingGroup(group.id);
                        setGroupRenameValue(group.name);
                      }}
                    >
                      {group.name}
                    </span>
                  )}
                  <Badge>{members.length}</Badge>
                  {/* Deleting a group keeps its tabs on purpose; saying so in place beats an operator discovering it. */}
                  <span className="cell-dim">delete keeps tabs</span>
                  <IconButton label={`Delete group ${group.name} (keeps its tabs)`} size="small" onClick={() => deleteRepeaterGroup(group.id)}>
                    <X size={11} />
                  </IconButton>
                </div>
                {!group.collapsed ? <div className="tabs-list">{members.map(renderTabTrigger)}</div> : null}
              </div>
            );
          })}
        </div>

        <div className="toolbar" style={{ marginTop: 10 }}>
          <Field label="Target" style={{ flex: 1, minWidth: "var(--w-lg)" }}>
            {(id) => (
              <Input
                id={id}
                value={active.target}
                onChange={(event) => {
                  // The URL is the single source of truth for the transport. A separate
                  // dropdown could contradict the scheme, which silently produced TLS
                  // handshake failures against plain-HTTP targets.
                  const next = event.target.value;
                  updateRepeaterTab(active.id, { target: next, protocol: schemeOf(next) });
                }}
                // Enter in a lone text field means "do the thing" everywhere else in the
                // console. Here it was swallowed — no form to submit — so typing a target
                // and pressing Enter looked like a broken Send. mod+Enter still works from
                // the editor; this makes the plain key do the obvious thing from the field.
                onKeyDown={(event) => {
                  if (event.key !== "Enter") return;
                  event.preventDefault();
                  submit(active);
                }}
                placeholder="https://host:443"
              />
            )}
          </Field>
          <Field label="Tab name" style={{ maxWidth: "var(--w-md)" }}>
            {(id) => <Input id={id} value={active.name} onChange={(event) => updateRepeaterTab(active.id, { name: event.target.value })} />}
          </Field>
          <Button variant="outline" onClick={() => void handOffToIntruder(active)} disabled={handingOff}>
            <Crosshair size={14} />
            {handingOff ? "Preparing…" : "To Intruder"}
          </Button>
        </div>

        {/* A cancellation is excluded: it is not a failed request, and an error notice inviting a
            retry would frame the operator's own decision as something that went wrong. */}
        {send.error && !(send.error instanceof SendCancelled) ? (
          <ErrorNotice error={send.error} onRetry={() => submit(active)} />
        ) : null}
        {configOpen ? <SendOptionsPanel options={active.options} onChange={applyOptions} onReset={() => setRepeaterTabOptions(active.id, {})} /> : null}
        {result?.redirects ? <RedirectChain chain={result.redirects} /> : null}
      </div>

      <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
        <HttpEditor
          label="Request"
          value={active.request}
          onChange={(value) => updateRepeaterTab(active.id, { request: value })}
          filename="repeater-request.txt"
          placeholder="GET / HTTP/1.1"
        />
        <HttpEditor
          label="Response"
          readOnly
          value={
                result?.response ??
                (send.isPending
                  ? "Waiting for the response…"
                  : send.error instanceof SendCancelled
                    ? "Cancelled. No response arrived, and no exchange was recorded — but anything already written to the target was sent."
                    : "Send the request to see the response bytes.")
              }
          filename="repeater-response.txt"
        />
        {inspector ? (
          // Pointed at the response with nothing to show yet, it falls back to the
          // request rather than rendering a pane of empty sections that looks like
          // a parse failure.
          inspecting === "request" || !result ? (
            <Inspector
              raw={active.request}
              label="Inspector · request"
              onChange={(next) => updateRepeaterTab(active.id, { request: next })}
              onSwitch={result ? () => setInspecting("response") : undefined}
              switchLabel="Inspect the response"
            />
          ) : (
            <Inspector
              raw={result.response}
              label="Inspector · response"
              readOnlyNote="A response that has already arrived cannot be edited — change the request and send it again."
              onSwitch={() => setInspecting("request")}
              switchLabel="Inspect the request"
            />
          )
        ) : null}
      </div>
    </div>
  );
}

/**
 * The per-send config-override panel (U20) — Burp's config-override menu, scoped to one tab.
 *
 * Every control writes into the tab's `options` object and unsetting a field removes it entirely:
 * the backend's contract is that absent means "standing behaviour", so an explicit default would
 * be a payload claiming choices the operator un-made. The two switches Burp ships that are NOT
 * here are absent for reasons recorded in internal/web/repeater_options.go: no ALPN knob exists a
 * raw-byte send could honour, and redirect hops do not replay cookies, so both checkboxes would
 * be lies with labels.
 */
function SendOptionsPanel({
  options,
  onChange,
  onReset,
}: {
  options?: RepeaterSendOptions;
  onChange: (patch: Partial<RepeaterSendOptions>) => void;
  onReset: () => void;
}): JSX.Element {
  return (
    <Card style={{ marginTop: 10, padding: 12, display: "grid", gap: 10 }}>
      <div className="toolbar">
        <Field label="Follow redirections">
          {(id) => (
            <Select
              id={id}
              value={options?.redirect_mode ?? ""}
              onChange={(event) => onChange({ redirect_mode: event.target.value as RepeaterSendOptions["redirect_mode"] })}
            >
              <option value="">Standing policy (Network settings)</option>
              <option value="never">Never</option>
              <option value="on_site">On-site only</option>
              <option value="in_scope">In-scope only</option>
              <option value="always">Always</option>
            </Select>
          )}
        </Field>
        <Field label="Protocol">
          {(id) => (
            <Select
              id={id}
              value={options?.protocol_preference ?? ""}
              onChange={(event) => onChange({ protocol_preference: event.target.value as RepeaterSendOptions["protocol_preference"] })}
            >
              <option value="">Auto (negotiate)</option>
              <option value="http1">Force HTTP/1.1</option>
            </Select>
          )}
        </Field>
        <Button variant="outline" onClick={onReset}>
          <RotateCcw size={14} />
          Reset overrides
        </Button>
      </div>
      <div className="toolbar">
        <Checkbox checked={!!options?.process_cookies} label="Process cookies in this request" onCheckedChange={(checked) => onChange({ process_cookies: checked })} />
        <Checkbox checked={!!options?.strip_connection} label="Strip Connection headers" onCheckedChange={(checked) => onChange({ strip_connection: checked })} />
        <Checkbox
          checked={!!options?.normalize_line_endings}
          label="Normalize line endings to CRLF"
          onCheckedChange={(checked) => onChange({ normalize_line_endings: checked })}
        />
        <Checkbox
          checked={!!options?.update_content_length}
          label="Update Content-Length from body"
          onCheckedChange={(checked) => onChange({ update_content_length: checked })}
        />
      </div>
      <p className="field-hint">
        Overrides ride on this one send; anything left unset uses the standing Network settings.
      </p>
    </Card>
  );
}

/**
 * The redirect chain a send produced.
 *
 * Rendered only when there was one, and it distinguishes the three outcomes that matter: a chain that
 * completed, a chain something stopped, and a chain that could not be evaluated. Collapsing those into
 * "1 redirect" would lose the only fact the operator needs — whether the hop was refused by scope, held
 * back by the policy, or followed to a real response.
 */
function RedirectChain({ chain }: { chain: RepeaterRedirects }): JSX.Element {
  const followed = chain.hops.filter((hop) => hop.followed).length;
  return (
    <div className="stack" style={{ marginTop: 10 }}>
      <div className="toolbar">
        <Badge tone={chain.complete ? "good" : "warn"}>
          {chain.complete ? "chain complete" : "chain stopped"}
        </Badge>
        <Badge>mode: {chain.mode}</Badge>
        <Badge>
          {chain.sent} request{chain.sent === 1 ? "" : "s"} sent
        </Badge>
        <Badge>
          {followed} of {chain.hops.length} hop{chain.hops.length === 1 ? "" : "s"} followed
        </Badge>
        {chain.final_status ? <Badge tone={statusTone(chain.final_status)}>final {chain.final_status}</Badge> : null}
      </div>
      {chain.error ? (
        <p className="field-hint">
          The chain could not be evaluated, so nothing here says whether a redirect was followed:{" "}
          {chain.error}
        </p>
      ) : null}
      <SimpleTable headers={["From", "Status", "Location", "Followed", "Why not"]}>
        {chain.hops.map((hop, index) => (
          <tr key={`${hop.from}-${index}`}>
            <td>
              <code>{hop.from}</code>
            </td>
            <td>
              <span className="cell-num">{hop.status}</span>
            </td>
            <td>
              <code>{hop.to ?? hop.location}</code>
            </td>
            <td>
              <Badge tone={hop.followed ? "good" : "warn"}>{hop.followed ? "sent" : "not sent"}</Badge>
            </td>
            <td>{hop.reason ? hop.reason : <span className="cell-dim">—</span>}</td>
          </tr>
        ))}
      </SimpleTable>
    </div>
  );
}
