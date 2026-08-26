import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, Columns3, Crosshair, Plus, Send, X } from "lucide-react";
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { api, formatDuration, json, statusTone, templateRequest } from "../lib/api";
import { useRepeaterSend } from "../lib/data.tools";
import { useApp, type RepeaterTab } from "../lib/store";
import type { Exchange, RepeaterRedirects, RepeaterResult } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, Field, IconButton, Input, Tooltip } from "../ui/primitives";
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
  const send = useRepeaterSend();

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
      { target: tab.target, request: tab.request, protocol: schemeOf(tab.target), from_exchange: tab.fromExchange },
      {
        onSuccess: (result) => {
          setHistory((current) => ({ ...current, [tab.id]: [...(current[tab.id] ?? []), result] }));
          // A new send always snaps the view forward: an operator who had paged back to compare is
          // still asking "what did this one do", and leaving them on an older entry would answer a
          // question they stopped asking.
          setViewing((current) => ({ ...current, [tab.id]: null }));
          toast.success(`${result.status} in ${formatDuration(result.duration_ms)}`);
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
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
          json("POST", { target: tab.target, request: tab.request, protocol: schemeOf(tab.target) }),
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
              <Tooltip content="Send the current request (mod+Enter)">
                <button type="button" className="button button-primary" onClick={() => submit(active)} disabled={send.isPending}>
                  <Send size={14} />
                  {send.isPending ? "Sending…" : "Send"}
                </button>
              </Tooltip>
            </>
          }
        />

        <div className="tabs-list" role="tablist" aria-label="Repeater requests" style={{ marginTop: 10 }}>
          {tabs.map((tab) => (
            <div
              key={tab.id}
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
              <span>{tab.name}</span>
              <button
                type="button"
                className="tab-close"
                aria-label={`Close ${tab.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  closeRepeaterTab(tab.id);
                  setHistory((current) => {
                    const { [tab.id]: _removed, ...rest } = current;
                    return rest;
                  });
                  setViewing((current) => {
                    const { [tab.id]: _dropped, ...rest } = current;
                    return rest;
                  });
                }}
              >
                <X size={11} />
              </button>
            </div>
          ))}
          <IconButton label="New request" size="small" onClick={newTab}>
            <Plus size={13} />
          </IconButton>
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

        {send.error ? <ErrorNotice error={send.error} onRetry={() => submit(active)} /> : null}
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
          value={result?.response ?? (send.isPending ? "Waiting for the response…" : "Send the request to see the response bytes.")}
          filename="repeater-response.txt"
        />
        {inspector ? <Inspector raw={active.request} label="Inspector · request" /> : null}
      </div>
    </div>
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
