import { useEffect, useMemo, useState } from "react";
import { Columns3, Crosshair, Plus, Send, X } from "lucide-react";
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { api, formatDuration, json, statusTone, templateRequest } from "../lib/api";
import { useRepeaterSend } from "../lib/data.tools";
import { useApp, type RepeaterTab } from "../lib/store";
import type { Exchange, RepeaterResult } from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Empty, ErrorNotice, IconButton, Input, Tooltip } from "../ui/primitives";

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

  // Responses are deliberately not persisted; only the request draft is.
  const [results, setResults] = useState<Record<string, RepeaterResult>>({});
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
          setResults((current) => ({ ...current, [tab.id]: result }));
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
      let exchangeId = results[tab.id]?.exchange_id;
      if (!exchangeId) {
        const sent = await api<RepeaterResult>(
          "/api/repeater/send",
          json("POST", { target: tab.target, request: tab.request, protocol: schemeOf(tab.target) }),
        );
        setResults((current) => ({ ...current, [tab.id]: sent }));
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

  const result = results[active.id];

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
                  setResults((current) => {
                    const { [tab.id]: _removed, ...rest } = current;
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
          <label className="field" style={{ flex: 1, minWidth: "var(--w-lg)" }}>
            <span>Target</span>
            <Input
              value={active.target}
              onChange={(event) => {
                // The URL is the single source of truth for the transport. A separate
                // dropdown could contradict the scheme, which silently produced TLS
                // handshake failures against plain-HTTP targets.
                const next = event.target.value;
                updateRepeaterTab(active.id, { target: next, protocol: schemeOf(next) });
              }}
              placeholder="https://host:443"
            />
          </label>
          <label className="field" style={{ maxWidth: "var(--w-md)" }}>
            <span>Tab name</span>
            <Input value={active.name} onChange={(event) => updateRepeaterTab(active.id, { name: event.target.value })} />
          </label>
          <Button variant="outline" onClick={() => void handOffToIntruder(active)} disabled={handingOff}>
            <Crosshair size={14} />
            {handingOff ? "Preparing…" : "To Intruder"}
          </Button>
        </div>

        {send.error ? <ErrorNotice error={send.error} onRetry={() => submit(active)} /> : null}
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
