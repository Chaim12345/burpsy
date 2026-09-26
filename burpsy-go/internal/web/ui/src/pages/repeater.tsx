import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { ArrowRightLeft, ChevronDown, ChevronLeft, ChevronRight, Columns3, Combine, Copy, Crosshair, FileOutput, List, Palette, Plus, Repeat2, RotateCcw, Rows3, Send, SlidersHorizontal, X } from "lucide-react";
import { TAB_COLOURS } from "../ui/highlight-icons";
import { cn } from "../lib/cn";
import { reorderTabWithinGroup, tabColour, tabDropdownGroups, type TabView } from "../lib/repeater-tabs";
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { api, formatDuration, json, statusTone, templateRequest , formatBytes } from "../lib/api";
import { usePluginExchangeActions } from "../lib/plugin-exchange-actions";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS, changeBodyEncoding, detectBodyEncoding, type BodyEncoding } from "../lib/body-encoding";
import { useExchange } from "../lib/data.observe";
import { useChord } from "../lib/keymap";
import { SendCancelled, useRepeaterSend, useRepeaterWsSend, useSendRepeaterGroup } from "../lib/data.tools";
import type { RepeaterWsHistoryEntry, WsRepeaterSendResult } from "../lib/types";
import { appendGroupResultsToHistory, followNewestAfterGroupSend } from "../lib/repeater-group";
import { useApp, type RepeaterTab } from "../lib/store";
import type {
  Exchange,
  RepeaterGroupSendMode,
  RepeaterGroupSendResult,
  RepeaterHistoryEntry,
  RepeaterRedirects,
  RepeaterResult,
  RepeaterSendOptions,
} from "../lib/types";
import { HttpEditor } from "../ui/editor";
import { Inspector } from "../ui/inspector";
import { PageHeader } from "../ui/layout";
import { DetailList } from "../ui/json";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Select, Tooltip } from "../ui/primitives";
import { ContextMenu, DropdownMenu, type MenuGroup } from "../ui/menu";
import { SimpleTable } from "../ui/table";

/**
 * The three ways a tab group can be sent, in the order Burp's dropdown lists them.
 *
 * Held as data rather than three copies of a menu row because each one needs the same three strings —
 * a label, the confirmation the toast repeats, and the sentence that says what the mode actually does
 * to the wire. "Single connection" in particular has to say what it is not: HTTP/1.1 keep-alive, not
 * HTTP/2 multiplexing.
 */
const GROUP_SEND_MODES: { mode: RepeaterGroupSendMode; label: string; detail: string }[] = [
  {
    mode: "sequence_single_conn",
    label: "Send group in sequence (single connection)",
    detail:
      "Every request in tab order down one shared HTTP/1.1 socket, keep-alive: write one, read its " +
      "response, write the next. This is what a request-smuggling or client-side-desync test needs. " +
      "Redirects are not followed — a hop is a new connection — and every request is scope-authorised " +
      "on its own bytes.",
  },
  {
    mode: "sequence_separate_conn",
    label: "Send group in sequence (separate connections)",
    detail: "Every request in tab order, each on its own fresh connection. The ordinary Send, once per tab.",
  },
  {
    mode: "parallel",
    label: "Send group in parallel",
    detail:
      "Every request fired at once, each on its own connection, so they overlap at the target. This is " +
      "the race-condition workflow.",
  },
];

/** The label a group-send mode carries in a badge or a toast. */
function groupModeLabel(mode: RepeaterGroupSendMode): string {
  return GROUP_SEND_MODES.find((entry) => entry.mode === mode)?.label ?? mode;
}

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
  const setComparerSlot = useApp((state) => state.setComparerSlot);
  const setDecoderSeed = useApp((state) => state.setDecoderSeed);

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
 // The tab strip's three view affordances (fkj): drag-to-reorder, a per-tab colour, and Burp's
 // scrolling / wrapped view toggle. The decisions live in lib/repeater-tabs.ts; this owns the DOM
 // and the drag events.
 const moveRepeaterTab = useApp((state) => state.moveRepeaterTab);
 const setRepeaterTabColor = useApp((state) => state.setRepeaterTabColor);
 const [tabView, setTabView] = useState<TabView>("scrolling");
 const [draggingTab, setDraggingTab] = useState<string | null>(null);
 const [dropTarget, setDropTarget] = useState<string | null>(null);

  /**
   * Every send a tab has made, oldest first — not just the latest. Held in memory only; the store
   * persists the request draft across reloads, deliberately not the responses.
   *
   * Burp keeps a per-tab history because the whole method of the tool is "change one thing and
   * compare": overwriting the previous response destroys the half of the comparison you were about
   * to make. This kept exactly one response per tab and dropped the rest on every send.
   *
   * Each entry is a request/response *pair* (RepeaterHistoryEntry). Storing the response alone made
   * paging back a half-answer: the response pane moved to entry 2 while the request pane went on
   * showing the live draft, so the operator could see that entry 2 behaved differently and not
   * which variation entry 2 was — the comparison the tool exists for.
   */
  const [history, setHistory] = useState<Record<string, (RepeaterHistoryEntry | RepeaterWsHistoryEntry)[]>>({});
  /** Which entry of the active tab's history is on screen. Null follows the newest. */
  const [viewing, setViewing] = useState<Record<string, number | null>>({});
  /**
   * The encoding each tab's body was in before its last conversion — what Burp's "Toggle body
   * encoding" switches back to (burpsy-react-ui-wv5).
   *
   * Keyed by tab id because Burp's own wording is "the two most recently used encodings in the
   * current Repeater tab": two tabs converted in different directions must toggle in different
   * directions, and one global "last encoding" would make the second tab's toggle do whatever the
   * first tab did. Only one encoding is remembered, not a third slot — the other half of "the two
   * most recently used" is the one the body is in now, which is read from the draft itself.
   *
   * Deliberately not in the store: this is a transient editing affordance, and a persisted toggle
   * direction surviving a page reload would be a state the operator cannot see and did not set.
   */
  const [previousEncoding, setPreviousEncoding] = useState<Record<string, BodyEncoding>>({});
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
 const wsSend = useRepeaterWsSend();
  const groupSend = useSendRepeaterGroup();
  /**
   * The last group send's outcome, or null when this session has not made one.
   *
   * Kept on screen until dismissed rather than living only in a toast, for two reasons. A group send
   * is N results and only one of them lands in the tab the operator is looking at — the other N-1
   * would otherwise be invisible until they click each tab. And the facts that make the
   * single-connection mode worth having (which framing rule delimited each response, whether each
   * read completed) are per-request comparisons, which means they have to be readable side by side or
   * they are not a comparison at all.
   */
  const [groupOutcome, setGroupOutcome] = useState<RepeaterGroupSendResult | null>(null);
  /**
   * Which response the pane shows when the last send followed a redirect chain:
   * "first" is the response to the request the operator wrote — the default,
   * because the 302 with its Set-Cookie is usually what the send was for — and a
   * number is the index of the chain hop whose response the operator asked to see,
   * the last followed hop being the chain's final response. A reset effect below
   * clears it whenever the result under the pane changes, so a stale hop index can
   * never show one send's bytes inside another's pane.
   */
  const [chainSide, setChainSide] = useState<"first" | number>("first");

  // Bulk closes (close others / left / right) remove many tabs at once, so per-close cleanup in
  // the click handlers no longer covers it. One pruning effect owns the invariant instead: the
  // response history and the view position only ever hold keys for tabs that still exist.
  useEffect(() => {
    const alive = new Set(tabs.map((tab) => tab.id));
    setHistory((current) => Object.fromEntries(Object.entries(current).filter(([id]) => alive.has(id))));
    setViewing((current) => Object.fromEntries(Object.entries(current).filter(([id]) => alive.has(id))));
    setPreviousEncoding((current) => Object.fromEntries(Object.entries(current).filter(([id]) => alive.has(id))));
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

  /**
   * The two tab kinds (burpsy-react-ui-6ex), Burp's "Select either HTTP or WebSocket"
   * (managing-tabs.html): a new HTTP request drafts a template request; a new WebSocket
   * message drafts an empty text frame against a ws:// target the operator types. The
   * dropdown rather than two buttons: the strip is already dense, and one trigger with the
   * choice inside is how Burp ships it.
   */
  const newTab = (kind: "http" | "ws" = "http") => {
    openRepeaterTab(
      kind === "ws"
        ? {
            name: `WS message ${tabs.length + 1}`,
            target: "ws://127.0.0.1:8080",
            protocol: "http",
            request: "",
            kind: "ws",
            wsPayload: "",
            wsOpcode: "text",
          }
        : {
            name: `Request ${tabs.length + 1}`,
            target: DEFAULT_TARGET,
            protocol: "https",
            request: templateRequest("example.com"),
          },
    );
  };

  const submit = (tab: RepeaterTab) => {
    // Paged back into history, the request pane shows a past entry's snapshot, not the draft this
    // would send. Sending anyway would fire bytes the operator cannot see — the pane says one
    // thing and the button does another. The Send button is disabled in that state, but the
    // hotkey and Enter-in-Target reach here directly, so the refusal lives with the send itself.
    if (viewing[tab.id] != null) {
      toast.info("Viewing a past send — step to the newest entry to edit and send the draft");
      return;
    }
    // The exact draft text that goes on the wire, captured here so the history entry below records
    // what was sent rather than what the draft says later.
    const sentRequest = tab.request;
    send.mutate(
      {
        target: tab.target,
        request: sentRequest,
        protocol: schemeOf(tab.target),
        from_exchange: tab.fromExchange,
        // Absent options means "standing behaviour" — the backend validates and applies whatever
        // arrives, so an empty object is never sent when the operator set nothing.
        ...(tab.options ? { options: tab.options } : {}),
      },
      {
        onSuccess: (result) => {
          setHistory((current) => ({
            ...current,
            [tab.id]: [...(current[tab.id] ?? []), { ...result, request: sentRequest }],
          }));
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

  /**
   * The WS send (burpsy-react-ui-6ex): a "ws" tab's Send dials a fresh WebSocket, sends the
   * frame and reads what comes back — one dial per send, not a held socket. The result rides
   * the same per-tab history as an HTTP send's, so edit-and-resend is paging back, changing
   * the payload and sending again; the honest note in the response pane says the frame went
   * out on a NEW connection, which Burp's own "set automatically" also does once the original
   * has closed. The direction choice is to-server here: the server refuses to-client with the
   * reason in the body, and that refusal is surfaced, never hidden.
   */
  const submitWs = (tab: RepeaterTab) => {
    if (viewing[tab.id] != null) {
      toast.info("Viewing a past send — step to the newest entry to edit and resend the frame");
      return;
    }
    const sentPayload = tab.wsPayload ?? "";
    const toClient = (tab.wsDirection ?? "server") === "client";
    wsSend.mutate(
      {
        message: tab.fromExchange ?? 0,
        target: tab.target,
        opcode: tab.wsOpcode ?? "text",
        payload: sentPayload,
        // The direction Burp offers as a choice. to-server is the half a fresh dial can do;
        // to-client is sent as the flag the wire refuses with its reason, so choosing it shows
        // exactly why it cannot run here instead of the control being absent.
        ...(toClient ? { to_client: true } : {}),
      },
      {
        onSuccess: (result) => {
          setHistory((current) => ({
            ...current,
            [tab.id]: [
              ...(current[tab.id] ?? []),
              {
                // The draft that went out, so paging back shows the frame as written.
                request: sentPayload,
                ws: result,
              } satisfies RepeaterWsHistoryEntry,
            ],
          }));
          setViewing((current) => ({ ...current, [tab.id]: null }));
          toast.success(`${result.handshake} — ${result.messages.length} reply frame(s) in ${formatDuration(result.elapsed_ms)}`);
        },
        onError: (error) => {
          if (error instanceof SendCancelled) {
            toast.info("Send cancelled — the frame may have reached the target");
            return;
          }
          toast.error(error instanceof Error ? error.message : String(error));
        },
      },
    );
  };

  /**
   * The active tab's group and its members, in tab order.
   *
   * Resolved through `groups` rather than trusted from `tab.groupId` alone, matching how `ungrouped`
   * below decides the same question: deleting a group deliberately keeps its tabs, so a tab can still
   * carry a dead group id, and treating that as membership would offer to send a group that no longer
   * exists.
   */
  const activeGroup = active ? (groups.find((group) => group.id === active.groupId) ?? null) : null;
  const groupMembers = activeGroup ? tabs.filter((tab) => tab.groupId === activeGroup.id) : [];

  /**
   * Send every tab in the active tab's group, in tab order, in one of the three modes.
   *
   * Ordering is the tab strip's order, which is what the group header renders, because in a smuggling
   * or desync test which request goes first *is* the test. It is never sorted or de-duplicated here;
   * the server refuses a repeated tab id rather than guessing.
   *
   * The paged-back refusal is the same one `submit` makes and for the same reason: the active tab's
   * request pane is then a snapshot, and sending would fire bytes the operator cannot see. Members
   * that are not the active tab may well be paged back too — their panes are not on screen, so there
   * is no pane contradicting the button, and their drafts are what goes out. A landed result snaps
   * each of those tabs forward to it, exactly as a single send does.
   */
  const submitGroup = (mode: RepeaterGroupSendMode) => {
    if (!active || !activeGroup) return;
    if (viewing[active.id] != null) {
      toast.info("Viewing a past send — step to the newest entry to edit and send the draft");
      return;
    }
    const members = groupMembers;
    if (members.length < 2) {
      toast.info("This group has one tab, so a group send is just Send");
      return;
    }
    // The exact drafts that go on the wire, captured before the request leaves, so each history entry
    // records what was sent rather than what that tab's draft says by the time the answer arrives.
    const sentRequests = new Map(members.map((tab) => [tab.id, tab.request]));
    groupSend.mutate(
      {
        mode,
        items: members.map((tab) => ({
          tab_id: tab.id,
          target: tab.target,
          request: tab.request,
          protocol: schemeOf(tab.target),
          ...(tab.fromExchange != null ? { from_exchange: tab.fromExchange } : {}),
          ...(tab.options ? { options: tab.options } : {}),
        })),
      },
      {
        onSuccess: (result) => {
          setGroupOutcome(result);
          // The fold lives in lib/repeater-group.ts and is unit tested there: each result lands in
          // its own tab's history, paired with the draft that produced it, and an item with no
          // response appends nothing rather than a fabricated entry.
          setHistory((current) => appendGroupResultsToHistory(current, result, sentRequests));
          setViewing((current) => followNewestAfterGroupSend(current, result));
          const answered = result.items.filter((item) => item.result).length;
          const failed = result.items.filter((item) => item.error).length;
          const summary = `${answered}/${result.items.length} answered in ${formatDuration(result.batch_duration_ms)}`;
          if (failed > 0) {
            // Not toast.error: some requests did answer, and calling a partly-successful group send a
            // failure would misreport what happened to the ones that landed.
            toast.warning(`${groupModeLabel(result.mode)} — ${summary}, ${failed} reported a problem`);
            return;
          }
          toast.success(`${groupModeLabel(result.mode)} — ${summary}`);
        },
        onError: (error) => {
          if (error instanceof SendCancelled) {
            toast.info("Group send cancelled — anything already written to the target was still sent");
            return;
          }
          toast.error(error instanceof Error ? error.message : String(error));
        },
      },
    );
  };

  // From the keymap registry, not a literal: `repeater.send` is a rebindable row in
  // Settings -> Hotkeys, and that table ran duplicate detection on an override nothing read.
  const sendChord = useChord("repeater.send");
  useHotkeys(
    sendChord,
    (event) => {
      event.preventDefault();
      if (active) active.kind === "ws" ? submitWs(active) : submit(active);
    },
    { enableOnFormTags: true, enableOnContentEditable: true },
    [sendChord, active],
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
      const last = known[known.length - 1];
      // A ws send's entry has no HTTP exchange to hand off (its handshake exchange is the reply's,
      // recorded for "view in WebSockets history"), so the hand-off resolves an HTTP entry's id.
      let exchangeId = last && "status" in last ? last.exchange_id : undefined;
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
        // Same pairing rule as a normal send: the entry this hand-off adds carries the draft it
        // sent, so history stays navigable rather than gaining one response with no request.
        setHistory((current) => ({
          ...current,
          [tab.id]: [...(current[tab.id] ?? []), { ...sent, request: tab.request }],
        }));
        // Same rule as the Send button: a send that lands snaps the view to it, so the counter and
        // both panes describe the request that just went out instead of an entry further back.
        setViewing((current) => ({ ...current, [tab.id]: null }));
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

  // The entry on screen: whichever the operator paged to, else the newest. These values — and the
  // hooks that read them below — live above the empty-state return because hooks run
  // unconditionally: a first render with no tabs used to run fewer of them than the first render
  // with a tab, and React answers that with "Rendered more hooks than during the previous render",
  // which the error boundary turned into a Repeater page where "New request" could never produce a
  // working tab.
  const activeHistory = active ? (history[active.id] ?? []) : [];
  const viewIndex = active ? (viewing[active.id] ?? activeHistory.length - 1) : 0;
  const result = activeHistory[viewIndex];
  /** The HTTP entry's own fields, or null when the entry on screen is a ws send's (6ex). */
  const httpResult = result && "status" in result ? result : null;
  /** The ws entry's reply frames, or null when it is an HTTP send's. */
  const wsResult = result && "ws" in result ? result.ws : null;

  /**
   * The request that produced the entry on screen, or null while the tab is following its newest
   * send — where the request pane is the live, editable draft and must stay that way.
   *
   * Null is the "not pinned" state rather than "index equals the last entry": paging forward onto
   * the newest entry clears the pin back to null (see the Next handler), and a send clears it too,
   * so a non-null pin always means the operator is deliberately looking at a past send.
   */
  const viewedRequest = active && viewing[active.id] != null ? (result?.request ?? null) : null;

  // The chain's hop selection, resolved to bytes. `lastFollowedHop` is the response the chain
  // landed on — the "final response" the toggle offers — and is null for a chain that followed
  // nothing, where the first response IS the final response and the toggle has nothing to offer.
  const lastFollowedHop =
    httpResult?.redirects?.hops.reduce<number | null>(
      (acc, hop, index) => (hop.followed && hop.response != null ? index : acc),
      null,
    ) ?? null;
  const finalResponse = lastFollowedHop != null ? (httpResult?.redirects?.hops[lastFollowedHop]?.response ?? null) : null;
  const chainResponse =
    typeof chainSide === "number" && httpResult?.redirects ? (httpResult.redirects.hops[chainSide]?.response ?? null) : null;

  // A stale hop index must never show one send's bytes inside another's pane: whenever the result
  // under the pane changes — a new send, or paging back through the tab's history — the selection
  // returns to the first response, which is what the pane shows by default.
  useEffect(() => setChainSide("first"), [httpResult?.exchange_id, active?.id]);

  /**
   * The exchange this send produced, so the two message panes carry the same menu every other
   * HTTP message editor does.
   *
   * A Repeater draft is not an exchange until it has been sent — that is why this is keyed on
   * `result.exchange_id` rather than on the tab. Before a send there is nothing in the traffic
   * store to act on, and the editor menu is then the selection codecs alone, which is honest:
   * "Send to Comparer" on a request that has never left the browser would be sending bytes the
   * store has never seen under an id it does not have.
   */
  const sentExchange = useExchange(httpResult?.exchange_id ?? null);
  const actions = usePluginExchangeActions();
  const messageMenu = sentExchange.data ? actions.menu(sentExchange.data) : undefined;


  if (!active) {
    return (
      <div className="page">
        <PageHeader title="Repeater" description="Craft one request and read its exact response." />
        <Empty
          title="No request open"
          detail="Start a blank request, or right-click any row in HTTP history and choose “Send to Repeater”."
          action={
            <Button onClick={() => newTab("http")}>
              <Plus size={14} />
              New request
            </Button>
          }
        />
      </div>
    );
  }

  /**
   * The Send to group for a draft that has never been sent (burpsy-react-ui-bg7j).
   *
   * # Why this cannot just call lib/actions.ts's menu()
   *
   * That factory takes an `Exchange`: a row in the traffic store with an id and message ids
   * behind it. An unsent Repeater draft is none of those things — the bytes exist only in the
   * editor, and no exchange row points at them. So the actions that need bytes are built here
   * from the draft itself, and the ones that need the traffic store are left out rather than
   * faked, exactly as Intercept's held-message menu reasons:
   *
   * - Send to Intruder is absent. Intruder splices payloads into a *stored* message id, which a
   *   draft does not have. Send the request once — that creates the stored message — and send
   *   to Intruder from HTTP history, or from this editor once the send's exchange menu appears.
   * - Send to Sequencer is absent for the same reason a request-only hand-off is refused
   *   elsewhere: Sequencer seeds from a request/response pair (the token lives in the
   *   response), and a draft has no response to give it.
   *
   * Everything else is the same matrix every other HTTP surface offers, and is offered on BOTH
   * the live draft and the paged-back "as written" pane, because both show the same draft's
   * bytes — only the sent exchange's own menu differs.
   *
   * The draft's bytes, never a stale buffer: the group is rebuilt on every render from
   * `draftRequest`, so a right-click after an edit acts on what the editor shows. (The menu
   * opens on mousedown, so an edit keystroke landing between render and open cannot desync.)
   */
  const draftRequest = viewedRequest ?? active.request;
  const draftSendMenu: MenuGroup[] = [
    {
      id: "send",
      actions: [
        {
          id: "repeater",
          label: "Send to Repeater",
          icon: Repeat2,
          onSelect: () => {
            // A copy, not a move: the operator forks the draft to work on a variant beside it,
            // and the source tab keeps its place in history — the same fork semantics every
            // other surface's Send to Repeater has.
            openRepeaterTab({
              name: `${active.name} (copy)`.slice(0, 42),
              target: active.target,
              protocol: active.protocol,
              request: draftRequest,
            });
            setRoute("repeater");
            toast.success(`Copied to a new Repeater tab (from ${active.name})`);
          },
        },
        {
          id: "compare-a",
          label: "Send to Comparer (A)",
          icon: Combine,
          onSelect: () => {
            setComparerSlot("a", draftRequest);
            setRoute("comparer");
          },
        },
        {
          id: "compare-b",
          label: "Send to Comparer (B)",
          icon: ArrowRightLeft,
          onSelect: () => {
            setComparerSlot("b", draftRequest);
            setRoute("comparer");
          },
        },
        {
          id: "decoder",
          label: "Send to Decoder",
          icon: FileOutput,
          onSelect: () => {
            setDecoderSeed({ label: active.name, input: draftRequest });
            setRoute("decoder");
          },
        },
      ],
    },
  ];

  /**
   * Burp's "Change body encoding" and "Toggle body encoding", on the draft itself (wv5).
   *
   * The row menu's copy of this opens a NEW tab, because there the operator is acting on a
   * captured exchange they must not overwrite. Here the draft IS the thing being edited, so the
   * conversion lands in place and the toggle can take it straight back — which is the whole point
   * of Burp offering the toggle: convert, send, convert back, send, and read the two responses.
   *
   * A refusal changes nothing at all: no tab, no draft edit, and a toast carrying the transform's
   * own reason. Half-converting a request that still looks sendable is the failure this exists to
   * avoid.
   */
  const convertDraft = (target: BodyEncoding) => {
    const from = detectBodyEncoding(active.request);
    const result = changeBodyEncoding(active.request, target);
    if (!result.ok) {
      toast.error(`Could not re-encode the body as ${BODY_ENCODING_LABELS[target]}: ${result.reason}`);
      return;
    }
    updateRepeaterTab(active.id, { request: result.raw });
    if (from) setPreviousEncoding((current) => ({ ...current, [active.id]: from }));
    toast.success(`Body re-encoded as ${BODY_ENCODING_LABELS[target]}`);
  };

  /**
   * The ws frame's own menu (6ex): the opcode switch, and the send/decode/compare actions on
   * the frame's bytes — the same matrix every other surface offers, built here from the draft
   * because a frame is not an exchange until it has been sent.
   */
  const wsFrameMenu: MenuGroup[] = [
    {
      id: "ws-frame",
      title: "WebSocket frame",
      actions: [
        ...(["text", "binary"] as const).map((opcode) => ({
          id: `opcode-${opcode}`,
          label: `Switch opcode to ${opcode}`,
          disabled: (active.wsOpcode ?? "text") === opcode,
          onSelect: () => updateRepeaterTab(active.id, { wsOpcode: opcode }),
        })),
        {
          id: "send-to-repeater",
          label: "Send to Repeater",
          icon: Repeat2,
          onSelect: () => {
            openRepeaterTab({
              name: `${active.name} (copy)`.slice(0, 42),
              target: active.target,
              protocol: active.protocol,
              request: "",
              kind: "ws",
              wsPayload: active.wsPayload ?? "",
              wsOpcode: active.wsOpcode ?? "text",
            });
            setRoute("repeater");
            toast.success(`Copied to a new Repeater tab (from ${active.name})`);
          },
        },
        {
          id: "decoder",
          label: "Send payload to Decoder",
          icon: FileOutput,
          onSelect: () => {
            setDecoderSeed({ label: active.name, input: active.wsPayload ?? "" });
            setRoute("decoder");
          },
        },
        {
          id: "compare-a",
          label: "Send payload to Comparer (A)",
          icon: Combine,
          onSelect: () => {
            setComparerSlot("a", active.wsPayload ?? "");
            setRoute("comparer");
          },
        },
        {
          id: "compare-b",
          label: "Send payload to Comparer (B)",
          icon: ArrowRightLeft,
          onSelect: () => {
            setComparerSlot("b", active.wsPayload ?? "");
            setRoute("comparer");
          },
        },
      ],
    },
  ];

  const draftEncoding = detectBodyEncoding(active.request);
  const previous = previousEncoding[active.id];
  /** Enabled only when this tab has actually been converted once and is not already back. */
  const canToggle = previous !== undefined && previous !== draftEncoding;

  /**
   * Offered on the request pane only, and only while the draft is editable — paged back through
   * the history the pane shows a request that has already been sent, and re-encoding it would
   * write over a draft that is not on screen.
   */
  const bodyEncodingMenu: MenuGroup[] =
    viewedRequest != null
      ? []
      : [
          {
            id: "body-encoding",
            title: "Body encoding",
            actions: [
              ...BODY_ENCODINGS.map((encoding) => ({
                id: `to-${encoding}`,
                label: `Change body encoding: ${BODY_ENCODING_LABELS[encoding]}`,
                // Here — unlike the row menu — the bytes are in hand, so the encoding the body is
                // already in is greyed out rather than offered and then refused.
                disabled: encoding === draftEncoding,
                onSelect: () => convertDraft(encoding),
              })),
              {
                id: "toggle",
                label: canToggle ? `Toggle body encoding (back to ${BODY_ENCODING_LABELS[previous]})` : "Toggle body encoding",
                disabled: !canToggle,
                onSelect: () => canToggle && convertDraft(previous),
              },
            ],
          },
        ];

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
    // The tab's own colour, read through the same structural type the rule takes. `RepeaterTab`
    // declares `color`, and tabColour's own signature documents the same two fields; naming the
    // shape here keeps the menu readable if the model ever grows another tab variant.
    const ownColour = (tab as { color?: string }).color ?? "";
    return [
      {
        id: "edit",
        actions: [
          { id: "duplicate", label: "Duplicate tab", icon: Copy, onSelect: () => duplicateRepeaterTab(tab.id) },
          // A tab's own colour (fkj). Burp colours a GROUP, and its tabs take that colour; the
          // gap this closes is that an UNGROUPED tab had no way to be marked at all, so an operator
          // pointing at the one request to attack next could not colour a whole group to say so.
          // This tab's own colour wins over its group's — see tabColour for why.
          {
            id: "tab-colour",
            label: "Tab colour",
            icon: Palette,
            submenu: [
              {
                id: "colours",
                actions: [
                  ...TAB_COLOURS.map((colour) => {
                    const wire = colour.value === "" ? "" : colour.value;
                    return {
                      id: colour.value,
                      label: colour.label,
                      icon: colour.icon,
                      disabled: ownColour === wire,
                      onSelect: () => setRepeaterTabColor(tab.id, wire),
                    };
                  }),
                ],
              },
            ],
            onSelect: () => {},
          },
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

  const renderTabTrigger = (tab: RepeaterTab): JSX.Element => {
   // The tab's own colour wins over its group's; the rule and the reason are in lib/repeater-tabs.ts.
   const colourForTab = tabColour(tab, groups);
   return (
    // Keyed here rather than at the .map call sites because the key must sit on the element the
    // function returns: a wrapper added without one makes every multi-tab strip render unkeyed
    // children, which React answers with a console error the e2e suite refuses to ship with.
    <ContextMenu key={tab.id} groups={tabMenuGroups(tab)}>
      <div
        role="tab"
        aria-selected={tab.id === active.id}
        className={cn("tabs-trigger", tabView === "wrapped" && "tabs-trigger-wrap")}
        data-state={tab.id === active.id ? "active" : undefined}
        // A tab's own colour, or its group's when it has none (fkj). Set as a custom property
        // rather than a hard-coded border so the CSS decides what "coloured" looks like and the
        // theme can change it in one place — the same shape the highlight swatches use.
        style={colourForTab.color ? ({ "--tab-color": `var(--highlight-${colourForTab.color})` } as CSSProperties) : undefined}
        draggable
        onDragStart={(event) => {
          setDraggingTab(tab.id);
          event.dataTransfer.effectAllowed = "move";
          // Firefox will not start a drag without payload; the id is what the drop reads back.
          event.dataTransfer.setData("text/plain", tab.id);
        }}
        onDragEnd={() => {
          setDraggingTab(null);
          setDropTarget(null);
        }}
        onDragOver={(event) => {
          if (!draggingTab || draggingTab === tab.id) return;
          // preventDefault is what marks this row as a drop target; without it the browser refuses
          // the drop and the drag ends with no feedback at all.
          event.preventDefault();
          event.dataTransfer.dropEffect = "move";
          setDropTarget(tab.id);
        }}
        onDrop={(event) => {
          event.preventDefault();
          const source = draggingTab ?? event.dataTransfer.getData("text/plain");
          setDraggingTab(null);
          setDropTarget(null);
          if (!source || source === tab.id) return;
          // Dropping ON a row means "take its place". reorderTabWithinGroup keeps the move inside
          // the source tab's own group, so a drag that merely crosses a group boundary does not
          // silently re-file the request — that is the menu's "Move to …" job, and a distinct
          // gesture.
          const target = tabs.findIndex((entry) => entry.id === tab.id);
          // The group's own ordering when both tabs are in one, the strip's otherwise: a drag
          // between groups is not a reorder, and reorderTabWithinGroup refuses it rather than
          // re-filing the request under a gesture aimed at position.
          const sourceTab = tabs.find((entry) => entry.id === source);
          if (sourceTab?.groupId && sourceTab.groupId === tab.groupId) {
            reorderTabWithinGroup(tabs, source, target);
          }
          moveRepeaterTab(source, target);
        }}
        onClick={() => setActiveRepeaterTab(tab.id)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") setActiveRepeaterTab(tab.id);
        }}
        tabIndex={0}
        title={
          colourForTab.color
            ? `${tab.name} — ${colourForTab.from === "tab" ? "this tab's colour" : "its group's colour"}`
            : tab.name
        }
        data-dragging={draggingTab === tab.id ? true : undefined}
        data-drop-target={dropTarget === tab.id ? true : undefined}
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
          <span>
            {tab.kind === "ws" ? <Repeat2 size={10} style={{ display: "inline", marginRight: 4, verticalAlign: "-1px" }} /> : null}
            {tab.name}
          </span>
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
  };

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
              {/* Burp's tab-view toggle (fkj): one scrollable row with a dropdown of the open
                  tabs, or tabs wrapped onto several rows. Scrolling is the default because a
                  wrapped strip eats vertical space on a page whose editor needs height, and the
                  dropdown means a tab forty positions along is still two clicks away rather than
                  scrolled to. */}
              <IconButton
                label={tabView === "scrolling" ? "Switch to wrapped tab view" : "Switch to scrolling tab view"}
                title={
                  tabView === "scrolling"
                    ? "Burp's wrapped view: tabs wrap onto several rows. Scrolling view keeps one row and puts the rest behind a dropdown."
                    : "Burp's scrolling view: one scrollable row, with every open tab behind the dropdown."
                }
                size="small"
                aria-pressed={tabView === "wrapped"}
                onClick={() => setTabView((current) => (current === "scrolling" ? "wrapped" : "scrolling"))}
              >
                {tabView === "scrolling" ? <Rows3 size={13} /> : <List size={13} />}
              </IconButton>
              {tabView === "scrolling" && tabs.length > 1 ? (
                <DropdownMenu
                  groups={tabDropdownGroups(tabs, groups).map((entry) => ({
                    id: entry.id === "" ? "ungrouped" : `group-${entry.id}`,
                    title: entry.title,
                    actions: entry.tabs.map((entryTab) => ({
                      id: entryTab.id,
                      label: entryTab.name,
                      disabled: entryTab.id === active.id,
                      onSelect: () => setActiveRepeaterTab(entryTab.id),
                    })),
                  }))}
                  trigger={
                    <IconButton
                      label={`All open tabs (${tabs.length})`}
                      title={`${tabs.length} open tabs — this lists them all, which is the point of the scrolling view`}
                      size="small"
                    >
                      <List size={13} />
                    </IconButton>
                  }
                />
              ) : null}
              {httpResult ? (
                <>
                  <Badge tone={statusTone(httpResult.status)}>{httpResult.status}</Badge>
                  {/* A single-connection group send has no per-request timing to report —
                      sender.SendKeepAlive owns the write/read loop — so this says "untimed" rather
                      than rendering the 0 it would otherwise have as though it were a measurement.
                      The group outcome panel carries the batch time, which is the real number. */}
                  {httpResult.duration_measured === false ? (
                    <Tooltip content="This request shared a socket with the rest of its group, and the shared-socket send reports no per-request timing. The group's total is in the group send panel.">
                      <Badge tone="warn">untimed</Badge>
                    </Tooltip>
                  ) : (
                    <Badge>{formatDuration(httpResult.duration_ms)}</Badge>
                  )}
                  {httpResult.exchange_id ? <Badge>#{httpResult.exchange_id}</Badge> : null}
                  {/* Which send produced the entry on screen. An entry that rode a shared socket is
                      not comparable with one that dialled fresh, and that difference is the whole
                      subject of the test the mode exists for. */}
                  {httpResult.group_mode ? (
                    <Tooltip content={groupModeLabel(httpResult.group_mode)}>
                      <Badge tone="info">
                        {httpResult.group_mode === "sequence_single_conn"
                          ? "one socket"
                          : httpResult.group_mode === "parallel"
                            ? "group, parallel"
                            : "group, sequence"}
                      </Badge>
                    </Tooltip>
                  ) : null}
                  {httpResult.framing ? <Badge>framing: {httpResult.framing}</Badge> : null}
                  {httpResult.response_complete === false ? (
                    <Tooltip content="The response was not read to a boundary burpsy is confident of — see the group send panel. On a shared socket that ambiguity is evidence, not a glitch.">
                      <Badge tone="warn">incomplete read</Badge>
                    </Tooltip>
                  ) : null}
                </>
              ) : null}
              {/* Labelled "send" rather than "response" because stepping moves both panes: the
                  request that was sent and the response it got, together. */}
              {activeHistory.length > 1 ? (
                <span className="repeater-history" role="group" aria-label="Send history">
                  <IconButton
                    label="Previous send"
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
                    label="Next send"
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
              {/* A group send is N requests and, in single-connection mode, N requests on one socket:
                  the operator needs a way out of that at least as much as out of a single send. */}
              {groupSend.isPending ? (
                <Tooltip content="Stop waiting and tell the sender to abandon this group send. Requests already written to the target were still sent.">
                  <button type="button" className="button button-outline" onClick={groupSend.cancel}>
                    <X size={14} />
                    Cancel group
                  </button>
                </Tooltip>
              ) : null}
              {/* Disabled while a past send is on screen: the request pane is then a snapshot, and
                  Send would fire the draft the operator can no longer see. The tooltip says which
                  control gets them back rather than leaving a dead button unexplained. */}
              <Tooltip
                content={
                  viewedRequest != null
                    ? "Viewing a past send — step to the newest entry to send the draft"
                    : "Send the current request (mod+Enter)"
                }
              >
                <button
                  type="button"
                  className="button button-primary"
                  onClick={() => (active.kind === "ws" ? submitWs(active) : submit(active))}
                  disabled={send.isPending || wsSend.isPending || groupSend.isPending || viewedRequest != null}
                >
                  <Send size={14} />
                  {send.isPending || wsSend.isPending ? "Sending…" : "Send"}
                </button>
              </Tooltip>
              {/* Burp grows a dropdown arrow beside Send exactly when the active tab belongs to a
                  group, and not otherwise: a permanently visible arrow whose menu is usually empty
                  teaches the operator to ignore it. One member is not a group send — it is Send —
                  so the threshold is two, which is also what makes any of the three modes mean
                  something different from each other. */}
              {activeGroup && groupMembers.length > 1 ? (
                <DropdownMenu
                  groups={[
                    {
                      id: "group-send",
                      title: `${activeGroup.name} — ${groupMembers.length} tabs, in tab order`,
                      actions: GROUP_SEND_MODES.map((entry) => ({
                        id: entry.mode,
                        label: entry.label,
                        disabled: send.isPending || groupSend.isPending || viewedRequest != null,
                        onSelect: () => submitGroup(entry.mode),
                      })),
                    },
                  ]}
                  trigger={
                    <button
                      type="button"
                      className="button button-primary"
                      aria-label={`Send group ${activeGroup.name} (${groupMembers.length} tabs)`}
                      disabled={send.isPending || groupSend.isPending || viewedRequest != null}
                      style={{ paddingInline: "var(--s2)" }}
                    >
                      {groupSend.isPending ? "Sending group…" : <ChevronDown size={14} />}
                    </button>
                  }
                />
              ) : null}
            </>
          }
        />

        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10 }}>
          <div className="tabs-list" role="tablist" aria-label="Ungrouped Repeater requests">
            {ungrouped.map(renderTabTrigger)}
            <DropdownMenu
              groups={[
                {
                  id: "new",
                  actions: [
                    { id: "new-http", label: "New HTTP request", icon: Plus, onSelect: () => newTab("http") },
                    { id: "new-ws", label: "New WebSocket message", icon: Plus, onSelect: () => newTab("ws") },
                  ],
                },
              ]}
              trigger={
                <IconButton label="New request" size="small">
                  <Plus size={13} />
                </IconButton>
              }
            />
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
                  active.kind === "ws" ? submitWs(active) : submit(active);
                }}
                placeholder="https://host:443"
              />
            )}
          </Field>
          <Field label="Tab name" style={{ maxWidth: "var(--w-md)" }}>
            {(id) => <Input id={id} value={active.name} onChange={(event) => updateRepeaterTab(active.id, { name: event.target.value })} />}
          </Field>
          {active.kind === "ws" ? (
            /* The opcode as a visible control, not only a menu row: it decides whether the
             * bytes go out as a text frame or a binary one, and that choice has to be legible
             * while reading the payload it applies to (6ex). */
            <Field label="Opcode" style={{ maxWidth: "var(--w-xs)" }}>
              {(id) => (
                <Select
                  id={id}
                  aria-label="WebSocket opcode"
                  value={active.wsOpcode ?? "text"}
                  onChange={(event) => updateRepeaterTab(active.id, { wsOpcode: event.target.value })}
                >
                  <option value="text">text</option>
                  <option value="binary">binary</option>
                </Select>
              )}
            </Field>
          ) : null}
          {active.kind === "ws" ? (
            /* Burp's direction choice, on the tab that has it (6ex). Both directions are
             * offered: "to client" is refused by the wire with the reason it cannot run on a
             * fresh connection, and a chooser that hid half of Burp's choice would misstate
             * what this tab can do. The refusal lands in the reply pane. */
            <Field label="Direction" style={{ maxWidth: "var(--w-md)" }}>
              {(id) => (
                <Select
                  id={id}
                  aria-label="Which way the frame goes"
                  value={active.wsDirection ?? "server"}
                  onChange={(event) =>
                    updateRepeaterTab(active.id, { wsDirection: event.target.value as "server" | "client" })
                  }
                >
                  <option value="server">To server</option>
                  <option value="client">To client (refused on a fresh connection)</option>
                </Select>
              )}
            </Field>
          ) : null}
          <Button variant="outline" onClick={() => void handOffToIntruder(active)} disabled={handingOff}>
            <Crosshair size={14} />
            {handingOff ? "Preparing…" : "To Intruder"}
          </Button>
        </div>

        {/* A cancellation is excluded: it is not a failed request, and an error notice inviting a
            retry would frame the operator's own decision as something that went wrong. */}
        {send.error && !(send.error instanceof SendCancelled) ? (
          <ErrorNotice error={send.error || wsSend.error} onRetry={() => (active.kind === "ws" ? submitWs(active) : submit(active))} />
        ) : null}
        {/* No retry button: retrying a group send is a choice of mode, and the last mode is not
            necessarily the one the operator wants after a failure. The dropdown is right there. */}
        {groupSend.error && !(groupSend.error instanceof SendCancelled) ? (
          <ErrorNotice error={groupSend.error} title="The group send was refused" />
        ) : null}
        {groupOutcome ? (
          <GroupSendOutcome
            outcome={groupOutcome}
            tabName={(id) => tabs.find((tab) => tab.id === id)?.name ?? id}
            onDismiss={() => setGroupOutcome(null)}
          />
        ) : null}
        {configOpen ? <SendOptionsPanel options={active.options} onChange={applyOptions} onReset={() => setRepeaterTabOptions(active.id, {})} /> : null}
        {httpResult?.redirects ? (
          <RedirectChain chain={httpResult.redirects} chainSide={chainSide} onViewHop={setChainSide} />
        ) : null}
      </div>

      <div className={inspector ? "editor-grid-inspected" : "editor-grid"}>
        {/* Paged back, this pane shows the request that produced the entry on screen — read-only,
            because it has already been sent and there is nothing left to change about it. The label
            carries the state: an editor that silently stopped accepting keystrokes would read as a
            broken editor. Following the newest send, it is the live draft, editable as always. */}
        {active.kind === "ws" ? (
          /* The frame editor (6ex): a ws tab's payload is the message, not an HTTP request.
           * views={false}: a frame has no head/body split, and the header decorations would be
           * decorations of nothing. The send button above is the same Send — its dispatch on the
           * tab kind is what makes it a ws send. */
          <HttpEditor
            label="WebSocket message"
            views={false}
            value={viewedRequest ?? (active.wsPayload ?? "")}
            readOnly={viewedRequest != null}
            onChange={(value) => updateRepeaterTab(active.id, { wsPayload: value })}
            filename="repeater-ws-frame.txt"
            placeholder="A text frame's payload, or switch the opcode to binary and paste bytes"
            menuGroups={wsFrameMenu}
          />
        ) : (
          <HttpEditor
            label={viewedRequest != null ? `Request · sent ${viewIndex + 1}/${activeHistory.length}, as written` : "Request"}
            value={viewedRequest ?? active.request}
            readOnly={viewedRequest != null}
            onChange={(value) => updateRepeaterTab(active.id, { request: value })}
            filename="repeater-request.txt"
            placeholder="GET / HTTP/1.1"
            menuGroups={[...(messageMenu ?? []), ...(sentExchange.data ? [] : draftSendMenu), ...bodyEncodingMenu]}
          />
        )}
        <div className="stack">
          {active.kind === "ws" ? (
            /* A ws tab's response pane (6ex): the handshake line, the reply frames the target
             * sent back in order, and how the conversation ended. Not an HTTP response editor —
             * a ws send has no status code or body to parse, and dressing frames up as one would
             * misstate the wire. The honest note says the frame went out on a NEW connection:
             * one dial per send, not a held socket — which is also what Burp's own "set
             * automatically" does once the original has closed.
             */
            <WsReplyPane
              result={wsResult ?? null}
              pending={wsSend.isPending}
              cancelled={wsSend.error instanceof SendCancelled}
              /* The refusal text. A ws send that was refused before the dial (a bad target, a
               * scope refusal) used to leave the idle placeholder on screen, which reads as
               * "nothing happened" rather than "the send was refused, and here is why" — the
               * exact shape the ws tab's own `unknown scheme "ws"` bug hid inside. */
              failure={wsSend.error && !(wsSend.error instanceof SendCancelled)
                ? wsSend.error instanceof Error ? wsSend.error.message : String(wsSend.error)
                : null}
              exchangeId={httpResult?.exchange_id ?? null}
            />
          ) : finalResponse != null ? (
            <div className="toolbar" role="group" aria-label="Which chain response to show">
              <Button
                variant={chainSide === "first" ? "outline" : "quiet"}
                size="small"
                aria-pressed={chainSide === "first"}
                onClick={() => setChainSide("first")}
              >
                First response ({httpResult?.status})
              </Button>
              <Button
                variant={chainSide === lastFollowedHop ? "outline" : "quiet"}
                size="small"
                aria-pressed={chainSide === lastFollowedHop}
                onClick={() => setChainSide(lastFollowedHop as number)}
              >
                Final response ({httpResult?.redirects?.final_status})
              </Button>
            </div>
          ) : null}
          {active.kind === "ws" ? null : (
            <HttpEditor
              label="Response"
              readOnly
              value={
                    chainResponse ??
                    httpResult?.response ??
                    (send.isPending
                      ? "Waiting for the response…"
                      : send.error instanceof SendCancelled
                        ? "Cancelled. No response arrived, and no exchange was recorded — but anything already written to the target was sent."
                        : "Send the request to see the response bytes.")
                  }
              filename="repeater-response.txt"
              menuGroups={messageMenu}
            />
          )}
        </div>
        {inspector ? (
          // Pointed at the response with nothing to show yet, it falls back to the
          // request rather than rendering a pane of empty sections that looks like
          // a parse failure.
          inspecting === "request" || !result ? (
            // On a past send the Inspector follows the pane: it parses that entry's request and
            // drops its editing affordances, the same way the response half already does, rather
            // than offering fields whose edits would land on a draft that is not on screen.
            <Inspector
              raw={viewedRequest ?? active.request}
              label={viewedRequest != null ? "Inspector · request as sent" : "Inspector · request"}
              onChange={viewedRequest != null ? undefined : (next) => updateRepeaterTab(active.id, { request: next })}
              readOnlyNote="This request has already been sent, so it is read-only here — step to the newest entry to edit the draft."
              onSwitch={result ? () => setInspecting("response") : undefined}
              switchLabel="Inspect the response"
            />
          ) : (
            <Inspector
              raw={chainResponse ?? httpResult?.response ?? ""}
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
 * A ws tab's response pane (burpsy-react-ui-6ex): the handshake line, the reply frames the
 * target sent back in order, and how the conversation ended. Not an HTTP response editor —
 * a ws send has no status code or body to parse, and dressing frames up as one would
 * misstate the wire. The honest note says the frame went out on a NEW connection: one dial
 * per send, not a held socket — which is also what Burp's own "set automatically" does once
 * the original has closed.
 */
function WsReplyPane({
  result,
  pending,
  cancelled,
  failure,
  exchangeId,
}: {
  result: WsRepeaterSendResult | null;
  pending: boolean;
  cancelled: boolean;
  failure: string | null;
  exchangeId: number | null;
}): JSX.Element {
  if (pending) {
    // The send's reply read runs to wsclient.ReplyDeadline (30s), on purpose: a WebSocket
    // reply is often a burst and stopping at the first frame would drop the rest of what the
    // target did. Saying so beats a spinner that looks hung — an operator who knows the wait
    // is the read, not a stall, can tell a slow target from a broken send.
    return (
      <HttpEditor
        label="WebSocket"
        views={false}
        readOnly
        value={"Waiting for reply frames — the read runs up to 30s so a burst is not cut short. The frames that arrive are shown as they land."}
        filename="repeater-ws.txt"
      />
    );
  }
  if (cancelled) {
    return (
      <div className="notice">
        Cancelled. No reply arrived, and no exchange was recorded — but the frame may have reached the target.
      </div>
    );
  }
  if (failure) {
    // The refusal in full, in place of the frame that never went out. A ws send can be refused
    // before the dial (an unusable target, a scope decision), and the pane is where the operator
    // is looking — a toast is gone by the time they wonder what happened.
    return (
      <div className="notice notice-warn" role="status">
        The send was refused: {failure}
      </div>
    );
  }
  if (!result) {
    return (
      <HttpEditor
        label="WebSocket"
        views={false}
        readOnly
        value="Send the frame to see what the target replies."
        filename="repeater-ws.txt"
      />
    );
  }
  return (
    <div className="detail-panel">
      <DetailList
        rows={[
          { label: "Handshake", value: result.handshake },
          { label: "Sent on", value: `a new connection (one dial per send)` },
          { label: "Exchange", value: exchangeId ? `#${exchangeId}` : "—" },
          ...(result.closed_by_peer
            ? [{ label: "Closed by peer", value: `${result.close_code ?? "?"}${result.close_reason ? ` (${result.close_reason})` : ""}` }]
            : []),
          { label: "Elapsed", value: formatDuration(result.elapsed_ms) },
        ]}
      />
      {result.messages.length ? (
        <div className="detail-actions" style={{ display: "grid", gap: 4 }}>
          {result.messages.map((message, index) => (
            <HttpEditor
              key={index}
              label={`Reply ${index + 1} · ${message.opcode} · ${formatBytes(message.len)}`}
              views={false}
              readOnly
              value={message.payload}
              filename={`repeater-ws-reply-${index + 1}.txt`}
            />
          ))}
        </div>
      ) : (
        <Empty title="No reply frames" detail="The target accepted the frame and sent nothing back." />
      )}
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
              <option value="http2">Force HTTP/2</option>
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
 * The last group send, one row per tab (burpsy-react-ui-03z).
 *
 * It exists because a group send answers N questions and only one of the answers lands in the tab on
 * screen. The three things it reports that a per-tab response pane cannot:
 *
 *   - which tabs answered and which did not, in one place, so a mode that half-worked cannot read as
 *     a mode that worked;
 *   - the framing rule that delimited each response and whether each read completed — a *comparison*
 *     across the group, which is the entire evidence a smuggling or desync test produces;
 *   - whether the redirect policy was applied at all, which is false for the shared socket and must
 *     not be mistaken for "there was nothing to follow".
 *
 * A row can carry both a response and an error: a head that arrived followed by a body that could not
 * be delimited is exactly the ambiguity being looked for, so both halves are shown.
 */
function GroupSendOutcome({
  outcome,
  tabName,
  onDismiss,
}: {
  outcome: RepeaterGroupSendResult;
  tabName: (tabId: string) => string;
  onDismiss: () => void;
}): JSX.Element {
  const answered = outcome.items.filter((item) => item.result).length;
  const failed = outcome.items.filter((item) => item.error).length;
  const detail = GROUP_SEND_MODES.find((entry) => entry.mode === outcome.mode)?.detail ?? "";
  return (
    <Card style={{ marginTop: 10, padding: 12, display: "grid", gap: 8 }}>
      <div className="toolbar">
        <Badge tone="info">{groupModeLabel(outcome.mode)}</Badge>
        <Badge tone={failed === 0 ? "good" : "warn"}>
          {answered} of {outcome.items.length} answered
        </Badge>
        {failed > 0 ? (
          <Badge tone="warn">
            {failed} problem{failed === 1 ? "" : "s"}
          </Badge>
        ) : null}
        {/* The batch total, which for the shared socket is the only measured duration there is. */}
        <Badge>group took {formatDuration(outcome.batch_duration_ms)}</Badge>
        {outcome.shared_connection ? <Badge tone="accent">one socket to {outcome.shared_connection}</Badge> : null}
        <Badge tone={outcome.followed_redirects ? "neutral" : "warn"}>
          {outcome.followed_redirects ? "redirect policy applied" : "redirects not followed"}
        </Badge>
        <IconButton label="Dismiss the group send summary" size="small" onClick={onDismiss}>
          <X size={11} />
        </IconButton>
      </div>
      {/* The arrival column exists only in Parallel mode: it is the ordinal the synchronized
          release makes measurable, and a sequence mode has a trivially known order (tab order)
          that a number would merely decorate. Items that never answered carry no ordinal, so
          they render as a dash rather than a rank. */}
      <SimpleTable
        headers={
          outcome.mode === "parallel"
            ? ["Tab", "Arrived", "Status", "Response", "Framing", "Read", "Problem"]
            : ["Tab", "Status", "Response", "Framing", "Read", "Problem"]
        }
      >
        {outcome.items.map((item) => (
          <tr key={item.tab_id}>
            <td>{tabName(item.tab_id)}</td>
            {outcome.mode === "parallel" ? (
              <td>
                {item.arrival ? (
                  <span className="cell-num">#{item.arrival}</span>
                ) : (
                  <span className="cell-dim">—</span>
                )}
              </td>
            ) : null}
            <td>
              {item.result ? (
                <Badge tone={statusTone(item.result.status)}>{item.result.status}</Badge>
              ) : (
                <span className="cell-dim">none</span>
              )}
            </td>
            <td>
              {/* Bytes, not a duration: on the shared socket there is no per-request duration to
                  show, and the response size is the fact that is actually known per request. */}
              {item.result ? (
                <span className="cell-num">{item.result.response.length} B</span>
              ) : (
                <span className="cell-dim">—</span>
              )}
            </td>
            <td>{item.framing ? <code>{item.framing}</code> : <span className="cell-dim">n/a</span>}</td>
            <td>
              {item.response_complete == null ? (
                <span className="cell-dim">n/a</span>
              ) : (
                <Badge tone={item.response_complete ? "good" : "warn"}>
                  {item.response_complete ? "complete" : "incomplete"}
                </Badge>
              )}
            </td>
            <td>{item.error ? item.error : <span className="cell-dim">—</span>}</td>
          </tr>
        ))}
      </SimpleTable>
      <p className="field-hint">{detail}</p>
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
function RedirectChain({
  chain,
  chainSide,
  onViewHop,
}: {
  chain: RepeaterRedirects;
  chainSide: "first" | number;
  onViewHop: (index: number) => void;
}): JSX.Element {
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
      <SimpleTable headers={["From", "Status", "Location", "Followed", "Why not", "Bytes"]}>
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
            <td>
              {hop.followed ? (
                <Button
                  variant={chainSide === index ? "outline" : "quiet"}
                  size="small"
                  aria-pressed={chainSide === index}
                  onClick={() => onViewHop(index)}
                >
                  View response
                </Button>
              ) : (
                <span className="cell-dim">—</span>
              )}
            </td>
          </tr>
        ))}
      </SimpleTable>
    </div>
  );
}
