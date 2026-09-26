import { useRef } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, json } from "./api";
import type { WsRepeaterSendResult } from "./types";
import type {
  RepeaterGroupSendItem,
  RepeaterGroupSendMode,
  RepeaterGroupSendResult,
  RepeaterResult,
  RepeaterSendOptions,
} from "./types";
import type { IntruderAttack, IntruderAttacksResp, PayloadRuleSpec, PayloadSource, PointView , WordlistsResponse } from "./types.tools";

export interface IntruderRunRequest {
  msg_id: number;
  target: string;
  all: boolean;
  mode: string;
  points: number[];
  /**
   * Hand-marked payload positions (Burp's Add §): raw byte ranges of the base request, spliced
   * wire-faithfully alongside the selected discovered points. The server refuses a span outside
   * the request or overlapping another position.
   */
  manual_points?: { start: number; end: number }[];
  payload_sets?: string[][];
  payload_sources?: PayloadSource[];
  payload_rules?: PayloadRuleSpec[];
  /**
   * Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): the characters
   * percent-encoded in every generated payload as the final pass, after the rule
   * chain. Omitted means none — spaces and control characters are always encoded
   * additionally server-side, since a request containing them cannot be delivered.
   */
  url_encode_characters?: string;
  /**
   * Burp's auto-pause (burpsy-react-ui-2cvk). Omitted entirely when the operator has not turned it
   * on, which is the point: an absent field and a present-but-empty expression list must not be two
   * wire shapes for "I did not choose", so the console sends neither. Expressions are compiled by
   * RE2 on the server and an uncompilable one is a 400, which surfaces next to the field.
   */
  auto_pause?: {
    expressions: string[];
    /** Pause when none of them appears, rather than when one does. */
    missing: boolean;
    /** Simple strings are matched literally and case-folded; false means RE2. */
    simple: boolean;
    /** Only meaningful with `simple`: regex entries carry their own case flags. */
    case_sensitive?: boolean;
  };
  /** Regular expressions, compiled by RE2 on the server — never literal strings. */
  grep_match?: string;
  grep_extract?: string;
  max_requests: number;
  /**
   * A saved resource pool by name (Burp's Resource pool sub-tab).
   *
   * Mutually exclusive with `max_in_flight`, `rps` and auto-throttle: the server refuses a request
   * carrying both, because a pool already states those bounds and accepting two answers to "how
   * fast may this attack run" would mean silently dropping one while the report named the pool.
   * See Server.intruderLimits in internal/web/api_tools.go. `max_requests` is not part of that
   * exclusion — it is the attack's size bound, not its rate — and still applies.
   */
  pool?: string;
  max_in_flight?: number;
  rps?: number;
  /**
   * Burp's resource-pool "With random variations" (burpsy-react-ui-nn0n), as a percentage of the
   * interval `rps` states: 25 makes every gap between requests land somewhere in ±25% of it. Part
   * of the same exclusion as `rps` — a named pool states how its own delay behaves.
   *
   * The server refuses 100 or more (a downward variation would be a zero gap) rather than clamping,
   * and the engine's schedule is seeded, so the delays a run takes can be replayed. See
   * intruder.DelayVariation in internal/intruder/limit.go.
   */
  delay_jitter_percent?: number;
  /** Burp's throttleIncrementMillis: every gap is this many milliseconds longer than the one
   *  before it. 0..600000, Burp's own bound on a delay; a negative one is refused, not clamped. */
  delay_increment_ms?: number;
  /** Seeds the jitter. Omitted is 0, which is a seed like any other — the schedule is replayable
   *  either way, and a different number is a differently-shaped run. */
  delay_seed?: number;
  /**
   * Burp's Intruder "Follow redirections" (tirx): "never" | "on_site" | "in_scope" | "always",
   * or omitted for the standing network-settings policy (never, by default). Each hop is
   * re-authorised through the same scope gate the first request went through — see
   * internal/web/api_tools.go's intruderRedirectPolicy.
   */
  follow_redirects?: string;
}

/**
 * Thrown when the operator cancelled a send. Its own type because a cancellation is not a failure:
 * the page must not show it as an error notice, and the toast should say "cancelled" rather than
 * repeating the browser's "The user aborted a request."
 */
export class SendCancelled extends Error {
  constructor() {
    super("Send cancelled");
    this.name = "SendCancelled";
  }
}

export interface RepeaterSendBody {
  target: string;
  request: string;
  protocol: string;
  from_exchange?: number;
  options?: RepeaterSendOptions;
}

/**
 * Repeater's send, with real cancellation (burpsy-react-ui-0c2).
 *
 * # Why the abort is not the whole story
 *
 * Aborting the fetch stops the *browser* waiting. On its own that would be the dishonest Cancel:
 * the operator would see the request stop while burpsy kept talking to the target, and would be
 * wrong about whether their bytes arrived — on a tool used under engagement rules, worse than
 * having no Cancel at all.
 *
 * It works because two things are true on the server, and both were checked rather than assumed:
 *
 *   1. handleRepeaterSend threads r.Context() into the sender (api_tools.go), and Go's http.Server
 *      cancels that context when the client disconnects. So the abort reaches the sender.
 *   2. The sender now unblocks its in-flight read when that context is cancelled. It did NOT before
 *      — setDeadline honoured only ctx.Deadline(), never ctx.Done(), so a cancelled send stayed
 *      blocked for the whole read timeout. See internal/sender/cancel.go; that fix went in first,
 *      and its test measures 0.03s against a 30s bound.
 *
 * No exchange row is written for a cancelled send: the sender returns an error, so the handler logs
 * it to the tool log and never reaches the Put. The cancellation is recorded as what it was.
 */
export interface RepeaterWsSendBody {
 /** The wshistory frame id being resent, 0 for a frame authored from scratch. */
 message?: number;
 /** "host:port"; the scheme rides `tls`. Optional when `message` names a frame. */
 target?: string;
 tls?: boolean;
 path?: string;
 /** "text" | "binary". */
 opcode: string;
 payload: string;
 /** Burp's other direction. Refused by the wire with its reason — see the store's wsDirection. */
 to_client?: boolean;
}

/**
 * The Repeater WebSocket send (burpsy-react-ui-6ex) — one dial per send, the wire half
 * `/api/repeater/ws-send`. The server refuses a to-client direction with the reason in the
 * body (a fresh dial has no client to send to), and records the handshake exchange so the
 * result can offer "view in WebSockets history".
 */
export function useRepeaterWsSend() {
 const inFlight = useRef<AbortController | null>(null);
 const mutation = useMutation({
  mutationFn: async (body: RepeaterWsSendBody) => {
   const controller = new AbortController();
   inFlight.current = controller;
   try {
    return await api<WsRepeaterSendResult>("/api/repeater/ws-send", {
     ...json("POST", body),
     signal: controller.signal,
    });
   } catch (failure) {
    if (controller.signal.aborted) throw new SendCancelled();
    throw failure;
   } finally {
    if (inFlight.current === controller) inFlight.current = null;
   }
  },
 });
 return mutation;
}

export function useRepeaterSend() {
  // One controller per hook instance, so the Cancel button can only ever abort this tab's send.
  const inFlight = useRef<AbortController | null>(null);

  const mutation = useMutation({
    mutationFn: async (body: RepeaterSendBody) => {
      const controller = new AbortController();
      inFlight.current = controller;
      try {
        return await api<RepeaterResult>("/api/repeater/send", {
          ...json("POST", body),
          signal: controller.signal,
        });
      } catch (failure) {
        // fetch rejects an aborted request with a DOMException named AbortError. Translated here so
        // no caller has to know that, and so a cancellation cannot be rendered as a request failure.
        if (controller.signal.aborted) throw new SendCancelled();
        throw failure;
      } finally {
        if (inFlight.current === controller) inFlight.current = null;
      }
    },
  });

  return {
    mutate: mutation.mutate,
    isPending: mutation.isPending,
    error: mutation.error,
    /** Abort the send in flight. A no-op when nothing is in flight, so it is safe to bind blindly. */
    cancel: () => inFlight.current?.abort(),
  };
}

export interface RepeaterGroupSendBody {
  mode: RepeaterGroupSendMode;
  /** The group's tabs in tab order. Order is the test in a smuggling or desync send, so it is not sorted. */
  items: RepeaterGroupSendItem[];
}

/**
 * Send a whole Repeater tab group (burpsy-react-ui-03z), in one of the three modes Burp's dropdown
 * beside Send offers.
 *
 * Cancellation works the same way useRepeaterSend's does and for the same reason — see that hook's
 * comment on why aborting the fetch is not the whole story. It matters more here, not less: a group
 * send is N requests, and in `sequence_single_conn` they share a socket, so an operator who wants to
 * stop needs the server to stop too. POST /api/repeater/send-group threads r.Context() into the
 * sender exactly as the single send does, and internal/sender/cancel.go unblocks the in-flight read.
 *
 * What Cancel here cannot promise, and does not claim: the requests already written. A group send is
 * partly-sent traffic by construction, and the toast says so.
 */
export function useSendRepeaterGroup() {
  const inFlight = useRef<AbortController | null>(null);

  const mutation = useMutation({
    mutationFn: async (body: RepeaterGroupSendBody) => {
      const controller = new AbortController();
      inFlight.current = controller;
      try {
        return await api<RepeaterGroupSendResult>("/api/repeater/send-group", {
          ...json("POST", body),
          signal: controller.signal,
        });
      } catch (failure) {
        if (controller.signal.aborted) throw new SendCancelled();
        throw failure;
      } finally {
        if (inFlight.current === controller) inFlight.current = null;
      }
    },
  });

  return {
    mutate: mutation.mutate,
    isPending: mutation.isPending,
    error: mutation.error,
    cancel: () => inFlight.current?.abort(),
  };
}

/**
 * Burp's two newline corrections for an EDITED interception (settings/tools/proxy.html:273-292,
 * burpsy-react-ui-80tg): add a missing blank line after the headers, and strip trailing newlines
 * from a urlencoded body.
 *
 * Its own route rather than two fields on the forward body, because they are not properties of a
 * forward: they are how the interception tool behaves, an operator sets them once, and a caller that
 * forgot them on a forward would silently rewrite nothing.
 *
 * The read is not optional decoration. Both default OFF, and a plugin or a previous session may have
 * set one — so a checkbox that showed the defaults rather than the in-force values would be a control
 * lying about what it is doing, which is the same defect as a missing panel.
 */
export interface InterceptNewlineCorrection {
  add_missing_blank_line: boolean;
  trim_trailing_newlines_urlencoded_body: boolean;
}

export function useInterceptNewlineCorrection() {
  return useQuery({
    queryKey: ["intercept", "newline-correction"],
    queryFn: ({ signal }) => api<InterceptNewlineCorrection>("/api/intercept/newline-correction", { signal }),
    // The settings do not change on their own, and the page already polls the queue; refetching this
    // on the same cadence would be a second request per poll for a value that only changes when the
    // operator changes it.
    staleTime: 30_000,
  });
}

export function useSetInterceptNewlineCorrection() {
  return useMutation({
    mutationFn: (next: InterceptNewlineCorrection) =>
      api<InterceptNewlineCorrection>("/api/intercept/newline-correction", json("PUT", next)),
  });
}

export function useIntruderPoints() {
  return useMutation({
    mutationFn: (body: { msg_id: number; all: boolean }) =>
      api<PointView[]>("/api/intruder/points", json("POST", body)),
  });
}

export function useIntruderRun() {
  return useMutation({
    mutationFn: (body: IntruderRunRequest) => api<unknown>("/api/intruder/run", json("POST", body)),
  });
}

/**
 * The attacks this process is running and can control (GET /api/intruder/attacks).
 *
 * Polled only while `enabled` — i.e. while this page has an attack in flight. /run is synchronous,
 * so a page cannot learn its own attack's task_id from the run response (which arrives only when the
 * attack is over, by which point control is moot). It learns it here instead, by watching this list
 * while it waits. The 1s cadence is chosen to feel live for pause/resume/stop without hammering a
 * process that is already busy driving the attack.
 */
export function useIntruderAttacks(enabled: boolean) {
  return useQuery({
    queryKey: ["intruder", "attacks"],
    queryFn: ({ signal }) => api<IntruderAttacksResp>("/api/intruder/attacks", { signal }),
    enabled,
    refetchInterval: enabled ? 1_000 : false,
  });
}

/**
 * Thrown when pause/resume/stop hit an attack that is no longer in a state the action can change
 * (HTTP 409): it already stopped, or its plan is exhausted and the report is assembling. Its own
 * type so the page can say "the attack already finished" rather than render a 409 as a failure —
 * the same reason SendCancelled is not an Error notice.
 */
export class AttackActionStale extends Error {
  constructor(readonly action: string) {
    super(`Attack is no longer in a state that ${action} can change`);
    this.name = "AttackActionStale";
  }
}

export interface IntruderAttackActionBody {
  task_id: number;
  action: "pause" | "resume" | "stop";
}

/** The 200 body of a successful action: the id, what was done, and the state it left the attack in. */
export interface IntruderAttackActionResult {
  task_id: number;
  action: string;
  applied: boolean;
  status: IntruderAttack["status"];
}

/**
 * Pause, resume or stop a running attack by task id.
 *
 * Stop is deliberately NOT paired with aborting the run fetch. The server, on stop, lets in-flight
 * sends land and returns the assembled report (a prefix of the payload sets) as the /run response —
 * so the launching page's run mutation resolves with a real stopped report the operator can read.
 * Aborting the fetch would throw that report away, which is the worse of the two honest options.
 */
export function useIntruderAttackAction() {
  return useMutation<IntruderAttackActionResult, Error, IntruderAttackActionBody>({
    mutationFn: async ({ task_id, action }) => {
      try {
        return await api<IntruderAttackActionResult>(`/api/intruder/attacks/${task_id}/${action}`, json("POST", {}));
      } catch (failure) {
        // 409 is "the action cannot apply", not a failure: the attack ended between the button
        // appearing and the click landing. Translated so the page reports it as information.
        if (failure && typeof failure === "object" && "status" in failure && (failure as { status: number }).status === 409) {
          throw new AttackActionStale(action);
        }
        throw failure;
      }
    },
  });
}

/** GET /api/wordlists (kal): the payload-corpus inventory, bundled and uploaded. No poll —
 * the bundled set is fixed at build time and an upload invalidates through its own mutation. */
export function useWordlists() {
 return useQuery({
  queryKey: ["wordlists"],
  queryFn: ({ signal }) => api<WordlistsResponse>("/api/wordlists", { signal }),
  staleTime: 30_000,
 });
}
