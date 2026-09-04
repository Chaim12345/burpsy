import { useRef } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, json } from "./api";
import type { RepeaterResult, RepeaterSendOptions } from "./types";
import type { IntruderAttack, IntruderAttacksResp, PayloadRuleSpec, PayloadSource, PointView } from "./types.tools";

export interface IntruderRunRequest {
  msg_id: number;
  target: string;
  all: boolean;
  mode: string;
  points: number[];
  payload_sets?: string[][];
  payload_sources?: PayloadSource[];
  payload_rules?: PayloadRuleSpec[];
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
