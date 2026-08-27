import { useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, json } from "./api";
import type { RepeaterResult, RepeaterSendOptions } from "./types";
import type { PayloadSource, PointView } from "./types.tools";

export interface IntruderRunRequest {
  msg_id: number;
  target: string;
  all: boolean;
  mode: string;
  points: number[];
  payload_sets?: string[][];
  payload_sources?: PayloadSource[];
  max_requests: number;
  max_in_flight: number;
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
