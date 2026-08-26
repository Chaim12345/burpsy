import { useMutation } from "@tanstack/react-query";
import { api, json } from "./api";
import type { RepeaterResult, RepeaterSendOptions } from "./types";
import type { PointView } from "./types.tools";

export interface IntruderRunRequest {
  msg_id: number;
  target: string;
  all: boolean;
  mode: string;
  points: number[];
  payload_sets: string[][];
  max_requests: number;
  max_in_flight: number;
}

export function useRepeaterSend() {
  return useMutation({
    mutationFn: (body: { target: string; request: string; protocol: string; from_exchange?: number; options?: RepeaterSendOptions }) =>
      api<RepeaterResult>("/api/repeater/send", json("POST", body)),
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
