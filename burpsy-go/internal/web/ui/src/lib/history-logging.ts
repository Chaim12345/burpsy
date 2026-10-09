/**
 * Burp's "Proxy history logging" (burpsy-react-ui-z80e): when hosts are added to the target scope,
 * whether the proxy stops sending out-of-scope items to history, asks each time, or does nothing.
 * The choice lives at /api/proxy/history-logging; the switch it acts on is the proxy option
 * dont_log_out_of_scope.
 */
import { toast } from "sonner";
import { api, json } from "./api";
import type { ProxyOptionsState } from "./data.proxyoptions";

export type HistoryLoggingMode = "stop" | "ask" | "nothing";

/** What adding to scope should do next. Nothing to do when out-of-scope items are already dropped. */
export function followUpAfterScopeAdd(mode: string, dontLogAlreadyOn: boolean): "none" | "stop" | "ask" {
 if (dontLogAlreadyOn) return "none";
 if (mode === "stop") return "stop";
 if (mode === "nothing") return "none";
 return "ask";
}

/**
 * Run after a successful Add to scope. onChanged refreshes whatever reads the proxy options.
 * Failures are reported, never thrown: the scope change itself already succeeded.
 */
export async function afterScopeAdd(onChanged: () => void): Promise<void> {
 let next: "none" | "stop" | "ask";
 try {
  const [choice, options] = await Promise.all([
   api<{ mode: string }>("/api/proxy/history-logging"),
   api<ProxyOptionsState>("/api/proxy/options"),
  ]);
  next = followUpAfterScopeAdd(choice.mode, options.options.dont_log_out_of_scope === true);
 } catch (error) {
  toast.error(`Could not read the Proxy history logging choice: ${error instanceof Error ? error.message : String(error)}`);
  return;
 }
 const stop = async () => {
  try {
   await api<ProxyOptionsState>("/api/proxy/options", json("PUT", { dont_log_out_of_scope: true }));
   onChanged();
   toast.success("Out-of-scope items will no longer be sent to Proxy history");
  } catch (error) {
   toast.error(`Could not stop logging out-of-scope items: ${error instanceof Error ? error.message : String(error)}`);
  }
 };
 if (next === "stop") {
  await stop();
 } else if (next === "ask") {
  toast("Stop sending out-of-scope items to Proxy history?", {
   description: "The target scope changed. Change this prompt under Settings → Proxy → Proxy history logging.",
   duration: 20_000,
   action: { label: "Stop logging", onClick: () => void stop() },
   cancel: { label: "Keep logging", onClick: () => undefined },
  });
 }
}
