import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";
import { api, json, query } from "./api";
import { keys, useResource } from "./data";
import type { ConsoleView, ExtensionApis, ExtensionList, ExtensionView, InvokeResult } from "./types.extensions";

/* --- reads --------------------------------------------------------------- */

export const useExtensions = (): UseQueryResult<ExtensionList> =>
  useResource<ExtensionList>(keys.extensions, "/api/extensions");

/**
 * The protocol contract, served from the same table the Go dispatcher is checked against. Fetched
 * rather than written into this file: a second copy of a wire protocol drifts and nothing notices.
 */
export const useExtensionApis = (): UseQueryResult<ExtensionApis> =>
  useResource<ExtensionApis>(keys.extensionApis, "/api/extensions/apis");

/**
 * One plugin's two consoles, in one read.
 *
 * Both streams together rather than a hook each: the case worth reading a console for is a plugin that
 * logged something and then died, and that is exactly where two reads taken a moment apart disagree.
 *
 * Not live. /api/events carries changes to the traffic stores and a plugin's log line is not one of
 * them, so there is nothing to subscribe to — the page offers a Refresh instead of a stream that would
 * look live and not be.
 */
export function useExtensionConsole(name: string | null, limit = 500): UseQueryResult<ConsoleView> {
  return useResource<ConsoleView>(
    keys.extensionConsole(name ?? "", limit),
    `/api/extensions/console${query({ name: name ?? "", limit })}`,
    name !== null,
  );
}

/* --- writes -------------------------------------------------------------- */

function useInvalidate(): (prefixes: readonly (readonly unknown[])[]) => void {
  const client = useQueryClient();
  return (prefixes) => {
    for (const prefix of prefixes) void client.invalidateQueries({ queryKey: prefix });
  };
}

/**
 * Start one allowlisted plugin.
 *
 * The mutation resolves with the plugin's row, and a failure carries the server's reason — which for
 * this route is the interesting part: a missing executable, a handshake that timed out and a protocol
 * mismatch are three different problems with three different fixes.
 */
export function useLoadExtension() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (name: string) =>
      api<{ extension: ExtensionView }>("/api/extensions/load", json("POST", { name })),
    // One prefix covers both: keys.extensionConsole is keyed under ["extensions"], so the row and
    // whatever the load wrote to its console refetch together. onSettled rather than onSuccess — a
    // failed load is the case where the console is worth re-reading.
    onSettled: () => invalidate([keys.extensions]),
  });
}

export function useUnloadExtension() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (name: string) =>
      api<{ extension: ExtensionView }>("/api/extensions/unload", json("POST", { name })),
    onSettled: () => invalidate([keys.extensions]),
  });
}

/**
 * Run one registration a loaded plugin declared.
 *
 * `exchange` and `message` are optional and are sent as given: exchange 0 and message 0 are real ids
 * in this engine, so a caller passing 0 means the first one and not "none".
 */
export function useInvokeExtension() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (body: {
      name: string;
      registration: string;
      exchange?: number;
      message?: number;
      raw?: string;
      selection?: string;
    }) => api<{ result: InvokeResult }>("/api/extensions/invoke", json("POST", body)),
    // The invocation counters live on the row, and anything the plugin logged is on its console;
    // both sit under the ["extensions"] prefix.
    onSettled: () => invalidate([keys.extensions]),
  });
}
