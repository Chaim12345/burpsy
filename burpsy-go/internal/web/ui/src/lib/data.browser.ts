/**
 * Burp's "Open browser" (burpsy-react-ui-bufa): a Chromium on its own profile, routed through a
 * burpsy Proxy listener and pinned to burpsy's CA — so the traffic the operator drives is captured
 * without touching their everyday browser.
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, ApiError, json } from "./api";

/** POST /api/browser/launch. Mirrors internal/browser's launch result. */
export interface BrowserLaunch {
 pid?: number;
 profile_dir: string;
 /** The Proxy listener the browser was pointed at. */
 proxy: string;
 pinned_ca?: string;
 /** True when the URL opened as a new tab in the burpsy browser that was already running. */
 handed_off?: boolean;
 binary: string;
}

/** GET/PUT /api/browser/settings — Burp's keys, saved with the project, plus three facts. */
export interface BrowserSettings {
 /** Empty means the per-project default; `profile_dir` is what a launch actually uses. */
 browser_data_directory: string;
 allow_saving_browser_settings: boolean;
 allow_running_without_sandbox: boolean;
 disable_gpu: boolean;
 profile_dir: string;
 running: boolean;
 /** The listener a launch would use; empty when none is usable. */
 proxy: string;
}

export type BrowserSettingsEdit = Partial<
 Pick<BrowserSettings, "browser_data_directory" | "allow_saving_browser_settings" | "allow_running_without_sandbox" | "disable_gpu">
>;

export const browserKeys = { settings: ["browser", "settings"] as const };

/** Launch the burpsy browser, optionally on a URL (http/https only — the server refuses others). */
export function launchBrowser(url?: string): Promise<BrowserLaunch> {
 return api<BrowserLaunch>("/api/browser/launch", json("POST", url ? { url } : {}));
}

/** What a successful launch is told as: where the traffic goes, and which profile it uses. */
export function describeLaunch(result: BrowserLaunch, url?: string): string {
 if (result.handed_off) return `Opened ${url ?? "a new tab"} in the running burpsy browser (proxy ${result.proxy})`;
 return `Browser opened through proxy ${result.proxy}, profile ${result.profile_dir}`;
}

/**
 * "Open URL in browser", proxied (bufa): launch the burpsy browser on the URL, so what the operator
 * does there is captured.
 *
 * When the launch is refused (503 — no listener, no Chromium, root with the sandbox on, no display)
 * the refusal is shown verbatim, because it is written for the operator, and the old behaviour is
 * offered as the toast's action: open the URL in THIS browser, unproxied. It is an action rather than
 * an automatic window.open because a popup opened after an awaited request is no longer inside the
 * click's user gesture, and browsers block it — the fallback would silently not happen.
 */
export async function openUrlInBrowser(url: string): Promise<void> {
 try {
  const result = await launchBrowser(url);
  toast.success(describeLaunch(result, url));
 } catch (failure) {
  if (failure instanceof ApiError && failure.status === 503) {
   toast.warning(`The burpsy browser did not open: ${failure.message}`, {
    description: "You can open the URL in this browser instead — it is captured only if this browser uses burpsy's proxy.",
    action: { label: "Open unproxied", onClick: () => void window.open(url, "_blank", "noopener") },
    duration: 15_000,
   });
   return;
  }
  toast.error(`Could not open the browser: ${failure instanceof Error ? failure.message : String(failure)}`);
 }
}

export function useLaunchBrowser() {
 const client = useQueryClient();
 return useMutation<BrowserLaunch, Error, string | undefined>({
  mutationFn: (url) => launchBrowser(url),
  onSuccess: () => void client.invalidateQueries({ queryKey: browserKeys.settings }),
 });
}

export const useBrowserSettings = (): UseQueryResult<BrowserSettings> =>
 useQuery({
  queryKey: browserKeys.settings,
  queryFn: ({ signal }) => api<BrowserSettings>("/api/browser/settings", { signal }),
 });

/** PUT a partial edit; the confirmed full view goes into the cache. */
export function useSaveBrowserSettings() {
 const client = useQueryClient();
 return useMutation<BrowserSettings, Error, BrowserSettingsEdit>({
  mutationFn: (edit) => api<BrowserSettings>("/api/browser/settings", json("PUT", edit)),
  onSuccess: (confirmed) => client.setQueryData(browserKeys.settings, confirmed),
 });
}

/** Burp's "Clear all browser data". riskDestructive: api() mints on the operator's confirmed click. */
export function useClearBrowserData() {
 const client = useQueryClient();
 return useMutation<{ cleared: string }, Error, void>({
  mutationFn: () => api<{ cleared: string }>("/api/browser/clear", { method: "POST" }),
  onSuccess: () => void client.invalidateQueries({ queryKey: browserKeys.settings }),
 });
}
