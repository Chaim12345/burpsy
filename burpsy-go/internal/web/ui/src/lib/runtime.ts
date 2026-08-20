/**
 * Desktop vs Web runtime detection for burpsy.
 *
 * When running inside a Wails desktop shell, `window.runtime` or `window.go` is available.
 * Otherwise, standard HTTP REST endpoints are used.
 */

export type RuntimeMode = "desktop" | "web";

export function getRuntimeMode(): RuntimeMode {
  return typeof window !== "undefined" && (window as any).runtime ? "desktop" : "web";
}

export function isDesktop(): boolean {
  return getRuntimeMode() === "desktop";
}

/**
 * Native file save dialog wrapper. Falls back to browser download in web mode.
 */
export async function saveFileDialog(filename: string, defaultPath?: string): Promise<string | null> {
  if (isDesktop() && (window as any).go?.main?.App?.SaveFileDialog) {
    try {
      return await (window as any).go.main.App.SaveFileDialog(filename, defaultPath ?? "");
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Native file open dialog wrapper. Falls back to web input in web mode.
 */
export async function openFileDialog(title: string, filter?: string): Promise<string | null> {
  if (isDesktop() && (window as any).go?.main?.App?.OpenFileDialog) {
    try {
      return await (window as any).go.main.App.OpenFileDialog(title, filter ?? "");
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Native desktop notification wrapper. Falls back to web Notification API / sonner toast.
 */
export function notifyDesktop(title: string, body: string): void {
  if (isDesktop() && (window as any).go?.main?.App?.Notify) {
    (window as any).go.main.App.Notify(title, body);
  } else if (typeof Notification !== "undefined" && Notification.permission === "granted") {
    new Notification(title, { body });
  }
}
