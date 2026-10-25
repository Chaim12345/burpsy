/**
 * The console's one confirm/prompt/form dialog channel (burpsy-react-ui-bea3).
 *
 * # Why a module store and not component state
 *
 * Twelve call sites used `window.confirm` / `window.prompt`, and the reason written beside most of
 * them was true: they are plain functions — a context-menu factory rebuilt on every right-click, a
 * menubar entry, a palette command — and none of them owns a React subtree a modal could live in.
 * Giving each of those six pages its own open/draft/target state for a one-line string was the
 * cost that justified the native dialog.
 *
 * The native dialog has its own cost, and it is the one Burp never pays (its option panes are its
 * own Look-and-Feel, /root/burp-re/out/theme/burp/theme/BurpOptionPaneUI.java): it ignores the theme
 * and the UI scale, it blocks the whole tab's event loop while open, and it returns focus wherever
 * the browser likes. So the state moves here, once, the same shape lib/keymap.ts uses for the
 * hotkey map: a module-level value plus a listener set. A caller awaits a promise; one host
 * component mounted in the shell (ui/dialog-host.tsx) renders whatever is current.
 *
 * Kept free of React and the DOM so the queueing and settle rules are unit-testable.
 */
import type { ConfirmedCallPreview } from "./api";

export interface ConfirmRequest {
  kind: "confirm";
  title: string;
  description?: string;
  /** The verb on the confirming button. Never "OK": the button says what it is about to do. */
  confirmLabel: string;
  cancelLabel?: string;
  /** Renders the confirming button in the danger style. For irreversible actions. */
  danger?: boolean;
  /**
   * The server's preview of the exact request the confirming button sends (burpsy-react-ui-e0yq).
   * Set by approveCall: the operator approves this request, and the token the gate checks is bound
   * to it — not to the route name the title happens to describe.
   */
  preview?: ConfirmedCallPreview;
}

export interface PromptRequest {
  kind: "prompt";
  title: string;
  description?: string;
  /** The field's visible label. */
  label: string;
  initial?: string;
  confirmLabel: string;
  /** A textarea instead of a single-line input. */
  multiline?: boolean;
  /** When false (the default) an empty or whitespace-only value cannot be submitted. */
  allowEmpty?: boolean;
  placeholder?: string;
}

export interface FormField {
  id: string;
  label: string;
  kind: "text" | "textarea" | "select";
  initial?: string;
  required?: boolean;
  /** For `select`: value/label pairs, in display order. */
  options?: { value: string; label: string }[];
  hint?: string;
}

export interface FormRequest {
  kind: "form";
  title: string;
  description?: string;
  fields: FormField[];
  confirmLabel: string;
}

export type DialogRequest = ConfirmRequest | PromptRequest | FormRequest;

type Answer<R extends DialogRequest> = R extends ConfirmRequest
  ? boolean
  : R extends PromptRequest
    ? string | null
    : Record<string, string> | null;

/** A request plus the settle function the host calls with the operator's answer. */
export interface PendingDialog {
  /** Monotonic, so the host can key its form state on it and a second dialog never inherits a draft. */
  serial: number;
  request: DialogRequest;
  settle: (answer: boolean | string | Record<string, string> | null) => void;
}

let serial = 0;
const queue: PendingDialog[] = [];
const listeners = new Set<() => void>();

function announce(): void {
  for (const listener of listeners) listener();
}

/** What a dismissal (Escape, overlay click, the close button) means for each kind. */
function dismissed(request: DialogRequest): boolean | null {
  return request.kind === "confirm" ? false : null;
}

/**
 * Publication waits for any open menu to finish unmounting. Most callers of this module are inside
 * a Radix menu's `onSelect`, and a Dialog that mounts while that menu is still in the document
 * loses focus to it: the menu's focus scope unmounts AFTER the dialog's has mounted and hands
 * focus back to the menu's trigger — the table — so the dialog shows while keystrokes (Enter
 * included, which activates the row) go to the table behind it. Observed in the live drive with a
 * plain setTimeout(0); a menu's exit takes longer than one task. The wait is capped so a menu that
 * never closes cannot swallow a dialog. The injectable scheduler exists for the tests.
 */
let schedule: (fn: () => void) => void = (fn) => {
  const started = Date.now();
  // One poll after the menu is gone, not zero: the menu's focus scope hands focus back to its
  // trigger from a setTimeout(0) queued as it unmounts, and that has to run before the dialog
  // mounts or it lands after the dialog has taken focus.
  let clearTicks = 0;
  const tick = () => {
    const menuOpen = typeof document !== "undefined" && document.querySelector('[role="menu"]') !== null;
    clearTicks = menuOpen ? 0 : clearTicks + 1;
    if (clearTicks < 2 && Date.now() - started < 1500) {
      setTimeout(tick, 16);
      return;
    }
    fn();
  };
  setTimeout(tick, 0);
};

/** Test seam: run publication synchronously. */
export function setDialogScheduler(next: (fn: () => void) => void): void {
  schedule = next;
}

function open<R extends DialogRequest>(request: R): Promise<Answer<R>> {
  return new Promise((resolve) => {
    const pending: PendingDialog = {
      serial: ++serial,
      request,
      settle: (answer) => {
        const at = queue.indexOf(pending);
        if (at < 0) return; // already settled: a double click on Confirm must not resolve twice
        queue.splice(at, 1);
        resolve(answer as Answer<R>);
        announce();
      },
    };
    schedule(() => {
      queue.push(pending);
      announce();
    });
  });
}

/** Ask a yes/no question. Resolves false on cancel or dismissal. */
export function confirmDialog(request: Omit<ConfirmRequest, "kind">): Promise<boolean> {
  return open({ kind: "confirm", ...request });
}

/**
 * An approver for gatedFetch's `approve` option: shows `request` with the server's preview of the
 * exact call, and resolves whether the operator confirmed it. The dialog is opened only once the
 * server has bound a token to that call, so what the operator reads is what the gate will admit.
 */
export function approveCall(request: Omit<ConfirmRequest, "kind" | "preview">): (call: ConfirmedCallPreview) => Promise<boolean> {
  return (call) => confirmDialog({ ...request, preview: call });
}

/** Ask for one string. Resolves null on cancel or dismissal — never "" for a cancel. */
export function promptDialog(request: Omit<PromptRequest, "kind">): Promise<string | null> {
  return open({ kind: "prompt", ...request });
}

/** Ask for several named values at once. Resolves null on cancel or dismissal. */
export function formDialog(request: Omit<FormRequest, "kind">): Promise<Record<string, string> | null> {
  return open({ kind: "form", ...request });
}

/** The dialog the host should show now: the oldest unanswered one. Later ones wait their turn. */
export function currentDialog(): PendingDialog | undefined {
  return queue[0];
}

/** Settle the current dialog as dismissed (Escape, overlay, close button). */
export function dismissDialog(pending: PendingDialog): void {
  pending.settle(dismissed(pending.request));
}

export function subscribeDialogs(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Whether a prompt/form answer may be submitted, and if not, why. The host disables the confirm
 * button on a non-null result and shows the reason; the same rule runs here so it is testable.
 */
export function submitBlocker(request: DialogRequest, values: Record<string, string>): string | null {
  if (request.kind === "prompt") {
    if (!request.allowEmpty && (values.value ?? "").trim() === "") return `${request.label} must not be blank`;
    return null;
  }
  if (request.kind === "form") {
    for (const field of request.fields) {
      if (field.required && (values[field.id] ?? "").trim() === "") return `${field.label} is required`;
      if (field.kind === "select" && field.options && !field.options.some((option) => option.value === values[field.id])) {
        return `${field.label} must be one of the listed values`;
      }
    }
  }
  return null;
}

/** The starting values a request's fields render with. */
export function initialValues(request: DialogRequest): Record<string, string> {
  if (request.kind === "prompt") return { value: request.initial ?? "" };
  if (request.kind === "form") {
    const out: Record<string, string> = {};
    for (const field of request.fields) {
      out[field.id] = field.initial ?? (field.kind === "select" ? (field.options?.[0]?.value ?? "") : "");
    }
    return out;
  }
  return {};
}
