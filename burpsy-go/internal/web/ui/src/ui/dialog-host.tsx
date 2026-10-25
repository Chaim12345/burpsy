/**
 * Renders lib/dialogs.ts's current request in the themed Modal (burpsy-react-ui-bea3).
 *
 * Mounted once, in the shell. Every confirm/prompt in the console comes through here, so the
 * theme, the UI scale and the focus-return rule are decided in one place rather than at twelve
 * call sites — which is the convention every other destructive action already followed
 * (pages/history.tsx's Delete items, pages/intercept.tsx's Drop all).
 *
 * # Focus return
 *
 * Radix returns focus to whatever was focused when the dialog opened. For a dialog opened from a
 * context menu that is a menu item which has already been unmounted, so focus would fall to
 * <body> and the operator's place in the table would be lost. The host therefore remembers the
 * last element focused OUTSIDE any menu or dialog — the table, the editor, the toolbar button —
 * and returns focus there, if it is still in the document.
 */
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { formatBytes, type ConfirmedCallPreview } from "../lib/api";
import {
  currentDialog,
  dismissDialog,
  initialValues,
  submitBlocker,
  subscribeDialogs,
  type PendingDialog,
} from "../lib/dialogs";
import { Button, Field, Input, Modal, Select, Textarea } from "./primitives";

function isTransient(element: Element): boolean {
  return Boolean(element.closest('[role="menu"], [role="dialog"], [role="alertdialog"], [data-radix-popper-content-wrapper]'));
}

export function DialogHost(): JSX.Element | null {
  const pending = useSyncExternalStore(subscribeDialogs, currentDialog, currentDialog);
  const lastOutside = useRef<HTMLElement | null>(null);
  const returnTo = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const onFocusIn = (event: FocusEvent) => {
      const target = event.target;
      if (target instanceof HTMLElement && target !== document.body && !isTransient(target)) lastOutside.current = target;
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, []);

  // Snapshot the return target when a dialog first appears, not when it closes: by close time the
  // dialog's own fields have been focused, and they are transient.
  useEffect(() => {
    if (pending) returnTo.current = lastOutside.current;
  }, [pending?.serial]);

  if (!pending) return null;
  return (
    <DialogBody
      key={pending.serial}
      pending={pending}
      onCloseAutoFocus={(event) => {
        const target = returnTo.current;
        if (target && target.isConnected) {
          event.preventDefault();
          target.focus();
        }
      }}
    />
  );
}

/**
 * The exact request a confirm dialog approves — the server's own preview of the call the gate's
 * token is bound to (burpsy-react-ui-e0yq). Shown as data, not prose: the verb and URL, the body as
 * the server will compare it, what was withheld from the preview, and the hash that covers it all.
 */
function CallPreview({ call }: { call: ConfirmedCallPreview }): JSX.Element {
  return (
    <section className="call-preview" aria-label="The request this confirms">
      <div className="call-preview-line">
        <strong>{call.method}</strong> <span className="call-preview-url">{call.url}</span>
      </div>
      {call.body_kind === "none" ? (
        <p className="call-preview-note">No body.</p>
      ) : call.body_kind === "binary" ? (
        <p className="call-preview-note">{formatBytes(call.body_bytes)} of binary body (not shown).</p>
      ) : (
        <>
          <pre className="call-preview-body">{call.body ?? ""}</pre>
          {call.body_truncated ? <p className="call-preview-note">The preview is truncated; the hash covers the whole {formatBytes(call.body_bytes)} body.</p> : null}
        </>
      )}
      {call.redacted && call.redacted.length > 0 ? (
        <p className="call-preview-note">Not shown here, but bound by the hash: {call.redacted.join(", ")}.</p>
      ) : null}
      <p className="call-preview-note">
        Body SHA-256 <span className="call-preview-hash">{call.body_sha256.slice(0, 16)}…</span> — the token is refused on any other request.
      </p>
    </section>
  );
}

function DialogBody({ pending, onCloseAutoFocus }: { pending: PendingDialog; onCloseAutoFocus: (event: Event) => void }): JSX.Element {
  const { request } = pending;
  const [values, setValues] = useState<Record<string, string>>(() => initialValues(request));
  const blocker = submitBlocker(request, values);
  const set = (id: string, value: string) => setValues((current) => ({ ...current, [id]: value }));

  const submit = (event?: FormEvent) => {
    event?.preventDefault();
    if (request.kind === "confirm") {
      pending.settle(true);
      return;
    }
    if (blocker) return;
    pending.settle(request.kind === "prompt" ? (values.value ?? "") : values);
  };

  return (
    <Modal
      open
      onOpenChange={(open) => {
        if (!open) dismissDialog(pending);
      }}
      title={request.title}
      description={request.description}
      onCloseAutoFocus={onCloseAutoFocus}
      onOpenAutoFocus={(event) => {
        // The field (or, for a confirm, the safe button) marked data-autofocus, focused from inside
        // Radix's own open-focus step so its focus trap records it (see Modal's prop doc).
        const container = event.currentTarget instanceof HTMLElement ? event.currentTarget : null;
        const target = container?.querySelector<HTMLElement>("[data-autofocus]");
        if (!target) return;
        event.preventDefault();
        target.focus();
        if (target instanceof HTMLInputElement) target.select();
      }}
    >
      <form className="dialog-form" onSubmit={submit} noValidate>
        {request.kind === "confirm" && request.preview ? <CallPreview call={request.preview} /> : null}
        {request.kind === "prompt" ? (
          <Field label={request.label}>
            {(id) =>
              request.multiline ? (
                <Textarea
                  id={id}
                  rows={4}
                  data-autofocus
                  value={values.value ?? ""}
                  placeholder={request.placeholder}
                  onChange={(event) => set("value", event.target.value)}
                />
              ) : (
                <Input
                  id={id}
                  data-autofocus
                  value={values.value ?? ""}
                  placeholder={request.placeholder}
                  onChange={(event) => set("value", event.target.value)}
                />
              )
            }
          </Field>
        ) : null}
        {request.kind === "form"
          ? request.fields.map((field, index) => (
              <Field key={field.id} label={field.required ? `${field.label} (required)` : field.label} hint={field.hint}>
                {(id) =>
                  field.kind === "select" ? (
                    <Select id={id} data-autofocus={index === 0 ? true : undefined} value={values[field.id] ?? ""} onChange={(event) => set(field.id, event.target.value)}>
                      {(field.options ?? []).map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </Select>
                  ) : field.kind === "textarea" ? (
                    <Textarea id={id} data-autofocus={index === 0 ? true : undefined} rows={4} value={values[field.id] ?? ""} onChange={(event) => set(field.id, event.target.value)} />
                  ) : (
                    <Input id={id} data-autofocus={index === 0 ? true : undefined} value={values[field.id] ?? ""} onChange={(event) => set(field.id, event.target.value)} />
                  )
                }
              </Field>
            ))
          : null}
        {blocker && request.kind !== "confirm" ? (
          <p className="dialog-form-blocker" role="status">
            {blocker}
          </p>
        ) : null}
        <div className="detail-actions">
          <Button
            type="submit"
            variant={request.kind === "confirm" && request.danger ? "danger" : "primary"}
            disabled={request.kind !== "confirm" && blocker !== null}
            // A destructive confirm starts on Cancel, so a stray Enter cannot delete anything.
            data-autofocus={request.kind === "confirm" && !request.danger ? true : undefined}
          >
            {request.confirmLabel}
          </Button>
          <Button variant="outline" data-autofocus={request.kind === "confirm" && request.danger ? true : undefined} onClick={() => dismissDialog(pending)}>
            {request.kind === "confirm" ? (request.cancelLabel ?? "Cancel") : "Cancel"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
