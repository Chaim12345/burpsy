import * as Dialog from "@radix-ui/react-dialog";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { X } from "lucide-react";
import { useId } from "react";
import type {
  AnchorHTMLAttributes,
  ButtonHTMLAttributes,
  CSSProperties,
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { cn } from "../lib/cn";

export type Tone = "neutral" | "good" | "warn" | "bad" | "info" | "accent";

/* --- accessible names, enforced at compile time ----------------------------
 * A UX audit reported forty-odd form controls in this console with no accessible
 * name; twenty-nine of those were real, and a screen reader read each of them as
 * "edit text, blank". Fixing them one at a time would have fixed today's
 * twenty-nine and none of tomorrow's, because nothing in the code stopped the
 * next control from shipping unnamed. So the rule lives in the types instead:
 * `Input`, `Textarea` and `Select` will not compile unless they are given a name,
 * and there are only three ways to give one.
 *
 * This binds the primitives, not the DOM: a bare <input> in a page still compiles
 * unnamed. That is why pages use these three for every text control, and why the
 * remaining raw ones (the command palette's search box) carry a name by hand.
 */

/**
 * Proof, carried by the type system, that an id belongs to a rendered `<label>`.
 *
 * `id?: string` cannot express this — a control with `id="foo"` and no label
 * anywhere is exactly as anonymous as one with no id at all, and typechecks the
 * same. The brand below is unforgeable outside this module: `Field` is the only
 * thing that mints one, and `Field` always renders the label that points at it.
 * So `id: LabelledId` on a control really does mean "a label names this".
 */
declare const labelledByField: unique symbol;
export type LabelledId = string & { readonly [labelledByField]: true };

/**
 * The three legitimate ways to name a control, as a union so that supplying
 * none of them is a type error rather than an audit finding:
 *
 *  - `id` from a `Field` render prop — the default, and the only one that also
 *    gives a sighted operator a visible label;
 *  - `aria-label` — for a dense toolbar filter, where a visible label would cost
 *    the row density that is the whole point of the layout. Pair it with `title`
 *    so the name is discoverable by hover as well as by screen reader;
 *  - `aria-labelledby` — when existing visible text already names the control.
 *
 * The `?: never` slots stop the two mistakes that look correct: naming a control
 * twice (an `aria-label` inside a `Field` silently overrides the visible label,
 * so the two can drift apart), and pointing `aria-labelledby` at nothing while
 * an `aria-label` quietly does the real work.
 */
type Named =
  | { id: LabelledId; "aria-label"?: never; "aria-labelledby"?: never }
  | { id?: string; "aria-label": string; "aria-labelledby"?: never }
  | { id?: string; "aria-label"?: never; "aria-labelledby": string };

type NamedProps<T> = Omit<T, "id" | "aria-label" | "aria-labelledby"> & Named;

export function Button({
  className,
  variant = "primary",
  size = "medium",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "outline" | "danger" | "quiet" | "ghost";
  size?: "medium" | "small";
}): JSX.Element {
  return <button type="button" className={cn("button", `button-${variant}`, size === "small" && "button-sm", className)} {...props} />;
}

export function LinkButton({
  className,
  variant = "outline",
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & { variant?: "primary" | "outline" | "quiet" }): JSX.Element {
  return <a className={cn("button", `button-${variant}`, className)} {...props} />;
}

export function IconButton({
  label,
  children,
  className,
  size = "medium",
  ...props
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> & {
  label: string;
  children: ReactNode;
  size?: "medium" | "small";
}): JSX.Element {
  return (
    <Tooltip content={label}>
      <button type="button" aria-label={label} className={cn("icon-button", size === "small" && "icon-button-sm", className)} {...props}>
        {children}
      </button>
    </Tooltip>
  );
}

export function Input({ className, ...props }: NamedProps<InputHTMLAttributes<HTMLInputElement>>): JSX.Element {
  return <input className={cn("input", className)} {...props} />;
}

export function Textarea({ className, ...props }: NamedProps<TextareaHTMLAttributes<HTMLTextAreaElement>>): JSX.Element {
  return <textarea className={cn("textarea", className)} spellCheck={false} {...props} />;
}

export function Select({ className, ...props }: NamedProps<SelectHTMLAttributes<HTMLSelectElement>>): JSX.Element {
  return <select className={cn("input", "select", className)} {...props} />;
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn("card", className)} {...props} />;
}

export function Badge({
  className,
  tone = "neutral",
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }): JSX.Element {
  return <span className={cn("badge", `badge-${tone}`, className)} {...props} />;
}

/**
 * A visible label and the control it names.
 *
 * The render-prop form is the one to reach for: `Field` generates the id, renders
 * the `<label htmlFor>` for it, and hands it to the control, so the label and the
 * control cannot come apart and the control satisfies `Named` without repeating
 * the label text as an `aria-label`.
 *
 *   <Field label="Host pattern">{(id) => <Input id={id} value={…} />}</Field>
 *
 * Plain children still work for a control that names itself — a `Switch`, a
 * `Checkbox`, a group of buttons — and `htmlFor` for a Radix widget whose id is
 * assigned by the caller.
 */
export function Field({
  label,
  hint,
  children,
  className,
  style,
  htmlFor,
}: {
  label: string;
  hint?: string;
  children: ReactNode | ((id: LabelledId) => ReactNode);
  className?: string;
  style?: CSSProperties;
  htmlFor?: string;
}): JSX.Element {
  // Called unconditionally: hooks cannot be skipped for the plain-children case.
  // The cast is the single point where a LabelledId is minted, and it is sound
  // here precisely because the branch below renders the matching <label>.
  const generated = useId() as LabelledId;

  if (typeof children === "function") {
    return (
      <div className={cn("field", className)} style={style}>
        <label htmlFor={generated}>
          <span>{label}</span>
        </label>
        {children(generated)}
        {hint ? <small className="field-hint">{hint}</small> : null}
      </div>
    );
  }

  // A wrapping <label> associates implicitly; an explicit htmlFor is needed when the
  // control is a Radix widget that renders its own focusable element.
  return htmlFor ? (
    <div className={cn("field", className)} style={style}>
      <label htmlFor={htmlFor}>
        <span>{label}</span>
      </label>
      {children}
      {hint ? <small className="field-hint">{hint}</small> : null}
    </div>
  ) : (
    <label className={cn("field", className)} style={style}>
      <span>{label}</span>
      {children}
      {hint ? <small className="field-hint">{hint}</small> : null}
    </label>
  );
}

export function Toolbar({ className, ...props }: HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn("toolbar", className)} {...props} />;
}

export function Empty({ title, detail, action }: { title: string; detail: string; action?: ReactNode }): JSX.Element {
  return (
    <div className="empty">
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </div>
  );
}

export function ErrorNotice({ error, onRetry }: { error: unknown; onRetry?: () => void }): JSX.Element {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="error-notice" role="alert">
      <div>
        <strong>Request failed</strong>
        <span>{message}</span>
      </div>
      {onRetry ? (
        <Button variant="outline" size="small" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function Metric({
  label,
  value,
  detail,
  accent,
  tone,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  accent?: boolean;
  tone?: Tone;
}): JSX.Element {
  return (
    <div className={cn("card", "metric", accent && "metric-accent", tone && `metric-${tone}`)}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }): JSX.Element {
  return <kbd className="kbd">{children}</kbd>;
}

export function Spinner({ label = "Loading" }: { label?: string }): JSX.Element {
  return <span className="spinner" role="status" aria-label={label} />;
}

export function Tooltip({ content, children }: { content: ReactNode; children: ReactNode }): JSX.Element {
  if (!content) return <>{children}</>;
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content className="tooltip" sideOffset={6} collisionPadding={8}>
          {content}
          <TooltipPrimitive.Arrow className="tooltip-arrow" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export function Switch({
  checked,
  onCheckedChange,
  id,
  label,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  id?: string;
  label: string;
}): JSX.Element {
  return (
    <SwitchPrimitive.Root id={id} aria-label={label} className="switch" checked={checked} onCheckedChange={onCheckedChange}>
      <SwitchPrimitive.Thumb className="switch-thumb" />
    </SwitchPrimitive.Root>
  );
}

export function Checkbox({
  checked,
  onCheckedChange,
  label,
  className,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <label className={cn("check-row", className)}>
      <input type="checkbox" checked={checked} onChange={(event) => onCheckedChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export const Tabs = TabsPrimitive.Root;

export function TabsList({ className, ...props }: TabsPrimitive.TabsListProps): JSX.Element {
  return <TabsPrimitive.List className={cn("tabs-list", className)} {...props} />;
}

export function TabsTrigger({ className, ...props }: TabsPrimitive.TabsTriggerProps): JSX.Element {
  return <TabsPrimitive.Trigger className={cn("tabs-trigger", className)} {...props} />;
}

export function TabsContent({ className, ...props }: TabsPrimitive.TabsContentProps): JSX.Element {
  return <TabsPrimitive.Content className={cn("tabs-content", className)} {...props} />;
}

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  wide,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  wide?: boolean;
}): JSX.Element {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className={cn("dialog-content", wide && "dialog-wide")}>
          <div className="dialog-head">
            <div>
              <Dialog.Title className="dialog-title">{title}</Dialog.Title>
              {description ? <Dialog.Description className="dialog-description">{description}</Dialog.Description> : null}
            </div>
            <Dialog.Close asChild>
              <IconButton label="Close">
                <X size={17} />
              </IconButton>
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
