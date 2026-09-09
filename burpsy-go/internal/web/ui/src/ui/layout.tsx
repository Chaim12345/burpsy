import { AlertTriangle, RefreshCw } from "lucide-react";
import { Component, useState, type ComponentType, type ErrorInfo, type ReactNode } from "react";
import { Group, Panel, Separator, useDefaultLayout } from "react-resizable-panels";
import { cn } from "../lib/cn";
import { Button, IconButton, Spinner } from "./primitives";
import { Columns2, Rows2, Square } from "lucide-react";

/**
 * Compact page header. A security console is judged by how many data rows fit on
 * screen, so the title line stays on one row and shares it with the actions.
 */
export function PageHeader({
 title,
 eyebrow,
 description,
 actions,
}: {
 title: string;
 eyebrow?: string;
 description?: string;
 actions?: ReactNode;
}): JSX.Element {
 return (
  <div className="page-header">
   <div className="page-header-text">
    <h1>
     {title}
     {eyebrow ? <span className="page-header-eyebrow">{eyebrow}</span> : null}
    </h1>
    {description ? <p>{description}</p> : null}
   </div>
   {actions ? <div className="page-actions">{actions}</div> : null}
  </div>
 );
}

export function SectionHeading({
 title,
 detail,
 actions,
}: {
 title: string;
 detail?: string;
 actions?: ReactNode;
}): JSX.Element {
 return (
  <div className="section-heading">
   <div>
    <h2>{title}</h2>
    {detail ? <p>{detail}</p> : null}
   </div>
   {actions ? <div className="page-actions">{actions}</div> : null}
  </div>
 );
}

export function RefreshButton({
 onClick,
 loading = false,
 label = "Refresh",
}: {
 onClick: () => void;
 loading?: boolean;
 label?: string;
}): JSX.Element {
 return (
  <Button variant="outline" onClick={onClick} disabled={loading} aria-label={label}>
   <RefreshCw size={14} className={loading ? "spin" : undefined} />
   {label}
  </Button>
 );
}

/**
 * Resizable master/detail split. `storageId` persists the drag position so an
 * operator's chosen layout survives navigation and reloads.
 */
export function SplitPane({
 master,
 detail,
 orientation = "vertical",
 storageId,
 defaultMasterSize = "58",
 minMasterSize = "20",
 className,
}: {
 master: ReactNode;
 detail: ReactNode;
 /** "vertical" stacks master above detail; "horizontal" puts them side by side. */
 orientation?: "vertical" | "horizontal";
 storageId: string;
 /** Unitless strings are percentages; numbers would be pixels. */
 defaultMasterSize?: string;
 minMasterSize?: string;
 className?: string;
}): JSX.Element {
 const { defaultLayout, onLayoutChanged } = useDefaultLayout({
  id: `burpsy.split.${storageId}`,
  panelIds: ["master", "detail"],
  storage: localStorage,
 });

 return (
  <Group
   className={cn("split-pane", `split-${orientation}`, className)}
   orientation={orientation}
   defaultLayout={defaultLayout}
   onLayoutChanged={onLayoutChanged}
  >
   <Panel id="master" defaultSize={defaultMasterSize} minSize={minMasterSize} className="split-panel">
    {master}
   </Panel>
   <Separator className={orientation === "vertical" ? "resize-handle resize-handle-y" : "resize-handle resize-handle-x"}>
    <span className="resize-grip" />
   </Separator>
   <Panel id="detail" minSize="15" className="split-panel">
    {detail}
   </Panel>
  </Group>
 );
}

export function LoadingPanel({ label = "Loading" }: { label?: string }): JSX.Element {
 return (
  <div className="loading-panel">
   <Spinner />
   <span>{label}</span>
  </div>
 );
}

/**
 * Burp's message-editor layout switcher (tools/message-editor/index.html): horizontal
 * (side by side), vertical (stacked) and combined (one pane, request/response tabs).
 * (burpsy-react-ui-446.)
 *
 * The choice persists per surface under `burpsy.layout.${storageId}` — the same contract
 * SplitPane's divider position already follows, so an operator's arrangement survives
 * navigation and reloads. Defaults to the surface's previous hardcoded orientation so the
 * switcher never moves a page on first render.
 */
export type MessageLayout = "horizontal" | "vertical" | "combined";

const LAYOUT_ICONS: Record<MessageLayout, ComponentType<{ size?: number }>> = {
 horizontal: Columns2,
 vertical: Rows2,
 combined: Square,
};

export function useMessageLayout(storageId: string, fallback: Exclude<MessageLayout, "combined"> = "vertical"): [MessageLayout, (next: MessageLayout) => void] {
 const key = `burpsy.layout.${storageId}`;
 const [layout, setLayout] = useState<MessageLayout>(() => {
  const stored = localStorage.getItem(key);
  if (stored === "horizontal" || stored === "vertical" || stored === "combined") return stored;
  return fallback;
 });
 const apply = (next: MessageLayout) => {
  setLayout(next);
  localStorage.setItem(key, next);
 };
 return [layout, apply];
}

/** The three-icon control itself, rendered in the pane's header row. */
export function MessageLayoutSwitch({ value, onChange }: { value: MessageLayout; onChange: (next: MessageLayout) => void }): JSX.Element {
 const options: { id: MessageLayout; label: string }[] = [
  { id: "horizontal", label: "Horizontal layout" },
  { id: "vertical", label: "Vertical layout" },
  { id: "combined", label: "Combined view" },
 ];
 return (
  <span className="layout-switch" role="radiogroup" aria-label="Message layout">
   {options.map((option) => {
    const Icon = LAYOUT_ICONS[option.id];
    return (
     <IconButton
      key={option.id}
      label={option.label}
      size="small"
      aria-pressed={value === option.id}
      onClick={() => onChange(option.id)}
     >
      <Icon size={13} />
     </IconButton>
    );
   })}
  </span>
 );
}

interface BoundaryState {
 error: Error | null;
}

/**
 * Keeps one broken page from blanking the whole console. Remounts the subtree on
 * retry so a transient render failure is recoverable without a reload.
 */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, BoundaryState> {
 override state: BoundaryState = { error: null };

 static getDerivedStateFromError(error: Error): BoundaryState {
  return { error };
 }

 override componentDidCatch(error: Error, info: ErrorInfo): void {
  console.error("page crashed", error, info.componentStack);
 }

 override componentDidUpdate(previous: { children: ReactNode; resetKey?: string }): void {
  if (previous.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
 }

 override render(): ReactNode {
  const { error } = this.state;
  if (!error) return this.props.children;
  return (
   <div className="crash-panel" role="alert">
    <AlertTriangle size={22} />
    <div>
     <strong>This view failed to render</strong>
     <p>{error.message}</p>
    </div>
    <Button variant="outline" onClick={() => this.setState({ error: null })}>
     Try again
    </Button>
   </div>
  );
 }
}
