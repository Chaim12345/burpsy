import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useState } from "react";
import { copyToClipboard } from "../lib/api";
import { IconButton } from "./primitives";

type Json = unknown;

function isRecord(value: Json): value is Record<string, Json> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function summarise(value: Json): string {
  if (Array.isArray(value)) return `${value.length} ${value.length === 1 ? "item" : "items"}`;
  if (isRecord(value)) {
    const keys = Object.keys(value);
    return `${keys.length} ${keys.length === 1 ? "field" : "fields"}`;
  }
  return "";
}

function Leaf({ value }: { value: Json }): JSX.Element {
  if (value === null) return <span className="json-null">null</span>;
  if (typeof value === "boolean") return <span className="json-bool">{String(value)}</span>;
  if (typeof value === "number") return <span className="json-number">{value.toLocaleString()}</span>;
  if (typeof value === "string") {
    if (!value) return <span className="json-empty">(empty)</span>;
    return <span className="json-string">{value}</span>;
  }
  return <span className="json-null">{String(value)}</span>;
}

function Node({ label, value, depth, defaultOpen }: { label: string; value: Json; depth: number; defaultOpen: number }): JSX.Element {
  const branch = Array.isArray(value) || isRecord(value);
  const [open, setOpen] = useState(depth < defaultOpen);

  if (!branch) {
    return (
      <div className="json-row" style={{ paddingLeft: `${depth * 14}px` }}>
        <span className="json-key">{label}</span>
        <Leaf value={value} />
      </div>
    );
  }

  const entries: [string, Json][] = Array.isArray(value)
    ? value.map((item, index) => [`${index}`, item])
    : Object.entries(value);

  return (
    <div className="json-branch">
      <button
        type="button"
        className="json-row json-toggle"
        style={{ paddingLeft: `${depth * 14}px` }}
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span className="json-key">{label}</span>
        <span className="json-summary">{summarise(value)}</span>
      </button>
      {open
        ? entries.map(([key, child]) => <Node key={key} label={key} value={child} depth={depth + 1} defaultOpen={defaultOpen} />)
        : null}
    </div>
  );
}

/**
 * Collapsible view for server payloads that have no bespoke presentation yet.
 * Preferred over dumping JSON.stringify into a <pre>, which is unreadable past a
 * few dozen lines and hides structure.
 */
export function JsonView({ value, defaultOpen = 2, label = "response" }: { value: Json; defaultOpen?: number; label?: string }): JSX.Element {
  return (
    <div className="json-view">
      <div className="json-view-head">
        <span className="editor-label-inline">{label}</span>
        <IconButton label="Copy JSON" size="small" onClick={() => void copyToClipboard(JSON.stringify(value, null, 2))}>
          <Copy size={13} />
        </IconButton>
      </div>
      <div className="json-view-body">
        {Array.isArray(value) || isRecord(value) ? (
          Object.entries(Array.isArray(value) ? Object.fromEntries(value.map((item, index) => [index, item])) : value).map(
            ([key, child]) => <Node key={key} label={key} value={child} depth={0} defaultOpen={defaultOpen} />,
          )
        ) : (
          <div className="json-row">
            <Leaf value={value} />
          </div>
        )}
      </div>
    </div>
  );
}

/** Compact label/value grid for known-shape detail panes. */
export function DetailList({ rows }: { rows: { label: string; value: React.ReactNode }[] }): JSX.Element {
  return (
    <dl className="detail-list">
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}
