import { ChevronDown, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { copyToClipboard, formatBytes } from "../lib/api";
import {
  bodyParamsOf,
  cookiesOf,
  headerValue,
  isResponse,
  parseMessage,
  parseRequestLine,
  parseStatusLine,
  queryOf,
} from "../lib/message";
import { Badge } from "./primitives";

interface Section {
  id: string;
  title: string;
  rows: [string, string][];
}

function SectionBlock({ section, open, onToggle }: { section: Section; open: boolean; onToggle: () => void }): JSX.Element {
  return (
    <div className="inspector-section">
      <button type="button" className="inspector-head" aria-expanded={open} onClick={onToggle}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span>{section.title}</span>
        <Badge>{section.rows.length}</Badge>
      </button>
      {open ? (
        section.rows.length ? (
          <dl className="inspector-rows">
            {section.rows.map(([name, value], index) => (
              <div key={`${name}-${index}`}>
                <dt title={name}>{name}</dt>
                <dd title={value}>
                  {/* Click-to-copy: reading a value out of a dense pane by hand is
                      exactly the friction the Inspector exists to remove. */}
                  <button
                    type="button"
                    className="inspector-value"
                    onClick={() => {
                      void copyToClipboard(value);
                      toast.success(`Copied ${name}`);
                    }}
                    title="Copy value"
                  >
                    {value === "" ? <span className="cell-dim">(empty)</span> : value}
                  </button>
                </dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="inspector-empty">none</p>
        )
      ) : null}
    </div>
  );
}

/**
 * Burp's Inspector: the same message broken into its addressable parts, so an
 * operator can read a cookie or a query parameter without counting bytes in the
 * raw view. Read-only — this reports what the message contains rather than
 * offering a second, competing way to edit it.
 */
export function Inspector({ raw, label = "Inspector" }: { raw: string; label?: string }): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);

  const sections = useMemo<Section[]>(() => {
    const request = response ? null : parseRequestLine(parsed.startLine);
    const status = response ? parseStatusLine(parsed.startLine) : null;
    const contentType = headerValue(parsed.headers, "content-type");

    const overview: [string, string][] = response
      ? [
          ["Status", status ? `${status.status} ${status.reason}`.trim() : parsed.startLine],
          ["Version", status?.version ?? "—"],
          ["Content type", contentType ?? "—"],
          ["Body", formatBytes(new TextEncoder().encode(parsed.body).length)],
        ]
      : [
          ["Method", request?.method ?? "—"],
          ["Target", request?.target ?? parsed.startLine],
          ["Version", request?.version ?? "—"],
          ["Host", headerValue(parsed.headers, "host") ?? "—"],
          ["Body", formatBytes(new TextEncoder().encode(parsed.body).length)],
        ];

    const list: Section[] = [{ id: "overview", title: response ? "Response" : "Request", rows: overview }];
    if (!response) list.push({ id: "query", title: "Query parameters", rows: queryOf(request?.target ?? "") });
    list.push({ id: "cookies", title: response ? "Set-Cookie" : "Cookies", rows: cookiesOf(parsed.headers, response) });
    if (!response) list.push({ id: "body", title: "Body parameters", rows: bodyParamsOf(parsed.body, contentType) });
    list.push({ id: "headers", title: "Headers", rows: parsed.headers });
    return list;
  }, [parsed, response]);

  // Sections with content start open; empty ones stay collapsed so the pane is
  // scannable rather than a wall of "none".
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const isOpen = (section: Section) => (section.id in closed ? !closed[section.id] : section.rows.length > 0);

  return (
    <div className="inspector">
      <div className="inspector-bar">
        <span className="editor-label-inline">{label}</span>
      </div>
      <div className="inspector-body">
        {sections.map((section) => (
          <SectionBlock
            key={section.id}
            section={section}
            open={isOpen(section)}
            onToggle={() => setClosed((current) => ({ ...current, [section.id]: isOpen(section) }))}
          />
        ))}
      </div>
    </div>
  );
}
