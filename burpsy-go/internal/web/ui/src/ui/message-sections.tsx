// The message editor's operator-added tabs (burpsy-react-ui-t94i): Headers, Query params,
// Body params, Cookies, Attributes — Burp's settings-menu extras.
//
// # Where the rows come from, and why not a second parser
//
// Every row is derived with the same `../lib/message` parsers the Inspector uses — headerSpans,
// querySpans, bodyParamSpans, cookieSpans, cookiesOf, parseMessage/parseRequestLine/
// parseStatusLine. A second set that split a header slightly differently would put two answers
// about the same bytes on screen at once, which is the exact defect a "same data, another tab"
// view must not introduce. What this file adds is presentation, not parsing.
//
// # Read-only, and why that is the honest shape for a first cut
//
// Burp's extra tabs are also inspection surfaces — the editable half of the same facts lives in
// Burp's own Inspector-equivalent, and burpsy's Inspector already offers edit-in-place for every
// row here. These tabs exist so the facts are reachable in the tab strip an operator expects;
// a value that needs changing is one "Inspect" click away, and duplicating the Inspector's whole
// write-back plumbing here would be a second implementation of the same writer, not a tab.
import { useMemo } from "react";
import {
  bodyParamSpans,
  cookiesOf,
  cookieSpans,
  headerSpans,
  headerValue,
  isResponse,
  parseMessage,
  parseRequestLine,
  parseStatusLine,
  querySpans,
} from "../lib/message";
import { formatBytes } from "../lib/api";

/** One row of an extra tab: a name, its value, and nothing else — the tab is a reading. */
export interface SectionRow {
  name: string;
  value: string;
}

function SectionTable({ rows, emptyNote }: { rows: SectionRow[]; emptyNote: string }): JSX.Element {
  if (rows.length === 0) {
    return <p className="typed-empty">{emptyNote}</p>;
  }
  return (
    <table className="typed-table">
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Value</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={`${row.name}-${index}`}>
            <td className="typed-name" title={row.name}>
              {row.name === "" ? <span className="cell-dim">(no name)</span> : row.name}
            </td>
            <td className="typed-value" title={row.value}>
              {row.value}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The request/response headers, one row each, in wire order. */
export function HeadersTab({ raw }: { raw: string }): JSX.Element {
  const rows = useMemo<SectionRow[]>(
    () => headerSpans(raw).map((header) => ({ name: header.name, value: header.value })),
    [raw],
  );
  const response = useMemo(() => isResponse(raw), [raw]);
  return (
    <div className="typed-view">
      <p className="typed-source">{response ? "The response's headers, in wire order." : "The request's headers, in wire order."}</p>
      <SectionTable rows={rows} emptyNote="No headers — a bare start line and body." />
    </div>
  );
}

/** Query parameters. A response has none; the tab says so rather than hiding. */
export function QueryParamsTab({ raw }: { raw: string }): JSX.Element {
  const rows = useMemo<SectionRow[]>(
    () => querySpans(raw).map((pair) => ({ name: pair.name, value: pair.value })),
    [raw],
  );
  const response = useMemo(() => isResponse(raw), [raw]);
  if (response) {
    return (
      <div className="typed-view">
        <p className="typed-empty">A response carries no query parameters.</p>
      </div>
    );
  }
  return (
    <div className="typed-view">
      <SectionTable rows={rows} emptyNote="No query parameters — the path has no ?part." />
    </div>
  );
}

/** Body parameters — urlencoded and JSON bodies only, the same rule the Inspector's section holds. */
export function BodyParamsTab({ raw }: { raw: string }): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);
  const rows = useMemo<SectionRow[]>(
    () => bodyParamSpans(raw).map((pair) => ({ name: pair.name, value: pair.value })),
    [raw],
  );
  if (response) {
    return (
      <div className="typed-view">
        <SectionTable rows={rows} emptyNote="This response's body breaks into no parameters — only urlencoded and JSON bodies do." />
      </div>
    );
  }
  const contentType = headerValue(parsed.headers, "content-type");
  return (
    <div className="typed-view">
      {rows.length === 0 ? (
        <p className="typed-empty">
          {contentType
            ? `This ${contentType} body breaks into no parameters — only urlencoded and JSON bodies do.`
            : "Only urlencoded and JSON bodies break into parameters."}
        </p>
      ) : (
        <SectionTable rows={rows} emptyNote="" />
      )}
    </div>
  );
}

/** Cookies: the request's Cookie jar on a request, Set-Cookie lines on a response. */
export function CookiesTab({ raw }: { raw: string }): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);
  const rows = useMemo<SectionRow[]>(() => {
    if (response) {
      // Each Set-Cookie is a whole header with attributes; the value column shows the pair the
      // way the Inspector's Set-Cookie section does, and the full line is in the Headers tab.
      return cookiesOf(parsed.headers, true).map(([name, value]) => ({ name, value }));
    }
    return cookieSpans(raw).map((pair) => ({ name: pair.name, value: pair.value }));
  }, [parsed, response, raw]);
  return (
    <div className="typed-view">
      <p className="typed-source">
        {response
          ? "Every Set-Cookie the response set, name=value pairs — Path/Expires/HttpOnly stay in the Headers tab, where the whole line is edited."
          : "The request's Cookie header, one pair per row."}
      </p>
      <SectionTable
        rows={rows}
        emptyNote={response ? "No Set-Cookie headers — the response set nothing." : "No Cookie header — the request carries no cookies."}
      />
    </div>
  );
}

/** Attributes: the start-line facts and body size, the Inspector's first section as a tab. */
export function AttributesTab({ raw }: { raw: string }): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);
  const rows = useMemo<SectionRow[]>(() => {
    const bodyBytes = new TextEncoder().encode(parsed.body).length;
    if (response) {
      const status = parseStatusLine(parsed.startLine);
      return [
        { name: "Version", value: status?.version ?? "—" },
        { name: "Status", value: status ? String(status.status) : parsed.startLine },
        { name: "Reason", value: status?.reason ?? "" },
        { name: "Body", value: formatBytes(bodyBytes) },
      ];
    }
    const request = parseRequestLine(parsed.startLine);
    return [
      { name: "Method", value: request?.method ?? "—" },
      { name: "Target", value: request?.target ?? parsed.startLine },
      { name: "Version", value: request?.version ?? "—" },
      { name: "Host", value: headerValue(parsed.headers, "host") ?? "—" },
      { name: "Body", value: formatBytes(bodyBytes) },
    ];
  }, [parsed, response]);
  return (
    <div className="typed-view">
      <SectionTable rows={rows} emptyNote="" />
    </div>
  );
}
