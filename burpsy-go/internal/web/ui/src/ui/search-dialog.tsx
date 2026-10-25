import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchRaw } from "../lib/actions";
import { api, formatBytes, relativeTime, statusTone } from "../lib/api";
import {
 buildSearchQuery,
 describeSearch,
 EMPTY_SEARCH_OPTIONS,
 firstMatch,
 highlightSegments,
 matchCountLabel,
 matchWindow,
 type SearchOptions,
 type SearchResponse,
 type SearchResult,
 type SearchTool,
} from "../lib/suite-search";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, Input, Modal, Select, Spinner } from "./primitives";
import { SimpleTable } from "./table";

/**
 * Burp's suite-wide Search dialog (burpsy-react-ui-vs9k).
 *
 * Burp's own copy is the specification: "You can perform suite-wide searches in the search dialog.
 * To access the search dialog, click Search on the tab bar." Its options are case sensitivity,
 * literal/regex, negative matches, in-scope only, a request-versus-response axis, a
 * headers-versus-body axis, and which tools to cross.
 *
 * # The dialog decides; the server answers
 *
 * Nothing is matched here. `/api/search` scans the store, because the rows this console holds carry
 * no bytes to search — /api/history serves index rows and never payloads, so a client-side "search"
 * could only ever search what some page had already fetched and would report "no matches" for
 * traffic it never looked at. The dialog's job is to ask precisely and then to show what came back,
 * including the parts of the answer that are inconvenient: how much was scanned, whether the result
 * list was cut off at the limit, and whether the offsets shown are all of a message's matches.
 *
 * # The checklist is served, not written here
 *
 * The tool list comes from the endpoint's own response. A hardcoded list here could offer a tool the
 * server refuses, which is a filter that silently does nothing — the same reason the session
 * rules' tools scope is served (see session.tsx).
 */
export function SearchDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
 const [options, setOptions] = useState<SearchOptions>(EMPTY_SEARCH_OPTIONS);
 const [response, setResponse] = useState<SearchResponse | null>(null);
 const [tools, setTools] = useState<SearchTool[]>([]);
 const [vocabularyError, setVocabularyError] = useState<unknown>(null);
 const [error, setError] = useState<unknown>(null);
 const [busy, setBusy] = useState(false);
 const [selected, setSelected] = useState<number | null>(null);

 // A blank term is not a failed search: the endpoint answers it with the tool vocabulary and no
 // results, which is how this dialog can draw its checklist before the operator has searched for
 // anything. An empty checklist would silently mean "every tool" and could not be told apart from
 // "the server did not answer".
 useEffect(() => {
  if (!open) return;
  let cancelled = false;
  api<SearchResponse>(`/api/search?${buildSearchQuery(EMPTY_SEARCH_OPTIONS)}`)
   .then((body) => {
    if (cancelled) return;
    setTools(body.tool_options);
    setVocabularyError(null);
   })
   .catch((failure) => {
    if (!cancelled) setVocabularyError(failure);
   });
  return () => {
   cancelled = true;
  };
 }, [open]);

 const run = useCallback(async () => {
  setBusy(true);
  setError(null);
  try {
   const body = await api<SearchResponse>(`/api/search?${buildSearchQuery(options)}`);
   setResponse(body);
   if (body.tool_options.length > 0) setTools(body.tool_options);
   const [first] = body.results;
   setSelected(first ? first.id : null);
  } catch (failure) {
   setResponse(null);
   setSelected(null);
   setError(failure);
  } finally {
   setBusy(false);
  }
 }, [options]);

 const row = useMemo(
  () => (response && selected !== null ? (response.results.find((entry) => entry.id === selected) ?? null) : null),
  [response, selected],
 );
 const focus = row ? firstMatch(row) : null;
 const previewId = row ? (focus?.message_id ?? row.request) : null;

 const [preview, setPreview] = useState("");
 const [previewError, setPreviewError] = useState<unknown>(null);
 useEffect(() => {
  if (previewId === null) {
   setPreview("");
   setPreviewError(null);
   return;
  }
  let cancelled = false;
  setPreviewError(null);
  fetchRaw(previewId)
   .then((text) => {
    if (!cancelled) setPreview(text);
   })
   .catch((failure) => {
    if (cancelled) return;
    setPreview("");
    setPreviewError(failure);
   });
  return () => {
   cancelled = true;
  };
 }, [previewId]);

 const toggleTool = (id: string) =>
  setOptions((current) => ({
   ...current,
   tools: current.tools.includes(id) ? current.tools.filter((name) => name !== id) : [...current.tools, id],
  }));

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   wide
   title="Search"
   description="Burp's suite-wide search: every tool the store keeps, in one pass. Nothing is sent to the target."
  >
   <div className="search-dialog">
    <div className="search-dialog-form">
     <Field label="Search for" hint="Regular expression syntax is Go's, not JavaScript's — the scan runs on the server.">
      {(id) => (
       <Input
        id={id}
        value={options.term}
        autoFocus
        placeholder="text or pattern"
        onChange={(event) => setOptions({ ...options, term: event.target.value })}
        onKeyDown={(event) => {
         if (event.key === "Enter") void run();
        }}
       />
      )}
     </Field>

     <div className="search-dialog-checks">
      <Checkbox
       label="Case sensitive"
       checked={options.caseSensitive}
       onCheckedChange={(checked) => setOptions({ ...options, caseSensitive: checked })}
      />
      <Checkbox
       label="Regular expression"
       checked={options.regex}
       onCheckedChange={(checked) => setOptions({ ...options, regex: checked })}
      />
      <Checkbox
       label="Negative matches"
       checked={options.negate}
       onCheckedChange={(checked) => setOptions({ ...options, negate: checked })}
      />
      <Checkbox
       label="In scope only"
       checked={options.inScope}
       onCheckedChange={(checked) => setOptions({ ...options, inScope: checked })}
      />
     </div>

     <div className="search-dialog-axes">
      <Field label="Location">
       {(id) => (
        <Select
         id={id}
         value={options.location}
         onChange={(event) => setOptions({ ...options, location: event.target.value as SearchOptions["location"] })}
        >
         <option value="both">Request and response</option>
         <option value="request">Request only</option>
         <option value="response">Response only</option>
        </Select>
       )}
      </Field>
      <Field label="Within">
       {(id) => (
        <Select
         id={id}
         value={options.area}
         onChange={(event) => setOptions({ ...options, area: event.target.value as SearchOptions["area"] })}
        >
         <option value="both">Headers and body</option>
         <option value="headers">Headers only</option>
         <option value="body">Body only</option>
        </Select>
       )}
      </Field>
     </div>

     <div className="stack-tight">
      <span className="eyebrow">Tools to search</span>
      <small className="field-hint">
       {vocabularyError
        ? "The server did not say which tools it can search, so this list is empty — every tool would be claimed for nothing."
        : options.tools.length === 0
          ? "No tools checked, so the search covers every tool the store keeps."
          : "Only the checked tools are scanned. Burp's dialog narrows the same way."}
      </small>
      {vocabularyError ? (
       <ErrorNotice error={vocabularyError} title="Could not load the tool list" />
      ) : (
       <div className="search-dialog-tools">
        {tools.map((tool) => (
         <Checkbox key={tool.id} label={tool.label} checked={options.tools.includes(tool.id)} onCheckedChange={() => toggleTool(tool.id)} />
        ))}
       </div>
      )}
     </div>

     <div className="search-dialog-actions">
      <Button onClick={() => void run()} disabled={busy}>
       {busy ? "Searching…" : "Search"}
      </Button>
      <span className="search-dialog-scope">{describeSearch(options)}</span>
     </div>
    </div>

    <div className="search-dialog-results">
     {error ? (
      <ErrorNotice error={error} title="The search did not run" />
     ) : response === null ? (
      <Empty
       title="No search yet"
       detail="Set the options and press Search. The scan runs on the server over stored traffic — nothing is sent to the target."
      />
     ) : response.results.length === 0 ? (
      <Empty
       title={response.negate ? "Everything matched" : "No matches"}
       detail={
        response.negate
         ? `No exchange among the ${response.scanned} examined is missing the term.`
         : response.scanned === 0
           ? "No exchanges matched the selected tools or scope, so nothing was examined."
           : `${response.scanned} exchanges were examined and none contains the term.`
       }
      />
     ) : (
      <>
       <div className="search-dialog-summary">
        <span>
         {response.returned} {response.returned === 1 ? "item" : "items"} of {response.scanned} examined
        </span>
        {response.truncated ? <Badge tone="warn">stopped at the limit — more traffic was not examined</Badge> : null}
       </div>
       <SimpleTable headers={["Source", "Host", "URL", "Status", "Length", "Time", "Matches"]}>
        {response.results.map((entry) => (
         <ResultRow key={entry.id} row={entry} selected={entry.id === selected} onSelect={() => setSelected(entry.id)} />
        ))}
       </SimpleTable>
      </>
     )}
    </div>

    <div className="search-dialog-preview">
     {row ? (
      <Preview row={row} messageId={previewId} text={preview} error={previewError} />
     ) : (
      <Empty title="Nothing selected" detail="Pick a result to read the message it matched in." />
     )}
    </div>
   </div>
  </Modal>
 );
}

/** One result row. The first cell carries a real button so the table is reachable by keyboard — a
 *  click handler on a `<tr>` alone would leave the preview unreachable without a mouse. */
function ResultRow({ row, selected, onSelect }: { row: SearchResult; selected: boolean; onSelect: () => void }): JSX.Element {
 return (
  <tr className={selected ? "search-row search-row-selected" : "search-row"} aria-selected={selected} onClick={onSelect}>
   <td>
    <Button
     variant="quiet"
     size="small"
     aria-pressed={selected}
     aria-label={`Preview ${row.method} ${row.path} from ${row.source ?? "unattributed"}`}
     onClick={(event) => {
      event.stopPropagation();
      onSelect();
     }}
    >
     {row.source ?? "unattributed"}
     {row.organizer ? " · organizer" : ""}
    </Button>
   </td>
   <td>{row.host}</td>
   <td className="search-url">{row.path}</td>
   <td>
    <Badge tone={statusTone(row.status)}>{row.status ?? "—"}</Badge>
   </td>
   <td>{formatBytes(row.response_len)}</td>
   <td>{relativeTime(row.started_ms)}</td>
   <td>{matchCountLabel(row)}</td>
  </tr>
 );
}

/**
 * The matched bytes, in context.
 *
 * The window is bounded and says when either end was cut: rendering a whole message to highlight
 * four bytes is how a 40 MB response locks up the tab, and a pane that silently showed the first
 * few kilobytes as though it were the message would make the operator read a truncated request as
 * the whole one.
 */
function Preview({
 row,
 messageId,
 text,
 error,
}: {
 row: SearchResult;
 messageId: number | null;
 text: string;
 error: unknown;
}): JSX.Element {
 const focus = firstMatch(row);
 const window = useMemo(() => matchWindow(focus?.offset ?? 0, focus?.len ?? 1, text.length), [focus?.offset, focus?.len, text.length]);
 const segments = useMemo(
  () =>
   highlightSegments(
    text.slice(window.start, window.end),
    window.start,
    row.matches.filter((match) => match.message_id === messageId),
   ),
  [text, window.start, window.end, row.matches, messageId],
 );

 return (
  <div className="stack-tight">
   <div className="search-dialog-summary">
    <span className="eyebrow">
     {row.method} {row.host}
     {row.path}
    </span>
    {focus ? (
     <span className="search-dialog-scope">
      {row.match_count} {row.match_count === 1 ? "match" : "matches"} — showing the {focus.direction} {focus.area}
      {row.matches_truncated ? ` (first ${row.matches.length} offsets recorded)` : ""}
     </span>
    ) : (
     <span className="search-dialog-scope">no match — listed by the negative filter</span>
    )}
   </div>
   {error ? (
    <ErrorNotice error={error} title="Could not read the message" />
   ) : text === "" ? (
    <Spinner label="Loading the message" />
   ) : (
    <>
     {window.leading ? <div className="search-dialog-cut">… earlier bytes not shown</div> : null}
     <pre className="search-dialog-message">
      {segments.map((segment, index) => (segment.hit ? <mark key={index}>{segment.text}</mark> : <span key={index}>{segment.text}</span>))}
     </pre>
     {window.trailing ? <div className="search-dialog-cut">… later bytes not shown</div> : null}
    </>
   )}
  </div>
 );
}
