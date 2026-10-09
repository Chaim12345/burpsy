import { useEffect, useMemo, useRef, useState } from "react";
import { useInterceptNewlineCorrection, useSetInterceptNewlineCorrection, type InterceptNewlineCorrection } from "../lib/data.tools";import { useHotkeys } from "react-hotkeys-hook";
import { ArrowDown, ArrowUp, Columns3, Combine, ArrowRightLeft, FileCode2, FileOutput, Globe, Link2, MessageSquare, Pencil, Plus, Repeat2, Send, ShieldCheck, Terminal, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { describeLaunch, openUrlInBrowser, useLaunchBrowser } from "../lib/data.browser";
import { api, copyToClipboard, downloadText, formatBytes, formatDuration, json } from "../lib/api";
import { exchangeUrl, rawToCurl } from "../lib/actions";
import { useChord } from "../lib/keymap";
import { useCommandHandler } from "../lib/commands";
import { useApp } from "../lib/store";
import { useInterceptControls } from "../lib/data";
import {
 useAnnotateHeld,
 useForwardHeld,
 useInterceptDetailed,
 useInterceptRules,
 useSaveInterceptRules,
 type InterceptDirection,
} from "../lib/data.attack";
import {
 describeTarget,
 sameTarget,
 targetFromDraft,
 targetOf,
 type InterceptTarget,
} from "../lib/intercept-target";
import type { HeldMessageDetail, InterceptRuleSpec } from "../lib/types.attack";
import { HttpEditor } from "../ui/editor";
import { faithfulRequestBase64, requestBodyChanged } from "../lib/message";
import { Inspector } from "../ui/inspector";
import { PageHeader, SplitPane } from "../ui/layout";
import {
 Badge,
 Button,
 Card,
 Checkbox,
 Empty,
 ErrorNotice,
 Field,
 IconButton,
 Input,
 Modal,
 Metric,
 Select,
 Switch,
 Tabs,
 TabsContent,
 TabsList,
 TabsTrigger,
 Toolbar,
 Tooltip,
} from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";
import type { MenuGroup } from "../ui/menu";

// Burp's rule dialog offers 18 match types; these are fifteen (burpsy-react-ui-1cuc + ajpn).
// `requests` marks the fields a REQUEST list can supply, because a request has no status code, no
// content type and no response body — a rule naming one of those there can never match, and offering
// it unlabelled would be a control that looks configured and is dead weight. The server agrees
// (intercept.Direction.HasField), so the two cannot drift into disagreeing about what a list can see.
//
// `member` marks the four fields that name a MEMBER of a list rather than a whole value: a header
// or a cookie. They are the same split Burp uses — the field says which list (Zpkq = the header
// list, Zpky/Zpkc = a cookie's name/value) and a second control says which one (Zero.java:16-62) —
// so the rule editor grows a member input exactly when one of these is chosen, and a rule that
// names no member matches nothing rather than matching the first header it finds.
const FIELDS: { value: InterceptRuleSpec["field"]; label: string; requests?: false; member?: string }[] = [
 { value: "host", label: "Host" },
 { value: "path", label: "Path" },
 { value: "extension", label: "File extension" },
 { value: "method", label: "Method" },
 { value: "url", label: "URL" },
 { value: "port", label: "Port" },
 { value: "protocol", label: "Protocol" },
 { value: "status_code", label: "Status code", requests: false },
 { value: "content_type", label: "Content type", requests: false },
 { value: "request_body", label: "Request body" },
 { value: "response_body", label: "Response body", requests: false },
 { value: "request_header", label: "Request header", member: "Header name" },
 { value: "response_header", label: "Response header", requests: false, member: "Header name" },
 { value: "request_cookie", label: "Request cookie", member: "Cookie name" },
 { value: "response_cookie", label: "Response cookie", requests: false, member: "Cookie name" },
];

/** The member-control placeholder for a field, or undefined when the field has no members. */
function memberLabelOf(field: InterceptRuleSpec["field"]): string | undefined {
 return FIELDS.find((f) => f.value === field)?.member;
}

const CATEGORIES: { value: InterceptRuleSpec["category"]; label: string }[] = [
 { value: "regex", label: "Regex" },
 { value: "literal", label: "Literal" },
];

/**
 * Everything that differs between the four directions, in one table.
 *
 * It is a table because the page previously carried `direction === "requests" ? … : …` in four
 * separate places, and every one of those ternaries silently treats a WebSocket direction as a
 * response — so adding the WebSocket panels by widening the union alone would have labelled them
 * "Response interception rules" and defaulted their rules to matching a status code, which a frame
 * does not have.
 *
 * `defaultField` is the field a new row is usually written against. A WebSocket frame has no method
 * and no status code, so host is the only sensible default of the seven.
 */
/**
 * What the queue filter can be set to. These are `Direction.String()` values from Go — singular,
 * and underscored for WebSocket — because they are compared against `held[].direction`. They are
 * deliberately NOT the same strings as `InterceptDirection`, which is the plural rule-endpoint
 * suffix; conflating the two yields a filter that always matches nothing.
 */
type HeldDirectionFilter =
 | "all"
 | "request"
 | "response"
 | "websocket_to_server"
 | "websocket_to_client";

const DIRECTIONS: Record<
 InterceptDirection,
 { title: string; noun: string; defaultField: InterceptRuleSpec["field"] }
> = {
 requests: { title: "Request", noun: "request", defaultField: "host" },
 responses: { title: "Response", noun: "response", defaultField: "status_code" },
 websocket_to_server: {
  title: "WebSocket → server",
  noun: "client frame",
  defaultField: "host",
 },
 websocket_to_client: {
  title: "WebSocket → client",
  noun: "server frame",
  defaultField: "host",
 },
};

/**
 * Final path segment's extension without the dot (burpsy-react-ui-35i4): mirrors the
 * proxy's extensionOf, which is what the engine will match the rule against.
 */
function extensionOf(path: string): string {
 const segment = path.split("?")[0]?.split("/").pop() ?? "";
 const dot = segment.lastIndexOf(".");
 return dot < 0 ? "" : segment.slice(dot + 1);
}

function defaultRule(dir: InterceptDirection): InterceptRuleSpec {
 return {
  field: DIRECTIONS[dir].defaultField,
  enabled: true,
  string_match: "",
  category: "regex",
  comment: "",
  action: "hold",
 };
}

/** States whether the list is doing anything, and — the state that looks selective and holds
 * nothing — whether every enabled condition is actually switched off. */
function describeRules(active: boolean, rules: InterceptRuleSpec[], noun: string): string {
 if (!active) return `off — no ${noun} is held`;
 if (rules.length === 0) return `on with no conditions — every ${noun} is held`;
 if (!rules.some((r) => r.enabled)) return `on, but every condition is unchecked — no ${noun} is held`;
 return `on with ${rules.length} condition(s)`;
}

function RuleEditor({ direction }: { direction: InterceptDirection }): JSX.Element {
 const { data, error, isFetching, refetch } = useInterceptRules(direction);
 const save = useSaveInterceptRules(direction);
 const { title, noun } = DIRECTIONS[direction];

 const [active, setActive] = useState(false);
 const [rules, setRules] = useState<InterceptRuleSpec[]>([]);
 const [dirty, setDirty] = useState(false);
 const [announcement, setAnnouncement] = useState("");
 const [pendingFocus, setPendingFocus] = useState<{ index: number; dir: "up" | "down" } | null>(null);
 const tableRef = useRef<HTMLDivElement>(null);

 // The server is the source of truth until the operator starts editing: re-syncing on every poll
 // would fight their cursor and revert an unsaved checkbox mid-keystroke.
 useEffect(() => {
  if (!data || dirty) return;
  setActive(data.active);
  setRules(data.rules);
 }, [data, dirty]);

 const update = (patch: (list: InterceptRuleSpec[]) => InterceptRuleSpec[]) => {
  setRules(patch);
  setDirty(true);
 };

 // Copied from matchreplace.tsx's move() (102-110) so the three rule-order tools behave
 // identically. Goes through `update`, so a reorder is marked dirty exactly like add/remove
 // are, and survives the server-sync effect above.
 const move = (index: number, delta: number) => {
  const target = index + delta;
  if (target < 0 || target >= rules.length) return;
  update((list) => {
   const next = [...list];
   const [moved] = next.splice(index, 1);
   if (!moved) return list;
   next.splice(target, 0, moved);
   return next;
  });
  // Focus follows the moved rule so a second press repeats the action, unless that would
  // land focus on the now-disabled control at the boundary — then it goes to the other
  // direction's button on the same row, which stays enabled.
  const disabledAtTarget = (delta < 0 && target === 0) || (delta > 0 && target === rules.length - 1);
  const dir: "up" | "down" = delta < 0 ? "up" : "down";
  setPendingFocus({ index: target, dir: disabledAtTarget ? (dir === "up" ? "down" : "up") : dir });
  setAnnouncement(`${noun === "request" ? "Request" : "Response"} rule moved to position ${target + 1} of ${rules.length}`);
 };

 useEffect(() => {
  if (!pendingFocus) return;
  const { index, dir } = pendingFocus;
  const label = `Move rule ${index + 1} ${dir}`;
  const el = tableRef.current?.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
  el?.focus();
  setPendingFocus(null);
 }, [pendingFocus, rules]);

 const onSave = () => {
  save.mutate(
   { active, rules },
   {
    onSuccess: (resp) => {
     setActive(resp.active);
     setRules(resp.rules);
     setDirty(false);
     toast.success(`${title} rules saved`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
   },
  );
 };

 if (error) return <ErrorNotice error={error} onRetry={() => void refetch()} />;
 if (!data && isFetching) return <Card>Loading…</Card>;
 if (data && !data.wired) {
  return (
   <div className="notice notice-warn">
    {title} interception rules are not wired up.
   </div>
  );
 }

 return (
  <Card>
   <div>
    <Toolbar>
     <Checkbox
      checked={active}
      onCheckedChange={(checked) => {
       setActive(checked);
       setDirty(true);
      }}
      label={`Hold ${noun}s matching these rules`}
     />
     <span className="field-hint">{describeRules(active, rules, noun)}</span>
     <span style={{ flex: 1 }} />
     <Button
      variant="outline"
      size="small"
      onClick={() =>
       update((list) => [...list, defaultRule(direction)])
      }
     >
      <Plus size={13} />
      Add rule
     </Button>
     <Button size="small" onClick={onSave} disabled={!dirty || save.isPending}>
      {save.isPending ? "Saving…" : "Save"}
     </Button>
    </Toolbar>
   </div>
   <div aria-live="polite" className="sr-only">
    {announcement}
   </div>
   <div className="table-frame" ref={tableRef}>
    <div className="table-scroll">
     <table>
      <thead>
       <tr>
        {/* Percentages so the columns track the table's own width; fixed
                    pixels do not scale under table-layout: fixed. */}
        <th style={{ width: "8%" }}>On</th>
        <th style={{ width: "18%" }}>Field</th>
        <th>Match</th>
        <th style={{ width: "12%" }}>Kind</th>
        <th style={{ width: "9%" }}>Combine</th>
        <th style={{ width: "14%" }}>Action</th>
        <th style={{ width: "18%" }}>Comment</th>
        <th style={{ width: "10%" }}>Order</th>
        <th style={{ width: "6%" }} />
       </tr>
      </thead>
      <tbody>
       {rules.length === 0 ? (
        <tr>
         <td colSpan={9} className="cell-dim">
          no rules — every {noun} is held while this list is on
         </td>
        </tr>
       ) : (
        rules.map((rule, index) => (
         <tr key={index}>
          <td>
           <Checkbox
            checked={rule.enabled}
            onCheckedChange={(checked) =>
             update((list) => list.map((r, i) => (i === index ? { ...r, enabled: checked } : r)))
            }
            label="On"
           />
          </td>
          <td>
           <Select
            aria-label={`Field for rule ${index + 1}`}
            value={rule.field}
            onChange={(event) => {
             const field = event.target.value as InterceptRuleSpec["field"];
             // The member is cleared when the new field has none: a member name on a field that
             // cannot carry one is refused by the server (intercept.NewMemberRule), and a UI that
             // can produce a refused rule is a UI that hands the operator a 400 with no clue why.
             update((list) =>
              list.map((r, i) =>
               i === index
                ? memberLabelOf(field) === undefined
                  ? { ...r, field, member: undefined }
                  : { ...r, field }
                : r,
              ),
             );
            }}
           >
            {FIELDS.map((f) => (
             // Every field is listed, and the ones this direction cannot supply are DISABLED with
             // the reason rather than hidden: a saved rule naming one is dead weight the operator
             // has to be able to see and change, and a hidden option would render its value blank
             // — which reads as a corrupt rule rather than as one the server will never match.
             <option
              key={f.value}
              value={f.value}
              disabled={f.requests === false && direction === "requests"}
              title={
               f.requests === false && direction === "requests"
                ? `A request carries no ${f.label.toLowerCase()}, so this rule could never match here`
                : undefined
              }
             >
              {f.label}
             </option>
            ))}
           </Select>
          </td>
          <td>
           {/* The member control, shown exactly when the chosen field names a member of a list
               (ajpn). Burp's dialog has the same shape — a match type plus the thing being
               matched — and a header rule with no header named matches nothing, which is what
               the empty state says rather than leaving the operator to wonder. */}
           {memberLabelOf(rule.field) ? (
            <Input
             aria-label={`${memberLabelOf(rule.field)} for rule ${index + 1}`}
             value={rule.member ?? ""}
             placeholder={memberLabelOf(rule.field)}
             style={{ marginBottom: 4 }}
             onChange={(event) =>
              update((list) => list.map((r, i) => (i === index ? { ...r, member: event.target.value } : r)))
             }
            />
           ) : null}
           <Input
            aria-label={`Match pattern for rule ${index + 1}`}
            value={rule.string_match}
            placeholder="pattern to match"
            onChange={(event) =>
             update((list) => list.map((r, i) => (i === index ? { ...r, string_match: event.target.value } : r)))
            }
           />
          </td>
          <td>
           <Select
            aria-label={`Match kind for rule ${index + 1}`}
            value={rule.category}
            onChange={(event) =>
             update((list) =>
              list.map((r, i) => (i === index ? { ...r, category: event.target.value as InterceptRuleSpec["category"] } : r)),
             )
            }
           >
            {CATEGORIES.map((c) => (
             <option key={c.value} value={c.value}>
              {c.label}
             </option>
            ))}
           </Select>
          </td>
          <td>
           {/* Burp's boolean column (burpsy-react-ui-80tg). The title says what the choice does
               rather than restating the option, because "combine with the rules above" is not
               self-explanatory in a table row that has no rules above it on screen. */}
           <Select
            aria-label={`Combine rule ${index + 1}`}
            title={
             index === 0
              ? "The first rule has nothing above it to combine with, so this choice is ignored"
              : rule.op === "and"
              ? "Hold only when this rule AND every rule above it match"
              : "Hold when this rule matches, whatever the rules above decided"
            }
            disabled={index === 0}
            value={rule.op ?? "or"}
            onChange={(event) =>
             update((list) =>
              list.map((r, i) => (i === index ? { ...r, op: event.target.value as "and" | "or" } : r)),
             )
            }
           >
            <option value="or">OR</option>
            <option value="and">AND</option>
           </Select>
          </td>
          <td>
           <Select
            aria-label={`Action for rule ${index + 1}`}
            title="Do intercept holds a match; Don't intercept lets it through"
            value={rule.action ?? "hold"}
            onChange={(event) =>
             update((list) =>
              list.map((r, i) => (i === index ? { ...r, action: event.target.value as InterceptRuleSpec["action"] } : r)),
             )
            }
           >
            <option value="hold">Do intercept</option>
            <option value="pass">Don&apos;t intercept</option>
           </Select>
          </td>
          <td>
           <Input
            aria-label={`Comment for rule ${index + 1}`}
            value={rule.comment}
            placeholder="label"
            onChange={(event) =>
             update((list) => list.map((r, i) => (i === index ? { ...r, comment: event.target.value } : r)))
            }
           />
          </td>
          <td>
           <div className="chip-row">
            <IconButton
             label={`Move rule ${index + 1} up`}
             size="small"
             disabled={index === 0}
             onClick={() => move(index, -1)}
            >
             <ArrowUp size={13} />
            </IconButton>
            <IconButton
             label={`Move rule ${index + 1} down`}
             size="small"
             disabled={index === rules.length - 1}
             onClick={() => move(index, 1)}
            >
             <ArrowDown size={13} />
            </IconButton>
           </div>
          </td>
          <td>
           <IconButton
            label={`Remove rule ${index + 1}`}
            size="small"
            onClick={() => update((list) => list.filter((_, i) => i !== index))}
           >
            <Trash2 size={13} />
           </IconButton>
          </td>
         </tr>
        ))
       )}
      </tbody>
     </table>
    </div>
   </div>
  </Card>
 );
}

/**
 * The three fields an operator edits to point a held request at another destination, with what each
 * one means (burpsy-react-ui-akv).
 *
 * A component of its own so the in-progress strings die with the dialog that holds it. Kept as state
 * in the page instead, a half-typed port would survive Cancel and be sent with the next Forward —
 * the trap the wire's own contract exists to avoid (api_intercept.go refuses a partial destination
 * rather than filling the missing fields in from the hold).
 *
 * Nothing here talks to the server. The draft is applied to the page's state and the request is not
 * affected until Forward, so the operator can see the new destination and change their mind with the
 * message still exactly where it was.
 */
function TargetEditor({
 original,
 onApply,
 onRevert,
}: {
 original: InterceptTarget;
 onApply: (target: InterceptTarget) => void;
 onRevert: () => void;
}): JSX.Element {
 const [host, setHost] = useState(original.host);
 const [port, setPort] = useState(String(original.port));
 const [tls, setTls] = useState(original.tls);
 const result = targetFromDraft(host, port, tls);
 const unchanged = result.ok && sameTarget(result.target, original);

 return (
  <>
   <div className="form-grid">
    <Field
     label="Host"
     hint="burpsy dials this name. The bytes are sent as they are, so a virtual host that routes on the Host header needs that header edited in the request above."
    >
     {(id) => (
      <Input id={id} value={host} autoFocus onChange={(event) => setHost(event.target.value)} />
     )}
    </Field>
    <Field label="Port" hint="1 to 65535.">
     {(id) => (
      <Input
       id={id}
       value={port}
       inputMode="numeric"
       onChange={(event) => setPort(event.target.value)}
      />
     )}
    </Field>
    <Field label="Scheme" hint="Whether burpsy wraps this one connection in TLS.">
     {(id) => (
      <Select
       id={id}
       value={tls ? "https" : "http"}
       onChange={(event) => setTls(event.target.value === "https")}
      >
       <option value="http">http</option>
       <option value="https">https</option>
      </Select>
     )}
    </Field>
   </div>

   {result.ok ? null : <div className="notice notice-warn">{result.error}</div>}

   {/* "Nothing changed" is worth saying rather than leaving as a silence: the operator may have
       opened this to check where the message is already going, and a Save button that looks
       identical either way would leave them unsure whether a retarget is now in force. */}
   {unchanged ? (
    <div className="notice">
     This is where the client already sent it — nothing will change.
    </div>
   ) : null}

   <div className="notice">
    Retargeting a request that is a WebSocket upgrade is refused: the client&apos;s frames keep
    arriving on the connection it opened, so the handshake would be answered from one origin while
    the frames went to another. burpsy answers the client with a 502 explaining that instead.
   </div>

   <div className="page-actions">
    <Button variant="outline" onClick={onRevert} disabled={unchanged}>
     Revert to {describeTarget(original)}
    </Button>
    <Button
     onClick={() => {
      // Narrowed rather than asserted: a disabled button should not be the only thing standing
      // between an unparseable draft and a Forward to it.
      if (result.ok) onApply(result.target);
     }}
     disabled={!result.ok || unchanged}
    >
     Use this destination
    </Button>
   </div>
  </>
 );
}

/** Both corrections are off by default, and the page shows exactly what the server reports. */
const NO_NEWLINE_CORRECTION: InterceptNewlineCorrection = {
 add_missing_blank_line: false,
 trim_trailing_newlines_urlencoded_body: false,
};

export function InterceptPage(): JSX.Element {
 const { data, error, isFetching, refetch } = useInterceptDetailed();
 // Burp's "Open browser" (bufa), in the toolbar where Burp puts it.
 const launch = useLaunchBrowser();
 // Enable and drop come from the shared controls; forward has its own hook because the shared one
 // hard-codes fix_content_length and this page offers it as a toggle.
 const controls = useInterceptControls();
 const forwardHeld = useForwardHeld();
 // The operator's annotation on the hold (burpsy-react-ui-5q8u): a comment and a highlight
 // colour that ride the message into HTTP history when the hold forwards into a recorded
 // exchange. Draft state keyed to the selection, same lifecycle as the edit buffer.
 const annotateHeld = useAnnotateHeld();
 const [commentDraft, setCommentDraft] = useState("");
 const [highlightDraft, setHighlightDraft] = useState("");
 const reqRules = useInterceptRules("requests");
 const resRules = useInterceptRules("responses");
 const saveReqRules = useSaveInterceptRules("requests");
 const saveResRules = useSaveInterceptRules("responses");
 const openRepeaterTab = useApp((state) => state.openRepeaterTab);
 const setRoute = useApp((state) => state.setRoute);
 const setComparerSlot = useApp((state) => state.setComparerSlot);
 const setDecoderSeed = useApp((state) => state.setDecoderSeed);

 const [selectedId, setSelectedId] = useState<number | null>(null);
 // burpsy-react-ui-s5g7: the checkbox subset for bulk forward/drop. Separate from the
 // single selection that drives the detail pane: checking boxes must not yank the editor
 // to another message, and the bulk actions send unedited row bytes (like Forward all),
 // never one row's edit buffer under N ids.
 const [selectedIds, setSelectedIds] = useState<number[]>([]);
 /**
  * Drop-all needs a confirm step: it discards traffic that cannot be recovered, and unlike a single
  * Drop it does so for messages the operator has not looked at.
  */
 const [confirmDropAll, setConfirmDropAll] = useState(false);
 const [raw, setRaw] = useState("");
 // The held body's exact octets, when `raw` cannot carry them (burpsy-react-ui-3pco) — the same shadow
 // Repeater keeps for a binary body. A body edit through the text drops it (it no longer matches what
 // the operator sees); a header edit keeps it; the Protobuf tab's Apply clears and then restores it.
 const [rawBodyBase64, setRawBodyBase64] = useState<string | undefined>(undefined);
 const editRaw = (next: string) => {
  if (rawBodyBase64 !== undefined && requestBodyChanged(raw, next)) setRawBodyBase64(undefined);
  setRaw(next);
 };
 const [fixContentLength, setFixContentLength] = useState(true);
 // Burp's two newline corrections (80tg), read from the server rather than seeded with the
 // defaults: both are OFF by default and a previous session or a plugin may have set one, so a
 // checkbox seeded here would show the wrong state for a control that rewrites bytes.
 const newlineQuery = useInterceptNewlineCorrection();
 const setNewlinesRaw = useSetInterceptNewlineCorrection();
 const newlines = newlineQuery.data ?? NO_NEWLINE_CORRECTION;
 const setNewlines = (next: typeof NO_NEWLINE_CORRECTION) => {
  setNewlinesRaw.mutate(next, {
   onSuccess: () => void newlineQuery.refetch(),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save that setting"),
  });
 };
 const [directionFilter, setDirectionFilter] = useState<HeldDirectionFilter>("all");
 const [inspector, setInspector] = useState(true);
 /**
  * Burp's "Edit target" (burpsy-react-ui-akv): where everything Forward will send THIS message, as
  * the operator last edited it. Keyed to the selection exactly like `raw` above, so a poll of the
  * same message cannot overwrite a destination mid-typing and a new selection starts from that row's
  * own authority rather than inheriting the previous row's.
  */
 const [targetDraft, setTargetDraft] = useState<InterceptTarget | null>(null);
 const [targetEditorOpen, setTargetEditorOpen] = useState(false);

 const heldAll = data?.held ?? [];
 // Apply direction filter to the held queue — the operator can focus on
 // just requests or just responses without losing the other half.
 const held = directionFilter === "all" ? heldAll : heldAll.filter((h) => h.direction === directionFilter);
 // Selection is held by id, not object identity, so a poll that rebuilds every row cannot silently
 // drop the operator's selection.
 const selected = useMemo(() => held.find((h) => h.id === selectedId) ?? null, [held, selectedId]);

 // The edit buffer resets only when the *selected id* changes, never on a background refresh of the
 // same message — otherwise every 1.5s poll would overwrite an operator's in-progress edit.
 useEffect(() => {
  setRaw(selected?.raw ?? "");
  setRawBodyBase64(selected?.raw_body_base64);
  setCommentDraft(selected?.comment ?? "");
  setHighlightDraft(selected?.highlight ?? "");
  // The destination draft follows the selection for the same reason: a target edited on one held
  // message must not become the destination of the next one the operator clicks.
  setTargetDraft(selected ? targetOf(selected) : null);
  setTargetEditorOpen(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional: keyed on id, not on `selected`'s contents
 }, [selectedId]);

 // A held message can resolve elsewhere (another operator, or a client that gave up waiting); drop a
 // selection that no longer exists in the queue rather than let the editor go stale.
 useEffect(() => {
  if (selectedId !== null && data && !held.some((h) => h.id === selectedId)) setSelectedId(null);
  if (data) {
   const live = new Set(held.map((h) => h.id));
   setSelectedIds((current) => (current.every((id) => live.has(id)) ? current : current.filter((id) => live.has(id))));
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [data]);

 const toggle = () => {
  if (!data?.wired) {
   toast.error("Interception is not wired up on this server");
   return;
  }
  controls.setEnabled.mutate(!data.enabled, { onError: (err) => toast.error(err instanceof Error ? err.message : String(err)) });
 };

 /**
 * Forward one held message by id, with its body, the Content-Length decision and — when the operator
 * has pointed it somewhere else — its destination all passed in.
 *
 * Taking all of them explicitly is the point. The previous shape closed over `selected` and `raw`,
  * which was fine for the toolbar — it only ever acts on the selection — and wrong for anything
  * that acts on a row the operator pointed at instead. A caller that set the selection and then
  * invoked a closure captured at the previous render would forward the PREVIOUS message, with the
  * previous message's edit buffer as its body, and the success toast would name the one that
  * actually went. See burpsy-react-ui-3g5.
  */
 // What a forward sends for message `id` whose buffer is `body` (burpsy-react-ui-3pco). Unedited: no raw
 // at all, so the server forwards exactly the held bytes — sending the text back would replace a binary
 // body with its mangled JSON rendering. Edited with the faithful body in hand (the detail selection,
 // e.g. a Protobuf Apply): the exact bytes as raw_base64. Otherwise: the edited text.
 const forwardPayload = (id: number, body: string): { raw?: string; rawBase64?: string } => {
  const held = heldAll.find((h) => h.id === id);
  const isSelection = selected?.id === id && body === raw;
  if (isSelection && rawBodyBase64 !== undefined) {
   if (held && body === held.raw && rawBodyBase64 === held.raw_body_base64) return {};
   return { rawBase64: faithfulRequestBase64(body, rawBodyBase64) };
  }
  if (held && body === held.raw) return {};
  return { raw: body };
 };
 const forwardMessage = (
  id: number,
  body: string,
  fixCL: boolean,
  holdResponse = false,
  target?: InterceptTarget,
 ) => {
  forwardHeld.mutate(
   { id, ...forwardPayload(id, body), fixContentLength: fixCL, holdResponse, target },
   {
    onSuccess: () => {
     setSelectedId(null);
     toast.success(`Held message #${id} forwarded`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
   },
  );
 };

 /**
  * The destination to send `row` to: the operator's edit, but only for the row it belongs to.
  *
  * The draft is keyed to the selection while a menu acts on whatever row was pointed at, so sending
  * the selection's edited destination under another row's id would be the same class of bug the
  * comment above records (burpsy-react-ui-3g5) — one message's instruction applied to another
  * message's bytes. A row that is not the selection forwards where the client asked, unchanged.
  */
 const targetFor = (row: HeldMessageDetail): InterceptTarget | undefined =>
  row.direction === "request" && row.id === selectedId && targetDraft ? targetDraft : undefined;

 /**
  * Burp's "Don't intercept ..." quick actions (burpsy-react-ui-35i4): append a pass rule
  * built from the message in front of the operator, then save the whole list. The list is
  * read from the last poll rather than refetched first: a rule added elsewhere between the
  * poll and this click would be dropped by the PUT, and that lossy read-modify-write is the
  * documented shape of this page's rule editing (the RuleEditor tab saves whole lists too).
  * First-match-wins evaluation means the new rule belongs at the TOP: appended at the end it
  * would sit behind broader hold rules and never fire, silently doing nothing.
  */
 const addPassRule = (
  dir: "requests" | "responses",
  field: InterceptRuleSpec["field"],
  match: string,
  comment: string,
 ) => {
  const current = dir === "requests" ? reqRules.data : resRules.data;
  if (!current) {
   toast.error("Rule list has not loaded yet");
   return;
  }
  const save = dir === "requests" ? saveReqRules : saveResRules;
  const rule: InterceptRuleSpec = {
   field,
   category: "literal",
   string_match: match,
   enabled: true,
   comment,
   action: "pass",
  };
  save.mutate(
   { active: current.active, rules: [rule, ...current.rules] },
   {
    onSuccess: () => toast.success(`Pass rule added — ${match} will no longer be held`),
    onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
   },
  );
 };

 const dropMessage = (id: number) => {
  controls.drop.mutate(id, {
   onSuccess: () => {
    setSelectedId(null);
    toast.success(`Held message #${id} dropped`);
   },
   onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
  });
 };
 /** Save the annotation draft (burpsy-react-ui-5q8u). Empty highlight clears, matching the
  *  shared annotation vocabulary everywhere else in the console. */
 const saveAnnotation = () => {
  if (!selected) return;
  annotateHeld.mutate(
   { id: selected.id, comment: commentDraft, highlight: highlightDraft },
   {
    onSuccess: () =>
     toast.success(
      commentDraft || (highlightDraft && highlightDraft !== "none")
       ? `Annotation saved on held #${selected.id}`
       : `Annotation cleared on held #${selected.id}`,
     ),
    onError: (err: Error) => toast.error(err instanceof Error ? err.message : String(err)),
   },
  );
 };


 /**
  * burpsy-react-ui-s5g7: forward/drop the checkbox subset, one resolved message at a time.
  * Sequential, not parallel: the queue shifts under each resolution and the toasts name what
  * actually happened, so a message resolved elsewhere mid-run is reported as skipped rather
  * than double-counted. Bulk sends carry unedited row bytes (like Forward all) — the edit
  * buffer belongs to the detail selection alone.
  */
 const forwardSelected = async () => {
  const targets = held.filter((h) => selectedIds.includes(h.id));
  let ok = 0;
  const failed: number[] = [];
  for (const target of targets) {
   try {
    // No raw: an unedited bulk forward sends exactly the held bytes. Sending target.raw back would
    // replace a binary body with its U+FFFD-mangled text (burpsy-react-ui-3pco).
    await forwardHeld.mutateAsync({ id: target.id, fixContentLength: fixContentLength, holdResponse: false });
    ok += 1;
   } catch {
    failed.push(target.id);
   }
  }
  setSelectedIds((current) => current.filter((id) => failed.includes(id)));
  if (selectedId !== null && !failed.includes(selectedId) && targets.some((t) => t.id === selectedId)) setSelectedId(null);
  toast.success(
   failed.length ? `Forwarded ${ok}, ${failed.length} failed (${failed.join(", ")})` : `Forwarded ${ok} message${ok === 1 ? "" : "s"}`,
  );
 };

 const dropSelected = async () => {
  const ids = selectedIds.filter((id) => held.some((h) => h.id === id));
  let ok = 0;
  const failed: number[] = [];
  for (const id of ids) {
   try {
    await controls.drop.mutateAsync(id);
    ok += 1;
   } catch {
    failed.push(id);
   }
  }
  setSelectedIds((current) => current.filter((id) => failed.includes(id)));
  if (selectedId !== null && !failed.includes(selectedId) && ids.includes(selectedId)) setSelectedId(null);
  if (failed.length) toast.error(`Dropped ${ok}, ${failed.length} failed (${failed.join(", ")})`);
  else toast.success(`Dropped ${ok} message${ok === 1 ? "" : "s"}`);
 };

 /**
  * The send-to matrix for a held message.
  *
  * # Why this cannot just call lib/actions.ts's menu()
  *
  * That factory takes an `Exchange`: a row in the traffic store with an id and message ids behind
  * it. A held message is none of those things yet — it exists only in the proxy's hold, has no
  * response, and has no stored message the server can be asked for. So the actions that need a
  * stored message are built here from the bytes the hold already handed us (`row.raw`), and the
  * one that cannot be built at all is left out rather than faked:
  *
  * - Send to Intruder is absent. Intruder splices payloads into a *stored* message id, which a
  *   held message does not have. Forward it and send from HTTP history, or send it to Repeater
  *   here and use Repeater's own hand-off, which sends once to create the stored message first.
  *
  * Everything else is the same matrix every other HTTP table offers, and the point of it is the
  * first entry: forking a copy to Repeater WITHOUT resolving the hold. Before this, a held
  * request had to be forwarded or dropped before it could be worked on, so the operator lost the
  * hold to get the copy — and forking an intercepted request to Repeater is the single most
  * common thing done from Burp's Intercept tab.
  *
  * `row`, never the selection or the edit buffer: a right-click selects the row, but the buffer
  * belongs to whatever was selected at the previous render. Sending one message's bytes under
  * another's id is the bug burpsy-react-ui-3g5 already cost this file once.
  */
 const heldMenu = (row: HeldMessageDetail): MenuGroup[] => {
  const url = exchangeUrl(row);
  const label = `held #${row.id} ${row.method} ${row.path}`;
  return [
   {
    id: "send",
    actions: [
     {
      id: "repeater",
      label: "Send to Repeater",
      icon: Repeat2,
      onSelect: () => {
       openRepeaterTab({
        name: label.slice(0, 42),
        target: `${row.tls ? "https" : "http"}://${row.host}:${row.port}`,
        protocol: row.tls ? "https" : "http",
        request: row.raw,
       });
       setRoute("repeater");
       toast.success(`Held message #${row.id} copied to Repeater — it is still held here`);
      },
     },
     {
      id: "compare-a",
      label: "Send to Comparer (A)",
      icon: Combine,
      onSelect: () => {
       setComparerSlot("a", row.raw);
       setRoute("comparer");
      },
     },
     {
      id: "compare-b",
      label: "Send to Comparer (B)",
      icon: ArrowRightLeft,
      onSelect: () => {
       setComparerSlot("b", row.raw);
       setRoute("comparer");
      },
     },
     {
      id: "decoder",
      label: "Send to Decoder",
      icon: FileOutput,
      onSelect: () => {
       setDecoderSeed({ label, input: row.raw });
       setRoute("decoder");
      },
     },
    ],
   },
   {
    id: "hold",
    title: "Resolve the hold",
    actions: [
     {
      id: "forward",
      label: "Forward",
      icon: Send,
      shortcut: "Ctrl+F",
      // row.raw, not the edit buffer: there is no edit buffer for a row that is not
      // selected, and sending the selection's bytes under another row's id is exactly the
      // confusion this menu was built to avoid.
      //
      // fixContentLength, not a hardcoded true: two forward paths disagreeing about
      // whether they rewrite a header is invisible from either one.
      onSelect: () => forwardMessage(row.id, row.raw, fixContentLength, false, targetFor(row)),
     },
     {
      id: "drop",
      label: "Drop",
      icon: Trash2,
      danger: true,
      onSelect: () => dropMessage(row.id),
     },
    ],
   },
   {
    id: "rules",
    title: "Interception rules from this message",
    actions: [
     ...(row.direction === "request"
      ? [
       {
        id: "dont-intercept-host",
        label: `Don't intercept requests to ${row.host}`,
        onSelect: () => addPassRule("requests", "host", row.host, `from held #${row.id}`),
       },
       ...(extensionOf(row.path)
        ? [
         {
          id: "dont-intercept-ext",
          label: `Don't intercept requests for .${extensionOf(row.path)} files`,
          onSelect: () =>
           addPassRule("requests", "extension", extensionOf(row.path), `from held #${row.id}`),
         },
        ]
        : []),
       {
        id: "intercept-response",
        label: "Do intercept the response to this request",
        onSelect: () => forwardMessage(row.id, row.raw, fixContentLength, true, targetFor(row)),
       },
      ]
      : row.direction === "response"
       ? [
        {
         id: "dont-intercept-host",
         label: `Don't intercept responses from ${row.host}`,
         onSelect: () => addPassRule("responses", "host", row.host, `from held #${row.id}`),
        },
       ]
       : []),
    ],
   },
   {
    id: "copy",
    actions: [
     {
      id: "url",
      label: "Copy URL",
      icon: Link2,
      onSelect: () => {
       void copyToClipboard(url);
       toast.success("URL copied");
      },
     },
     {
      id: "curl",
      label: "Copy as curl",
      icon: Terminal,
      onSelect: () => {
       void copyToClipboard(rawToCurl(row.raw, url));
       toast.success("curl command copied");
      },
     },
     {
      id: "to-file",
      label: "Copy request to file",
      icon: FileCode2,
      onSelect: () =>
       downloadText(`held-${row.id}-${row.method}.txt`.replace(/[^a-z0-9.\-]+/gi, "_"), row.raw),
     },
    ],
   },
   {
    id: "scope",
    actions: [
     {
      id: "add-scope",
      label: `Add ${row.host} to scope`,
      icon: ShieldCheck,
      onSelect: () => {
       void api<unknown>("/api/scope", json("POST", { action: "include", pattern: row.host }))
        .then(() => toast.success(`${row.host} added to scope`))
        .catch((error: unknown) =>
         toast.error(`Could not scope ${row.host}: ${error instanceof Error ? error.message : String(error)}`),
        );
      },
     },
     {
      id: "browser",
      label: "Open URL in browser",
      icon: Globe,
      // The burpsy browser, proxied (bufa); a refusal is shown and offers this browser instead.
      onSelect: () => void openUrlInBrowser(url),
     },
    ],
   },
  ];
 };

 // The toolbar's two actions: the selection, its edit buffer, and the operator's toggle.
 const forward = () => {
  if (!selected) return;
  forwardMessage(selected.id, raw, fixContentLength, false, targetFor(selected));
 };

 const drop = () => {
  if (!selected) return;
  dropMessage(selected.id);
 };

 // Burp's proxy bindings. ctrl+F forwards — in Burp that is Forward, not Find, and
 // the editor's search lives on ctrl+S to match. alt+T stands in for Burp's ctrl+T
 // because Chrome and Firefox reserve ctrl+T for a new tab and a page cannot claim it.
 // Both chords come from the keymap registry rather than being literals here: `proxy.forward` and
 // `proxy.toggleIntercept` are rebindable rows in Settings -> Hotkeys, and that table was running
 // duplicate detection on overrides nothing ever read.
 const forwardChord = useChord("proxy.forward");
 const toggleChord = useChord("proxy.toggleIntercept");
 useHotkeys(
  forwardChord,
  (event) => {
   if (!selected) return;
   event.preventDefault();
   forward();
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [forwardChord, selected],
 );
 useHotkeys(
  toggleChord,
  (event) => {
   event.preventDefault();
   toggle();
  },
  { enableOnFormTags: true },
  [toggleChord, data],
 );

 const forwardAllHeld = () => {
  const expected = held.length;
  controls.forwardAll.mutate(undefined, {
   onSuccess: (result) => {
    setSelectedId(null);
    const forwarded = result.forwarded;
    if (forwarded === expected) {
     toast.success(`Forwarded ${forwarded} held message${forwarded === 1 ? "" : "s"}`);
    } else {
     toast.success(
      `Forwarded ${forwarded} of the ${expected} shown — the rest resolved elsewhere before this request arrived`,
     );
    }
   },
   onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
  });
 };

 // Burp's queue actions as catalogue entries (2czi), registered for the palette and their chords.
 // Drop all opens the same confirmation the toolbar button does: a chord is a faster way to ask,
 // never a way past the question. Intercept-response is the held request's own menu entry.
 useCommandHandler("proxy.forwardAll", held.length > 0 && !controls.forwardAll.isPending ? forwardAllHeld : "Nothing is held");
 useCommandHandler("proxy.dropAll", held.length > 0 && !controls.dropAll.isPending ? () => setConfirmDropAll(true) : "Nothing is held");
 useCommandHandler(
  "proxy.interceptResponse",
  selected && selected.direction === "request"
   ? () => forwardMessage(selected.id, selected.raw, fixContentLength, true, targetFor(selected))
   : "Select a held request first",
 );

 const columns = useMemo<Column<HeldMessageDetail>[]>(
  () => [
   {
    id: "select",
    header: "✓",
    size: 40,
    enableSorting: false,
    cell: (info) => {
     const id = info.row.original.id;
     return (
      <Checkbox
       checked={selectedIds.includes(id)}
       onCheckedChange={(checked) => {
        setSelectedIds((current) =>
         checked ? (current.includes(id) ? current : [...current, id]) : current.filter((v) => v !== id),
        );
       }}
       label={`Select held #${id} for bulk forward or drop`}
      />
     );
    },
   },
   { accessorKey: "id", header: "#", size: 56, cell: (info) => <span className="cell-num">{info.getValue<number>()}</span> },
   {
    accessorKey: "direction",
    header: "Dir",
    size: 76,
    cell: (info) => <Badge tone={info.getValue<string>() === "request" ? "info" : "good"}>{info.getValue<string>()}</Badge>,
   },
   { accessorKey: "method", header: "Method", size: 74 },
   {
    id: "authority",
    header: "Host",
    size: 180,
    accessorFn: (row) => `${row.host}:${row.port}${row.tls ? " (tls)" : ""}`,
    cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
   },
   { accessorKey: "path", header: "Path", size: 260, cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code> },
   {
    accessorKey: "status",
    header: "Status",
    size: 70,
    cell: (info) => {
     const value = info.getValue<number | null>();
     return value === null ? <span className="cell-dim">—</span> : <Badge>{value}</Badge>;
    },
   },
   { accessorKey: "held_ms", header: "Held", size: 80, cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span> },
   { accessorKey: "len", header: "Len", size: 76, cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span> },
  ],
  [selectedIds],
 );

 /**
  * The destination the header bar names: the operator's edit when they have made one, the row's own
  * authority otherwise. Spelled by `describeTarget`, the same function the held-message table's Host
  * column uses, so the row an operator clicked and the bar above the editor cannot disagree about
  * where the message is going.
  */
 const authority = targetDraft ?? selected;
 /**
  * Whether the draft is the operator's edit rather than the row's own authority. Reported in the
  * header bar because a retarget is otherwise invisible once the editor closes: the bytes look the
  * same, and an operator who pointed a message elsewhere a minute ago would have no way to tell that
  * this Forward is not the ordinary one.
  */
 const retargeted = authority !== null && selected !== null && !sameTarget(authority, targetOf(selected));

 const detail = selected ? (
  <div className="tabs-fill">
   <div className="detail-head">
    <div className="detail-head-title">
     <span className="eyebrow">HELD #{selected.id}</span>
     <strong
      title={
       retargeted
        ? `The client asked for ${selected.host}:${selected.port}${selected.tls ? " (tls)" : ""}. This Forward goes to the destination shown instead.`
        : undefined
      }
     >
      {selected.direction === "response" ? `${selected.status ?? "?"} response to ` : ""}
      {selected.method} {describeTarget(authority ?? selected)}
      {selected.path}
     </strong>
     {/* Burp's "Edit target" pencil (BurpClass9694.java proxyInterceptEditTargetButton, tooltip
         "Click to modify"), beside the authority label rather than inside a menu, because the
         destination is a property of the message on screen and not an action on it. Requests only:
         a response has already come back from a destination, and a WebSocket frame has no
         addressing of its own — the engine refuses a retarget on both, so offering the control
         would promise something the wire answers with an error. */}
     {selected.direction === "request" ? (
      <IconButton
       label={retargeted ? `Edit target — currently ${describeTarget(authority ?? selected)}` : "Edit target"}
       size="small"
       aria-pressed={targetEditorOpen}
       onClick={() => setTargetEditorOpen(true)}
      >
       <Pencil size={13} />
      </IconButton>
     ) : null}
     {retargeted ? <Badge tone="warn">retargeted</Badge> : null}
    </div>
    <div className="detail-actions">
     {/* The frame type, when there is one. A WebSocket payload alone does not say how to read
              it, and an operator handed unlabelled binary bytes will edit them as text and forward a
              structurally valid frame with a corrupted body. Warn tone on binary because that is
              the case where the editor below is the wrong tool. */}
     {selected.opcode ? (
      <Badge tone={selected.opcode === "text" ? "info" : "warn"}>{selected.opcode}</Badge>
     ) : null}
     <Badge tone={selected.direction === "request" ? "info" : "good"}>{selected.direction}</Badge>
     <IconButton
      label={inspector ? "Hide Inspector" : "Show Inspector"}
      size="small"
      aria-pressed={inspector}
      onClick={() => setInspector((current) => !current)}
     >
      <Columns3 size={13} />
     </IconButton>
     <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
      <X size={13} />
     </IconButton>
    </div>
   </div>
   <div style={{ display: "grid", gridTemplateRows: "minmax(0, 1fr) auto", minHeight: 0 }}>
    <div className={inspector ? "held-grid-inspected" : "held-grid"}>
     <HttpEditor
      label="Held bytes"
      value={raw}
      onChange={editRaw}
      bodyBase64={rawBodyBase64}
      onBodyBytesChange={setRawBodyBase64}
      requestPath={selected.direction === "response" ? selected.path : undefined}
      filename={`held-${selected.id}.txt`}
      menuGroups={heldMenu(selected)}
     />
     {/* The Inspector edits `raw` — the same buffer the Forward button sends — so an
              edit made here is in the bytes that reach the client or the upstream, not a
              second draft that has to be copied across. This is the surface where that
              matters most: the message is held open and nothing else can change it. */}
     {inspector ? (
      <Inspector
       raw={raw}
       label={`Inspector · held ${selected.direction}`}
       onChange={editRaw}
      />
     ) : null}
    </div>
    {/* The operator's annotation (burpsy-react-ui-5q8u): comment + highlight, saved while
            the message is still held, riding into HTTP history when the hold forwards into a
            recorded exchange — Burp's "annotations that you make also appear against the item
            in the HTTP history". Lives under the editor, above the resolve toolbar, because
            annotating is triage of THIS message, not a resolve action. */}
    <Toolbar style={{ borderTop: "1px solid var(--line)", background: "var(--field-bg, transparent)" }}>
     <Input
      aria-label={`Annotation comment for held #${selected.id}`}
      value={commentDraft}
      onChange={(event) => setCommentDraft(event.target.value)}
      placeholder="Add a note…"
      style={{ maxWidth: "var(--w-md)" }}
     />
     <Select
      aria-label={`Highlight colour for held #${selected.id}`}
      value={highlightDraft}
      onChange={(event) => setHighlightDraft(event.target.value)}
      style={{ maxWidth: "var(--w-xs)" }}
     >
      <option value="">No highlight</option>
      <option value="red">Red</option>
      <option value="orange">Orange</option>
      <option value="yellow">Yellow</option>
      <option value="green">Green</option>
      <option value="blue">Blue</option>
      <option value="purple">Purple</option>
      <option value="pink">Pink</option>
     </Select>
     <Button
      variant="outline"
      size="small"
      onClick={saveAnnotation}
      disabled={annotateHeld.isPending || (commentDraft === (selected.comment ?? "") && highlightDraft === (selected.highlight ?? ""))}
     >
      <MessageSquare size={13} />
      Save annotation
     </Button>
    </Toolbar>
    <Toolbar style={{ borderTop: "1px solid var(--line)" }}>
     <Checkbox
      checked={fixContentLength}
      onCheckedChange={setFixContentLength}
      label="Fix Content-Length when forwarding"
     />
     {/* Burp's two newline corrections for an EDITED interception (80tg). Two switches rather than
         one because they are two different defects with two different symptoms: the missing blank
         line is a framing error the target reads as a header name, and the trailing newline in a form
         body is a value error a signature then fails. Fixing one does not fix the other, and an
         operator whose forward was rejected has no way to tell which they made.

         Both apply only to a request the operator EDITED. Untouched traffic came off the wire and is
         well-formed by construction, so rewriting it could only change bytes the target accepted. */}
     <Checkbox
      checked={newlines.add_missing_blank_line}
      onCheckedChange={(v) => setNewlines({ ...newlines, add_missing_blank_line: v })}
      label="Add a missing blank line after the headers when forwarding an edit"
     />
     <Checkbox
      checked={newlines.trim_trailing_newlines_urlencoded_body}
      onCheckedChange={(v) => setNewlines({ ...newlines, trim_trailing_newlines_urlencoded_body: v })}
      label="Remove trailing newlines from a URL-encoded body when forwarding an edit"
     />
     {/* Burp's "Only intercept in-scope messages" (burpsy-react-ui-cz1). Disabled with the
              reason shown when no scope is attached, rather than offered as a control that silently
              does nothing — the engine deliberately refuses to filter in that case, because an empty
              queue an operator cannot connect to a switch they flipped is worse than an unfiltered
              one. */}
     <Tooltip
      content={
       data?.scope_attached
        ? "Hold only traffic the engagement scope allows. Messages already held are untouched."
        : "No scope is attached to the intercept engine, so this would not filter anything."
      }
     >
      <span>
       <Checkbox
        checked={data?.in_scope_only ?? false}
        disabled={!data?.scope_attached}
        onCheckedChange={(next) =>
         controls.setInScopeOnly.mutate(next === true, {
          onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
         })
        }
        label="Only intercept in-scope messages"
       />
      </span>
     </Tooltip>
     <span style={{ flex: 1 }} />
     <Button onClick={forward} disabled={forwardHeld.isPending}>
      <Send size={14} />
      Forward
     </Button>
     <Button variant="danger" onClick={drop} disabled={controls.drop.isPending}>
      <Trash2 size={14} />
      Drop
     </Button>
     {/* Burp's queue toolbar pairs Forward with "Forward all" and Drop with "Drop all"
              (proxyForwardOptionsButton), and the destructive half shipped without the safe one
              (burpsy-react-ui-4v3): a queue that can only be emptied by dropping teaches the
              operator to stop queueing traffic at all. No confirmation, unlike Drop all — this
              forwards exactly what the clients sent, and the destructive direction is the one
              that needs the guard.

              Disabled, not hidden, when the queue is empty: a control that vanishes reads as a
              missing feature, and an operator who used it once will look for it again. */}
     <Button
      variant="outline"
      onClick={forwardAllHeld}
      disabled={held.length === 0 || controls.forwardAll.isPending}
      title={held.length === 0 ? "Nothing is held" : `Forward all ${held.length} held messages unmodified`}
     >
      <Send size={14} />
      Forward all{held.length > 0 ? ` (${held.length})` : ""}
     </Button>
     {/* Burp's queue toolbar has this, and burpsy's route has answered the count actually
              dropped since it was written — nothing called it (burpsy-react-ui-t6f).

              Disabled, not hidden, when the queue is empty: a control that vanishes reads as a
              missing feature, and an operator who used it once will look for it again. */}
     <Button
      variant="outline"
      onClick={() => setConfirmDropAll(true)}
      disabled={held.length === 0 || controls.dropAll.isPending}
      title={held.length === 0 ? "Nothing is held" : `Drop all ${held.length} held messages`}
     >
      <Trash2 size={14} />
      Drop all{held.length > 0 ? ` (${held.length})` : ""}
     </Button>
    </Toolbar>


    {/* Burp's "Edit target" editor. A dialog rather than an editable authority in the header bar:
        the header is a display, and making it hold a three-part destination would leave a Forward
        one keystroke away from a half-typed host. Nothing is sent until Forward, so the
        operator can look at the new destination and change their mind without the message having
        moved. */}
    <Modal
     open={targetEditorOpen}
     onOpenChange={setTargetEditorOpen}
     title={`Send held #${selected.id} somewhere else`}
     description={`Applies to this one request. The client's connection stays where it is, and the next request on it goes to ${selected.host}:${selected.port} again.`}
    >
     <TargetEditor
      original={targetOf(selected)}
      onApply={(target) => {
       setTargetDraft(target);
       setTargetEditorOpen(false);
      }}
      onRevert={() => {
       setTargetDraft(targetOf(selected));
       setTargetEditorOpen(false);
      }}
     />
    </Modal>
   </div>
  </div>
 ) : (
  <Empty title="Nothing selected" detail="Select a held message to view and edit its exact bytes before forwarding or dropping it." />
 );

 return (
  <div className="page-fill">
   {/* Drop all's confirmation lives at the page root, not inside the selected message's pane where
       its toolbar button is: Drop all is a queue-wide action, and the catalogue chord and palette
       entry (2czi) must reach the same confirmation with nothing selected. Inside the pane it was
       not mounted then, so the palette's Drop all set state no dialog read. */}
    <Modal
     open={confirmDropAll}
     onOpenChange={(open) => {
      if (!open) setConfirmDropAll(false);
     }}
     title={`Drop all ${held.length} held messages?`}
     description="Each client sees its request fail. Dropped traffic is not recoverable, and this discards messages you have not looked at."
    >
     <div className="page-actions">
      <Button variant="outline" onClick={() => setConfirmDropAll(false)}>
       Keep them held
      </Button>
      <Button
       variant="danger"
       disabled={controls.dropAll.isPending}
       onClick={() => {
        // `expected` is read before the call so the two numbers can be compared. The route
        // answers what it actually dropped, and a message resolved elsewhere between the
        // last poll and this request is not counted — so a smaller number is not an error,
        // it is the queue having moved. Saying so is how the operator learns that rather
        // than concluding the button half-worked.
        const expected = held.length;
        controls.dropAll.mutate(undefined, {
         onSuccess: (result) => {
          setConfirmDropAll(false);
          setSelectedId(null);
          const dropped = result.dropped;
          if (dropped === expected) {
           toast.success(`Dropped ${dropped} held message${dropped === 1 ? "" : "s"}`);
          } else {
           toast.success(
            `Dropped ${dropped} of the ${expected} shown — the rest resolved elsewhere before this request arrived`,
           );
          }
         },
         onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
        });
       }}
      >
       <Trash2 size={13} />
       {controls.dropAll.isPending ? "Dropping…" : `Drop all ${held.length}`}
      </Button>
     </div>
    </Modal>
   <div>
    <PageHeader
     title="Intercept"
     actions={
      <>
       <Badge tone={data?.wired ? "good" : "warn"}>{data?.wired ? "wired" : "not wired"}</Badge>
       <Switch
        checked={data?.enabled ?? false}
        onCheckedChange={toggle}
        label="Intercept is on"
       />
       <Button
        variant="outline"
        size="small"
        disabled={launch.isPending}
        title="Burp's Open browser: Chromium on its own profile, routed through burpsy's proxy and trusting burpsy's CA"
        onClick={() =>
         launch.mutate(undefined, {
          onSuccess: (result) => toast.success(describeLaunch(result)),
          // 503 is a named refusal written for the operator (no listener, no Chromium, root with the
          // sandbox on, no display) — shown verbatim.
          onError: (failure) => toast.error(`The browser did not open: ${failure.message}`, { duration: 15_000 }),
         })
        }
       >
        <Globe size={14} aria-hidden="true" />
        {launch.isPending ? "Opening…" : "Open browser"}
       </Button>
       {/* The protocol consequence belongs beside the switch, not only on the affected rows in
        history. This switch is where the operator decides to intercept, and turning it on moves
        every HTTP/2 client to HTTP/1.1 upstream because the hold queue holds whole HTTP/1-shaped
        messages. An operator who reads that here is choosing; an operator who only finds it on a
        history row has already been moved. burpsy-react-ui-y0l2. */}
       {data?.enabled ? (
        <span className="field-hint">
         Intercept is on — intercepted traffic is carried as HTTP/1.1, including clients that offered HTTP/2. Held rows
         from a downgraded client say so.
        </span>
       ) : (
        <span className="field-hint">Intercept is off</span>
       )}
      </>
     }
    />
    {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
    {data && !data.wired ? (
     <div className="notice notice-warn">{data.hint ?? "interception is not wired up"}</div>
    ) : null}
    <div className="metric-grid compact" style={{ marginTop: 10 }}>
     <Metric accent label="Pending" value={data?.pending ?? 0} />
     <Metric label="Mode" value={data?.enabled ? "Holding" : "Passing"} />
     <Metric label="Transport" value={data?.wired ? "Connected" : "Unavailable"} />
     <Metric label="Queue depth" value={heldAll.length} />
     <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <label htmlFor="direction-filter" style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>Show:</label>
      <Select
       id="direction-filter"
       aria-label="Filter by direction"
       value={directionFilter}
       onChange={(e) => setDirectionFilter(e.target.value as HeldDirectionFilter)}
       style={{ width: "auto" }}
      >
       <option value="all">All messages</option>
       <option value="request">Requests only</option>
       <option value="response">Responses only</option>
       {/* These values are Go's Direction.String(), which is what the API puts on each held
                  row — not the plural rule-endpoint suffixes. Using the wrong one filters to nothing
                  and looks exactly like an empty queue. */}
       <option value="websocket_to_server">WebSocket → server only</option>
       <option value="websocket_to_client">WebSocket → client only</option>
      </Select>
     </div>
    </div>
   </div>

   <Tabs defaultValue="queue" className="tabs-fill">
    <TabsList>
     <TabsTrigger value="queue">Queue</TabsTrigger>
     <TabsTrigger value="rules">Interception rules</TabsTrigger>
    </TabsList>
    <TabsContent value="queue" style={{ display: "grid", minHeight: 0 }}>
     {selectedIds.length > 0 ? (
      <Toolbar aria-label="Bulk actions for the checked messages">
       <span className="cell-dim">
        {selectedIds.length} checked
       </span>
       <Button size="small" onClick={() => void forwardSelected()} disabled={forwardHeld.isPending}>
        <Send size={13} />
        Forward checked
       </Button>
       <Button size="small" variant="danger" onClick={() => void dropSelected()} disabled={controls.drop.isPending}>
        <Trash2 size={13} />
        Drop checked
       </Button>
       <Button size="small" variant="outline" onClick={() => setSelectedIds([])}>
        Clear
       </Button>
      </Toolbar>
     ) : null}
     <SplitPane
      storageId="intercept"
      orientation="vertical"
      defaultMasterSize="50"
      master={
       <VirtualTable
        ariaLabel="Held messages"
        docTopic="intercept"
        data={held}
        columns={columns}
        getRowId={(row) => String(row.id)}
        selectedId={selectedId === null ? null : String(selectedId)}
        onSelect={(row) => setSelectedId(row.id)}
        onActivate={(row) => setSelectedId(row.id)}
        menuGroups={heldMenu}
        loading={isFetching && !data}
        empty={
         <Empty
          title="Queue is clear"
          detail={data?.enabled ? "Requests will stop here when a rule matches." : "Enable interception to hold matching traffic."}
         />
        }
       />
      }
      detail={detail}
     />
    </TabsContent>
    <TabsContent value="rules" style={{ overflowY: "auto", padding: 10 }}>
     <div className="two-col">
      <RuleEditor direction="requests" />
      <RuleEditor direction="responses" />
      <RuleEditor direction="websocket_to_server" />
      <RuleEditor direction="websocket_to_client" />
     </div>
     {/* Stated on the surface where the operator switches these on, because the limits are not
              guessable from the controls and each one changes what the queue will contain. See
              wsHoldable in internal/proxy/ws.go. */}
     <div className="notice" style={{ marginTop: 10 }}>
      <strong>What WebSocket interception does not hold.</strong> Control frames (ping, pong,
      close) are always relayed: holding a ping stalls the peer&apos;s keepalive and holding a
      close leaves a socket that cannot be ended. Compressed frames are relayed untouched too, and
      they only occur if you have turned off <code>Sec-WebSocket-Extensions</code> stripping in
      proxy options. They are now <em>decoded for WebSocket history</em> where the handshake
      agreed <code>no_context_takeover</code>, so you can read them — but they are still not
      offered for editing, because re-compressing one message of a shared compression stream
      would corrupt every later message on that connection, not just the edited one.
      <br />
      Fragmented messages <em>are</em> reassembled and offered whole, so nothing is relayed until
      the final fragment arrives. Forwarding without editing relays the original frames exactly
      as they came; an edit is sent as one unfragmented frame. A message larger than 1&nbsp;MiB is
      relayed unheld rather than buffered without bound.
     </div>
    </TabsContent>
   </Tabs>
  </div>
 );
}
