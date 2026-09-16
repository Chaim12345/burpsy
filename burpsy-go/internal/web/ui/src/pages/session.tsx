import { useEffect, useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, History, KeyRound, Pencil, Play, Plus, RotateCcw, Save, Trash2, Upload, X } from "lucide-react";
import { toast } from "sonner";
import { useDeleteSessionRule, useSaveSessionRule } from "../lib/data";
import { useMoveSessionRule, useSessionCookies, useSessionLogin, useSessionRulesFull, useTestSessionRule, useUpdateSessionMacro, useCookieJarWrite } from "../lib/data.policy";
import { MacroRecorder } from "../ui/macro-recorder";
import type {
 SessionAction,
 SessionExtractFrom,
 SessionExtractHow,
 SessionExtraction,
 SessionTestResponse,
 SessionLoginResponse,
 SessionMacroStep,
 SessionRuleFull,
 SessionValidity,
} from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { DetailList } from "../ui/json";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Switch, Textarea } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/* --- editor shapes --------------------------------------------------------
 * The wire carries `from` and `how` as unions and the scope as a document.
 * They are flattened on the way in and rebuilt on the way out, so every field
 * an operator edits is a real control instead of a JSON blob.
 */

interface ExtractDraft {
 name: string;
 fromKind: "body" | "header";
 header: string;
 how: "regex" | "json_path" | "whole";
 pattern: string;
 /** Blank means the server's default of 1 (the first capture), not group 0. */
 group: string;
}

interface StepDraft {
 method: string;
 url: string;
 headers: [string, string][];
 body: string;
 extract: ExtractDraft[];
}

interface RuleDraft {
 id?: number;
 name: string;
 enabled: boolean;
 /** Host patterns for the custom scope; an empty list means "applies everywhere". */
 hosts: string[];
 /** Burp's URL-scope radio (7nh2), from its own labels: "all" = Include all URLs, "suite" =
  * Use suite scope [defined in Target tab], "custom" = Use custom scope. The custom arms below
  * ride alongside the host list. */
 scopeMode: "all" | "suite" | "custom";
 /** Custom-scope arms: path prefix, port, protocol. Empty/undefined = the arm does not apply. */
 scopePath: string;
 scopePort: string;
 scopeProtocol: "" | "http" | "https";	/** Burp's parameter scope (burpsy-react-ui-9hip): the rule applies only where every named
	 * parameter exists. Empty = everywhere. */
	params: string[];
	/** Burp's tools scope (so3): the tools the rule applies to, from the server's own list.
	 * Empty = everywhere, which the section says out loud — the server refuses the wire form of
	 * "checked nothing" precisely so this reading is never what an operator gets by accident. */
	tools: string[];
 validity: SessionValidity;
 /** Kept as text so "" can mean "the server's default" rather than one attempt. */
 maxAttempts: string;
 steps: StepDraft[];
 /**
  * Burp's rule shape (burpsy-react-ui-ayi): the ordered list of things the rule does, and what the
  * proxy actually runs. `steps` below is the login flow a "Run a macro" action replays — one entry
  * of this list, not the list itself.
  *
  * Never empty, because the server never sends an empty one: a rule written before actions existed
  * arrives as the synthesis "check validity, and if not valid run the macro", which is what it
  * already behaved as. So the editor always has at least one row to show, and an operator clearing
  * every row is refused rather than silently given the login rule back.
  */
 actions: ActionDraft[];
}

/**
 * One rule action as the editor holds it. Nested children are kept only under `check_validity`,
 * which is where Burp nests and the only place the executor looks.
 */
interface ActionDraft {
 kind: string;
 enabled: boolean;
 stop: boolean;
 /** A RunMacro action's own steps; empty means the rule's own macro below. */
 macro: StepDraft[];
 then: ActionDraft[];
 else: ActionDraft[];
 name: string;
 value: string;
 in: "" | "query" | "body";
 match: string;
 replacement: string;
 regex: boolean;
 /** An InvokeExtension action's registration id. */
 extension: string;
}

const VALIDITY_FIELDS: { key: "body_contains" | "body_not_contains" | "header_present" | "header_absent"; label: string; hint: string }[] = [
 { key: "body_contains", label: "Body contains", hint: "Session is valid when the probe body contains this." },
 { key: "body_not_contains", label: "Body does not contain", hint: "For example a login form marker." },
 { key: "header_present", label: "Header present", hint: "Name only." },
 { key: "header_absent", label: "Header absent", hint: "Name only." },
];

const OUTCOME_TONE: Record<string, "good" | "warn" | "bad"> = {
 already_valid: "good",
 recovered: "good",
 no_rule_applies: "warn",
 still_invalid_after_relogin: "bad",
 gave_up: "bad",
 macro_failed: "bad",
 retry_failed: "bad",
 probe_failed: "bad",
};

function extractionIn(extraction: SessionExtraction): ExtractDraft {
 const from: SessionExtractFrom = extraction.from ?? "body";
 const how = extraction.how;
 const draft: ExtractDraft = {
  name: extraction.name,
  fromKind: typeof from === "object" ? "header" : "body",
  header: typeof from === "object" ? from.header : "",
  how: "regex",
  pattern: "",
  group: "1",
 };
 if (how === "whole") draft.how = "whole";
 else if ("json_path" in how) {
  draft.how = "json_path";
  draft.pattern = how.json_path;
 } else {
  draft.pattern = how.regex.pattern;
  draft.group = String(how.regex.group ?? 1);
 }
 return draft;
}

function extractionOut(draft: ExtractDraft): SessionExtraction {
 const from: SessionExtractFrom = draft.fromKind === "header" ? { header: draft.header } : "body";
 let how: SessionExtractHow;
 if (draft.how === "whole") how = "whole";
 else if (draft.how === "json_path") how = { json_path: draft.pattern };
 else {
  const parsed = Number(draft.group.trim());
  how = { regex: { pattern: draft.pattern, group: Number.isInteger(parsed) && parsed >= 0 ? parsed : 1 } };
 }
 return { name: draft.name, from, how };
}

/**
 * One wire step as an editable draft. Shared by the rule loader and the Macro Recorder, so a step
 * recorded from history and a step read back from a saved rule land in the editor in exactly the
 * same shape — a second mapping in the recorder is how a recorded step ends up with headers the
 * editor cannot round-trip.
 */
function stepIn(step: SessionMacroStep): StepDraft {
 return {
  method: step.method || "GET",
  url: step.url,
  headers: (step.headers ?? []).map(([name, value]) => [name, value] as [string, string]),
  body: step.body,
  extract: (step.extract ?? []).map(extractionIn),
 };
}

/**
 * One wire action as an editable draft, recursively.
 *
 * `macro` is left empty when the wire omits it, and that is the whole point of the field: an action
 * with no steps of its own runs the rule's macro below, so materialising the rule's steps into the
 * action here would launder a reference into a copy — the operator would edit the macro underneath
 * and find this action still sending the old text, with nothing on screen saying so.
 */
function actionIn(action: SessionAction): ActionDraft {
 return {
  kind: action.kind,
  enabled: action.enabled,
  stop: action.stop === true,
  macro: (action.macro ?? []).map(stepIn),
  then: (action.then ?? []).map(actionIn),
  else: (action.else ?? []).map(actionIn),
  name: action.name ?? "",
  value: action.value ?? "",
  in: (action.in as ActionDraft["in"]) ?? "",
  match: action.match ?? "",
  replacement: action.replacement ?? "",
  regex: action.regex === true,
  extension: action.extension ?? "",
 };
}

/**
 * Back to the wire. Fields a kind does not read are omitted rather than sent empty, because the
 * server *refuses* a kind-only field it does not use: sending the whole draft would make every rule
 * with a conditional check unsaveable the moment the editor carried a stray field.
 */
function actionOut(draft: ActionDraft): SessionAction {
 // `label` is deliberately not sent: it is the server's own words for the kind, and echoing a copy
 // back would make the editor's vocabulary look like the client's.
 const out: SessionAction = { kind: draft.kind, label: "", enabled: draft.enabled };
 if (draft.stop) out.stop = true;
 const macro = draft.macro.filter((step) => !isBlankStep(step)).map(stepOut);
 if (macro.length) out.macro = macro;
 if (draft.kind === "check_validity") {
  const then = draft.then.map(actionOut);
  const otherwise = draft.else.map(actionOut);
  if (then.length) out.then = then;
  if (otherwise.length) out.else = otherwise;
 }
 switch (draft.kind) {
  case "set_cookie":
  case "set_header":
   out.name = draft.name.trim();
   out.value = draft.value;
   break;
  case "set_param":
   out.name = draft.name.trim();
   out.value = draft.value;
   if (draft.in) out.in = draft.in;
   break;
  case "replace":
   out.match = draft.match;
   out.replacement = draft.replacement;
   if (draft.regex) out.regex = true;
   break;
  case "invoke_extension":
   out.extension = draft.extension.trim();
   break;
  default:
   break;
 }
 return out;
}

/** One fresh action of a kind, with the fields that kind requires pre-filled where there is a choice. */
function emptyAction(kind: string): ActionDraft {
 return {
  kind,
  enabled: true,
  stop: false,
  macro: [],
  then: [],
  else: [],
  name: "",
  value: "",
  in: "",
  match: "",
  replacement: "",
  regex: false,
  extension: "",
 };
}

function ruleIn(rule: SessionRuleFull): RuleDraft {
 const draft: RuleDraft = {
  name: rule.name,
  enabled: rule.enabled,
  hosts: (rule.scope?.rules ?? []).map((entry) => entry.host ?? "").filter(Boolean),
  // URL scope (7nh2): the mode and custom arms ride the scope block.
  scopeMode: (rule.scope?.mode as RuleDraft["scopeMode"]) ?? "all",
  scopePath: rule.scope?.path ?? "",
  scopePort: rule.scope?.port !== undefined && rule.scope?.port !== null ? String(rule.scope.port) : "",
  scopeProtocol: (rule.scope?.protocol as RuleDraft["scopeProtocol"]) ?? "",	params: rule.scope_params ?? [],
	tools: rule.scope_tools ?? [],
  validity: rule.validity ?? {},
  maxAttempts: rule.max_attempts === undefined ? "" : String(rule.max_attempts),
  steps: (rule.steps ?? []).map(stepIn),
  actions: (rule.actions ?? []).map(actionIn),
 };
 if (rule.id !== undefined) draft.id = rule.id;
 return draft;
}

function stepOut(step: StepDraft): SessionMacroStep {
 const wire: SessionMacroStep = {
  method: step.method.trim() || "GET",
  url: step.url.trim(),
  headers: step.headers.filter(([name]) => name.trim() !== ""),
  body: step.body,
 };
 const extract = step.extract.filter((entry) => entry.name.trim() !== "").map(extractionOut);
 if (extract.length) wire.extract = extract;
 return wire;
}

function ruleOut(draft: RuleDraft): SessionRuleFull {
 const steps: SessionMacroStep[] = draft.steps.map(stepOut);
 const actions: SessionAction[] = draft.actions.map(actionOut);
 const out: SessionRuleFull = {
  name: draft.name.trim(),
  enabled: draft.enabled,
  steps,
  validity: draft.validity,
  actions,
 };
 if (draft.id !== undefined) out.id = draft.id;
 // Omitted rather than sent empty: absent means "applies everywhere", and a stated
 // but empty scope is refused by the server because it would match nothing.
 // URL scope (7nh2): Burp's three-mode radio. "all" sends nothing (the historical shape);
 // "suite" sends the mode alone; "custom" sends the mode, the host rules and the URL arms.
 if (draft.scopeMode === "suite") {
  out.scope = { allow_all: true, mode: "suite", rules: [] };
 } else if (draft.scopeMode === "custom") {
  const port = Number(draft.scopePort.trim());
  out.scope = {
   allow_all: false,
   mode: "custom",
   ...(draft.scopePath.trim() ? { path: draft.scopePath.trim() } : {}),
   ...(draft.scopePort.trim() && Number.isInteger(port) && port > 0 ? { port } : {}),
   ...(draft.scopeProtocol ? { protocol: draft.scopeProtocol } : {}),
   rules: draft.hosts.map((host) => ({ kind: "Include" as const, host })),
  };
 } else if (draft.hosts.length) {
  out.scope = { allow_all: false, rules: draft.hosts.map((host) => ({ kind: "Include" as const, host })) };
 }	// Parameter scope is omitted when empty, like the host scope: absent means "applies
	// everywhere", so an operator who never opened the field never changes a rule's meaning.
	if (draft.params.length) {
		const names = draft.params.map((name) => name.trim()).filter(Boolean);
		if (names.length) out.scope_params = names;
	}
	// Same again for the tools scope. Omitted rather than sent empty: an empty array is the
	// server's refused "names no tools at all", which is a different statement from "every tool"
	// and must not be what the form says when the operator has restricted nothing.
	if (draft.tools.length) out.scope_tools = [...draft.tools];
 const attempts = Number(draft.maxAttempts.trim());
 if (draft.maxAttempts.trim() !== "" && Number.isInteger(attempts) && attempts > 0) out.max_attempts = attempts;
 return out;
}

/**
 * True for a step the editor created and nobody has touched yet.
 *
 * `emptyRule` seeds a rule with one of these, and "Add step" appends more of them, so before an
 * operator types anything every step in the editor is a placeholder. They exist to be typed into,
 * not to be sent: a macro step with an empty URL fails validation, so leaving them below recorded
 * steps would put an unrunnable step at the top of a login flow.
 *
 * The method is part of the test, and it is the only part that is not obviously required. Changing
 * it is the one edit an operator can make to a placeholder without typing any content, so a step
 * whose method is no longer the template's is a step somebody has formed an intention about — and
 * quietly discarding a deliberate choice is worse than leaving a visibly blank step on screen for
 * them to fill in.
 */
function isBlankStep(step: StepDraft): boolean {
  return (
    step.url === "" &&
    step.body === "" &&
    step.headers.length === 0 &&
    step.extract.length === 0 &&
    step.method.toUpperCase() === "POST"
  );
}

/**
 * Where recorded steps go: onto the end of what is already there, minus any untouched placeholders.
 *
 * Trailing placeholders only. A blank step the operator deliberately left in the middle of a flow
 * still marks a position — dropping it would silently renumber every step after it, and an
 * extraction is only usable by a *later* step, so renumbering is how a macro breaks. Trailing ones
 * are the ones the editor adds, and they hold no position to preserve: the recorded steps are about
 * to occupy exactly that place.
 */
function withRecordedSteps(current: StepDraft[], recorded: StepDraft[]): StepDraft[] {
  let keep = current.length;
  while (keep > 0) {
    const step = current[keep - 1];
    if (step === undefined || !isBlankStep(step)) break;
    keep -= 1;
  }
  return [...current.slice(0, keep), ...recorded];
}

function emptyRule(): RuleDraft {
 return {
  name: "",
  enabled: true,
  hosts: [],
  scopeMode: "all",
  scopePath: "",
  scopePort: "",
  scopeProtocol: "",	params: [],
	tools: [],
  validity: { status_is: 200 },
  maxAttempts: "",
  steps: [{ method: "POST", url: "", headers: [], body: "", extract: [] }],
  // A new rule starts as the flow burpsy already had — check, then log in — rather than as an empty
  // list, for the reason the server refuses an empty one: a rule with no actions does nothing, and
  // the operator's next step is to add to this list, not to discover it is inert.
  actions: [
   { ...emptyAction("check_validity"), else: [emptyAction("run_macro")] },
  ],
 };
}

function scopeSummary(rule: SessionRuleFull): string {
 const hosts = (rule.scope?.rules ?? []).map((entry) => entry.host ?? "").filter(Boolean);
 let hostPart = "every host";
 if (rule.scope && !rule.scope.allow_all && hosts.length > 0) hostPart = hosts.join(", ");	// The tools scope is a restriction on a different axis, and it is the one an operator is most
	// likely to have forgotten, so it is named first — "every host" alone reads as "fires for
	// everything" when a tools restriction may be quietly holding it back.
	const toolsPart = rule.scope_tools?.length ? `from ${rule.scope_tools.join(", ")}` : "";
	// A parameter scope is a further restriction; say what it needs so the row reads whole.
	if (rule.scope_params?.length) {
		return toolsPart
			? `${hostPart} ${toolsPart} carrying ${rule.scope_params.join(" + ")}`
			: `${hostPart} carrying ${rule.scope_params.join(" + ")}`;
	}
	return toolsPart ? `${hostPart} ${toolsPart}` : hostPart;
}

function hasNestedValidity(validity: SessionValidity): boolean {
 return validity.all !== undefined || validity.any !== undefined || validity.not !== undefined;
}

/** Editable [name, value] pairs. A JSON blob here was the single worst part of the old page. */
function HeaderPairs({
 headers,
 onChange,
 scope,
 disabled,
}: {
 headers: [string, string][];
 onChange: (next: [string, string][]) => void;
 /** Prefix for every accessible name, so two editors on one page stay distinguishable. */
 scope: string;
 disabled?: boolean;
}): JSX.Element {
 return (
  <div className="stack-tight">
   <span className="eyebrow">Headers</span>
   {headers.length === 0 ? <small className="field-hint">No headers. The sender adds only what a request needs.</small> : null}
   {headers.map(([name, value], index) => (
    <div className="kv-row" key={index}>
     <Input
      aria-label={`${scope} header ${index + 1} name`}
      title={`${scope} header ${index + 1} name`}
      value={name}
      placeholder="Content-Type"
      disabled={disabled}
      onChange={(event) => onChange(headers.map((pair, i) => (i === index ? [event.target.value, pair[1]] : pair)))}
     />
     <Input
      aria-label={`${scope} header ${index + 1} value`}
      title={`${scope} header ${index + 1} value`}
      value={value}
      placeholder="application/x-www-form-urlencoded"
      disabled={disabled}
      onChange={(event) => onChange(headers.map((pair, i) => (i === index ? [pair[0], event.target.value] : pair)))}
     />
     <IconButton
      label={`Remove ${scope} header ${index + 1}`}
      size="small"
      disabled={disabled}
      onClick={() => onChange(headers.filter((_, i) => i !== index))}
     >
      <X size={13} />
     </IconButton>
    </div>
   ))}
   <div>
    <Button variant="outline" size="small" disabled={disabled} onClick={() => onChange([...headers, ["", ""]])}>
     <Plus size={13} />
     Add header
    </Button>
   </div>
  </div>
 );
}

function ExtractionRows({
 step,
 index,
 onChange,
 disabled,
}: {
 step: StepDraft;
 index: number;
 onChange: (next: ExtractDraft[]) => void;
 disabled?: boolean;
}): JSX.Element {
 const patch = (position: number, changes: Partial<ExtractDraft>) =>
  onChange(step.extract.map((entry, i) => (i === position ? { ...entry, ...changes } : entry)));

 return (
  <div className="stack-tight">
   <span className="eyebrow">Extract from this step&apos;s response</span>
   {step.extract.length === 0 ? (
    <small className="field-hint">
     A later step sends an earlier extraction as <code>{"{{name}}"}</code>.
    </small>
   ) : null}
   {step.extract.map((entry, position) => (
    <div className="ex-row" key={position}>
     <Input
      aria-label={`Step ${index + 1} extraction ${position + 1} name`}
      title={`Step ${index + 1} extraction ${position + 1} name`}
      value={entry.name}
      placeholder="csrf"
      disabled={disabled}
      onChange={(event) => patch(position, { name: event.target.value })}
     />
     <Select
      aria-label={`Step ${index + 1} extraction ${position + 1} source`}
      title={`Step ${index + 1} extraction ${position + 1} source`}
      value={entry.fromKind}
      disabled={disabled}
      onChange={(event) => patch(position, { fromKind: event.target.value === "header" ? "header" : "body" })}
     >
      <option value="body">From body</option>
      <option value="header">From header</option>
     </Select>
     <Input
      aria-label={`Step ${index + 1} extraction ${position + 1} header name`}
      title={`Step ${index + 1} extraction ${position + 1} header name`}
      value={entry.header}
      placeholder="X-Token"
      disabled={disabled || entry.fromKind !== "header"}
      onChange={(event) => patch(position, { header: event.target.value })}
     />
     <Select
      aria-label={`Step ${index + 1} extraction ${position + 1} method`}
      title={`Step ${index + 1} extraction ${position + 1} method`}
      value={entry.how}
      disabled={disabled}
      onChange={(event) => {
       const value = event.target.value;
       patch(position, { how: value === "json_path" ? "json_path" : value === "whole" ? "whole" : "regex" });
      }}
     >
      <option value="regex">Regex</option>
      <option value="json_path">JSON path</option>
      <option value="whole">Whole value</option>
     </Select>
     <Input
      aria-label={`Step ${index + 1} extraction ${position + 1} pattern`}
      title={`Step ${index + 1} extraction ${position + 1} pattern`}
      value={entry.pattern}
      placeholder={entry.how === "json_path" ? "data.token" : 'name="csrf" value="([^"]+)"'}
      disabled={disabled || entry.how === "whole"}
      onChange={(event) => patch(position, { pattern: event.target.value })}
     />
     <Input
      aria-label={`Step ${index + 1} extraction ${position + 1} capture group`}
      title={`Step ${index + 1} extraction ${position + 1} capture group`}
      value={entry.group}
      placeholder="1"
      disabled={disabled || entry.how !== "regex"}
      onChange={(event) => patch(position, { group: event.target.value })}
     />
     <IconButton
      label={`Remove step ${index + 1} extraction ${position + 1}`}
      size="small"
      disabled={disabled}
      onClick={() => onChange(step.extract.filter((_, i) => i !== position))}
     >
      <X size={13} />
     </IconButton>
    </div>
   ))}
   <div>
    <Button
     variant="outline"
     size="small"
     disabled={disabled}
     onClick={() => onChange([...step.extract, { name: "", fromKind: "body", header: "", how: "regex", pattern: "", group: "1" }])}
    >
     <Plus size={13} />
     Add extraction
    </Button>
   </div>
  </div>
 );
}

function StepCard({
 step,
 index,
 total,
 disabled,
 onChange,
 onMove,
 onRemove,
}: {
 step: StepDraft;
 index: number;
 total: number;
 disabled?: boolean;
 onChange: (next: StepDraft) => void;
 onMove: (delta: number) => void;
 onRemove: () => void;
}): JSX.Element {
 return (
  <div className="step-card">
   <div className="step-head">
    {/* Step numbers are load-bearing: an extraction is only usable by a later step. */}
    <Badge tone="info">step {index + 1}</Badge>
    <Input
     aria-label={`Step ${index + 1} method`}
     title={`Step ${index + 1} method`}
     value={step.method}
     placeholder="POST"
     disabled={disabled}
     style={{ maxWidth: "clamp(70px, 7vw, 120px)" }}
     onChange={(event) => onChange({ ...step, method: event.target.value })}
    />
    <Input
     aria-label={`Step ${index + 1} URL`}
     title={`Step ${index + 1} URL`}
     value={step.url}
     placeholder="https://target.test/login"
     disabled={disabled}
     onChange={(event) => onChange({ ...step, url: event.target.value })}
    />
    <IconButton label={`Move step ${index + 1} up`} size="small" disabled={disabled || index === 0} onClick={() => onMove(-1)}>
     <ArrowUp size={13} />
    </IconButton>
    <IconButton
     label={`Move step ${index + 1} down`}
     size="small"
     disabled={disabled || index === total - 1}
     onClick={() => onMove(1)}
    >
     <ArrowDown size={13} />
    </IconButton>
    <IconButton label={`Remove step ${index + 1}`} size="small" disabled={disabled} onClick={onRemove}>
     <Trash2 size={13} />
    </IconButton>
   </div>
   <HeaderPairs
    headers={step.headers}
    scope={`Step ${index + 1}`}
    disabled={disabled}
    onChange={(headers) => onChange({ ...step, headers })}
   />
   <Field label={`Step ${index + 1} body`} hint="Sent verbatim; {{name}} is replaced by an earlier extraction.">
    {(id) => (
     <Textarea
      id={id}
      value={step.body}
      placeholder="user=admin&password={{password}}"
      disabled={disabled}
      onChange={(event) => onChange({ ...step, body: event.target.value })}
     />
    )}
   </Field>
   <ExtractionRows step={step} index={index} disabled={disabled} onChange={(extract) => onChange({ ...step, extract })} />
  </div>
 );
}

/**
 * One action row, and its branches when it is a validity check.
 *
 * # Why the branches are edited here rather than as a separate list
 *
 * Burp nests sub-actions under "Check whether the current session is valid, and perform sub-actions
 * conditionally on the result", and that nesting *is* the parallelism an operator reasons about —
 * flattening it into one list with a "branch" column would make two runs of the same rule look like
 * one sequence. So the shape on screen is the shape the executor walks.
 *
 * Depth is bounded at two levels of check, and the add control says so rather than disappearing: a
 * check inside a check inside a check is a rule nobody can read the outcome of, and the server's own
 * validation walks the tree rather than bounding it, so the bound belongs to the editor's judgement
 * and is stated where an operator would look for it.
 */
function ActionCard({
 action,
 index,
 total,
 depth,
 palette,
 ruleStepCount,
 disabled,
 onChange,
 onMove,
 onRemove,
}: {
 action: ActionDraft;
 index: number;
 total: number;
 depth: number;
 palette: { kind: string; label: string }[];
 /** How many steps the rule's own macro has, so a RunMacro action can say what it will replay. */
 ruleStepCount: number;
 disabled?: boolean;
 onChange: (next: ActionDraft) => void;
 onMove: (delta: number) => void;
 onRemove: () => void;
}): JSX.Element {
 const label = palette.find((entry) => entry.kind === action.kind)?.label ?? action.kind;
 const isCheck = action.kind === "check_validity";
 const isMacro = action.kind === "run_macro" || action.kind === "run_post_request_macro";
 const patch = (next: Partial<ActionDraft>) => onChange({ ...action, ...next });

 const branch = (which: "then" | "else") => (
  <div className="stack-tight">
   <span className="eyebrow">{which === "then" ? "If the session is valid" : "If it is not (or cannot be told)"}</span>
   {action[which].length === 0 ? (
    <small className="field-hint">
     {which === "then"
      ? "Nothing runs when the check says the session is valid."
      : "Nothing runs when the check says the session is not valid. An undecidable check takes this branch too — reading \u201cI could not tell\u201d as \u201cit is fine\u201d is the wrong way to fail."}
    </small>
   ) : null}
   {action[which].map((child, childIndex) => (
    <ActionCard
     key={childIndex}
     action={child}
     index={childIndex}
     total={action[which].length}
     depth={depth + 1}
     palette={palette}
     ruleStepCount={ruleStepCount}
     disabled={disabled}
     onChange={(next) => patch({ [which]: action[which].map((value, i) => (i === childIndex ? next : value)) } as Partial<ActionDraft>)}
     onMove={(delta) => {
      const list = [...action[which]];
      const to = childIndex + delta;
      if (to < 0 || to >= list.length) return;
      const moved = list[childIndex];
      const target = list[to];
      if (moved === undefined || target === undefined) return;
      list[to] = moved;
      list[childIndex] = target;
      patch({ [which]: list } as Partial<ActionDraft>);
     }}
     onRemove={() => patch({ [which]: action[which].filter((_, i) => i !== childIndex) } as Partial<ActionDraft>)}
    />
   ))}
   <div className="inline-add">
    <Select
     aria-label={`Add an action to the ${which} branch`}
     title={`Add an action to the ${which} branch`}
     value=""
     disabled={disabled || depth >= 2}
     onChange={(event) => {
      if (!event.target.value) return;
      patch({ [which]: [...action[which], emptyAction(event.target.value)] } as Partial<ActionDraft>);
     }}
    >
     <option value="">{depth >= 2 ? "Nesting stops here" : "Add an action\u2026"}</option>
     {palette.map((entry) => (
      <option key={entry.kind} value={entry.kind}>
       {entry.label}
      </option>
     ))}
    </Select>
   </div>
  </div>
 );

 return (
  <div className="step-card" style={depth > 0 ? { marginLeft: "1rem" } : undefined}>
   <div className="step-head">
    <Badge tone={action.enabled ? "info" : "neutral"}>{index + 1}</Badge>
    <Select
     aria-label={`Action ${index + 1} kind`}
     title={`Action ${index + 1} kind`}
     value={action.kind}
     disabled={disabled}
     onChange={(event) => patch({ kind: event.target.value })}
    >
     {palette.map((entry) => (
      <option key={entry.kind} value={entry.kind}>
       {entry.label}
      </option>
     ))}
    </Select>
    <IconButton label={`Move action ${index + 1} up`} size="small" disabled={disabled || index === 0} onClick={() => onMove(-1)}>
     <ArrowUp size={13} />
    </IconButton>
    <IconButton
     label={`Move action ${index + 1} down`}
     size="small"
     disabled={disabled || index === total - 1}
     onClick={() => onMove(1)}
    >
     <ArrowDown size={13} />
    </IconButton>
    <IconButton label={`Remove action ${index + 1}`} size="small" disabled={disabled} onClick={onRemove}>
     <Trash2 size={13} />
    </IconButton>
   </div>
   <div className="inline-add">
    <Checkbox
     label="Enabled"
     checked={action.enabled}
     disabled={disabled}
     onCheckedChange={(on) => patch({ enabled: on })}
    />
    {/* Burp's "unless one of the actions specifies that no further actions should be applied to
        the request". Offered on every kind, because that is what Burp does — the switch is about
        the request, not about the action that happens to carry it. */}
    <Checkbox
     label="No further actions apply to this request"
     checked={action.stop}
     disabled={disabled}
     onCheckedChange={(on) => patch({ stop: on })}
    />
   </div>

   {isMacro ? (
    action.macro.length > 0 ? (
     <div className="notice notice-warn">
      <span>
       This action carries its own {action.macro.length} step(s), so it replays those and not the
       rule&apos;s macro below. That is what the rule already states — it is shown rather than folded
       into the macro section, because editing that section would otherwise appear to change this
       action and would not.
      </span>
      <Button variant="outline" size="small" disabled={disabled} onClick={() => patch({ macro: [] })}>
       Use the rule&apos;s macro instead
      </Button>
     </div>
    ) : (
     <small className="field-hint">
      Runs the rule&apos;s {ruleStepCount} macro step(s) below. A macro action never sends the request
      being processed — for that, use "Run a post-request macro".
     </small>
    )
   ) : null}

   {action.kind === "add_cookies_from_jar" ? (
    <small className="field-hint">
     Attaches the session-handling jar&apos;s cookies for this request&apos;s own host, port and
     scheme. That used to happen implicitly on every send; as an action it can be ordered against a
     macro that rewrites the cookie the request should carry.
    </small>
   ) : null}

   {action.kind === "set_cookie" || action.kind === "set_header" || action.kind === "set_param" ? (
    <div className="form-grid">
     <Field label={action.kind === "set_cookie" ? "Cookie name" : action.kind === "set_header" ? "Header name" : "Parameter name"}>
      {(id) => (
       <Input id={id} value={action.name} disabled={disabled} onChange={(event) => patch({ name: event.target.value })} />
      )}
     </Field>
     <Field label="Value" hint="{{name}} is replaced by a value a macro action extracted earlier in this list.">
      {(id) => (
       <Input id={id} value={action.value} disabled={disabled} onChange={(event) => patch({ value: event.target.value })} />
      )}
     </Field>
     {action.kind === "set_param" ? (
      <Field label="Where" hint="Blank means wherever the parameter already is, and the query string when it is nowhere.">
       {(id) => (
        <Select
         id={id}
         value={action.in}
         disabled={disabled}
         onChange={(event) => patch({ in: event.target.value as ActionDraft["in"] })}
        >
         <option value="">Wherever it is</option>
         <option value="query">Query string</option>
         <option value="body">Form body</option>
        </Select>
       )}
      </Field>
     ) : null}
    </div>
   ) : null}

   {action.kind === "replace" ? (
    <>
     <div className="form-grid">
      <Field label="Match">
       {(id) => <Input id={id} value={action.match} disabled={disabled} onChange={(event) => patch({ match: event.target.value })} />}
      </Field>
      <Field label="Replace with">
       {(id) => (
        <Input id={id} value={action.replacement} disabled={disabled} onChange={(event) => patch({ replacement: event.target.value })} />
       )}
      </Field>
     </div>
     <div className="inline-add">
      <Checkbox
       label="Regular expression"
       checked={action.regex}
       disabled={disabled}
       onCheckedChange={(on) => patch({ regex: on })}
      />
     </div>
     <small className="field-hint">
      Applied to the URL, every header name and value, and the body — over the request as the actions
      before it left it.
     </small>
    </>
   ) : null}

   {action.kind === "invoke_extension" ? (
    <>
     <Field
      label="Extension registration"
      hint="The registration id a loaded plugin declared as a session-handling action. The plugin is resolved by that id, so two plugins must not use the same one."
     >
      {(id) => (
       <Input id={id} value={action.extension} disabled={disabled} onChange={(event) => patch({ extension: event.target.value })} />
      )}
     </Field>
     <small className="field-hint">
      The plugin is handed the request as the actions before this one left it, and answers with the
      request to send. With no plugin loaded the action is refused and says so — nothing is sent
      silently unchanged.
     </small>
    </>
   ) : null}

   {isCheck ? (
    <>
     <small className="field-hint">
      Evaluated against the rule&apos;s validity check below, unless this action states one of its
      own (in which case that one is used, and the section below is not consulted by this action).
     </small>
     {branch("then")}
     {branch("else")}
    </>
   ) : null}

   <p className="field-hint">Kind: {label}</p>
  </div>
 );
}

export function SessionPage(): JSX.Element {
 const rulesQuery = useSessionRulesFull();
 const cookiesQuery = useSessionCookies();
 // The jar's write surface (dkb): edit, remove per cookie, clear per authority. Every action
 // goes through one mutation so the table cannot show a state the write side disagrees with.
 const jarWrite = useCookieJarWrite();
 const [editingCookie, setEditingCookie] = useState<{ host: string; port: number; tls: boolean; name: string; value: string } | null>(null);

 const applyCookieWrite = (vars: { action: "set" | "remove" | "clear"; host: string; port: number; tls: boolean; name?: string; value?: string }, label: string) =>
  jarWrite.mutate(vars, {
   onSuccess: (out) => {
    if (out.action === "remove" && out.removed === false) {
     toast.warning(`${label}: the cookie was not in the jar`);
    } else if (out.action === "clear" && out.cleared === false) {
     toast.warning(`${label}: the authority had no jar`);
    } else {
     toast.success(label);
    }
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Cookie jar write failed"),
  });
 const saveRule = useSaveSessionRule();
 const deleteRule = useDeleteSessionRule();
 const moveRuleMut = useMoveSessionRule();
 const login = useSessionLogin();
 const promoteMacro = useUpdateSessionMacro();
 const testMacro = useTestSessionRule();
 // The Test-macro report for the open rule (burpsy-react-ui-7zdm). State, not cache: a dry-run is
 // a one-shot answer to "what would this macro do right now", not a resource to re-render from.
 const [testReport, setTestReport] = useState<SessionTestResponse | null>(null);

 /** Selection is by rule id; a new rule is `{ id: null }` until the server assigns one. */
 const [editing, setEditing] = useState<RuleDraft | null>(null);
 const [baseline, setBaseline] = useState("");
 const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
 const [newHost, setNewHost] = useState("");
 const [newParam, setNewParam] = useState("");

 // The Macro Recorder (burpsy-react-ui-escl): Burp builds a macro by selecting rows out of the
 // Proxy history, and until this existed the only way to reproduce a documented login flow was to
 // retype a request the proxy had already captured.
 const [recorderOpen, setRecorderOpen] = useState(false);

 const [probe, setProbe] = useState<StepDraft>({ method: "GET", url: "", headers: [], body: "", extract: [] });
 const [loginResult, setLoginResult] = useState<SessionLoginResponse | null>(null);
 /** Only a run that actually replayed a macro leaves something to promote. */
 const [promotable, setPromotable] = useState<{ id: number; name: string } | null>(null);

 const wired = rulesQuery.data?.wired ?? true;
 const rules = rulesQuery.data?.rules ?? [];
 // The action palette and the declined list come from the same response as the rules, so the
 // editor's vocabulary cannot drift from what this build validates — see the response's own note.
 const actionKinds = rulesQuery.data?.action_kinds;
 const declinedActions = rulesQuery.data?.declined_actions;
 const dirty = editing !== null && JSON.stringify(editing) !== baseline;

 // Re-adopt the server's copy of the open rule only while nothing is unsaved.
 useEffect(() => {
  if (editing?.id === undefined || dirty) return;
  const fresh = rules.find((rule) => rule.id === editing.id);
  if (!fresh) return;
  const next = ruleIn(fresh);
  const encoded = JSON.stringify(next);
  if (encoded === baseline) return;
  setEditing(next);
  setBaseline(encoded);
 }, [rules, editing, dirty, baseline]);

 const open = (rule: SessionRuleFull) => {
  const draft = ruleIn(rule);
  setEditing(draft);
  setBaseline(JSON.stringify(draft));
 };

 const startNew = () => {
  const draft = emptyRule();
  setEditing(draft);
  // A new rule is dirty by definition: nothing on the server matches it yet.
  setBaseline("");
 };

 const patchStep = (index: number, next: StepDraft) =>
  setEditing((current) =>
   current === null ? current : { ...current, steps: current.steps.map((step, i) => (i === index ? next : step)) },
  );

 const moveStep = (index: number, delta: number) =>
  setEditing((current) => {
   if (current === null) return current;
   const target = index + delta;
   if (target < 0 || target >= current.steps.length) return current;
   const steps = [...current.steps];
   const [moved] = steps.splice(index, 1);
   if (!moved) return current;
   steps.splice(target, 0, moved);
   return { ...current, steps };
  });

 const onSave = () => {
  if (!editing) return;
  if (!editing.name.trim()) {
   toast.error("A rule needs a name");
   return;
  }
  if (editing.steps.length === 0) {
   toast.error("A rule needs at least one macro step");
   return;
  }
  const payload = ruleOut(editing);
  saveRule.mutate(payload, {
   onSuccess: (result) => {
    // The server assigns the id on create; re-read it so the next save is a PUT.
    const assigned = result.rule?.id;
    const draft = ruleIn(assigned === undefined ? payload : { ...payload, id: assigned });
    setEditing(draft);
    setBaseline(JSON.stringify(draft));
    toast.success(`Saved “${payload.name}”`);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Save failed"),
  });
 };

 const runTestMacro = () => {
  if (editing?.id === undefined) return;
  testMacro.mutate(editing.id, {
   onSuccess: (report) => {
    setTestReport(report);
    toast.success(`Test macro ran ${report.steps.length} step${report.steps.length === 1 ? "" : "s"}`);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Test macro failed"),
  });
 };

 const onDelete = (id: number) => {
  deleteRule.mutate(id, {
   onSuccess: () => {
    if (editing?.id === id) {
     setEditing(null);
     setBaseline("");
    }
    if (promotable?.id === id) setPromotable(null);
    toast.success("Rule deleted");
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Delete failed"),
  });
  setConfirmDelete(null);
 };

 const toggleEnabled = (rule: SessionRuleFull, enabled: boolean) => {
  const payload: SessionRuleFull = { ...rule, enabled };
  saveRule.mutate(payload, {
   onSuccess: () => toast.success(enabled ? `“${rule.name}” enabled` : `“${rule.name}” paused`),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not change the rule"),
  });
 };

 /**
  * Move a rule within the evaluation order. MatchingRule runs the first enabled rule whose
  * scope covers a host, so list position is which login wins for an overlapping host; the
  * server refuses a move past either end (400 naming the edge) rather than clamping, and the
  * rules list re-reads on success so the row order here is always the evaluation order.
  */
 const moveRule = (rule: SessionRuleFull, offset: number) => {
  if (rule.id === undefined) return;
  moveRuleMut.mutate(
   { id: rule.id, offset },
   {
    onSuccess: () => undefined,
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not move the rule"),
   },
  );
 };

 const runLogin = () => {
  if (!probe.url.trim()) {
   toast.error("The probe needs a URL to test the session against");
   return;
  }
  setPromotable(null);
  const step: SessionMacroStep = {
   method: probe.method.trim() || "GET",
   url: probe.url.trim(),
   headers: probe.headers.filter(([name]) => name.trim() !== ""),
   body: probe.body,
  };
  login.mutate(step, {
   onSuccess: (result) => {
    setLoginResult(result);
    const tone = result.outcome ? OUTCOME_TONE[result.outcome] : undefined;
    // Reported honestly: "the login ran and did not work" is not a success.
    if (tone === "good") toast.success(`Session ${result.outcome === "recovered" ? "recovered" : "already valid"}`);
    else toast.error(`Login outcome: ${result.outcome ?? "unknown"}`);
    if (result.outcome === "recovered" && typeof result.rule_id === "number") {
     setPromotable({ id: result.rule_id, name: result.rule ?? `rule ${result.rule_id}` });
    }
   },
   onError: (failure: unknown) => {
    setLoginResult(null);
    toast.error(failure instanceof Error ? failure.message : "Login attempt failed");
   },
  });
 };

 const cookieRows = useMemo(
  () =>
   (cookiesQuery.data?.cookies ?? []).flatMap((jar) =>
    jar.cookies.map((cookie) => ({
     host: jar.host,
     // The scheme is what distinguishes two jars for the same host:port, so it is shown rather
     // than left to be inferred from the port — 8443 over plain HTTP is a real configuration.
     scheme: jar.tls ? "https" : "http",
     name: cookie.name,
     value: cookie.value,
    })),
   ),
  [cookiesQuery.data],
 );

 const loginRows = useMemo(() => {
  const result = loginResult;
  if (!result) return [];
  const rows: { label: string; value: ReactNode }[] = [];
  if (result.outcome) {
   rows.push({
    label: "Outcome",
    value: <Badge tone={OUTCOME_TONE[result.outcome] ?? "neutral"}>{result.outcome}</Badge>,
   });
  }
  if (result.rule) rows.push({ label: "Rule", value: result.rule });
  if (result.url) rows.push({ label: "Probe URL", value: <code>{result.url}</code> });
  if (typeof result.rules === "number") rows.push({ label: "Rules configured", value: result.rules });
  if (typeof result.login_attempts === "number") rows.push({ label: "Login attempts", value: result.login_attempts });
  if (typeof result.attempt === "number") rows.push({ label: "Failed on attempt", value: result.attempt });
  if (typeof result.step_index === "number") rows.push({ label: "Failed at step", value: result.step_index + 1 });
  if (result.validity) rows.push({ label: "Validity", value: result.validity });
  if (typeof result.response?.status === "number") rows.push({ label: "Probe status", value: result.response.status });
  if (result.hint) rows.push({ label: "Hint", value: result.hint });
  if (result.error) rows.push({ label: "Error", value: result.error });
  return rows;
 }, [loginResult]);

 if (rulesQuery.error) {
  return (
   <div className="page">
    <PageHeader title="Session" />
    <ErrorNotice error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
   </div>
  );
 }

 if (rulesQuery.isLoading) {
  return (
   <div className="page">
    <PageHeader title="Session" />
    <LoadingPanel label="Loading session rules" />
   </div>
  );
 }

 const nested = editing !== null && hasNestedValidity(editing.validity);

 return (
  <div className="page">
   <PageHeader
    title="Session"
    description="A rule names a login: which hosts it covers, the steps to replay, and what a valid session looks like."
    actions={
     <>
      <Badge tone={wired ? "good" : "warn"}>{wired ? "wired" : "not wired"}</Badge>
      <Button variant="outline" size="small" onClick={startNew} disabled={!wired}>
       <Plus size={13} />
       New rule
      </Button>
      <RefreshButton onClick={() => void rulesQuery.refetch()} loading={rulesQuery.isFetching} />
     </>
    }
   />

   {!wired ? (
    <div className="notice notice-warn" role="status">
     <span>{rulesQuery.data?.hint ?? "Session re-login is not attached to this process, so nothing here can run."}</span>
    </div>
   ) : null}

   <Card>
    <SectionHeading
     title="Login rules"
     detail="Rules are matched by host; the first that applies owns the recovery."
     actions={<Badge>{rules.length} configured</Badge>}
    />
    {rules.length === 0 ? (
     <Empty
      title="No session rules"
      detail="Create a rule to describe how to log in again when the proxy sees an expired session."
      action={
       <Button variant="outline" size="small" onClick={startNew} disabled={!wired}>
        <Plus size={13} />
        New rule
       </Button>
      }
     />
    ) : (
     <SimpleTable headers={["On", "Name", "Hosts", "Steps", "Extractions", "Max attempts", ""]}>
      {rules.map((rule, index) => {
       const id = rule.id;
       const extractions = (rule.steps ?? []).reduce((total, step) => total + (step.extract?.length ?? 0), 0);
       return (
        <tr key={id ?? `unsaved-${index}`} className={editing?.id !== undefined && editing.id === id ? "selected-row" : undefined}>
         <td>
          <Switch
           label={`Enable ${rule.name || `rule ${index + 1}`}`}
           checked={rule.enabled}
           onCheckedChange={(checked) => toggleEnabled(rule, checked)}
          />
         </td>
         <td>
          <strong>{rule.name || `Rule ${index + 1}`}</strong>
         </td>
         <td>
          <span className="cell-dim">{scopeSummary(rule)}</span>
         </td>
         <td>
          <span className="cell-num">{rule.steps?.length ?? 0}</span>
         </td>
         <td>
          <span className="cell-num">{extractions}</span>
         </td>
         <td>
          <span className="cell-dim">{rule.max_attempts ?? "default"}</span>
         </td>
         <td>
          <div className="chip-row">
           <IconButton
            label={`Move ${rule.name || `rule ${index + 1}`} up — it is evaluated before the rule below it`}
            size="small"
            disabled={id === undefined || index === 0}
            onClick={() => (id === undefined ? undefined : moveRule(rule, -1))}
           >
            <ArrowUp size={13} />
           </IconButton>
           <IconButton
            label={`Move ${rule.name || `rule ${index + 1}`} down`}
            size="small"
            disabled={id === undefined || index === rules.length - 1}
            onClick={() => (id === undefined ? undefined : moveRule(rule, 1))}
           >
            <ArrowDown size={13} />
           </IconButton>
           <IconButton label={`Edit ${rule.name || `rule ${index + 1}`}`} size="small" onClick={() => open(rule)}>
            <Pencil size={13} />
           </IconButton>
           <IconButton
            label={`Delete ${rule.name || `rule ${index + 1}`}`}
            size="small"
            disabled={id === undefined}
            onClick={() => (id === undefined ? undefined : setConfirmDelete(id))}
           >
            <Trash2 size={13} />
           </IconButton>
          </div>
         </td>
        </tr>
       );
      })}
     </SimpleTable>
    )}
   </Card>

   {editing ? (
    <Card>
     <SectionHeading
      title={editing.id === undefined ? "New rule" : `Rule ${editing.id}`}
      detail="Saved as one document: scope, macro steps, extractions and the validity check."
      actions={
       <>
        {dirty ? <Badge tone="warn">unsaved changes</Badge> : <Badge tone="good">saved</Badge>}
        <Button
         variant="outline"
         size="small"
         disabled={!dirty || !baseline}
         onClick={() => {
          if (!baseline) return;
          setEditing(JSON.parse(baseline) as RuleDraft);
          toast.success("Reverted to the saved rule");
         }}
        >
         <RotateCcw size={13} />
         Revert
        </Button>
        <Button size="small" onClick={onSave} disabled={!wired || saveRule.isPending}>
         <Save size={13} />
         {saveRule.isPending ? "Saving…" : "Save rule"}
        </Button>
        <Button
         variant="outline"
         size="small"
         disabled={!wired || editing.id === undefined || testMacro.isPending}
         title={editing.id === undefined ? "Save the rule before testing it" : "Dry-run this rule's macro steps"}
         onClick={runTestMacro}
        >
         <Play size={13} />
         {testMacro.isPending ? "Testing…" : "Test macro"}
        </Button>
        <IconButton
         label="Close the rule editor"
         size="small"
         onClick={() => {
          setEditing(null);
          setBaseline("");
         }}
        >
         <X size={13} />
        </IconButton>
       </>
      }
     />

     <div className="stack">
      <div className="form-grid">
       <Field label="Name" hint="Shown in the rule list and in login outcomes.">
        {(id) => (
         <Input
          id={id}
          value={editing.name}
          placeholder="admin login"
          disabled={!wired}
          onChange={(event) => setEditing({ ...editing, name: event.target.value })}
         />
        )}
       </Field>
       <Field label="Enabled" htmlFor="session-rule-enabled">
        <Switch
         id="session-rule-enabled"
         label="Rule enabled"
         checked={editing.enabled}
         onCheckedChange={(checked) => setEditing({ ...editing, enabled: checked })}
        />
       </Field>
       <Field label="Max attempts" hint="Blank uses the server default (3).">
        {(id) => (
         <Input
          id={id}
          value={editing.maxAttempts}
          placeholder="default"
          inputMode="numeric"
          disabled={!wired}
          onChange={(event) => setEditing({ ...editing, maxAttempts: event.target.value })}
         />
        )}
       </Field>
      </div>

      {/* Tools scope (so3) — Burp's first axis on the Scope tab, and the one with no substitute:
          URL scope is coarser host matching, parameter scope needs content the rule can inspect,
          but "not Intruder" cannot be expressed any other way. The names come from the server's
          own list so this checklist cannot offer a tool the API would refuse. */}
      <div className="stack-tight">
       <span className="eyebrow">Tools this rule applies to</span>
       <small className="field-hint">
        {editing.tools.length === 0
         ? "No tools checked, so the rule applies to every tool."
         : "The rule fires only for requests made by the checked tools — Burp's tools scope. A re-login rule kept away from Intruder is the case this exists for: an Intruder attack that is deliberately fuzzing the session cookie must not be repaired mid-flight."}
       </small>
       <div className="row-list">
        {(rulesQuery.data?.tools ?? []).map((tool) => (
         <label
          key={tool}
          className="field-label"
          style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "var(--fs-sm)" }}
         >
          <input
           type="checkbox"
           aria-label={`Apply this rule to ${tool}`}
           checked={editing.tools.includes(tool)}
           disabled={!wired}
           onChange={() =>
            setEditing({
             ...editing,
             tools: editing.tools.includes(tool)
              ? editing.tools.filter((name) => name !== tool)
              : [...editing.tools, tool],
            })
           }
          />
          {tool}
         </label>
        ))}
       </div>
      </div>

      {/* URL scope (7nh2) — Burp's own radio, with its own labels (Zgw7): Include all URLs /
          Use suite scope [defined in Target tab] / Use custom scope. The host list and the
          path/port/protocol arms belong to the custom mode; nothing is auto-selected. */}
      <div className="stack-tight">
       <span className="eyebrow">URL scope</span>
       <div className="row-list">
        {([["all", "Include all URLs"], ["suite", "Use suite scope [defined in Target tab]"], ["custom", "Use custom scope"]] as const).map(
          ([mode, label]) => (
            <label key={mode} className="field-label" style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "var(--fs-sm)" }}>
              <input
                type="radio"
                name="url-scope-mode"
                value={mode}
                checked={editing.scopeMode === mode}
                disabled={!wired}
                onChange={() => setEditing({ ...editing, scopeMode: mode })}
              />
              {label}
            </label>
          ),
        )}
       </div>
       {editing.scopeMode === "custom" ? (
        <>
         <div className="form-grid">
          <Field label="Path prefix" hint="Blank covers the whole host.">
           {(id) => (
            <Input id={id} value={editing.scopePath} disabled={!wired} placeholder="/api"
             onChange={(event) => setEditing({ ...editing, scopePath: event.target.value })} />
           )}
          </Field>
          <Field label="Port" hint="Blank matches any port.">
           {(id) => (
            <Input id={id} value={editing.scopePort} disabled={!wired} placeholder="443" inputMode="numeric"
             onChange={(event) => setEditing({ ...editing, scopePort: event.target.value })} />
           )}
          </Field>
          <Field label="Protocol" hint="Blank matches either scheme.">
           {(id) => (
            <select id={id} value={editing.scopeProtocol} disabled={!wired}
             onChange={(event) => setEditing({ ...editing, scopeProtocol: event.target.value as "" | "http" | "https" })}>
             <option value="">Any</option>
             <option value="http">http</option>
             <option value="https">https</option>
            </select>
           )}
          </Field>
         </div>
        </>
       ) : null}
      </div>

      {editing.scopeMode === "custom" ? (
      <div className="stack-tight">
       <span className="eyebrow">Hosts this rule covers</span>
       {editing.hosts.length === 0 ? (
        <small className="field-hint">No hosts listed, so the rule applies everywhere.</small>
       ) : null}
       {editing.hosts.map((host, index) => (
        <div className="kv-row" key={index}>
         <Input
          aria-label={`Scope host ${index + 1}`}
          title={`Scope host ${index + 1}`}
          value={host}
          disabled={!wired}
          onChange={(event) =>
           setEditing({ ...editing, hosts: editing.hosts.map((value, i) => (i === index ? event.target.value : value)) })
          }
         />
         <span className="cell-dim">host pattern</span>
         <IconButton
          label={`Remove scope host ${index + 1}`}
          size="small"
          disabled={!wired}
          onClick={() => setEditing({ ...editing, hosts: editing.hosts.filter((_, i) => i !== index) })}
         >
          <X size={13} />
         </IconButton>
        </div>
       ))}
       <div className="inline-add">
        <Input
         aria-label="New scope host"
         title="New scope host"
         value={newHost}
         placeholder="target.test"
         disabled={!wired}
         onChange={(event) => setNewHost(event.target.value)}
        />
        <Button
         variant="outline"
         size="small"
         disabled={!wired || !newHost.trim()}
         onClick={() => {
          setEditing({ ...editing, hosts: [...editing.hosts, newHost.trim()] });
          setNewHost("");
         }}
        >
         <Plus size={13} />
         Add host
        </Button>
       </div>
       </div>
      ) : null}

      <div className="stack-tight">
       <span className="eyebrow">Only requests carrying these parameters</span>
       <small className="field-hint">
        Optional. The rule applies only where every named parameter exists — Burp's parameter
        scope, for the canonical "update the CSRF token wherever it appears" rule. No names, no
        restriction: the rule follows its hosts alone.
       </small>
       {editing.params.map((param, index) => (
        <div className="kv-row" key={index}>
         <Input
          aria-label={`Scope parameter ${index + 1}`}
          title={`Scope parameter ${index + 1}`}
          value={param}
          placeholder="csrf_token"
          disabled={!wired}
          onChange={(event) =>
           setEditing({ ...editing, params: editing.params.map((value, i) => (i === index ? event.target.value : value)) })
          }
         />
         <span className="cell-dim">parameter name</span>
         <IconButton
          label={`Remove scope parameter ${index + 1}`}
          size="small"
          disabled={!wired}
          onClick={() => setEditing({ ...editing, params: editing.params.filter((_, i) => i !== index) })}
         >
          <X size={13} />
         </IconButton>
        </div>
       ))}
       <div className="inline-add">
        <Input
         aria-label="New scope parameter"
         title="New scope parameter"
         value={newParam}
         placeholder="csrf_token"
         disabled={!wired}
         onChange={(event) => setNewParam(event.target.value)}
        />
        <Button
         variant="outline"
         size="small"
         disabled={!wired || !newParam.trim()}
         onClick={() => {
          setEditing({ ...editing, params: [...editing.params, newParam.trim()] });
          setNewParam("");
         }}
        >
         <Plus size={13} />
         Add parameter
        </Button>
       </div>
      </div>

      {testReport ? (
       <div className="stack-tight">
        <span className="eyebrow">Test macro report</span>
        <small className="field-hint">
         The dry-run as it just ran: each step's request, the response, cookies the response set,
         and every extraction's outcome. Nothing was promoted — run the login to do that.
        </small>
        <div className="stack-tight">
         {testReport.steps.map((step) => (
          <Card key={step.index}>
           <SectionHeading
            title={`Step ${step.index + 1} — ${step.sent.method} ${step.sent.url}`}
            detail={
             step.response
              ? `answered ${step.response.status}`
              : (step.skipped ?? "no response")
            }
           />
           {step.sent_cookie ? (
            <p className="field-hint">Sent with Cookie: {step.sent_cookie}</p>
           ) : null}
           {step.set_cookies && step.set_cookies.length > 0 ? (
            <div className="stack-tight">
             {step.set_cookies.map((cookie, i) => (
              <p key={i} className="field-hint">Set-Cookie: {cookie}</p>
             ))}
            </div>
           ) : null}
           {step.extractions && step.extractions.length > 0 ? (
            <SimpleTable headers={["Extraction", "Outcome", "Value"]}>
             {step.extractions.map((ex) => (
              <tr key={ex.name}>
               <td>{ex.name}</td>
               <td>
                <Badge tone={ex.outcome === "resolved" ? "good" : "warn"}>{ex.outcome}</Badge>
               </td>
               <td>{ex.value || <span className="cell-dim">{ex.detail ?? "—"}</span>}</td>
              </tr>
             ))}
            </SimpleTable>
           ) : null}
           {step.response && step.response.body ? (
            <HttpEditor
             label={`Step ${step.index + 1} response body`}
             readOnly
             height="160px"
             value={step.response.body}
             filename={`test-macro-step-${step.index + 1}.txt`}
            />
           ) : null}
          </Card>
         ))}
        </div>
       </div>
      ) : null}

      <div className="stack-tight">
       <span className="eyebrow">Validity check</span>
       <small className="field-hint">
        Every stated field has to hold for the probe response to count as a valid session.
       </small>
       <div className="form-grid">
        <Field label="Status is" hint="Blank means status is not checked.">
         {(id) => (
          <Input
           id={id}
           value={editing.validity.status_is === undefined ? "" : String(editing.validity.status_is)}
           placeholder="200"
           inputMode="numeric"
           disabled={!wired}
           onChange={(event) => {
            const raw = event.target.value.trim();
            const parsed = Number(raw);
            setEditing({
             ...editing,
             validity: {
              ...editing.validity,
              status_is: raw === "" || !Number.isInteger(parsed) ? undefined : parsed,
             },
            });
           }}
          />
         )}
        </Field>
        {VALIDITY_FIELDS.map((field) => (
         <Field key={field.key} label={field.label} hint={field.hint}>
          {(id) => (
           <Input
            id={id}
            value={editing.validity[field.key] ?? ""}
            disabled={!wired}
            onChange={(event) =>
             setEditing({
              ...editing,
              validity: { ...editing.validity, [field.key]: event.target.value || undefined },
             })
            }
           />
          )}
         </Field>
        ))}
       </div>
       {nested ? (
        <div className="notice notice-warn">
         <span>
          This rule combines conditions with all / any / not. Those nested branches are kept exactly as
          saved — the fields above edit the flat conditions only.
         </span>
        </div>
       ) : null}
       <div className="inline-add">
        <Checkbox
         label="Regular expression"
         checked={editing.validity.regex === true}
         disabled={!wired}
         onCheckedChange={(on) => setEditing({ ...editing, validity: { ...editing.validity, regex: on || undefined } })}
        />
        <Checkbox
         label="Case sensitive"
         checked={editing.validity.case_sensitive === true}
         disabled={!wired}
         onCheckedChange={(on) => setEditing({ ...editing, validity: { ...editing.validity, case_sensitive: on || undefined } })}
        />
       </div>
       <Field
        label="Redirect target URL contains"
        hint="Optional. Matched against where a redirect at the last step lands — resolved, not followed. Blank means the redirect target is not checked."
       >
        {(id) => (
         <Input
          id={id}
          value={editing.validity.url_contains ?? ""}
          placeholder="/dashboard"
          disabled={!wired}
          onChange={(event) =>
           setEditing({
            ...editing,
            validity: { ...editing.validity, url_contains: event.target.value || undefined },
           })
          }
         />
        )}
       </Field>
      </div>

      {/* Burp's rule shape: the action list is what the rule does, and the macro below is the flow
          a "Run a macro" action replays. It is placed above the macro section for that reason — the
          macro is a thing the actions refer to, not the rule's behaviour. */}
      <SectionHeading
       title="Rule actions"
       detail="Run in order. This is what the rule does; the macro below is the login flow a \u201cRun a macro\u201d action replays."
       actions={
        <div className="page-actions">
         <Select
          aria-label="Add a rule action"
          title="Add a rule action"
          value=""
          disabled={!wired}
          onChange={(event) => {
           if (!event.target.value) return;
           setEditing((current) =>
            current === null ? current : { ...current, actions: [...current.actions, emptyAction(event.target.value)] },
           );
          }}
         >
          <option value="">Add an action\u2026</option>
          {(actionKinds ?? []).map((entry) => (
           <option key={entry.kind} value={entry.kind}>
            {entry.label}
           </option>
          ))}
         </Select>
        </div>
       }
      />
      {editing.actions.length === 0 ? (
       <Empty
        title="No actions"
        detail="A rule with no actions does nothing, and the server refuses one rather than quietly running a login instead."
       />
      ) : (
       <div className="stack">
        {editing.actions.map((action, index) => (
         <ActionCard
          key={index}
          action={action}
          index={index}
          total={editing.actions.length}
          depth={0}
          palette={actionKinds ?? []}
          ruleStepCount={editing.steps.length}
          disabled={!wired}
          onChange={(next) => setEditing({ ...editing, actions: editing.actions.map((value, i) => (i === index ? next : value)) })}
          onMove={(delta) => {
           const to = index + delta;
           if (to < 0 || to >= editing.actions.length) return;
           const list = [...editing.actions];
           const moved = list[index];
           const target = list[to];
           if (moved === undefined || target === undefined) return;
           list[to] = moved;
           list[index] = target;
           setEditing({ ...editing, actions: list });
          }}
          onRemove={() => setEditing({ ...editing, actions: editing.actions.filter((_, i) => i !== index) })}
         />
        ))}
       </div>
      )}
      {/* Burp's rule editor shows nine actions and this build shows eight. Named here with the reason
          so an operator following Burp's documentation learns what is missing and what to use
          instead, rather than concluding the ninth was overlooked. */}
      {(declinedActions ?? []).map((entry) => (
       <div className="notice notice-warn" key={entry.name}>
        <span>
         <strong>Not implemented: {entry.name}.</strong> {entry.reason}
        </span>
       </div>
      ))}

      <SectionHeading
       title="Macro steps"
       detail="Replayed in order. A later step can send an earlier step's extracted value as {{name}}."
       actions={
        <div className="page-actions">
         <Button variant="outline" size="small" disabled={!wired} onClick={() => setRecorderOpen(true)}>
          <History size={13} />
          Record from history
         </Button>
         <Button
          variant="outline"
          size="small"
          disabled={!wired}
          onClick={() =>
           setEditing({
            ...editing,
            steps: [...editing.steps, { method: "POST", url: "", headers: [], body: "", extract: [] }],
           })
          }
         >
          <Plus size={13} />
          Add step
         </Button>
        </div>
       }
      />
      {editing.steps.length === 0 ? (
       <Empty title="No steps" detail="A login macro needs at least one request to replay." />
      ) : (
       <div className="stack">
        {editing.steps.map((step, index) => (
         <StepCard
          key={index}
          step={step}
          index={index}
          total={editing.steps.length}
          disabled={!wired}
          onChange={(next) => patchStep(index, next)}
          onMove={(delta) => moveStep(index, delta)}
          onRemove={() => setEditing({ ...editing, steps: editing.steps.filter((_, i) => i !== index) })}
         />
        ))}
       </div>
      )}
      {/* Recorded steps land on the end, replacing any untouched placeholder steps already
          sitting there — see withRecordedSteps. Insertion at the caret would be the other reading of
          "add", and it is the wrong one: the recorder seeds a rule from traffic, so the flow it
          records has to come out in the order the operator selected rather than after whatever
          happened to be in the editor. */}
      <MacroRecorder
       open={recorderOpen}
       onOpenChange={setRecorderOpen}
       onRecord={(steps) =>
        setEditing((current) =>
         current === null
          ? current
          : { ...current, steps: withRecordedSteps(current.steps, steps.map(stepIn)) },
        )
       }
      />
     </div>
    </Card>
   ) : null}

   <Card>
    <SectionHeading
     title="Log in again"
     detail="Sends this probe, and lets the matching rule recover the session if the probe says it is expired."
     actions={
      promotable ? (
       <Button
        variant="outline"
        size="small"
        disabled={promoteMacro.isPending}
        onClick={() =>
         promoteMacro.mutate(promotable.id, {
          onSuccess: (result) => {
           toast.success(`Macro of “${promotable.name}” replaced with ${result.steps.length} observed step(s)`);
           setPromotable(null);
          },
          onError: (failure: unknown) =>
           toast.error(failure instanceof Error ? failure.message : "Could not promote the macro"),
         })
        }
       >
        <Upload size={13} />
        Update macro from this run
       </Button>
      ) : null
     }
    />
    <div className="stack">
     <div className="form-grid">
      {/* These two carried an aria-label repeating the Field's own label text. An
                aria-label wins over the visible label, so the two could drift apart and
                only the invisible one would be announced. The generated id makes the
                visible label the accessible name, with nothing to keep in sync. */}
      <Field label="Probe method">
       {(id) => (
        <Input
         id={id}
         value={probe.method}
         placeholder="GET"
         disabled={!wired}
         onChange={(event) => setProbe({ ...probe, method: event.target.value })}
        />
       )}
      </Field>
      <Field label="Probe URL" hint="A request whose response proves whether the session is still valid.">
       {(id) => (
        <Input
         id={id}
         value={probe.url}
         placeholder="https://target.test/whoami"
         disabled={!wired}
         onChange={(event) => setProbe({ ...probe, url: event.target.value })}
        />
       )}
      </Field>
     </div>
     <HeaderPairs headers={probe.headers} scope="Probe" disabled={!wired} onChange={(headers) => setProbe({ ...probe, headers })} />
     <Field label="Probe body" hint="Optional.">
      {(id) => (
       <Textarea id={id} value={probe.body} disabled={!wired} onChange={(event) => setProbe({ ...probe, body: event.target.value })} />
      )}
     </Field>
     <div>
      <Button onClick={runLogin} disabled={!wired || login.isPending}>
       <KeyRound size={13} />
       {login.isPending ? "Running…" : "Run login now"}
      </Button>
     </div>
     {loginRows.length ? <DetailList rows={loginRows} /> : null}
     {loginResult?.response ? (
      <HttpEditor
       label="Probe response body"
       readOnly
       height="200px"
       value={loginResult.response.body || "The probe response had an empty body."}
       filename="session-probe-response.txt"
      />
     ) : null}
    </div>
   </Card>

   <Card>
    <SectionHeading
     title="Cookie jar"
     detail="The jar shared by the session coordinator and this tool's own senders."
     actions={
      <>
       <RefreshButton onClick={() => void cookiesQuery.refetch()} loading={cookiesQuery.isFetching} label="Refresh jar" />
       {/* Empty the jar altogether (dkb) — per authority of the first visible row group is not
           the Burp shape; Burp empties THE jar. burpsy's jar is per-authority by design, so the
           control clears every authority the read side currently lists. */}
       {cookieRows.length > 0 ? (
        <Button
         variant="outline"
         size="small"
         disabled={jarWrite.isPending}
         onClick={() => {
          const authorities = [...new Set(cookieRows.map((row) => row.host))];
          for (const authority of authorities) {
           const scheme = authority.includes(":443") ? "https" : "http";
           applyCookieWrite(
            {
             action: "clear",
             host: authority.split(":").slice(0, -1).join(":") || authority,
             port: Number(authority.split(":").pop()) || (scheme === "https" ? 443 : 80),
             tls: scheme === "https",
            },
            `Emptied ${authority}`,
           );
          }
         }}
        >
         Empty jar
        </Button>
       ) : null}
      </>
     }
    />
    {cookiesQuery.error ? (
     <ErrorNotice error={cookiesQuery.error} onRetry={() => void cookiesQuery.refetch()} />
    ) : cookiesQuery.data && !cookiesQuery.data.wired ? (
     <div className="notice notice-warn">
      <span>{cookiesQuery.data.hint ?? "The cookie jar is not attached to this process."}</span>
     </div>
    ) : cookieRows.length === 0 ? (
     <Empty
      title="No cookies to show"
      detail={
       cookiesQuery.data?.hint ??
       "The jar is attached and empty: no Set-Cookie has been absorbed yet. Run a login macro, or send authenticated traffic through the proxy."
      }
     />
    ) : (
     <SimpleTable headers={["Authority", "Name", "Value", ""]}>
      {cookieRows.map((row, index) => (
       <tr key={`${row.scheme}-${row.host}-${row.name}-${index}`}>
        <td>
         {row.host}
         <span className="cell-dim"> · {row.scheme}</span>
        </td>
        <td>
         <code>{row.name}</code>
        </td>
        <td>
         <span className="cell-dim">{row.value}</span>
        </td>
        <td>
         <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
          <IconButton
           label={`Edit cookie ${row.name}`}
           size="small"
           onClick={() =>
            setEditingCookie({
             host: row.host,
             // The table's authority string is "host:port"; the write takes the tuple.
             port: Number(row.host.split(":").pop()) || (row.scheme === "https" ? 443 : 80),
             tls: row.scheme === "https",
             name: row.name,
             value: row.value,
            })
           }
          >
           <Pencil size={13} />
          </IconButton>
          <IconButton
           label={`Remove cookie ${row.name}`}
           size="small"
           onClick={() =>
            applyCookieWrite(
             {
              action: "remove",
              host: row.host.split(":").slice(0, -1).join(":") || row.host,
              port: Number(row.host.split(":").pop()) || (row.scheme === "https" ? 443 : 80),
              tls: row.scheme === "https",
              name: row.name,
             },
             `Removed ${row.name}`,
            )
           }
          >
           <Trash2 size={13} />
          </IconButton>
         </div>
        </td>
       </tr>
      ))}
     </SimpleTable>
    )}
   </Card>

   {/* Edit one cookie (dkb): the write takes the tuple and replaces the value; the read side
       refetches through the hook's invalidation, so the table cannot drift from the jar. */}
   <Modal
    open={editingCookie !== null}
    onOpenChange={(nextOpen) => {
     if (!nextOpen) setEditingCookie(null);
    }}
    title={`Edit cookie ${editingCookie?.name ?? ""}`}
    description={`On ${editingCookie?.host ?? ""}. The value replaces what the jar sends with every matching request.`}
   >
    {editingCookie ? (
     <div className="stack">
      <Field label="Value">
       {(id) => (
        <Input
         id={id}
         value={editingCookie.value}
         onChange={(e) => setEditingCookie({ ...editingCookie, value: e.target.value })}
        />
       )}
      </Field>
      <div className="page-actions">
       <Button variant="outline" onClick={() => setEditingCookie(null)}>
        Cancel
       </Button>
       <Button
        disabled={jarWrite.isPending}
        onClick={() => {
         applyCookieWrite(
          { action: "set", host: editingCookie.host.split(":").slice(0, -1).join(":") || editingCookie.host, port: editingCookie.port, tls: editingCookie.tls, name: editingCookie.name, value: editingCookie.value },
          `Updated ${editingCookie.name}`,
         );
         setEditingCookie(null);
        }}
       >
        Save
       </Button>
      </div>
     </div>
    ) : null}
   </Modal>

   <Modal
    open={confirmDelete !== null}
    onOpenChange={(nextOpen) => {
     if (!nextOpen) setConfirmDelete(null);
    }}
    title="Delete this session rule?"
    description="The rule and its macro are removed from the coordinator immediately."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmDelete(null)}>
      Keep it
     </Button>
     <Button variant="danger" disabled={deleteRule.isPending} onClick={() => (confirmDelete === null ? undefined : onDelete(confirmDelete))}>
      <Trash2 size={13} />
      Delete rule
     </Button>
    </div>
   </Modal>
  </div>
 );
}
