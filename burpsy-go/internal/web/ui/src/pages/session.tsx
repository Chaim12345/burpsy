import { useEffect, useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, KeyRound, Pencil, Plus, RotateCcw, Save, Trash2, Upload, X } from "lucide-react";
import { toast } from "sonner";
import { useDeleteSessionRule, useSaveSessionRule } from "../lib/data";
import { useSessionCookies, useSessionLogin, useSessionRulesFull, useUpdateSessionMacro } from "../lib/data.policy";
import type {
  SessionExtractFrom,
  SessionExtractHow,
  SessionExtraction,
  SessionLoginResponse,
  SessionMacroStep,
  SessionRuleFull,
  SessionValidity,
} from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { DetailList } from "../ui/json";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Switch, Textarea } from "../ui/primitives";
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
  /** Only host patterns are read server-side; an empty list means "applies everywhere". */
  hosts: string[];
  validity: SessionValidity;
  /** Kept as text so "" can mean "the server's default" rather than one attempt. */
  maxAttempts: string;
  steps: StepDraft[];
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

function ruleIn(rule: SessionRuleFull): RuleDraft {
  const draft: RuleDraft = {
    name: rule.name,
    enabled: rule.enabled,
    hosts: (rule.scope?.rules ?? []).map((entry) => entry.host ?? "").filter(Boolean),
    validity: rule.validity ?? {},
    maxAttempts: rule.max_attempts === undefined ? "" : String(rule.max_attempts),
    steps: (rule.steps ?? []).map((step) => ({
      method: step.method || "GET",
      url: step.url,
      headers: (step.headers ?? []).map(([name, value]) => [name, value] as [string, string]),
      body: step.body,
      extract: (step.extract ?? []).map(extractionIn),
    })),
  };
  if (rule.id !== undefined) draft.id = rule.id;
  return draft;
}

function ruleOut(draft: RuleDraft): SessionRuleFull {
  const steps: SessionMacroStep[] = draft.steps.map((step) => {
    const wire: SessionMacroStep = {
      method: step.method.trim() || "GET",
      url: step.url.trim(),
      headers: step.headers.filter(([name]) => name.trim() !== ""),
      body: step.body,
    };
    const extract = step.extract.filter((entry) => entry.name.trim() !== "").map(extractionOut);
    if (extract.length) wire.extract = extract;
    return wire;
  });
  const out: SessionRuleFull = { name: draft.name.trim(), enabled: draft.enabled, steps, validity: draft.validity };
  if (draft.id !== undefined) out.id = draft.id;
  // Omitted rather than sent empty: absent means "applies everywhere", and a stated
  // but empty scope is refused by the server because it would match nothing.
  if (draft.hosts.length) {
    out.scope = { allow_all: false, rules: draft.hosts.map((host) => ({ kind: "Include" as const, host })) };
  }
  const attempts = Number(draft.maxAttempts.trim());
  if (draft.maxAttempts.trim() !== "" && Number.isInteger(attempts) && attempts > 0) out.max_attempts = attempts;
  return out;
}

function emptyRule(): RuleDraft {
  return {
    name: "",
    enabled: true,
    hosts: [],
    validity: { status_is: 200 },
    maxAttempts: "",
    steps: [{ method: "POST", url: "", headers: [], body: "", extract: [] }],
  };
}

function scopeSummary(rule: SessionRuleFull): string {
  const hosts = (rule.scope?.rules ?? []).map((entry) => entry.host ?? "").filter(Boolean);
  if (!rule.scope || rule.scope.allow_all || hosts.length === 0) return "every host";
  return hosts.join(", ");
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
            value={name}
            placeholder="Content-Type"
            disabled={disabled}
            onChange={(event) => onChange(headers.map((pair, i) => (i === index ? [event.target.value, pair[1]] : pair)))}
          />
          <Input
            aria-label={`${scope} header ${index + 1} value`}
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
            value={entry.name}
            placeholder="csrf"
            disabled={disabled}
            onChange={(event) => patch(position, { name: event.target.value })}
          />
          <Select
            aria-label={`Step ${index + 1} extraction ${position + 1} source`}
            value={entry.fromKind}
            disabled={disabled}
            onChange={(event) => patch(position, { fromKind: event.target.value === "header" ? "header" : "body" })}
          >
            <option value="body">From body</option>
            <option value="header">From header</option>
          </Select>
          <Input
            aria-label={`Step ${index + 1} extraction ${position + 1} header name`}
            value={entry.header}
            placeholder="X-Token"
            disabled={disabled || entry.fromKind !== "header"}
            onChange={(event) => patch(position, { header: event.target.value })}
          />
          <Select
            aria-label={`Step ${index + 1} extraction ${position + 1} method`}
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
            value={entry.pattern}
            placeholder={entry.how === "json_path" ? "data.token" : 'name="csrf" value="([^"]+)"'}
            disabled={disabled || entry.how === "whole"}
            onChange={(event) => patch(position, { pattern: event.target.value })}
          />
          <Input
            aria-label={`Step ${index + 1} extraction ${position + 1} capture group`}
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
          value={step.method}
          placeholder="POST"
          disabled={disabled}
          style={{ maxWidth: "clamp(70px, 7vw, 120px)" }}
          onChange={(event) => onChange({ ...step, method: event.target.value })}
        />
        <Input
          aria-label={`Step ${index + 1} URL`}
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
        <Textarea
          value={step.body}
          placeholder="user=admin&password={{password}}"
          disabled={disabled}
          onChange={(event) => onChange({ ...step, body: event.target.value })}
        />
      </Field>
      <ExtractionRows step={step} index={index} disabled={disabled} onChange={(extract) => onChange({ ...step, extract })} />
    </div>
  );
}

export function SessionPage(): JSX.Element {
  const rulesQuery = useSessionRulesFull();
  const cookiesQuery = useSessionCookies();
  const saveRule = useSaveSessionRule();
  const deleteRule = useDeleteSessionRule();
  const login = useSessionLogin();
  const promoteMacro = useUpdateSessionMacro();

  /** Selection is by rule id; a new rule is `{ id: null }` until the server assigns one. */
  const [editing, setEditing] = useState<RuleDraft | null>(null);
  const [baseline, setBaseline] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [newHost, setNewHost] = useState("");

  const [probe, setProbe] = useState<StepDraft>({ method: "GET", url: "", headers: [], body: "", extract: [] });
  const [loginResult, setLoginResult] = useState<SessionLoginResponse | null>(null);
  /** Only a run that actually replayed a macro leaves something to promote. */
  const [promotable, setPromotable] = useState<{ id: number; name: string } | null>(null);

  const wired = rulesQuery.data?.wired ?? true;
  const rules = rulesQuery.data?.rules ?? [];
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
                <Input
                  value={editing.name}
                  placeholder="admin login"
                  disabled={!wired}
                  onChange={(event) => setEditing({ ...editing, name: event.target.value })}
                />
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
                <Input
                  value={editing.maxAttempts}
                  placeholder="default"
                  inputMode="numeric"
                  disabled={!wired}
                  onChange={(event) => setEditing({ ...editing, maxAttempts: event.target.value })}
                />
              </Field>
            </div>

            <div className="stack-tight">
              <span className="eyebrow">Hosts this rule covers</span>
              {editing.hosts.length === 0 ? (
                <small className="field-hint">No hosts listed, so the rule applies everywhere.</small>
              ) : null}
              {editing.hosts.map((host, index) => (
                <div className="kv-row" key={index}>
                  <Input
                    aria-label={`Scope host ${index + 1}`}
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

            <div className="stack-tight">
              <span className="eyebrow">Validity check</span>
              <small className="field-hint">
                Every stated field has to hold for the probe response to count as a valid session.
              </small>
              <div className="form-grid">
                <Field label="Status is" hint="Blank means status is not checked.">
                  <Input
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
                </Field>
                {VALIDITY_FIELDS.map((field) => (
                  <Field key={field.key} label={field.label} hint={field.hint}>
                    <Input
                      value={editing.validity[field.key] ?? ""}
                      disabled={!wired}
                      onChange={(event) =>
                        setEditing({
                          ...editing,
                          validity: { ...editing.validity, [field.key]: event.target.value || undefined },
                        })
                      }
                    />
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
            </div>

            <SectionHeading
              title="Macro steps"
              detail="Replayed in order. A later step can send an earlier step's extracted value as {{name}}."
              actions={
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
            <Field label="Probe method">
              <Input
                aria-label="Probe method"
                value={probe.method}
                placeholder="GET"
                disabled={!wired}
                onChange={(event) => setProbe({ ...probe, method: event.target.value })}
              />
            </Field>
            <Field label="Probe URL" hint="A request whose response proves whether the session is still valid.">
              <Input
                aria-label="Probe URL"
                value={probe.url}
                placeholder="https://target.test/whoami"
                disabled={!wired}
                onChange={(event) => setProbe({ ...probe, url: event.target.value })}
              />
            </Field>
          </div>
          <HeaderPairs headers={probe.headers} scope="Probe" disabled={!wired} onChange={(headers) => setProbe({ ...probe, headers })} />
          <Field label="Probe body" hint="Optional.">
            <Textarea value={probe.body} disabled={!wired} onChange={(event) => setProbe({ ...probe, body: event.target.value })} />
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
          actions={<RefreshButton onClick={() => void cookiesQuery.refetch()} loading={cookiesQuery.isFetching} label="Refresh jar" />}
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
          <SimpleTable headers={["Authority", "Name", "Value"]}>
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
              </tr>
            ))}
          </SimpleTable>
        )}
      </Card>

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
