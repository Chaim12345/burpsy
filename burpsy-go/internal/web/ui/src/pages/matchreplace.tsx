import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Copy, FlaskConical, Plus, RotateCcw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useMatchReplace, useSaveMatchReplace } from "../lib/data";
import { useTestMatchReplace } from "../lib/data.policy";
import type {
  MatchReplaceCategory,
  MatchReplaceDirection,
  MatchReplaceRuleSpec,
  MatchReplaceTarget,
} from "../lib/types.policy";
import { HttpEditor } from "../ui/editor";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Switch, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/** The targets the Go handler compiles. An unknown one is refused with a 400, not silently accepted. */
const TARGETS: { value: MatchReplaceTarget; label: string }[] = [
  { value: "request_first_line", label: "Request line" },
  { value: "request_header", label: "Request header" },
  { value: "request_body", label: "Request body" },
  { value: "request_param_name", label: "Request parameter name" },
  { value: "request_param_value", label: "Request parameter value" },
  { value: "response_header", label: "Response header" },
  { value: "response_body", label: "Response body" },
  { value: "websocket_to_server", label: "WebSocket → server" },
  { value: "websocket_to_client", label: "WebSocket → client" },
];

const CATEGORIES: { value: MatchReplaceCategory; label: string }[] = [
  { value: "literal", label: "Literal" },
  { value: "regex", label: "Regex" },
];

const TARGET_LABEL = new Map(TARGETS.map((target) => [target.value, target.label]));

/**
 * Which half of the traffic a target belongs to.
 *
 * A table rather than the ternary this was. That ternary read "response if it is one of two response
 * targets, otherwise request" — so the moment WebSocket targets existed they would have been
 * reported as affecting *requests*, and the summary badge would have told the operator a WebSocket
 * rule rewrites their HTTP requests. Same shape as the if-chain that had to be replaced in
 * internal/matchreplace's targetsDir, for the same reason.
 */
const TARGET_DIRECTION: Record<MatchReplaceTarget, MatchReplaceDirection> = {
  request_first_line: "request",
  request_header: "request",
  request_body: "request",
  request_param_name: "request",
  request_param_value: "request",
  response_header: "response",
  response_body: "response",
  websocket_to_server: "websocket",
  websocket_to_client: "websocket",
};

function directionOf(target: MatchReplaceTarget): MatchReplaceDirection {
  return TARGET_DIRECTION[target] ?? "request";
}

/** The wire allows any string; only these five do anything, so an unknown one is shown as-is and kept. */
function asTarget(value: string): MatchReplaceTarget {
  return TARGET_LABEL.has(value as MatchReplaceTarget) ? (value as MatchReplaceTarget) : "request_header";
}

function asCategory(value: string): MatchReplaceCategory {
  return value === "regex" ? "regex" : "literal";
}

interface Draft {
  rules: MatchReplaceRuleSpec[];
  update_content_length: boolean;
  /** Burp's "Only apply to in-scope items". Set-wide, not per rule — see types.ts. */
  in_scope_only: boolean;
}

const SAMPLE_PLACEHOLDER = "Paste a raw request or response to run the draft rules against.";

export function MatchReplacePage(): JSX.Element {
  const { data, error, isFetching, refetch } = useMatchReplace();
  const save = useSaveMatchReplace();
  const test = useTestMatchReplace();

  const [draft, setDraft] = useState<Draft | null>(null);
  /** The server state the draft was adopted from; the dirty check compares against it. */
  const [baseline, setBaseline] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [direction, setDirection] = useState<MatchReplaceDirection>("request");
  const [sample, setSample] = useState("");
  const [output, setOutput] = useState<{ text: string; changed: boolean } | null>(null);

  const dirty = draft !== null && JSON.stringify(draft) !== baseline;

  // Adopt server state only while the operator has nothing unsaved: a background
  // refetch must never discard edits that are not yet persisted.
  useEffect(() => {
    if (!data) return;
    const normalised: Draft = {
      rules: data.config.rules.map((rule) => ({
        rule_type: asTarget(rule.rule_type),
        enabled: rule.enabled,
        string_match: rule.string_match,
        string_replace: rule.string_replace,
        category: asCategory(rule.category),
        comment: rule.comment ?? "",
      })),
      update_content_length: data.config.update_content_length,
      in_scope_only: data.config.in_scope_only,
    };
    const next = JSON.stringify(normalised);
    if (next === baseline) return;
    if (draft !== null && JSON.stringify(draft) !== baseline) return;
    setDraft(normalised);
    setBaseline(next);
  }, [data, baseline, draft]);

  const rules = draft?.rules ?? [];

  const patch = (index: number, changes: Partial<MatchReplaceRuleSpec>) =>
    setDraft((current) =>
      current === null
        ? current
        : { ...current, rules: current.rules.map((rule, i) => (i === index ? { ...rule, ...changes } : rule)) },
    );

  const replaceRules = (next: MatchReplaceRuleSpec[]) =>
    setDraft((current) => (current === null ? current : { ...current, rules: next }));

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    const next = [...rules];
    const [moved] = next.splice(index, 1);
    if (!moved) return;
    next.splice(target, 0, moved);
    replaceRules(next);
  };

  const addRule = () =>
    replaceRules([
      ...rules,
      {
        rule_type: direction === "response" ? "response_header" : "request_header",
        enabled: true,
        string_match: "",
        string_replace: "",
        category: "literal",
        comment: "",
      },
    ]);

  const onSave = () => {
    if (!draft) return;
    const payload = {
      rules: draft.rules,
      update_content_length: draft.update_content_length,
      in_scope_only: draft.in_scope_only,
    };
    save.mutate(payload, {
      onSuccess: () => {
        setBaseline(JSON.stringify(draft));
        toast.success(`Saved ${draft.rules.length} rule${draft.rules.length === 1 ? "" : "s"}`);
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Save failed"),
    });
  };

  const onRevert = () => {
    if (!baseline) return;
    setDraft(JSON.parse(baseline) as Draft);
    toast.success("Reverted to the saved rule set");
  };

  const runTest = () => {
    if (!draft) return;
    test.mutate(
      { input: sample, direction, draft_rules: draft.rules },
      {
        onSuccess: (result) => setOutput({ text: result.output.text, changed: result.changed }),
        onError: (failure: unknown) => {
          setOutput(null);
          toast.error(failure instanceof Error ? failure.message : "Test failed");
        },
      },
    );
  };

  // What the *draft* touches, next to what the server says the saved set touches.
  const draftAffects = useMemo(() => {
    let request = false;
    let response = false;
    let websocket = false;
    for (const rule of rules) {
      if (!rule.enabled) continue;
      const dir = directionOf(rule.rule_type);
      if (dir === "response") response = true;
      else if (dir === "websocket") websocket = true;
      else request = true;
    }
    return { request, response, websocket };
  }, [rules]);

  if (error) {
    return (
      <div className="page">
        <PageHeader title="Match / replace" />
        <ErrorNotice error={error} onRetry={() => void refetch()} />
      </div>
    );
  }

  if (!draft) {
    return (
      <div className="page">
        <PageHeader title="Match / replace" />
        <LoadingPanel label="Loading rule set" />
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        title="Match / replace"
        description="Rules run in order on every proxied message. Nothing here changes traffic until it is saved."
        actions={
          <>
            {dirty ? <Badge tone="warn">unsaved changes</Badge> : <Badge tone="good">saved</Badge>}
            <Button variant="outline" size="small" onClick={onRevert} disabled={!dirty}>
              <RotateCcw size={13} />
              Revert
            </Button>
            <Button size="small" onClick={onSave} disabled={!dirty || save.isPending}>
              <Save size={13} />
              {save.isPending ? "Saving…" : "Save rules"}
            </Button>
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />

      <Card>
        <SectionHeading
          title="Rules"
          detail="Order matters: each rule sees the output of the ones above it."
          actions={
            <>
              <Badge tone={data?.affects_requests ? "info" : "neutral"}>
                saved · requests {data?.affects_requests ? "yes" : "no"}
              </Badge>
              <Badge tone={data?.affects_responses ? "info" : "neutral"}>
                saved · responses {data?.affects_responses ? "yes" : "no"}
              </Badge>
              {dirty ? (
                <Badge tone="warn">
                  draft · requests {draftAffects.request ? "yes" : "no"} / responses {draftAffects.response ? "yes" : "no"}
                </Badge>
              ) : null}
              <Button variant="outline" size="small" onClick={addRule}>
                <Plus size={13} />
                Add rule
              </Button>
            </>
          }
        />

        <Toolbar>
          <Field label="Fix Content-Length" hint="Rewrites the header after a body rule changes its length." htmlFor="mr-ucl">
            <Switch
              id="mr-ucl"
              label="Update Content-Length after a body rewrite"
              checked={draft.update_content_length}
              onCheckedChange={(checked) => setDraft({ ...draft, update_content_length: checked })}
            />
          </Field>
          <Field
            label="Only apply to in-scope items"
            hint="A message whose URL the Target scope excludes is passed through untouched. Burp has this one switch and no per-rule scope."
            htmlFor="mr-scope"
          >
            <Switch
              id="mr-scope"
              label="Only apply these rules to in-scope items"
              checked={draft.in_scope_only}
              onCheckedChange={(checked) => setDraft({ ...draft, in_scope_only: checked })}
            />
          </Field>
          <Badge>{rules.filter((rule) => rule.enabled).length} of {rules.length} enabled</Badge>
          {/*
            The evidence that the switch is doing something. "A rule that stopped matching" and
            "a rule that scope no longer lets look" are the same thing to watch and different
            things to fix, so when any message has been turned away the page says so with a
            number rather than leaving the operator to guess whether their rules still run.
          */}
          {data && data.scope_skipped > 0 ? (
            <Badge tone="warn">{data.scope_skipped} message(s) left alone by scope</Badge>
          ) : null}
        </Toolbar>

        {rules.length === 0 ? (
          <Empty
            title="No rules"
            detail="Add a rule to rewrite a header, a request line, or a body on the way through the proxy."
            action={
              <Button variant="outline" size="small" onClick={addRule}>
                <Plus size={13} />
                Add rule
              </Button>
            }
          />
        ) : (
          <SimpleTable headers={["On", "Target", "Match kind", "Match", "Replace with", "Comment", "Order", ""]}>
            {rules.map((rule, index) => (
              // Index is the identity here: the wire carries an ordered list with no ids, and a
              // background refetch cannot renumber a draft the operator is editing.
              <tr key={index}>
                <td>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={(event) => patch(index, { enabled: event.target.checked })}
                    />
                    <span className="sr-only">Rule {index + 1} enabled</span>
                  </label>
                </td>
                <td>
                  <Select
                    aria-label={`Rule ${index + 1} target`}
                    value={rule.rule_type}
                    onChange={(event) => patch(index, { rule_type: asTarget(event.target.value) })}
                  >
                    {TARGETS.map((target) => (
                      <option key={target.value} value={target.value}>
                        {target.label}
                      </option>
                    ))}
                  </Select>
                </td>
                <td>
                  <Select
                    aria-label={`Rule ${index + 1} match kind`}
                    value={rule.category}
                    onChange={(event) => patch(index, { category: asCategory(event.target.value) })}
                  >
                    {CATEGORIES.map((category) => (
                      <option key={category.value} value={category.value}>
                        {category.label}
                      </option>
                    ))}
                  </Select>
                </td>
                <td>
                  <Input
                    aria-label={`Rule ${index + 1} match`}
                    value={rule.string_match}
                    placeholder="empty = add this header"
                    onChange={(event) => patch(index, { string_match: event.target.value })}
                  />
                </td>
                <td>
                  <Input
                    aria-label={`Rule ${index + 1} replacement`}
                    value={rule.string_replace}
                    placeholder="empty = delete the match"
                    onChange={(event) => patch(index, { string_replace: event.target.value })}
                  />
                </td>
                <td>
                  <Input
                    aria-label={`Rule ${index + 1} comment`}
                    value={rule.comment}
                    placeholder="why this rule exists"
                    onChange={(event) => patch(index, { comment: event.target.value })}
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
                  <div className="chip-row">
                    <IconButton
                      label={`Duplicate rule ${index + 1}`}
                      size="small"
                      onClick={() => {
                        const next = [...rules];
                        next.splice(index + 1, 0, { ...rule });
                        replaceRules(next);
                      }}
                    >
                      <Copy size={13} />
                    </IconButton>
                    <IconButton label={`Delete rule ${index + 1}`} size="small" onClick={() => setConfirmDelete(index)}>
                      <Trash2 size={13} />
                    </IconButton>
                  </div>
                </td>
              </tr>
            ))}
          </SimpleTable>
        )}

      </Card>

      <Card>
        <SectionHeading
          title="Draft test"
          detail="Compiled and applied server-side as a throwaway rule set — the saved rules and live traffic are untouched."
          actions={
            <>
              <Badge tone={dirty ? "warn" : "neutral"}>
                testing {rules.length} {dirty ? "unsaved draft" : "saved"} rule{rules.length === 1 ? "" : "s"}
              </Badge>
              {output ? <Badge tone={output.changed ? "info" : "neutral"}>{output.changed ? "changed" : "no change"}</Badge> : null}
            </>
          }
        />
        <Toolbar>
          <Field label="Direction" hint="Request rules and response rules are applied separately.">
            <Select
              aria-label="Test direction"
              value={direction}
              onChange={(event) => {
                setDirection(event.target.value === "response" ? "response" : "request");
                setOutput(null);
              }}
              style={{ maxWidth: "var(--w-sm)" }}
            >
              <option value="request">Request rules</option>
              <option value="response">Response rules</option>
            </Select>
          </Field>
          <Button onClick={runTest} disabled={!sample || test.isPending}>
            <FlaskConical size={13} />
            {test.isPending ? "Testing…" : "Test draft"}
          </Button>
        </Toolbar>
        <div className="editor-grid">
          <HttpEditor
            label="Sample input"
            height="260px"
            value={sample}
            placeholder={SAMPLE_PLACEHOLDER}
            filename="matchreplace-sample.txt"
            onChange={(value) => {
              setSample(value);
              setOutput(null);
            }}
          />
          <HttpEditor
            label="Transformed output"
            height="260px"
            readOnly
            value={output?.text ?? "Run the test to see what the draft rules would produce."}
            filename="matchreplace-output.txt"
          />
        </div>
      </Card>

      <Modal
        open={confirmDelete !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmDelete(null);
        }}
        title="Delete this rule?"
        description="The rule leaves the draft; the saved rule set only changes when you save."
      >
        <div className="page-actions">
          <Button variant="outline" onClick={() => setConfirmDelete(null)}>
            Keep it
          </Button>
          <Button
            variant="danger"
            onClick={() => {
              if (confirmDelete === null) return;
              replaceRules(rules.filter((_, i) => i !== confirmDelete));
              setConfirmDelete(null);
            }}
          >
            <Trash2 size={13} />
            Delete rule
          </Button>
        </div>
      </Modal>
    </div>
  );
}
