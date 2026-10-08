import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  blankStep,
  describeDraft,
  draftFromView,
  useDeleteRecordedLogin,
  useRecordedLogins,
  useReplayRecordedLogin,
  useSaveRecordedLogin,
  type ImportNote,
  type LoginStepKind,
  type RecordedLoginView,
  type ReplayReply,
  type StepDraft,
} from "../lib/data.recordedlogin";
import { Badge, Button, Checkbox, Empty, ErrorNotice, Field, Input, Select, Textarea } from "./primitives";
import { SimpleTable } from "./table";

/**
 * Recorded login sequences (burpsy-react-ui-xhtk) — Burp's "Use recorded login sequences" on the scan
 * launcher's Application login tab: add one by pasting a recorder script, edit its events, see it as
 * JSON, Replay it, delete it. Secrets never reach this component; a stored one shows as "stored".
 */

const KIND_LABELS: Record<LoginStepKind, string> = {
  click: "Click",
  type: "Type",
  totp: "TOTP",
  key: "Key press",
  goto: "Go to",
  wait: "Wait",
};

function errorText(failure: unknown, fallback: string): string {
  return failure instanceof Error ? failure.message : fallback;
}

/** The picker the New scan dialog shows: which sequence the crawl logs in with, and the library. */
export function RecordedLoginPicker({ value, onChange }: { value: string; onChange: (id: string) => void }): JSX.Element {
  const logins = useRecordedLogins();
  const [managing, setManaging] = useState(false);
  const chosen = logins.data?.logins.find((login) => login.id === value);
  return (
    <div className="stack">
      <h3 className="subheading">Application login</h3>
      <div className="toolbar">
        <Field label="Recorded login sequence">
          {(id) => (
            <Select id={id} value={value} onChange={(event) => onChange(event.target.value)}>
              <option value="">None — crawl without logging in</option>
              {(logins.data?.logins ?? []).map((login) => (
                <option key={login.id} value={login.id}>
                  {login.label} ({login.steps.length} steps{login.has_totp ? ", TOTP" : ""})
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button variant="outline" size="small" onClick={() => setManaging((open) => !open)} aria-expanded={managing}>
          {managing ? "Hide recorded logins" : "Manage recorded logins"}
        </Button>
      </div>
      {logins.error ? <ErrorNotice error={logins.error} title="Recorded logins could not be loaded" /> : null}
      {chosen ? (
        <p className="cell-dim" style={{ margin: 0 }}>
          The crawl replays “{chosen.label}” in an isolated headless browser before its first request, carries the session it
          earns on every request, and replays it again when the session is lost. Every request the replay sends is checked
          against scope — an SSO identity provider must be in scope, or its requests are refused and the login fails, named.
        </p>
      ) : null}
      {managing ? <RecordedLoginsManager onUse={(id) => onChange(id)} /> : null}
    </div>
  );
}

/** The library: import, list, edit, replay, delete. */
export function RecordedLoginsManager({ onUse }: { onUse?: (id: string) => void }): JSX.Element {
  const logins = useRecordedLogins();
  const save = useSaveRecordedLogin();
  const remove = useDeleteRecordedLogin();
  const replay = useReplayRecordedLogin();
  const [label, setLabel] = useState("");
  const [script, setScript] = useState("");
  const [notes, setNotes] = useState<ImportNote[] | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [replayed, setReplayed] = useState<ReplayReply | null>(null);
  const editingLogin = logins.data?.logins.find((login) => login.id === editing) ?? null;

  const importScript = () => {
    save.mutate(
      { label: label.trim(), script },
      {
        onSuccess: (reply) => {
          setNotes(reply.notes);
          setScript("");
          setLabel("");
          setEditing(reply.login.id);
          toast.success(`Imported “${reply.login.label}”: ${reply.login.steps.length} steps (${reply.format})`);
        },
        onError: (failure) => toast.error(errorText(failure, "Import failed")),
      },
    );
  };

  return (
    <div className="stack recorded-logins">
      {logins.data?.restore_note ? <p className="warn-text">{logins.data.restore_note}</p> : null}
      {logins.isLoading ? (
        <p className="cell-dim">Loading recorded logins…</p>
      ) : logins.data && logins.data.logins.length === 0 ? (
        <Empty title="No recorded logins" detail="Paste a script from the Login Recorder for Burp Suite extension (or a Chrome DevTools Recorder export) below." />
      ) : logins.data ? (
        <SimpleTable headers={["Label", "Steps", "Source", "Status check", ""]}>
          {logins.data.logins.map((login) => (
            <tr key={login.id}>
              <td>{login.label}</td>
              <td>
                {login.steps.length}
                {login.has_totp ? <Badge tone="info"> TOTP</Badge> : null}
              </td>
              <td className="cell-dim">{login.source ?? "—"}</td>
              <td className="cell-dim">{login.status_check ? <code>{login.status_check.url}</code> : "none"}</td>
              <td>
                <div className="toolbar">
                  {onUse ? (
                    <Button variant="outline" size="small" onClick={() => onUse(login.id)}>
                      Use
                    </Button>
                  ) : null}
                  <Button variant="outline" size="small" onClick={() => setEditing(editing === login.id ? null : login.id)}>
                    {editing === login.id ? "Close" : "Edit"}
                  </Button>
                  <Button
                    variant="outline"
                    size="small"
                    disabled={replay.isPending}
                    onClick={() =>
                      replay.mutate(login.id, {
                        onSuccess: (reply) => setReplayed(reply),
                        onError: (failure) => toast.error(errorText(failure, "Replay failed to start")),
                      })
                    }
                  >
                    {replay.isPending && replay.variables === login.id ? "Replaying…" : "Replay"}
                  </Button>
                  <Button
                    variant="outline"
                    size="small"
                    onClick={() =>
                      remove.mutate(login.id, {
                        onSuccess: () => {
                          if (editing === login.id) setEditing(null);
                          toast.success(`Deleted “${login.label}”`);
                        },
                        onError: (failure) => toast.error(errorText(failure, "Delete failed")),
                      })
                    }
                  >
                    Delete
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}

      {replayed ? <ReplayResult reply={replayed} onDismiss={() => setReplayed(null)} /> : null}
      {editingLogin ? <RecordedLoginEditor key={editingLogin.id + editingLogin.updated} login={editingLogin} /> : null}

      <h4 className="subheading">New recorded login</h4>
      <Field label="Label">{(id) => <Input id={id} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="alice (user)" />}</Field>
      <Field
        label="Paste script"
        hint="The JSON the Login Recorder for Burp Suite copies to the clipboard. Events that cannot be replayed are listed after the import, never dropped silently."
      >
        {(id) => <Textarea id={id} rows={5} value={script} onChange={(event) => setScript(event.target.value)} placeholder='[{"eventType":"start",…},{"eventType":"goto","url":"https://…"}]' />}
      </Field>
      <div className="toolbar-end">
        <Button size="small" disabled={script.trim() === "" || save.isPending} onClick={importScript}>
          Import
        </Button>
      </div>
      {notes ? <ImportNotes notes={notes} onDismiss={() => setNotes(null)} /> : null}
    </div>
  );
}

function ImportNotes({ notes, onDismiss }: { notes: ImportNote[]; onDismiss: () => void }): JSX.Element {
  return (
    <div className="stack">
      <div className="toolbar">
        <strong>Import notes</strong>
        <Button variant="outline" size="small" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
      {notes.length === 0 ? (
        <p className="cell-dim" style={{ margin: 0 }}>
          Every recorded event became a step.
        </p>
      ) : (
        <SimpleTable headers={["Event", "Type", "Outcome", "Why"]}>
          {notes.map((note) => (
            <tr key={`${note.event}-${note.outcome}-${note.detail}`}>
              <td>{note.event}</td>
              <td>
                <code>{note.event_type}</code>
              </td>
              <td>
                <Badge tone={note.outcome === "dropped" ? "warn" : "info"}>{note.outcome}</Badge>
              </td>
              <td>{note.detail}</td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </div>
  );
}

function ReplayResult({ reply, onDismiss }: { reply: ReplayReply; onDismiss: () => void }): JSX.Element {
  const { replay } = reply;
  return (
    <div className="stack replay-result">
      <div className="toolbar">
        <strong>Replay of “{reply.label}”</strong>
        <Badge tone={replay.succeeded ? "good" : "bad"}>{replay.succeeded ? "logged in" : "login failed"}</Badge>
        <span className="cell-dim">{(replay.elapsed_ms / 1000).toFixed(1)} s</span>
        <Button variant="outline" size="small" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
      {replay.reason ? <p className="warn-text" style={{ margin: 0 }}>{replay.reason}</p> : null}
      <SimpleTable headers={["#", "Step", "Result", "Page after"]}>
        {replay.steps.map((step) => (
          <tr key={step.index}>
            <td>{step.index}</td>
            <td>{step.description}</td>
            <td>{step.ok ? <Badge tone="good">done</Badge> : <Badge tone="bad">{step.error ?? "failed"}</Badge>}</td>
            <td className="cell-dim">
              <code>{step.url ?? ""}</code>
            </td>
          </tr>
        ))}
      </SimpleTable>
      <p className="cell-dim" style={{ margin: 0 }}>
        Ended on <code>{replay.final_url || "—"}</code>
        {replay.status_check ? (
          <>
            {" "}
            · status check <code>{replay.status_check.url}</code>: {replay.status_check.found ? "confirmation text found" : "confirmation text NOT found"}
          </>
        ) : (
          " · no status check configured"
        )}
        {" · "}
        {reply.cookie_names.length > 0 ? `cookies earned: ${reply.cookie_names.join(", ")}` : "no cookies earned"}
      </p>
      {replay.blocked.length > 0 ? (
        <div>
          <strong>Refused by scope ({replay.blocked.length})</strong>
          <p className="cell-dim" style={{ margin: 0 }}>
            A GET or POST line is a request the login page made, with its full URL. A CONNECT line is a tunnel the browser
            opened — the page, a frame, or Chrome's own background traffic — where only the host is visible. Add a host to scope
            only if the login needs it.
          </p>
          <ul className="replay-blocked">
            {replay.blocked.map((line) => (
              <li key={line}>
                <code>{line}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="cell-dim" style={{ margin: 0 }}>
          The scope gate refused nothing during this replay.
        </p>
      )}
      {reply.screenshot ? <img className="replay-shot" src={reply.screenshot} alt={`The page the replay of ${reply.label} ended on`} /> : <p className="cell-dim">No screenshot could be taken.</p>}
    </div>
  );
}

/** Burp's Edit Recorded Login dialog: the events as a table, or "See as JSON". */
function RecordedLoginEditor({ login }: { login: RecordedLoginView }): JSX.Element {
  const save = useSaveRecordedLogin();
  const [label, setLabel] = useState(login.label);
  const [steps, setSteps] = useState<StepDraft[]>(() => login.steps.map(draftFromView));
  const [checkURL, setCheckURL] = useState(login.status_check?.url ?? "");
  const [checkText, setCheckText] = useState(login.status_check?.text ?? "");
  const [asJSON, setAsJSON] = useState(false);
  const [jsonText, setJSONText] = useState("");
  const [jsonError, setJSONError] = useState("");
  const [newKind, setNewKind] = useState<LoginStepKind>("click");

  useEffect(() => {
    if (asJSON) setJSONText(JSON.stringify(steps, null, 2));
    // Only on entering the JSON view: the text is then the operator's to edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asJSON]);

  const update = (index: number, patch: Partial<StepDraft>) => setSteps((all) => all.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  const move = (index: number, by: number) =>
    setSteps((all) => {
      const next = [...all];
      const target = index + by;
      if (target < 0 || target >= next.length) return all;
      const a = next[index];
      const b = next[target];
      if (!a || !b) return all;
      next[index] = b;
      next[target] = a;
      return next;
    });

  const applyJSON = (): StepDraft[] | null => {
    try {
      const parsed = JSON.parse(jsonText) as unknown;
      if (!Array.isArray(parsed)) throw new Error("the JSON must be an array of steps");
      setJSONError("");
      return parsed as StepDraft[];
    } catch (failure) {
      setJSONError(errorText(failure, "not JSON"));
      return null;
    }
  };

  const submit = () => {
    const current = asJSON ? applyJSON() : steps;
    if (!current) return;
    if (asJSON) setSteps(current);
    const statusCheck = checkURL.trim() || checkText.trim() ? { url: checkURL.trim(), text: checkText } : null;
    save.mutate(
      { id: login.id, label, steps: current, status_check: statusCheck },
      {
        onSuccess: () => toast.success(`Saved “${label}”`),
        onError: (failure) => toast.error(errorText(failure, "Save failed")),
      },
    );
  };

  return (
    <div className="stack recorded-login-editor">
      <h4 className="subheading">Edit “{login.label}”</h4>
      <Field label="Label">{(id) => <Input id={id} value={label} onChange={(event) => setLabel(event.target.value)} />}</Field>
      <div className="toolbar">
        <Button variant={asJSON ? "outline" : "primary"} size="small" onClick={() => setAsJSON(false)} disabled={!asJSON}>
          View as events
        </Button>
        <Button
          variant={asJSON ? "primary" : "outline"}
          size="small"
          disabled={asJSON}
          onClick={() => setAsJSON(true)}
        >
          See as JSON
        </Button>
      </div>
      {asJSON ? (
        <>
          <Field label="Steps as JSON" hint="Secrets are never shown: a stored one appears as has_value / has_secret and is kept when you save.">
            {(id) => <Textarea id={id} rows={14} value={jsonText} onChange={(event) => setJSONText(event.target.value)} spellCheck={false} />}
          </Field>
          {jsonError ? <p className="warn-text">{jsonError}</p> : null}
        </>
      ) : (
        <SimpleTable className="login-steps-table" headers={["#", "Event", "Details", ""]}>
          {steps.map((step, index) => (
            <tr key={index}>
              <td>{index + 1}</td>
              <td>
                <Select aria-label={`Step ${index + 1} kind`} value={step.kind} onChange={(event) => update(index, blankStep(event.target.value as LoginStepKind))}>
                  {(Object.keys(KIND_LABELS) as LoginStepKind[]).map((kind) => (
                    <option key={kind} value={kind}>
                      {KIND_LABELS[kind]}
                    </option>
                  ))}
                </Select>
              </td>
              <td>
                <StepFields step={step} index={index} onChange={(patch) => update(index, patch)} />
                <small className="cell-dim">{describeDraft(step)}</small>
              </td>
              <td>
                <div className="toolbar">
                  <Button variant="outline" size="small" disabled={index === 0} onClick={() => move(index, -1)} aria-label={`Move step ${index + 1} up`}>
                    ↑
                  </Button>
                  <Button variant="outline" size="small" disabled={index === steps.length - 1} onClick={() => move(index, 1)} aria-label={`Move step ${index + 1} down`}>
                    ↓
                  </Button>
                  <Button variant="outline" size="small" onClick={() => setSteps((all) => all.filter((_, i) => i !== index))} aria-label={`Delete step ${index + 1}`}>
                    Delete
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </SimpleTable>
      )}
      {!asJSON ? (
        <div className="toolbar">
          <Select aria-label="Kind of step to insert" value={newKind} onChange={(event) => setNewKind(event.target.value as LoginStepKind)}>
            {(Object.keys(KIND_LABELS) as LoginStepKind[]).map((kind) => (
              <option key={kind} value={kind}>
                {KIND_LABELS[kind]}
              </option>
            ))}
          </Select>
          <Button variant="outline" size="small" onClick={() => setSteps((all) => [...all, blankStep(newKind)])}>
            Insert step
          </Button>
        </div>
      ) : null}
      <h4 className="subheading">Status check</h4>
      <p className="cell-dim" style={{ margin: 0 }}>
        After the steps, this page is loaded and must contain the confirmation text, or the login counts as failed. Required when the
        sequence has a TOTP step.
      </p>
      <div className="metric-grid wide">
        <Field label="URL">{(id) => <Input id={id} value={checkURL} onChange={(event) => setCheckURL(event.target.value)} placeholder="https://app.example/account" />}</Field>
        <Field label="Confirmation text">{(id) => <Input id={id} value={checkText} onChange={(event) => setCheckText(event.target.value)} placeholder="Sign out" />}</Field>
      </div>
      <div className="toolbar-end">
        <Button size="small" disabled={save.isPending} onClick={submit}>
          Save
        </Button>
      </div>
    </div>
  );
}

function StepFields({ step, index, onChange }: { step: StepDraft; index: number; onChange: (patch: Partial<StepDraft>) => void }): JSX.Element {
  const n = index + 1;
  const locator = (
    <>
      <Input aria-label={`Step ${n} CSS selector`} value={step.selector ?? ""} onChange={(event) => onChange({ selector: event.target.value })} placeholder="CSS selector, e.g. #username" />
      <Input aria-label={`Step ${n} XPath`} value={step.xpath ?? ""} onChange={(event) => onChange({ xpath: event.target.value })} placeholder="XPath fallback" />
    </>
  );
  switch (step.kind) {
    case "goto":
      return <Input aria-label={`Step ${n} URL`} value={step.url ?? ""} onChange={(event) => onChange({ url: event.target.value })} placeholder="https://app.example/login" />;
    case "click":
      return <div className="step-fields">{locator}</div>;
    case "type":
      return (
        <div className="step-fields">
          {locator}
          {step.secret ? (
            <Input
              aria-label={`Step ${n} secret value`}
              type="password"
              autoComplete="off"
              value={step.value ?? ""}
              onChange={(event) => onChange({ value: event.target.value })}
              placeholder={step.has_value ? "stored — type to replace" : "secret value"}
            />
          ) : (
            <Input aria-label={`Step ${n} text`} value={step.value ?? ""} onChange={(event) => onChange({ value: event.target.value })} placeholder="text to type" />
          )}
          <Checkbox
            checked={step.secret === true}
            label="Secret (redacted everywhere)"
            onCheckedChange={(secret) => onChange(secret ? { secret } : { secret, value: step.has_value && !step.value ? "" : step.value, has_value: false })}
          />
        </div>
      );
    case "totp": {
      const totp = step.totp ?? { algorithm: "SHA1", period: 30, digits: 6 };
      return (
        <div className="step-fields">
          {locator}
          <Input
            aria-label={`Step ${n} TOTP secret (Base32)`}
            type="password"
            autoComplete="off"
            value={totp.secret ?? ""}
            onChange={(event) => onChange({ totp: { ...totp, secret: event.target.value } })}
            placeholder={totp.has_secret ? "stored — type to replace" : "Base32 secret, e.g. JBSWY3DPEHPK3PXP"}
          />
          <Select aria-label={`Step ${n} TOTP algorithm`} value={totp.algorithm ?? "SHA1"} onChange={(event) => onChange({ totp: { ...totp, algorithm: event.target.value } })}>
            <option value="SHA1">SHA1</option>
            <option value="SHA256">SHA256</option>
            <option value="SHA512">SHA512</option>
          </Select>
          <Input aria-label={`Step ${n} TOTP period (seconds)`} type="number" min={1} value={totp.period} onChange={(event) => onChange({ totp: { ...totp, period: Number(event.target.value) } })} />
          <Input aria-label={`Step ${n} TOTP digits`} type="number" min={1} max={10} value={totp.digits} onChange={(event) => onChange({ totp: { ...totp, digits: Number(event.target.value) } })} />
        </div>
      );
    }
    case "key":
      return <Input aria-label={`Step ${n} key`} value={step.key ?? ""} onChange={(event) => onChange({ key: event.target.value })} placeholder="Enter, Tab, Escape…" />;
    case "wait":
      return <Input aria-label={`Step ${n} wait (ms)`} type="number" min={0} max={10000} value={step.wait_ms ?? 0} onChange={(event) => onChange({ wait_ms: Number(event.target.value) })} />;
  }
}
