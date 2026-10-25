import { useEffect, useMemo, useState } from "react";
import { Plus, RotateCcw, Save, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { formatCount } from "../lib/api";
import { useScanConfigLibrary, useScannerIssueTypes } from "../lib/data.attack";
import {
  addParameter,
  draftFrom,
  filterIssueTypes,
  hexIndex,
  methodEnabled,
  saveBlocker,
  setMethodEnabled,
  setOnlySelected,
  setTypeRuns,
  settingsPatch,
  typeRuns,
  type SelectionDraft,
  type SelectionFilter,
} from "../lib/scan-selection";
import type { AuditConfigView, BuiltInConfigView, IssueTypeRow } from "../lib/types.attack";
import { DetailList } from "../ui/json";
import { LoadingPanel } from "../ui/layout";
import { Badge, Button, Checkbox, ErrorNotice, Field, IconButton, Input, Select } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/**
 * One scan configuration's per-issue selection, parameter exemptions and run overrides
 * (burpsy-react-ui-saq3.3.1), opened from a row of the Configuration library.
 *
 * In its own file rather than grown inside settings.tsx, for the reason settings.network.tsx gives:
 * concurrent work on that page and on this surface cannot collide over the same lines.
 *
 * # What it edits, and through what
 *
 * The allow list (`issue_types`), its deny half (`disabled_issue_types`, and per-type
 * `disabled_detection_methods`), and Burp's two parameter skip lists — written through the library's
 * `settings` block, which overlays only the keys a save carries, onto the SAVED configuration of the
 * same name. Before this the API carried all five and an operator could only set them by importing
 * a Burp file. A shipped configuration opens read-only, with every control visibly disabled rather
 * than hidden, so the panel still answers "what does this preset select?".
 *
 * # What it shows and does not edit
 *
 * The declines (what an imported selection named that this engine did not act on) are a derived
 * report the server never accepts as input. The per-run overrides and JavaScript-analysis keys
 * (o2p3, 9mti) are set by importing a configuration file; they are shown so a run's behaviour is
 * readable here, and labelled as not editable rather than rendered as inert inputs.
 */
export function ScanConfigDetail({ config, onClose }: { config: BuiltInConfigView; onClose: () => void }): JSX.Element {
  const readOnly = config.shipped;
  const catalogue = useScannerIssueTypes();
  const library = useScanConfigLibrary();
  const base = useMemo(() => draftFrom(config.resolved), [config.resolved]);
  const [draft, setDraft] = useState<SelectionDraft>(base);
  // A refetch that brings a new saved version replaces the draft: the editor must not go on showing,
  // and then saving, what the configuration was before another tab changed it.
  useEffect(() => setDraft(base), [base]);

  const patch = settingsPatch(base, draft);
  const dirty = Object.keys(patch).length > 0;
  const blocker = saveBlocker(draft);
  const headingId = "scan-config-detail-heading";

  const save = (): void => {
    library.mutate(
      { action: "save", name: config.name, from: config.name, settings: patch },
      {
        onSuccess: () => toast.success(`Saved ${config.name}`),
        onError: (cause: Error) => toast.error(cause.message),
      },
    );
  };

  return (
    <section className="stack scan-config-detail" aria-labelledby={headingId}>
      <div className="toolbar">
        <h3 className="subheading" id={headingId}>
          {readOnly ? "Viewing" : "Editing"} {config.name}
        </h3>
        {readOnly ? <Badge>shipped (read-only)</Badge> : <Badge tone="info">saved</Badge>}
        {dirty ? <Badge tone="warn">unsaved changes</Badge> : null}
        <span style={{ flex: 1 }} />
        <IconButton label="Close this configuration" size="small" onClick={onClose}>
          <X size={14} />
        </IconButton>
      </div>
      {readOnly ? (
        <p className="field-hint">
          burpsy ships this configuration, so it is read-only: save a copy of it above under your own name and edit that.
        </p>
      ) : null}

      <IssueSelection catalogue={catalogue} draft={draft} setDraft={setDraft} readOnly={readOnly} />

      <Declines declines={config.resolved.declined_detection_methods ?? []} />

      <h4 className="subheading">Parameter exemptions</h4>
      <p className="field-hint">
        Matched by parameter name, case-insensitively, wherever the parameter appears. Burp also accepts match rules
        (by location, item and regular expression); this engine has no matcher for those, so only names are offered.
      </p>
      <div className="scan-config-exemptions">
        <ParameterList
          title="Skip all tests for these parameters"
          hint="Every check skips these parameters' insertion points, and each skip is recorded on the audit item."
          names={draft.skipAll}
          readOnly={readOnly}
          onChange={(skipAll) => setDraft((current) => ({ ...current, skipAll }))}
        />
        <ParameterList
          title="Skip server-side injection tests for these parameters"
          hint="SQL injection, XPath and the other server-side injection checks skip these parameters; every other check still tests them."
          names={draft.skipServerSide}
          readOnly={readOnly}
          onChange={(skipServerSide) => setDraft((current) => ({ ...current, skipServerSide }))}
        />
      </div>

      <RunOverrides view={config.resolved} />

      {readOnly ? null : (
        <div className="stack">
          {blocker ? (
            <p className="field-hint warn-text" role="status">
              {blocker}
            </p>
          ) : null}
          <div className="toolbar">
            <Button size="small" disabled={!dirty || blocker !== null || library.isPending} onClick={save}>
              <Save size={14} />
              {library.isPending ? "Saving…" : "Save changes"}
            </Button>
            <Button variant="outline" size="small" disabled={!dirty || library.isPending} onClick={() => setDraft(base)}>
              <RotateCcw size={14} />
              Revert
            </Button>
            {dirty ? (
              <span className="field-hint">
                Will write {Object.keys(patch).join(", ")}; every other setting of {config.name} stays as saved.
              </span>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}

const FILTERS: { value: SelectionFilter; label: string }[] = [
  { value: "all", label: "All issue types" },
  { value: "running", label: "Runs" },
  { value: "not-running", label: "Does not run" },
  { value: "changed", label: "Changed from the default" },
];

function IssueSelection({
  catalogue,
  draft,
  setDraft,
  readOnly,
}: {
  catalogue: ReturnType<typeof useScannerIssueTypes>;
  draft: SelectionDraft;
  setDraft: (update: (current: SelectionDraft) => SelectionDraft) => void;
  readOnly: boolean;
}): JSX.Element {
  const [term, setTerm] = useState("");
  const [filter, setFilter] = useState<SelectionFilter>("all");
  const rows = catalogue.data?.issue_types ?? [];
  const shown = useMemo(() => filterIssueTypes(rows, draft, term, filter), [rows, draft, term, filter]);
  const running = rows.filter((row) => typeRuns(draft, row.type_index)).length;

  return (
    <div className="stack">
      <h4 className="subheading">Issue selection</h4>
      <Checkbox
        label="Run only the selected issue types"
        checked={draft.onlySelected}
        disabled={readOnly}
        onCheckedChange={(on) => setDraft((current) => setOnlySelected(current, on))}
      />
      <p className="field-hint">
        {draft.onlySelected
          ? "Only the ticked issue types run (Burp's “scan only selected issues”). Switching this off clears the selection."
          : "Every issue type runs except the ones unticked below. Unticking a detection method withholds that method's probes for its issue type."}
      </p>
      {catalogue.error ? <ErrorNotice error={catalogue.error} onRetry={() => void catalogue.refetch()} /> : null}
      {catalogue.isLoading ? <LoadingPanel label="Loading the issue catalogue" /> : null}
      {catalogue.data ? (
        <>
          <p className="field-hint" role="status">
            {formatCount(running)} of {formatCount(rows.length)} issue types run · {formatCount(draft.disabledMethods.length)}{" "}
            detection {draft.disabledMethods.length === 1 ? "method" : "methods"} switched off · {formatCount(shown.length)} shown
          </p>
          <div className="toolbar">
            <Field label="Search issue types">
              {(id) => (
                <Input
                  id={id}
                  type="search"
                  value={term}
                  onChange={(event) => setTerm(event.target.value)}
                  placeholder="name, or a type index like 0x00100200"
                  style={{ minWidth: "var(--w-md)" }}
                />
              )}
            </Field>
            <Field label="Show">
              {(id) => (
                <Select id={id} value={filter} onChange={(event) => setFilter(event.target.value as SelectionFilter)}>
                  {FILTERS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          {shown.length === 0 ? (
            <p className="field-hint">No issue type matches this search and filter.</p>
          ) : (
            // The height bound lives on this wrapper rather than inside SimpleTable, so the scrolling
            // element can be a named, focusable region: a read-only (shipped) configuration disables
            // every checkbox, and a scroll box with nothing focusable in it cannot be scrolled by
            // keyboard at all (axe scrollable-region-focusable, found on the shipped view).
            <div className="scan-selection-scroll" role="region" aria-label="Issue types" tabIndex={0}>
              <SimpleTable headers={["Issue type", "Type index", "Detection methods"]} className="scan-selection-table">
                {shown.map((row) => (
                  <IssueTypeRowView key={row.type_index} row={row} draft={draft} setDraft={setDraft} readOnly={readOnly} />
                ))}
              </SimpleTable>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}

function IssueTypeRowView({
  row,
  draft,
  setDraft,
  readOnly,
}: {
  row: IssueTypeRow;
  draft: SelectionDraft;
  setDraft: (update: (current: SelectionDraft) => SelectionDraft) => void;
  readOnly: boolean;
}): JSX.Element {
  const runs = typeRuns(draft, row.type_index);
  return (
    <tr>
      <td>
        <Checkbox
          label={row.name}
          checked={runs}
          disabled={readOnly}
          onCheckedChange={(on) => setDraft((current) => setTypeRuns(current, row.type_index, on))}
        />
      </td>
      <td>
        <span className="cell-dim">{hexIndex(row.type_index)}</span>
      </td>
      <td>
        {row.detection_methods.length === 0 ? (
          <span className="cell-dim">selected by type alone</span>
        ) : (
          <div className="chip-row">
            {row.detection_methods.map((method) => {
              const implemented = row.implemented_methods.includes(method);
              return (
                <Checkbox
                  key={method}
                  checked={methodEnabled(draft, row.type_index, method)}
                  disabled={readOnly}
                  onCheckedChange={(on) => setDraft((current) => setMethodEnabled(current, row.type_index, method, on))}
                  label={
                    <>
                      {method}
                      <span className="sr-only"> for {row.name}</span>
                      {implemented ? null : <span className="cell-dim"> (not run here)</span>}
                    </>
                  }
                />
              );
            })}
          </div>
        )}
      </td>
    </tr>
  );
}

function Declines({ declines }: { declines: AuditConfigView["declined_detection_methods"] }): JSX.Element {
  return (
    <div className="stack">
      <h4 className="subheading">Declined from the imported selection</h4>
      {declines.length === 0 ? (
        <p className="field-hint">None: everything this configuration's selection names is acted on as written.</p>
      ) : (
        <>
          <p className="field-hint">
            What an imported Burp selection named that this engine does not act on. Read-only: it is recomputed from the
            selection, and switching a method off removes its row here.
          </p>
          <SimpleTable headers={["Issue type", "Method", "Reason"]} className="scan-config-declines">
            {declines.map((decline) => (
              <tr key={`${decline.type_index}:${decline.method}:${decline.reason}`}>
                <td>{decline.issue || hexIndex(decline.type_index)}</td>
                <td>{decline.method || <span className="cell-dim">the whole issue type</span>}</td>
                <td>{decline.reason}</td>
              </tr>
            ))}
          </SimpleTable>
        </>
      )}
    </div>
  );
}

function ParameterList({
  title,
  hint,
  names,
  readOnly,
  onChange,
}: {
  title: string;
  hint: string;
  names: string[];
  readOnly: boolean;
  onChange: (names: string[]) => void;
}): JSX.Element {
  const [entry, setEntry] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = (): void => {
    const next = addParameter(names, entry);
    if (next.error) {
      setError(next.error);
      return;
    }
    onChange(next.list);
    setEntry("");
    setError(null);
  };
  return (
    <div className="stack">
      <h5 className="subheading">{title}</h5>
      <p className="field-hint">{hint}</p>
      {names.length === 0 ? (
        <p className="field-hint">No parameters: none is exempted.</p>
      ) : (
        <ul className="chip-row" aria-label={title}>
          {names.map((name) => (
            <li key={name}>
              <Badge>
                <code>{name}</code>
                {readOnly ? null : (
                  <IconButton
                    label={`Remove ${name} from “${title}”`}
                    size="small"
                    onClick={() => onChange(names.filter((existing) => existing !== name))}
                  >
                    <Trash2 size={12} />
                  </IconButton>
                )}
              </Badge>
            </li>
          ))}
        </ul>
      )}
      {readOnly ? null : (
        <div className="toolbar">
          <Input
            aria-label={`Parameter name to add to “${title}”`}
            value={entry}
            onChange={(event) => {
              setEntry(event.target.value);
              setError(null);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                add();
              }
            }}
            placeholder="parameter name"
            style={{ maxWidth: "var(--w-md)" }}
          />
          <Button variant="outline" size="small" disabled={entry.trim() === ""} onClick={add}>
            <Plus size={14} />
            Add
          </Button>
        </div>
      )}
      {error ? (
        <p className="field-hint warn-text" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

const onOff = (value: boolean | null, unset: string): string => (value === null ? unset : value ? "on" : "off");
const seconds = (value: number | null, unset: string): string =>
  value === null ? unset : value === 0 ? "no limit" : `${formatCount(value)} s`;

function RunOverrides({ view }: { view: AuditConfigView }): JSX.Element {
  return (
    <div className="stack">
      <h4 className="subheading">Run overrides and JavaScript analysis</h4>
      <p className="field-hint">
        Set by importing a Burp configuration file, not editable here. “Not overridden” means the run uses the
        engagement's own setting.
      </p>
      <DetailList
        rows={[
          { label: "Follow redirections", value: onOff(view.follow_redirections ?? null, "not overridden") },
          { label: "Connect timeout", value: seconds(view.connect_timeout_s ?? null, "not overridden") },
          { label: "Normal timeout", value: seconds(view.normal_timeout_s ?? null, "not overridden") },
          { label: "JavaScript analysis", value: onOff(view.javascript_analysis ?? null, "inherited") },
          { label: "Static analysis", value: onOff(view.javascript_static_analysis ?? null, "on (unset)") },
          { label: "Dynamic analysis", value: onOff(view.javascript_dynamic_analysis ?? null, "on (unset)") },
          { label: "Max static time per item", value: seconds(view.max_static_time_per_item_s ?? null, "no limit (unset)") },
          { label: "Max dynamic time per item", value: seconds(view.max_dynamic_time_per_item_s ?? null, "no limit (unset)") },
        ]}
      />
    </div>
  );
}
