// The custom scan check editor (burpsy-react-ui-kbu1): Burp's Custom scan checks editor — write or
// edit a BCheck, Validate it, Run test against messages sent to the editor, and Save it into the
// corpus. Nothing is saved or filed until Save; a test run reports findings without recording them.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ApiError } from "../lib/api";
import { useApp } from "../lib/store";
import { confirmDialog } from "../lib/dialogs";
import {
  useImportCheck,
  useTestCheck,
  validateCheck,
  type CheckTestRun,
  type CheckValidation,
} from "../lib/data.customchecks";
import { Badge, Button, Input, Modal, NeedsValueButton, Textarea } from "./primitives";
import { SimpleTable } from "./table";

export interface EditorTarget {
  /** The draft to open with. */
  source: string;
  /** A console check being edited: Save replaces it. Null for a new draft or a copy of a file check. */
  editing: string | null;
  /** True for a file check opened read-only (it is saved by editing the file and reloading). */
  readOnly?: boolean;
  title: string;
}

function parseIds(text: string): number[] {
  return [...new Set(text.split(/[\s,]+/).map((v) => Number(v)).filter((n) => Number.isInteger(n) && n >= 0))];
}

export function CustomCheckEditor({ target, onClose }: { target: EditorTarget | null; onClose: () => void }): JSX.Element {
  const [source, setSource] = useState("");
  const [validation, setValidation] = useState<CheckValidation | null>(null);
  const [run, setRun] = useState<CheckTestRun | null>(null);
  const testIds = useApp((state) => state.customCheckTestIds);
  const setTestIds = useApp((state) => state.setCustomCheckTestIds);
  const [idsText, setIdsText] = useState("");
  const save = useImportCheck();
  const test = useTestCheck();

  useEffect(() => {
    if (!target) return;
    setSource(target.source);
    setValidation(null);
    setRun(null);
  }, [target]);
  useEffect(() => setIdsText(testIds.join(", ")), [testIds]);

  const validate = async (): Promise<CheckValidation | null> => {
    try {
      const v = await validateCheck(source);
      setValidation(v);
      return v;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
      return null;
    }
  };

  const onSave = async () => {
    const v = await validate();
    if (!v?.valid) return;
    let replace = target?.editing !== null && target?.editing === v.name;
    if (!replace && v.existing_origin === "console") {
      replace = await confirmDialog({
        title: `Replace "${v.name}"?`,
        description: `A console check named "${v.name}" is already loaded. Saving replaces it.`,
        confirmLabel: "Replace it",
      });
      if (!replace) return;
    }
    save.mutate(
      { source, replace },
      {
        onSuccess: (out) => {
          toast.success(
            out.persisted ? `Saved "${out.name}" (${out.kind}) into the corpus and the project` : `Loaded "${out.name}" (${out.kind}); no project database, so it lasts until restart`,
          );
          onClose();
        },
        onError: (error) => toast.error(error instanceof ApiError ? error.body || error.message : String(error)),
      },
    );
  };

  const onTest = () => {
    const ids = parseIds(idsText);
    setTestIds(ids);
    if (!ids.length) {
      toast.error("Add at least one exchange id — or use \"Send to custom scan check editor\" on a history row");
      return;
    }
    test.mutate(
      { source, exchange_ids: ids },
      {
        onSuccess: setRun,
        onError: (error) => toast.error(error instanceof ApiError ? error.body || error.message : String(error)),
      },
    );
  };

  const errorLine = validation?.error?.line;
  return (
    <Modal open={target !== null} onOpenChange={(open) => !open && onClose()} title={target?.title ?? "Custom scan check"} wide>
      <Textarea
        aria-label="BCheck source"
        className="mono"
        rows={20}
        spellCheck={false}
        value={source}
        readOnly={target?.readOnly}
        onChange={(event) => {
          setSource(event.target.value);
          setValidation(null);
        }}
      />
      <div className="toolbar" style={{ marginTop: 8, gap: 8, flexWrap: "wrap" }}>
        <Button variant="outline" onClick={() => void validate()}>
          Validate
        </Button>
        {!target?.readOnly ? (
          <Button onClick={() => void onSave()} disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save to corpus"}
          </Button>
        ) : (
          <span className="cell-dim">Loaded from {target.title.replace(/^.*— /, "")}: edit the file and Reload to change it.</span>
        )}
        {validation ? (
          validation.valid ? (
            <span role="status">
              <Badge tone="good">valid</Badge> {validation.name} · {validation.kind?.replace("_", " ")}
              {validation.existing_origin === "file" ? " · a file check has this name, so Save will be refused" : ""}
            </span>
          ) : (
            <span role="alert" className="cell-bad">
              <Badge tone="bad">invalid</Badge> {errorLine ? `line ${errorLine}:${validation.error?.column ?? 0} — ` : ""}
              {validation.error?.message}
            </span>
          )
        ) : null}
      </div>
      <div className="toolbar" style={{ marginTop: 12, gap: 8, alignItems: "flex-end", flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <Input
            aria-label="Test against exchanges (ids)"
            value={idsText}
            onChange={(event) => setIdsText(event.target.value)}
            placeholder="Exchange ids to test against, e.g. 3, 7, 12"
          />
        </div>
        <NeedsValueButton
          variant="outline"
          onClick={onTest}
          disabled={test.isPending}
          missing={parseIds(idsText).length ? null : "needs an exchange id"}
        >
          {test.isPending ? "Testing…" : "Run test"}
        </NeedsValueButton>
      </div>
      <p className="field-hint">
        An active check sends its probes to each exchange's target through the scope gate; nothing is filed.
      </p>
      {run ? (
        <SimpleTable headers={["Exchange", "Findings", "Probes", "Notes"]}>
          {run.results.map((r) => (
            <tr key={r.exchange_id}>
              <td title={r.url}>
                #{r.exchange_id} <span className="cell-dim">{r.url}</span>
              </td>
              <td>
                {r.findings.length ? (
                  r.findings.map((f, i) => (
                    <div key={i}>
                      <Badge tone="warn">{f.severity}</Badge> {f.name}
                      {f.param ? <span className="cell-dim"> · {f.param}</span> : null}
                    </div>
                  ))
                ) : (
                  <span className="cell-dim">none</span>
                )}
              </td>
              <td className="cell-num">
                {r.sent} sent{r.refused ? `, ${r.refused} refused (out of scope)` : ""}
              </td>
              <td>
                {r.error || r.unsupported || (r.unresolved.length ? `unresolved: ${r.unresolved.join(", ")}` : <span className="cell-dim">—</span>)}
              </td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
    </Modal>
  );
}
