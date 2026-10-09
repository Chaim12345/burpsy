import { useMemo, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { useMessage } from "../lib/data";
import { buildExtractRule, MAX_EXTRACT_BYTES, previewExtract } from "../lib/intruder-extract";
import { HttpEditor } from "./editor";
import { Badge, Button, Field, Input, Modal } from "./primitives";

/**
 * Burp's "Define extract grep from response" (burpsy-react-ui-df8r): "Open the response extraction rule
 * dialog, and create a new extract grep item from the response" (intruder/results/workflow.html). The
 * operator highlights the value in the stored response; the rule is rebuilt as the selection changes —
 * Burp's "Update config based on selection" — and previewed against this same response before it can
 * be saved.
 *
 * Save is offered only when the preview extracts exactly the highlighted text at the highlighted place
 * (or, with nothing highlighted, extracts something at all): a rule that pulls a different value out of
 * the very response it was built from is not the rule the operator asked for, and saving it would make
 * every later row's Grep extract column quietly wrong. burpsy has one Grep - Extract rule, so a rule
 * already set is named and replaced deliberately, never overwritten silently.
 */
export function ExtractGrepDialog({
  responseId,
  label,
  currentExtract,
  onSave,
  onClose,
}: {
  responseId: number;
  label: string;
  currentExtract: string;
  onSave: (regex: string) => void;
  onClose: () => void;
}): JSX.Element {
  const message = useMessage(responseId);
  const text = message.data?.text ?? null;
  const [selection, setSelection] = useState<{ start: number; end: number } | null>(null);
  const [rule, setRule] = useState("");
  const [buildError, setBuildError] = useState<string | null>(null);

  const onRawSelection = (next: { start: number; end: number } | null) => {
    setSelection(next);
    if (!next || text === null) return;
    const built = buildExtractRule(text, next.start, next.end);
    if (built.ok) {
      setRule(built.rule.regex);
      setBuildError(null);
    } else {
      setBuildError(built.reason);
    }
  };

  const preview = useMemo(
    () => (text !== null && rule.trim() !== "" ? previewExtract(rule, text, selection ?? undefined) : null),
    [rule, text, selection],
  );
  const canSave =
    preview !== null && preview.ok && preview.value !== null && (selection === null || preview.matchesSelection);
  const replacing = currentExtract.trim() !== "" && currentExtract.trim() !== rule.trim();

  return (
    <Modal
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title="Define extract grep from response"
      description={`${label} · stored message ${responseId}`}
      wide
    >
      <div className="stack">
        <p className="field-hint">
          Highlight the value to extract in the Raw view below. The rule is rebuilt from your selection: the text just
          before it and just after it, grown until each occurs first where you highlighted, with the value captured
          between them.
        </p>
        <HttpEditor
          label={`Response · message ${responseId}`}
          readOnly
          height="320px"
          value={
            text ??
            (message.isFetching
              ? "Loading the stored response…"
              : message.error
                ? `Could not load message ${responseId}: ${message.error instanceof Error ? message.error.message : String(message.error)}`
                : "No bytes stored for this message.")
          }
          onRawSelection={text === null ? undefined : onRawSelection}
          filename={`intruder-response-${responseId}.txt`}
        />
        <Field
          label="Grep extract rule (regular expression)"
          hint="The first capture group of the first match is extracted from every response. Edit it if it should match more loosely."
        >
          {(id) => <Input id={id} value={rule} onChange={(event) => setRule(event.target.value)} placeholder="Highlight a value above" />}
        </Field>
        {buildError ? <p className="field-hint">{buildError}</p> : null}
        {preview === null ? null : !preview.ok ? (
          <div className="notice notice-warn">
            <AlertTriangle size={15} />
            <div>{preview.reason}</div>
          </div>
        ) : preview.value === null ? (
          <div className="notice notice-warn">
            <AlertTriangle size={15} />
            <div>This rule extracts nothing from this response.</div>
          </div>
        ) : (
          <div className={selection && !preview.matchesSelection ? "notice notice-warn" : "notice"}>
            <div>
              <strong>Extracts</strong> <code>{preview.value}</code>{" "}
              {selection ? (
                preview.matchesSelection ? (
                  <Badge tone="good">the highlighted text</Badge>
                ) : (
                  <Badge tone="warn">not the highlighted text — it matches at offset {preview.at}</Badge>
                )
              ) : null}
              {preview.truncated ? <p className="field-hint">The attack keeps the first {MAX_EXTRACT_BYTES} bytes of a longer value.</p> : null}
            </div>
          </div>
        )}
        {replacing ? (
          <p className="field-hint">
            This replaces the current Grep extract rule <code>{currentExtract}</code> — an attack has one.
          </p>
        ) : null}
        <p className="field-hint">It applies to the next attack you launch; the rows of this report keep what they extracted.</p>
        <div className="toolbar">
          <Button
            onClick={() => {
              onSave(rule.trim());
              onClose();
            }}
            disabled={!canSave}
          >
            {replacing ? "Replace grep extract" : "Use as grep extract"}
          </Button>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </div>
    </Modal>
  );
}
