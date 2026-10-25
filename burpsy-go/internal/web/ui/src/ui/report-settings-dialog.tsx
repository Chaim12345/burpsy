import { useEffect, useState } from "react";
import { Button, Checkbox, Field, Input, Modal, Select, Toolbar } from "./primitives";

/**
 * The report-settings dialog (burpsy-react-ui-a9qy) — Burp's reporting wizard
 * ("Report settings", report-settings.html) as one small surface on the Issues
 * page. Every choice here is a query parameter on the export links, so the
 * file the operator downloads is the file the settings describe.
 *
 * Which choices reach which formats is the wizard's own split, kept honest
 * here: title, organisation and TOC depth are HTML-report details ("For HTML
 * reports, you can specify the following details"); the issue-detail sections
 * and the HTTP-messages mode and length apply to the HTML report and to the
 * Burp-XML export alike, because Burp's own XML writer reads the same
 * issue-details settings.
 */

/** The four issue-detail sections, in the wizard's order. */
export const REPORT_SECTIONS = [
 { value: "background", label: "Issue background", hint: "the catalogue's standard description and remediation advice" },
 { value: "detail", label: "Issue detail", hint: "this finding's own detail text" },
 { value: "remediation", label: "Remediation detail", hint: "this finding's own remediation text" },
 { value: "classifications", label: "Vulnerability classifications", hint: "the CWE mappings and further-reading links" },
] as const;

export type ReportSection = (typeof REPORT_SECTIONS)[number]["value"];

export type ReportSettings = {
 /** The document's h1 and <title>; empty is burpsy's default heading. */
 title: string;
 /** The primary grouping: severity (the default), type or url. */
 organiseBy: "severity" | "type" | "url";
 /** 0 = no TOC, 1 = groups, 2 = groups plus findings. */
 tocDepth: 0 | 1 | 2;
 /** Which issue-detail sections print. An empty set prints every section. */
 sections: Set<ReportSection>;
 /** How evidence messages appear. "none" is the bulk export's rule. */
 messageMode: "none" | "relevant" | "full";
 /** Bound each message at this many bytes; "" means no bound. */
 maxMessageLen: string;
};

export const DEFAULT_REPORT_SETTINGS: ReportSettings = {
 title: "",
 organiseBy: "severity",
 tocDepth: 0,
 sections: new Set(REPORT_SECTIONS.map((s) => s.value)),
 messageMode: "none",
 maxMessageLen: "",
};

/**
 * The query-string form of the settings, for the export links. Only the
 * parameters the format consumes are sent: the JSON and SARIF exports have no
 * document structure to configure, and sending them a title would be a
 * parameter that quietly does nothing.
 *
 * `sections` is the one subtlety: absent means every section (the default),
 * so it is only sent when the operator changed it — and "sections=" with
 * nothing on it means every section off, which the API treats as its own
 * state, not as the default.
 */
export function reportSettingsQuery(settings: ReportSettings, format: string): string {
 const params = new URLSearchParams();
 if (format === "html") {
  if (settings.title.trim()) params.set("title", settings.title.trim());
  if (settings.organiseBy !== "severity") params.set("organise_by", settings.organiseBy);
  if (settings.tocDepth > 0) params.set("toc_depth", String(settings.tocDepth));
 }
 if (format === "html" || format === "xml") {
  if (settings.sections.size !== REPORT_SECTIONS.length) {
   if (settings.sections.size === 0) params.set("sections", "");
   else params.set("sections", [...settings.sections].join(","));
  }
  // The XML export defaults to full messages when the mode is unstated, so "Do not include" has to
  // be said out loud for it; the HTML export's own default is none, and the query stays minimal.
  if (settings.messageMode !== "none" || format === "xml") params.set("message_mode", settings.messageMode);
  const len = settings.maxMessageLen.trim();
  if (len) params.set("max_message_len", len);
 }
 return params.toString();
}

/** True when any setting differs from the defaults, for the toolbar hint. */
export function reportSettingsActive(settings: ReportSettings): boolean {
 return (
  settings.title.trim() !== DEFAULT_REPORT_SETTINGS.title ||
  settings.organiseBy !== DEFAULT_REPORT_SETTINGS.organiseBy ||
  settings.tocDepth !== DEFAULT_REPORT_SETTINGS.tocDepth ||
  settings.sections.size !== REPORT_SECTIONS.length ||
  settings.messageMode !== DEFAULT_REPORT_SETTINGS.messageMode ||
  settings.maxMessageLen.trim() !== DEFAULT_REPORT_SETTINGS.maxMessageLen
 );
}

export function ReportSettingsDialog({
 open,
 onOpenChange,
 settings,
 onApply,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 settings: ReportSettings;
 onApply: (settings: ReportSettings) => void;
}): JSX.Element {
 // A draft edited in the dialog, applied only on Apply — a cancelled edit must
 // not change what the export links carry.
 const [draft, setDraft] = useState<ReportSettings>(settings);
 useEffect(() => {
  if (open) setDraft(settings);
 }, [open, settings]);

 const lenOk = draft.maxMessageLen.trim() === "" || /^\d+$/.test(draft.maxMessageLen.trim());
 const titleOk = draft.title.length <= 200;

 const apply = () => {
  if (!lenOk || !titleOk) return;
  onApply({
   ...draft,
   title: draft.title.trim(),
   maxMessageLen: draft.maxMessageLen.trim(),
   sections: new Set(draft.sections),
  });
  onOpenChange(false);
 };

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   title="Report settings"
   description="Burp's reporting wizard: what the exported HTML and XML reports carry. Title, organisation and contents are HTML-only; sections and messages apply to both."
  >
   <div className="stack">
    <Field
     label="Report title"
     hint={titleOk ? "replaces “burpsy scan report” as the document's heading" : "the title is capped at 200 characters"}
    >
     {(id) => (
      <Input
       id={id}
       value={draft.title}
       maxLength={200}
       placeholder="burpsy scan report"
       aria-invalid={!titleOk}
       onChange={(event) => setDraft((d) => ({ ...d, title: event.target.value }))}
      />
     )}
    </Field>

    <Field label="Organise issues by" hint="severity is the reader-first default; each group still leads with its worst finding">
     {(id) => (
      <Select
       id={id}
       value={draft.organiseBy}
       onChange={(event) => setDraft((d) => ({ ...d, organiseBy: event.target.value as ReportSettings["organiseBy"] }))}
      >
       <option value="severity">Severity</option>
       <option value="type">Issue type</option>
       <option value="url">URL</option>
      </Select>
     )}
    </Field>

    <Field label="Contents" hint="levels of detail in the table of contents">
     {(id) => (
      <Select
       id={id}
       value={String(draft.tocDepth)}
       onChange={(event) => setDraft((d) => ({ ...d, tocDepth: Number(event.target.value) as ReportSettings["tocDepth"] }))}
      >
       <option value="0">No table of contents</option>
       <option value="1">Groups only</option>
       <option value="2">Groups and findings</option>
      </Select>
     )}
    </Field>

    <Field label="Issue detail sections" hint="every section prints when all are ticked — an unticked box is the only way one is dropped">
     {() => (
      <div className="stack">
       {REPORT_SECTIONS.map((section) => (
        <Checkbox
         key={section.value}
         checked={draft.sections.has(section.value)}
         label={
          <>
           {section.label} — <small>{section.hint}</small>
          </>
         }
         onCheckedChange={(on) =>
          setDraft((d) => {
           const sections = new Set(d.sections);
           if (on) sections.add(section.value);
           else sections.delete(section.value);
           return { ...d, sections };
          })
         }
        />
       ))}
      </div>
     )}
    </Field>

    <Field
     label="HTTP messages"
     hint={
      draft.messageMode === "relevant"
       ? "the header block of each evidence message, labelled as an extract — burpsy's findings carry no highlight spans, so Burp's highlighted extract cannot be located (gaps.md)"
       : draft.messageMode === "full"
         ? "whole messages, bounded by the maximum length"
         : "the bulk export's rule: a scan-wide report that inlined every request body would be unusable as a document"
     }
    >
     {() => (
      <div className="stack">
       <Checkbox
        checked={draft.messageMode === "none"}
        label="Do not include"
        onCheckedChange={() => setDraft((d) => ({ ...d, messageMode: "none" }))}
       />
       <Checkbox
        checked={draft.messageMode === "relevant"}
        label="Include relevant extract (headers)"
        onCheckedChange={() => setDraft((d) => ({ ...d, messageMode: "relevant" }))}
       />
       <Checkbox
        checked={draft.messageMode === "full"}
        label="Include in full"
        onCheckedChange={() => setDraft((d) => ({ ...d, messageMode: "full" }))}
       />
      </div>
     )}
    </Field>

    <Field
     label="Maximum message length (bytes)"
     hint={lenOk ? "0 or empty means no bound; a message cut by the bound carries a [truncated] marker" : "the length is a number of bytes"}
    >
     {(id) => (
      <Input
       id={id}
       value={draft.maxMessageLen}
       inputMode="numeric"
       placeholder="no bound"
       aria-invalid={!lenOk}
       onChange={(event) => setDraft((d) => ({ ...d, maxMessageLen: event.target.value }))}
      />
     )}
    </Field>

    <Toolbar>
     <Button onClick={apply} disabled={!lenOk || !titleOk}>
      Apply
     </Button>
     <Button variant="outline" onClick={() => setDraft(DEFAULT_REPORT_SETTINGS)}>
      Reset to defaults
     </Button>
    </Toolbar>
   </div>
  </Modal>
 );
}
