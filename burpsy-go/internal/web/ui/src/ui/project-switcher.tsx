import { useId, useState } from "react";
import { FileWarning, FolderCheck, FolderOpen, FolderPlus } from "lucide-react";
import { toast } from "sonner";
import { useOpenProject, useProject, useProjects } from "../lib/data";
import { existingProjectFor, newProjectFilename, projectEntries, readProjectRefusal, type ProjectRefusal } from "../lib/project-switch";
import type { ProjectListEntry } from "../lib/types";
import { Badge, Button, ErrorNotice, Field, Input, Modal, Spinner } from "./primitives";

/** The switch the operator has chosen and not yet confirmed. */
interface PendingSwitch {
 /** What is sent: a listed file's absolute path, or the typed name (resolved server-side). */
 path: string;
 /** How the target is named in the confirmation. */
 label: string;
 /** True when the file does not exist yet, so the switch creates an empty project. */
 creating: boolean;
}

/**
 * The project switcher (burpsy-react-ui-dlw2) — Burp's open/new project, over what burpsy has: a
 * directory of SQLite files beside the one this process has open.
 *
 * # Why a modal and not a submenu
 *
 * Choosing a project changes which engagement every other page in the console shows. A submenu has
 * no room for the consequence; the modal lists the directory, marks the open project, and states
 * what the switch replaces before the click that does it.
 *
 * # Two confirmations, on purpose
 *
 * Choosing a row (or typing a new file name) only stages the switch. The staged switch names the
 * project being left and the one being opened, and only its explicit "Switch" button mints the
 * server's one-time confirmation for /api/project/open and spends it — the gate's record of a human
 * click. Nothing is minted on open or on a row click.
 *
 * # New project
 *
 * The server creates a project when the path it is sent does not exist yet, so "new" is an open of
 * a new file name. `.db` is appended (the list only shows .db files, so a project without it could
 * never be listed again), and the resulting name is shown before anything is sent. A name that is
 * already listed is said to OPEN that project, not create an empty one.
 */
export function ProjectSwitcher({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
 const projects = useProjects(open);
 const current = useProject();
 const openProject = useOpenProject();
 const [pending, setPending] = useState<PendingSwitch | null>(null);
 const [typed, setTyped] = useState("");
 const [refusal, setRefusal] = useState<ProjectRefusal | null>(null);
 const confirmHeadingId = useId();
 const listHeadingId = useId();

 const list = projects.data;
 const entries = projectEntries(list);
 const dir = list?.project_dir ?? "";
 const filename = newProjectFilename(typed);
 const existing = existingProjectFor(filename, list);
 // Typing the open project's own name is not a switch: staging it would reset every page for nothing.
 const typedIsOpen = existing?.active ?? false;
 const leaving = !current.data
  ? "the open project"
  : current.data.persisted
    ? `${current.data.name} (${current.data.database})`
    : "this in-memory session (no project file — what it holds is not saved anywhere)";

 const close = (next: boolean) => {
  if (!next) {
   setPending(null);
   setRefusal(null);
   setTyped("");
  }
  onOpenChange(next);
 };

 const stageListed = (entry: ProjectListEntry) => {
  setRefusal(null);
  setPending({ path: entry.path, label: `${entry.name} (${entry.path})`, creating: false });
 };

 const stageNew = () => {
  if (filename === "" || typedIsOpen) return;
  setRefusal(null);
  setPending(
   existing
    ? { path: existing.path, label: `${existing.name} (${existing.path})`, creating: false }
    : { path: filename, label: dir && !filename.includes("/") ? `${dir}/${filename}` : filename, creating: true },
  );
 };

 const confirmSwitch = () => {
  if (!pending) return;
  setRefusal(null);
  openProject.mutate(pending.path, {
   onSuccess: (confirmed) => {
    if (confirmed.restore_error) {
     // The switch happened, so this is not a refusal — but it is not a clean switch either: what is
     // on screen may be missing part of the project. Said as a warning that stays until dismissed.
     toast.warning(`Switched to ${confirmed.database ?? pending.path}, but the project did not load completely`, {
      description: confirmed.restore_error,
      duration: Number.POSITIVE_INFINITY,
      closeButton: true,
     });
     close(false);
     return;
    }
    toast.success(
     confirmed.unnamed
      ? `Switched project — now writing to ${confirmed.database ?? pending.path}`
      : `Switched to ${confirmed.name} — ${confirmed.database ?? pending.path}`,
    );
    close(false);
   },
   onError: (failure) => {
    setRefusal(readProjectRefusal(failure));
    setPending(null);
   },
  });
 };

 return (
  <Modal
   open={open}
   onOpenChange={close}
   wide
   title="Open or create a project"
   description="A project is a burpsy database file. Opening one replaces everything this console shows — history, findings, scope, site map, organizer, rules — with that file's, and everything captured from then on is written to it."
  >
   <div className="stack">
    <p className="field-hint">
     Open now:{" "}
     {current.isPending ? (
      <Spinner label="Reading the open project" />
     ) : current.isError ? (
      "could not be read"
     ) : current.data?.persisted ? (
      <>
       <strong>{current.data.name}</strong> <span className="project-path">{current.data.database}</span>
      </>
     ) : (
      (current.data?.database_note ?? "no project file — this instance persists nothing")
     )}
    </p>

    {pending ? (
     <section className="notice notice-warn project-confirm" role="group" aria-labelledby={confirmHeadingId}>
      <FileWarning size={15} aria-hidden="true" />
      <div className="stack">
       <strong id={confirmHeadingId}>{pending.creating ? "Create and switch to a new project?" : "Switch project?"}</strong>
       <span>
        Leaving <strong>{leaving}</strong>.
       </span>
       <span>
        {pending.creating ? "Creating and opening " : "Opening "}
        <strong className="project-path">{pending.label}</strong>
        {pending.creating ? " — a new, empty project." : "."}
       </span>
       <span>
        Every page is reloaded from the project being opened: nothing from the one you are leaving stays on screen. Running crawls and
        audits are paused for the switch and resumed after it. Repeater tabs and Intruder&apos;s payloads, settings and last report are
        drafts kept in this browser, so they stay — but Intruder&apos;s base request and its insertion points belong to the project you are
        leaving and are cleared.
       </span>
       <div className="page-actions">
        <Button variant="outline" autoFocus disabled={openProject.isPending} onClick={() => setPending(null)}>
         Cancel
        </Button>
        <Button variant="danger" disabled={openProject.isPending} onClick={confirmSwitch}>
         {openProject.isPending ? "Switching…" : pending.creating ? "Create and switch" : "Switch project"}
        </Button>
       </div>
      </div>
     </section>
    ) : null}

    {refusal ? (
     <div className="error-notice" role="alert">
      <span className="error-notice-icon" aria-hidden="true">
       ⚠
      </span>
      <div>
       <strong>The project was not switched</strong>
       <span>{refusal.reason}</span>
       {refusal.remedy ? <span>{refusal.remedy}</span> : null}
      </div>
     </div>
    ) : null}

    <section className="stack" aria-labelledby={listHeadingId}>
     <strong id={listHeadingId}>{dir ? `Project files in ${dir}` : "Project files"}</strong>
     {projects.isPending ? (
      <Spinner label="Reading the project directory" />
     ) : projects.isError ? (
      <ErrorNotice title="Could not list the project files" error={projects.error} onRetry={() => void projects.refetch()} />
     ) : entries.length === 0 ? (
      <p className="field-hint">{list?.note ?? `No .db project files were found in ${dir || "the project directory"}.`}</p>
     ) : (
      <>
       {list?.note ? <p className="field-hint">{list.note}</p> : null}
       <ul className="project-list">
        {entries.map((entry) => (
         <li className="project-row" key={entry.path}>
          {entry.active ? <FolderCheck size={15} aria-hidden="true" /> : <FolderOpen size={15} aria-hidden="true" />}
          <div className="project-row-name">
           <strong>{entry.name}</strong>
           <span className="project-path">{entry.path}</span>
          </div>
          <Badge tone={entry.named ? "info" : "neutral"}>{entry.named ? "named" : "file name"}</Badge>
          {entry.active ? (
           <Badge tone="good">open now</Badge>
          ) : (
           <Button
            variant="outline"
            size="small"
            aria-label={`Open project ${entry.name}`}
            disabled={openProject.isPending}
            onClick={() => stageListed(entry)}
           >
            Open…
           </Button>
          )}
         </li>
        ))}
       </ul>
      </>
     )}
    </section>

    <form
     className="stack"
     onSubmit={(event) => {
      event.preventDefault();
      stageNew();
     }}
    >
     <Field
      label="New project file"
      hint={
       dir
        ? `A bare name is created in ${dir}; an absolute path anywhere. ".db" is added if it is missing.`
        : 'This instance has no project directory, so give an absolute path — a relative one resolves against burpsy\'s working directory. ".db" is added if it is missing.'
      }
     >
      {(id) => <Input id={id} value={typed} autoComplete="off" spellCheck={false} onChange={(event) => setTyped(event.target.value)} />}
     </Field>
     {filename !== "" ? (
      <p className="field-hint" aria-live="polite">
       {typedIsOpen
        ? `${filename} is the project already open.`
        : existing
          ? `${filename} already exists — this opens ${existing.name}, it does not create an empty project.`
          : `Will create ${filename}.`}
      </p>
     ) : null}
     <div className="page-actions">
      <Button type="submit" variant="outline" disabled={filename === "" || typedIsOpen || openProject.isPending}>
       <FolderPlus size={14} aria-hidden="true" />
       {existing ? "Open…" : "Create…"}
      </Button>
     </div>
    </form>
   </div>
  </Modal>
 );
}
