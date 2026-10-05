/**
 * The pure half of the in-console project switch (burpsy-react-ui-dlw2): reading the list, turning
 * what the operator typed into the path that will be sent, and reading a refusal. Kept out of the
 * component so each rule can be asserted in `bun test` without a DOM.
 */
import { ApiError } from "./api";
import type { ProjectList, ProjectListEntry } from "./types";

/** The list's rows, with Go's nil slice (`"projects": null`) read as no rows. */
export function projectEntries(list: ProjectList | undefined): ProjectListEntry[] {
 return list?.projects ?? [];
}

/**
 * The file name a "new project" entry becomes. GET /api/projects lists only `.db` files, so a new
 * project created without the extension would be a project the switcher could never show again;
 * the extension is appended, and the component shows the result before anything is sent, so the
 * operator never confirms a path they did not see.
 */
export function newProjectFilename(typed: string): string {
 const trimmed = typed.trim();
 if (trimmed === "") return "";
 return trimmed.toLowerCase().endsWith(".db") ? trimmed : `${trimmed}.db`;
}

/**
 * The listed project a typed name already names, if any — so "Create" on an existing file is
 * stated as what it is (opening that project) rather than letting the operator believe they made
 * a new, empty one. Only bare names (resolved beside the current project) and exact absolute
 * paths are matched; anything else is not claimed either way.
 */
export function existingProjectFor(filename: string, list: ProjectList | undefined): ProjectListEntry | undefined {
 if (filename === "") return undefined;
 const dir = list?.project_dir ?? "";
 const isBare = !filename.includes("/") && !filename.includes("\\");
 const candidate = isBare && dir !== "" ? `${dir.replace(/[/\\]+$/, "")}/${filename}` : filename;
 return projectEntries(list).find((entry) => entry.path === candidate);
}

/** A refused switch: the reason, and what the operator can do about it when there is something. */
export interface ProjectRefusal {
 reason: string;
 remedy?: string;
}

/**
 * Read why POST /api/project/open failed.
 *
 * The handler refuses with `{reason, remedy}` JSON (a bad path, a file that is not a database) and
 * with plain text for a malformed request, and the gate in front of it answers 428 with `{error}`.
 * The shared `api()` reader only knows `error`/`message`, so a `{reason, remedy}` body would reach
 * the operator as raw JSON — this reads the body itself and falls back to the message.
 */
export function readProjectRefusal(failure: unknown): ProjectRefusal {
 if (failure instanceof ApiError) {
  const body = failure.body.trim();
  if (body.startsWith("{")) {
   try {
    const parsed = JSON.parse(body) as { reason?: unknown; remedy?: unknown; error?: unknown };
    if (typeof parsed.reason === "string" && parsed.reason !== "") {
     return {
      reason: parsed.reason,
      remedy: typeof parsed.remedy === "string" && parsed.remedy !== "" ? parsed.remedy : undefined,
     };
    }
   } catch {
    // Not JSON after all: the message below is the plain text.
   }
  }
  return { reason: failure.message || `the server answered ${failure.status}` };
 }
 if (failure instanceof Error) return { reason: failure.message };
 return { reason: String(failure) };
}
