// Which message editor a palette-run codec acts on (burpsy-react-ui-1wrb).
//
// The editor's own "Convert selection" rows have the answer for free: they are rendered by the
// editor that owns the selection. A palette entry has no such owner — mod+K opens a dialog over
// a console that may be showing a request editor, a response editor, both, or neither — so the
// palette has to work out its target before it can honestly claim the command will run.
//
// The rule mirrors the editor's: a codec acts on a *selection*, and with no selection the row is
// disabled rather than silently doing nothing (`disabled: !hasSelection`, and the menu's own
// heading "Convert selection (select text first)"). Two things are added here because a global
// command has to deal with them and a per-editor menu never does: a selection can belong to a
// read-only message, and two editors on screen can each be holding one.
import { EditorView } from "@codemirror/view";
import { selectionText, selectionTransformSpec } from "./editor-eol";

/** One candidate editor, reduced to the three facts the choice turns on. */
export interface CandidateEditor<V> {
 view: V;
 /** Whether it holds a non-empty selection range right now. */
 hasSelection: boolean;
 /** Whether a dispatch into it would be applied rather than dropped on the floor. */
 writable: boolean;
 /** Whether it is the editor the operator touched most recently. */
 lastFocused: boolean;
}

export type SelectionChoice<V> =
 /** Nothing is selected anywhere, so there is nothing to convert. */
 | { kind: "none" }
 /** Several editors hold a selection and none of them was focused last: converting one of them
  *  would be a guess, and a guess that rewrites bytes is worse than a disabled row. */
 | { kind: "ambiguous"; count: number }
 | { kind: "ready"; view: V; writable: boolean };

/**
 * The editor a codec should act on, or why there isn't one.
 *
 * Last-focused wins when several editors hold a selection, because CodeMirror keeps each view's
 * selection through a blur: opening a request editor, selecting, then clicking into the response
 * leaves *both* views holding one, and the operator means the one they were last in.
 */
export function chooseSelectionTarget<V>(candidates: CandidateEditor<V>[]): SelectionChoice<V> {
 const selecting = candidates.filter((candidate) => candidate.hasSelection);
 if (selecting.length === 0) return { kind: "none" };
 const focused = selecting.find((candidate) => candidate.lastFocused);
 const chosen = focused ?? (selecting.length === 1 ? selecting[0] : undefined);
 if (!chosen) return { kind: "ambiguous", count: selecting.length };
 return { kind: "ready", view: chosen.view, writable: chosen.writable };
}

/**
 * What to tell the operator about this choice, in the palette's hint line.
 *
 * A ready-and-writable target needs no explanation — the entry does the obvious thing. Every
 * other case gets a sentence naming the condition, so a disabled row is never a mystery.
 */
export function selectionHint<V>(choice: SelectionChoice<V>): string | undefined {
 if (choice.kind === "none") return "select text in a message editor first";
 if (choice.kind === "ambiguous") {
  return `${choice.count} editors hold a selection — click into the one you mean`;
 }
 if (!choice.writable) return "read-only message — the result is copied to the clipboard";
 return undefined;
}

/** Whether the palette should offer this choice as a runnable entry at all. */
export function selectionRunnable<V>(choice: SelectionChoice<V>): boolean {
 return choice.kind === "ready";
}

/* --- the live document --------------------------------------------------- */

let lastFocusedEditor: Element | null = null;

/**
 * Remember which editor the operator was last in.
 *
 * A capturing document listener rather than a per-editor handler: the editors are built by
 * `ui/editor.tsx`, which this work does not own, and focus order is a property of the page
 * rather than of any one editor. Returns its own uninstaller, so a caller's effect can clean up.
 */
export function watchEditorFocus(target: Document = document): () => void {
 const onFocusIn = (event: Event) => {
  const node = event.target;
  if (!(node instanceof Element)) return;
  const editor = node.closest(".cm-editor");
  if (editor) lastFocusedEditor = editor;
 };
 target.addEventListener("focusin", onFocusIn, true);
 return () => {
  target.removeEventListener("focusin", onFocusIn, true);
 };
}

/** True when the element is rendered — a tab that is not showing still has its editors in the DOM. */
function isVisible(element: HTMLElement): boolean {
 const check = (element as HTMLElement & { checkVisibility?: () => boolean }).checkVisibility;
 if (typeof check === "function") return check.call(element);
 return element.offsetParent !== null;
}

/**
 * Every mounted, visible CodeMirror view, with the facts `chooseSelectionTarget` needs.
 *
 * `EditorView.findFromDOM` rather than a registry the editors push themselves into: the view is
 * already discoverable from its own DOM, and a registry would mean editing the editor.
 */
export function candidateEditors(root: ParentNode = document): CandidateEditor<EditorView>[] {
 const found: CandidateEditor<EditorView>[] = [];
 for (const element of root.querySelectorAll(".cm-editor")) {
  if (!(element instanceof HTMLElement) || !isVisible(element)) continue;
  const view = EditorView.findFromDOM(element);
  if (!view) continue;
  found.push({
   view,
   hasSelection: view.state.selection.ranges.some((range) => !range.empty),
   // `state.readOnly` alone: ui/editor.tsx sets the CodeMirror `editable` and `readOnly` props
   // from the same expression, so they cannot disagree, and readOnly is the one that decides
   // whether a dispatch survives.
   writable: !view.state.readOnly,
   lastFocused: lastFocusedEditor === element,
  });
 }
 return found;
}

/** The live answer: what a codec entry would act on if it were run right now. */
export function liveSelectionChoice(root: ParentNode = document): SelectionChoice<EditorView> {
 return chooseSelectionTarget(candidateEditors(root));
}

/**
 * The selected text, as the read-only path needs it: the main range, like the editor's own dialog.
 * Read as the message's real text, CR bytes included — CodeMirror's document has every CRLF as a
 * lone "\n" (lib/editor-eol.ts, burpsy-react-ui-eslt).
 */
export function selectedText(view: EditorView): string {
 return selectionText(view.state);
}

/**
 * Rewrite every non-empty selected range through `transform`, and report the result.
 *
 * The same spec as `transformSelection` in ui/editor.tsx (selectionTransformSpec) — all ranges, not
 * just the main one, read as real text and written back verbatim, so a multi-cursor selection and a
 * selection across a CRLF convert the way the editor's own menu converts them.
 */
export function transformSelectionIn(view: EditorView, transform: (input: string) => string): string {
 const spec = selectionTransformSpec(view.state, transform);
 if (!spec) return "";
 view.dispatch(spec);
 view.focus();
 return spec.changes.map((change) => change.insert).join("\n");
}
