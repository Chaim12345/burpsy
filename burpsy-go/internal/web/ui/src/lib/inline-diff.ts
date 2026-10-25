/**
 * Inline "compare with previous response" for the Repeater (burpsy-react-ui-6ibj): @codemirror/merge's
 * unified view laid over the response editor, so the operator sees deleted and inserted text in place
 * without leaving the pane for the Comparer page. Read-only use: no accept/reject controls, since the
 * previous response is evidence, not something to merge back.
 *
 * The previous response is split on the same separator the editor's own document uses
 * (lib/editor-eol.ts), so a CRLF response and its CRLF predecessor compare line for line.
 */
import { unifiedMergeView } from "@codemirror/merge";
import { Text, type Extension } from "@codemirror/state";

export function inlineDiffExtension(previous: string, separator: "\r\n" | "\r" | "\n"): Extension {
  return unifiedMergeView({
    original: Text.of(previous.split(separator)),
    mergeControls: false,
    gutter: true,
    highlightChanges: true,
    syntaxHighlightDeletions: false,
  });
}
