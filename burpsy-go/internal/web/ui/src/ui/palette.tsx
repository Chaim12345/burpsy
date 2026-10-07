import * as Dialog from "@radix-ui/react-dialog";
import { Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { cn } from "../lib/cn";
import { keys, useResource } from "../lib/data";
import { useInvokeExtension } from "../lib/data.extensions";
import {
  RECENTS_GROUP,
  codecCommands,
  extensionCommands,
  recentCommands,
  type PaletteCommand,
} from "../lib/palette-commands";
import { paletteRecency, recordPaletteUse } from "../lib/palette-recency";
import {
  liveSelectionChoice,
  selectedText,
  selectionHint,
  selectionRunnable,
  transformSelectionIn,
  watchEditorFocus,
} from "../lib/palette-selection";
import type { PluginInvocation } from "../lib/plugin-registrations";
import type { SelectionCodec } from "../lib/selection-codecs";
import type { ExtensionList } from "../lib/types.extensions";
import { Kbd } from "./primitives";

export interface PaletteAction {
  id: string;
  label: string;
  group: string;
  hint?: string;
  shortcut?: string;
  keywords?: string;
  icon?: ComponentType<{ size?: number }>;
  /** Listed, but not runnable in the current state. The commit refuses it. */
  disabled?: boolean;
  /** Why it cannot run. Printed on rows the Recents group lifts away from their own heading. */
  disabledReason?: string;
  run: () => void;
}

/**
 * How many rows the result list renders.
 *
 * A bound on the DOM, not on what the palette offers — but it has to stay above the size of the
 * *whole* list, because the empty query matches everything and a cap below that count would
 * silently drop real commands off the bottom of the first thing an operator sees. The console's
 * own list is around eighty rows (navigation, settings sections, commands, seventeen codecs),
 * so this is roomy on purpose.
 */
const MAX_RESULTS = 160;

/**
 * Subsequence match with a bias toward word starts, so "hh" finds "HTTP history"
 * and "sqli" finds a payload named "SQL injection".
 */
function score(action: PaletteAction, term: string): number {
  if (!term) return 1;
  const haystack = `${action.label} ${action.group} ${action.keywords ?? ""}`.toLowerCase();
  const needle = term.toLowerCase();
  const direct = haystack.indexOf(needle);
  if (direct === 0) return 1000;
  if (direct > 0) return 700 - direct;

  const initials = haystack
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
    .map((word) => word[0] ?? "")
    .join("");
  if (initials.startsWith(needle)) return 600;

  let cursor = 0;
  for (const character of needle) {
    cursor = haystack.indexOf(character, cursor);
    if (cursor < 0) return 0;
    cursor += 1;
  }
  return 200;
}

export function CommandPalette({
  open,
  onOpenChange,
  actions,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actions: PaletteAction[];
}): JSX.Element {
  const [term, setTerm] = useState("");
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  // What a codec entry could do if it were run, resolved when the palette opens rather than at
  // render time: the answer is a fact about the page behind the dialog, and the dialog does not
  // change it while it is up. Only the two derived facts are kept — whether a codec can run, and
  // what to say when it cannot — because the entry itself re-resolves the live target when run.
  const [codecState, setCodecState] = useState<{ runnable: boolean; note?: string }>({
    runnable: false,
    note: "select text in a message editor first",
  });

  // The recency ledger, re-read every time the palette opens. Read inside the sort's useMemo it
  // was effectively frozen at mount — the memo's deps are the action list and the query, neither
  // of which changes when a command runs, so running a command never moved it. Recents that do
  // not move are not recents.
  const [recency, setRecency] = useState<Record<string, number>>({});

  // This component is mounted for the life of the console, so its effect is the natural place to
  // watch focus for the whole page (see watchEditorFocus).
  useEffect(() => watchEditorFocus(), []);

  /**
   * The extension list, fetched only while the palette is open.
   *
   * The same query key the Extensions page uses, so an operator who has been on that page pays
   * nothing here — but gated on `open`, because a console whose operator never presses mod+K
   * should not spend a request on a list only the palette would read.
   */
  const extensions = useResource<ExtensionList>(keys.extensions, "/api/extensions", open);
  const invokeExtension = useInvokeExtension();

  /**
   * Run one codec against whatever the page has selected.
   *
   * Editable target: the bytes are rewritten in place, which is what the editor's own menu row
   * does. Read-only target: the editor's menu shows the result in a dialog it owns and the
   * palette cannot open, so the result goes to the clipboard instead — a real result either way,
   * never a dispatch into a read-only view, which CodeMirror drops on the floor.
   */
  const runCodec = useCallback((codec: SelectionCodec) => {
    const choice = liveSelectionChoice();
    if (choice.kind !== "ready") {
      toast.error(`${codec.label}: ${selectionHint(choice) ?? "nothing to convert"}`);
      return;
    }
    if (choice.writable) {
      transformSelectionIn(choice.view, codec.transform);
      toast.success(`${codec.label} applied to the selection`);
      return;
    }
    const output = codec.transform(selectedText(choice.view));
    void copyToClipboard(output);
    toast.success(`${codec.label}: the message is read-only, so the result is on the clipboard`);
  }, []);

  const runExtension = useCallback(
    (call: PluginInvocation) => {
      invokeExtension.mutate(
        { name: call.plugin, registration: call.registration.id },
        {
          onSuccess: (answer) => {
            const said = answer.result.text ?? answer.result.output;
            toast.success(said ? `${call.registration.label}: ${said}` : `${call.registration.label} ran`);
          },
          onError: (failure: unknown) =>
            toast.error(
              failure instanceof Error
                ? `${call.registration.label}: ${failure.message}`
                : `${call.registration.label} failed`,
            ),
        },
      );
    },
    [invokeExtension],
  );

  /**
   * Everything the palette offers: what the shell handed in, plus the groups that are
   * enumerations of something the console already knows.
   *
   * Built here rather than by the caller because both extra groups depend on state only this
   * component holds — the open-time selection, and a query it only runs while it is open.
   */
  const allActions = useMemo<PaletteAction[]>(() => {
    const codecs: PaletteCommand[] = codecCommands(runCodec, codecState);
    const plugins: PaletteCommand[] = extensionCommands(extensions.data, runExtension);
    return [...actions, ...codecs, ...plugins];
  }, [actions, codecState, extensions.data, runCodec, runExtension]);

  const matches = useMemo(() => {
    const query = term.trim();
    return allActions
      .map((action) => {
        // Recency breaks ties only while the operator is typing: among two equally good text
        // matches the more recently run sorts first. It deliberately does *not* apply to the
        // empty query any more — every action ranks 1 there, so recency used to lift single rows
        // out of their group and print that group's heading twice. The Recents group below now
        // carries that signal, in one block, which is where Burp puts it.
        const rank = score(action, query);
        return { action, rank: query ? rank * 1000 + (recency[action.id] ?? 0) : rank };
      })
      .filter((entry) => entry.rank > 0)
      .sort((a, b) => b.rank - a.rank)
      .slice(0, MAX_RESULTS)
      .map((entry) => entry.action);
  }, [allActions, term, recency]);

  /**
   * Burp's "recently used commands at the top", shown on the empty query only — once a query is
   * typed the list is an answer to that query, and a block of unrelated commands above it would
   * push the answer off the screen.
   */
  const recents = useMemo(
    () => (term.trim() ? [] : recentCommands(allActions, recency)),
    [allActions, recency, term],
  );

  // The rendered order, with the group each row prints its heading from. A recent row is the
  // *same action object* as its copy further down: running it from here records the same id and
  // performs the same work, so Recents cannot drift from the list it summarises.
  //
  // A recent row does print its own hint, though. The list below states why a command cannot run
  // on its group heading, the way the editor's menu does — and Recents lifts the row out from
  // under that heading, so without this a disabled codec would sit among the recents looking
  // exactly like a working one and do nothing when chosen.
  const rows = useMemo(
    () => [
      ...recents.map((action) => ({
        key: `recent:${action.id}`,
        action,
        group: RECENTS_GROUP,
        hint: (action.disabled ? action.disabledReason : undefined) ?? action.hint,
      })),
      ...matches.map((action) => ({ key: action.id, action, group: action.group, hint: action.hint })),
    ],
    [recents, matches],
  );

  useEffect(() => {
    if (open) {
      setTerm("");
      setCursor(0);
      setRecency(paletteRecency());
      const choice = liveSelectionChoice();
      setCodecState({ runnable: selectionRunnable(choice), note: selectionHint(choice) });
    }
  }, [open]);

  useEffect(() => {
    setCursor(0);
  }, [term]);

  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" });
  }, [cursor, rows.length]);

  const commit = (action: PaletteAction | undefined) => {
    if (!action) return;
    // A disabled row states its condition in its group heading and stays where it is: closing the
    // palette on a command that cannot run would look exactly like running it.
    if (action.disabled) return;
    onOpenChange(false);
    recordPaletteUse(action.id);
    action.run();
  };

  // Group headings are rendered inline, so the flat list stays keyboard-addressable.
  let lastGroup = "";

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="palette" aria-label="Command palette">
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <div className="palette-input">
            <Search size={16} />
            {/* A raw input rather than the Input primitive: `.palette-input input` strips the
                border and background the primitive brings, and the palette is one search box in
                a dialog that already announces itself. It carries its own aria-label — the type
                system can only require a name on the primitive, so the handful of raw inputs
                left in the console have to supply one by hand. */}
            <input
              autoFocus
              value={term}
              placeholder="Jump to a view or run a command"
              aria-label="Search commands"
              aria-controls="palette-results"
              onChange={(event) => setTerm(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") {
                  event.preventDefault();
                  setCursor((current) => Math.min(rows.length - 1, current + 1));
                } else if (event.key === "ArrowUp") {
                  event.preventDefault();
                  setCursor((current) => Math.max(0, current - 1));
                } else if (event.key === "Enter") {
                  event.preventDefault();
                  commit(rows[cursor]?.action);
                }
              }}
            />
            <Kbd>esc</Kbd>
          </div>
          <div className="palette-results" id="palette-results" ref={listRef} role="listbox" aria-label="Commands">
            {rows.length === 0 ? <div className="palette-empty">No matching command</div> : null}
            {rows.map((row, index) => {
              const action = row.action;
              const heading = row.group !== lastGroup ? row.group : null;
              lastGroup = row.group;
              const Icon = action.icon;
              return (
                <div key={row.key}>
                  {heading ? <div className="palette-group">{heading}</div> : null}
                  <button
                    type="button"
                    role="option"
                    aria-selected={index === cursor}
                    // aria-disabled rather than the disabled attribute: `role="option"` has no
                    // disabled state of its own, and a disabled button stops firing the pointer
                    // events the cursor tracks.
                    aria-disabled={action.disabled || undefined}
                    data-active={index === cursor}
                    className={cn("palette-item", index === cursor && "palette-item-active")}
                    onMouseMove={() => setCursor(index)}
                    onClick={() => commit(action)}
                  >
                    <span className="palette-item-icon">{Icon ? <Icon size={14} /> : null}</span>
                    <span className="palette-item-label">
                      {action.label}
                      {row.hint ? <small>{row.hint}</small> : null}
                    </span>
                    {action.shortcut ? <Kbd>{action.shortcut}</Kbd> : null}
                  </button>
                </div>
              );
            })}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
