import * as Dialog from "@radix-ui/react-dialog";
import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { cn } from "../lib/cn";
import { paletteRecency, recordPaletteUse } from "../lib/palette-recency";
import { Kbd } from "./primitives";

export interface PaletteAction {
  id: string;
  label: string;
  group: string;
  hint?: string;
  shortcut?: string;
  keywords?: string;
  icon?: ComponentType<{ size?: number }>;
  run: () => void;
}

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

  const matches = useMemo(() => {
    const recency = paletteRecency();
    return actions
      .map((action) => {
        const rank = score(action, term.trim());
        // Recency only breaks ties between equal text ranks (the empty query's flat 1, or two
        // actions matching equally well): among equal ranks the larger recency sequence — the
        // more recently run — sorts first. A genuinely better text match still wins over a
        // recently-run worse one, because rank dominates the comparison (Burp's palette
        // behaves the same way).
        return { action, rank: rank * 1000 + (recency[action.id] ?? 0) };
      })
      .filter((entry) => entry.rank > 0)
      .sort((a, b) => b.rank - a.rank)
      .slice(0, 60)
      .map((entry) => entry.action);
  }, [actions, term]);

  useEffect(() => {
    if (open) {
      setTerm("");
      setCursor(0);
    }
  }, [open]);

  useEffect(() => {
    setCursor(0);
  }, [term]);

  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" });
  }, [cursor, matches.length]);

  const commit = (action: PaletteAction | undefined) => {
    if (!action) return;
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
                  setCursor((current) => Math.min(matches.length - 1, current + 1));
                } else if (event.key === "ArrowUp") {
                  event.preventDefault();
                  setCursor((current) => Math.max(0, current - 1));
                } else if (event.key === "Enter") {
                  event.preventDefault();
                  commit(matches[cursor]);
                }
              }}
            />
            <Kbd>esc</Kbd>
          </div>
          <div className="palette-results" id="palette-results" ref={listRef} role="listbox" aria-label="Commands">
            {matches.length === 0 ? <div className="palette-empty">No matching command</div> : null}
            {matches.map((action, index) => {
              const heading = action.group !== lastGroup ? action.group : null;
              lastGroup = action.group;
              const Icon = action.icon;
              return (
                <div key={action.id}>
                  {heading ? <div className="palette-group">{heading}</div> : null}
                  <button
                    type="button"
                    role="option"
                    aria-selected={index === cursor}
                    data-active={index === cursor}
                    className={cn("palette-item", index === cursor && "palette-item-active")}
                    onMouseMove={() => setCursor(index)}
                    onClick={() => commit(action)}
                  >
                    <span className="palette-item-icon">{Icon ? <Icon size={14} /> : null}</span>
                    <span className="palette-item-label">
                      {action.label}
                      {action.hint ? <small>{action.hint}</small> : null}
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
