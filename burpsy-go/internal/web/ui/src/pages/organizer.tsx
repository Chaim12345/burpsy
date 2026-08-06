import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Plus, RotateCcw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useOrganizer, useOrganizerMutations } from "../lib/data";
import { useApp } from "../lib/store";
import type { OrganizerItem } from "../lib/types";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Textarea, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/** The highlight vocabulary the organizer stores; "none" is the absence of one. */
const HIGHLIGHTS = ["none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"];

const HIGHLIGHT_TONE: Record<string, "neutral" | "bad" | "warn" | "good" | "info" | "accent"> = {
  red: "bad",
  orange: "warn",
  yellow: "warn",
  green: "good",
  cyan: "info",
  blue: "info",
  pink: "accent",
  magenta: "accent",
};

interface Draft {
  title: string;
  note: string;
  highlight: string;
}

function draftOf(item: OrganizerItem): Draft {
  return { title: item.title, note: item.note, highlight: item.highlight || "none" };
}

export function OrganizerPage(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useOrganizer();
  const mutations = useOrganizerMutations();
  const focusExchange = useApp((state) => state.focusExchange);
  const setRoute = useApp((state) => state.setRoute);

  /** Selection is by item id: a refetch reorders or replaces objects, ids survive it. */
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [baseline, setBaseline] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [exchangeId, setExchangeId] = useState("");

  const items = useMemo(() => data?.items ?? [], [data]);
  const selected = useMemo(() => items.find((item) => item.id === selectedId) ?? null, [items, selectedId]);
  const dirty = draft !== null && JSON.stringify(draft) !== baseline;

  // Adopt the server's copy only while the note has no unsaved edits, so a refetch
  // triggered by another pane cannot throw away what the operator is typing.
  useEffect(() => {
    if (!selected) {
      if (draft !== null) {
        setDraft(null);
        setBaseline("");
      }
      return;
    }
    const next = JSON.stringify(draftOf(selected));
    if (next === baseline) return;
    if (draft !== null && JSON.stringify(draft) !== baseline) return;
    setDraft(draftOf(selected));
    setBaseline(next);
  }, [selected, draft, baseline]);

  const select = (item: OrganizerItem) => {
    setSelectedId(item.id);
    setDraft(draftOf(item));
    setBaseline(JSON.stringify(draftOf(item)));
  };

  const add = () => {
    const exchange = Number(exchangeId.trim());
    // `< 0`, not `<= 0`. Exchange ids count from zero, so exchange 0 is the first request captured in
    // a session — the one most likely to be reached for first, and the one this guard used to refuse.
    if (!Number.isInteger(exchange) || exchange < 0) {
      toast.error("Enter an exchange id — a whole number, counting from 0");
      return;
    }
    mutations.add.mutate(exchange, {
      onSuccess: (item) => {
        setExchangeId("");
        select(item);
        toast.success(`Saved exchange #${exchange}`);
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save that exchange"),
    });
  };

  const save = () => {
    if (!selected || !draft) return;
    const payload: OrganizerItem = {
      id: selected.id,
      exchange: selected.exchange,
      title: draft.title,
      note: draft.note,
      highlight: draft.highlight === "none" ? "" : draft.highlight,
    };
    mutations.save.mutate(payload, {
      onSuccess: () => {
        setBaseline(JSON.stringify(draft));
        toast.success("Note saved");
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Save failed"),
    });
  };

  const remove = (id: number) => {
    mutations.remove.mutate(id, {
      onSuccess: () => {
        if (selectedId === id) {
          setSelectedId(null);
          setDraft(null);
          setBaseline("");
        }
        toast.success("Removed from the organizer");
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Delete failed"),
    });
    setConfirmDelete(null);
  };

  /** Reveal the underlying exchange in HTTP history rather than copying its bytes here. */
  const openInHistory = (exchange: number) => {
    focusExchange(exchange);
    setRoute("history");
  };

  if (error) {
    return (
      <div className="page">
        <PageHeader title="Organizer" />
        <ErrorNotice error={error} onRetry={() => void refetch()} />
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        title="Organizer"
        description="A shortlist of exchanges worth coming back to, with the note that says why."
        actions={
          <>
            <Badge>{items.length} saved</Badge>
            <RefreshButton onClick={() => void refetch()} loading={isFetching} />
          </>
        }
      />

      <Card>
        <SectionHeading
          title="Saved exchanges"
          detail="Usually added from HTTP history's save action; an exchange id works too."
        />
        <Toolbar>
          <div className="inline-add">
            <Input
              aria-label="Exchange id to save"
              value={exchangeId}
              inputMode="numeric"
              placeholder="exchange id"
              onChange={(event) => setExchangeId(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") add();
              }}
              style={{ maxWidth: "var(--w-sm)" }}
            />
            <Button variant="outline" size="small" onClick={add} disabled={!exchangeId.trim() || mutations.add.isPending}>
              <Plus size={13} />
              Save exchange
            </Button>
          </div>
        </Toolbar>
        {isLoading ? (
          <LoadingPanel label="Loading saved exchanges" />
        ) : items.length === 0 ? (
          <Empty
            title="Nothing saved yet"
            detail="Save an exchange from HTTP history, or add one by id above, to start an investigation note."
          />
        ) : (
          <SimpleTable headers={["#", "Exchange", "Title", "Highlight", "Note", ""]}>
            {items.map((item) => (
              <tr
                key={item.id}
                className={item.id === selectedId ? "data-row clickable selected-row" : "data-row clickable"}
                onClick={() => select(item)}
              >
                <td>
                  <span className="cell-num">{item.id}</span>
                </td>
                <td>
                  <span className="cell-num">#{item.exchange}</span>
                </td>
                <td>{item.title || <span className="cell-dim">untitled</span>}</td>
                <td>
                  {item.highlight ? (
                    <Badge tone={HIGHLIGHT_TONE[item.highlight] ?? "neutral"}>{item.highlight}</Badge>
                  ) : (
                    <span className="cell-dim">—</span>
                  )}
                </td>
                <td>
                  <span className="cell-dim">{item.note ? item.note.split("\n")[0] : "no note"}</span>
                </td>
                <td>
                  <div className="chip-row">
                    <IconButton
                      label={`Open exchange #${item.exchange} in HTTP history`}
                      size="small"
                      onClick={(event) => {
                        event.stopPropagation();
                        openInHistory(item.exchange);
                      }}
                    >
                      <ExternalLink size={13} />
                    </IconButton>
                    <IconButton
                      label={`Remove item ${item.id}`}
                      size="small"
                      onClick={(event) => {
                        event.stopPropagation();
                        setConfirmDelete(item.id);
                      }}
                    >
                      <Trash2 size={13} />
                    </IconButton>
                  </div>
                </td>
              </tr>
            ))}
          </SimpleTable>
        )}
      </Card>

      <Card>
        {selected && draft ? (
          <>
            <SectionHeading
              title={`Exchange #${selected.exchange}`}
              detail="The note stays attached to the exchange, not to a copy of its bytes."
              actions={
                <>
                  {dirty ? <Badge tone="warn">unsaved changes</Badge> : <Badge tone="good">saved</Badge>}
                  <Button variant="outline" size="small" onClick={() => openInHistory(selected.exchange)}>
                    <ExternalLink size={13} />
                    Show in history
                  </Button>
                  <Button
                    variant="outline"
                    size="small"
                    disabled={!dirty}
                    onClick={() => {
                      setDraft(JSON.parse(baseline) as Draft);
                      toast.success("Reverted to the saved note");
                    }}
                  >
                    <RotateCcw size={13} />
                    Revert
                  </Button>
                  <Button size="small" onClick={save} disabled={!dirty || mutations.save.isPending}>
                    <Save size={13} />
                    {mutations.save.isPending ? "Saving…" : "Save"}
                  </Button>
                  <Button variant="danger" size="small" onClick={() => setConfirmDelete(selected.id)}>
                    <Trash2 size={13} />
                    Remove
                  </Button>
                </>
              }
            />
            <div className="stack">
              <div className="form-grid">
                <Field label="Title" hint="What this exchange is, in a few words.">
                  <Input
                    value={draft.title}
                    placeholder="admin panel exposes user list"
                    onChange={(event) => setDraft({ ...draft, title: event.target.value })}
                  />
                </Field>
                <Field label="Highlight" hint="Matches the colour vocabulary used across the console.">
                  <Select
                    aria-label="Highlight colour"
                    value={draft.highlight}
                    onChange={(event) => setDraft({ ...draft, highlight: event.target.value })}
                  >
                    {HIGHLIGHTS.map((colour) => (
                      <option key={colour} value={colour}>
                        {colour}
                      </option>
                    ))}
                  </Select>
                </Field>
              </div>
              <Field label="Investigation note" hint="Saved explicitly; a background refresh will not overwrite an edit in progress.">
                <Textarea
                  value={draft.note}
                  rows={8}
                  placeholder="What was observed, what to try next, and which request reproduces it."
                  onChange={(event) => setDraft({ ...draft, note: event.target.value })}
                />
              </Field>
            </div>
          </>
        ) : (
          <Empty title="No item selected" detail="Choose a saved exchange to read or edit its note." />
        )}
      </Card>

      <Modal
        open={confirmDelete !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmDelete(null);
        }}
        title="Remove this item?"
        description="The note is deleted. The exchange itself stays in HTTP history."
      >
        <div className="page-actions">
          <Button variant="outline" onClick={() => setConfirmDelete(null)}>
            Keep it
          </Button>
          <Button
            variant="danger"
            disabled={mutations.remove.isPending}
            onClick={() => (confirmDelete === null ? undefined : remove(confirmDelete))}
          >
            <Trash2 size={13} />
            Remove item
          </Button>
        </div>
      </Modal>
    </div>
  );
}
