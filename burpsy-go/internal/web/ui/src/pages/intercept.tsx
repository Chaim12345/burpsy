import { useEffect, useMemo, useRef, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { ArrowDown, ArrowUp, Plus, Send, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatDuration } from "../lib/api";
import { useInterceptControls } from "../lib/data";
import {
  useForwardHeld,
  useInterceptDetailed,
  useInterceptRules,
  useSaveInterceptRules,
  type InterceptDirection,
} from "../lib/data.attack";
import type { HeldMessageDetail, InterceptRuleSpec } from "../lib/types.attack";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SplitPane } from "../ui/layout";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  Empty,
  ErrorNotice,
  IconButton,
  Input,
  Metric,
  Select,
  Switch,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Toolbar,
} from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";

const FIELDS: { value: InterceptRuleSpec["field"]; label: string }[] = [
  { value: "host", label: "Host" },
  { value: "path", label: "Path" },
  { value: "extension", label: "File extension" },
  { value: "method", label: "Method" },
  { value: "url", label: "URL" },
  { value: "status_code", label: "Status code" },
  { value: "content_type", label: "Content type" },
];

const CATEGORIES: { value: InterceptRuleSpec["category"]; label: string }[] = [
  { value: "regex", label: "Regex" },
  { value: "literal", label: "Literal" },
];

/** A new row's field defaults to what that direction is usually written against: a host for a
 * request, a status code for a response — matching the vanilla intercept.ts default. */
function defaultRule(dir: InterceptDirection): InterceptRuleSpec {
  return {
    field: dir === "requests" ? "host" : "status_code",
    enabled: true,
    string_match: "",
    category: "regex",
    comment: "",
  };
}

/** States whether the list is doing anything, and — the state that looks selective and holds
 * nothing — whether every enabled condition is actually switched off. */
function describeRules(active: boolean, rules: InterceptRuleSpec[], noun: string): string {
  if (!active) return `off — no ${noun} is held`;
  if (rules.length === 0) return `on with no conditions — every ${noun} is held`;
  if (!rules.some((r) => r.enabled)) return `on, but every condition is unchecked — no ${noun} is held`;
  return `on with ${rules.length} condition(s)`;
}

function RuleEditor({ direction }: { direction: InterceptDirection }): JSX.Element {
  const { data, error, isFetching, refetch } = useInterceptRules(direction);
  const save = useSaveInterceptRules(direction);
  const noun = direction === "requests" ? "request" : "response";

  const [active, setActive] = useState(false);
  const [rules, setRules] = useState<InterceptRuleSpec[]>([]);
  const [dirty, setDirty] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const [pendingFocus, setPendingFocus] = useState<{ index: number; dir: "up" | "down" } | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  // The server is the source of truth until the operator starts editing: re-syncing on every poll
  // would fight their cursor and revert an unsaved checkbox mid-keystroke.
  useEffect(() => {
    if (!data || dirty) return;
    setActive(data.active);
    setRules(data.rules);
  }, [data, dirty]);

  const update = (patch: (list: InterceptRuleSpec[]) => InterceptRuleSpec[]) => {
    setRules(patch);
    setDirty(true);
  };

  // Copied from matchreplace.tsx's move() (102-110) so the three rule-order tools behave
  // identically. Goes through `update`, so a reorder is marked dirty exactly like add/remove
  // are, and survives the server-sync effect above.
  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    update((list) => {
      const next = [...list];
      const [moved] = next.splice(index, 1);
      if (!moved) return list;
      next.splice(target, 0, moved);
      return next;
    });
    // Focus follows the moved rule so a second press repeats the action, unless that would
    // land focus on the now-disabled control at the boundary — then it goes to the other
    // direction's button on the same row, which stays enabled.
    const disabledAtTarget = (delta < 0 && target === 0) || (delta > 0 && target === rules.length - 1);
    const dir: "up" | "down" = delta < 0 ? "up" : "down";
    setPendingFocus({ index: target, dir: disabledAtTarget ? (dir === "up" ? "down" : "up") : dir });
    setAnnouncement(`${noun === "request" ? "Request" : "Response"} rule moved to position ${target + 1} of ${rules.length}`);
  };

  useEffect(() => {
    if (!pendingFocus) return;
    const { index, dir } = pendingFocus;
    const label = `Move rule ${index + 1} ${dir}`;
    const el = tableRef.current?.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
    el?.focus();
    setPendingFocus(null);
  }, [pendingFocus, rules]);

  const onSave = () => {
    save.mutate(
      { active, rules },
      {
        onSuccess: (resp) => {
          setActive(resp.active);
          setRules(resp.rules);
          setDirty(false);
          toast.success(`${direction === "requests" ? "Request" : "Response"} rules saved`);
        },
        onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  if (error) return <ErrorNotice error={error} onRetry={() => void refetch()} />;
  if (!data && isFetching) return <Card>Loading…</Card>;
  if (data && !data.wired) {
    return (
      <div className="notice notice-warn">
        {direction === "requests" ? "Request" : "Response"} interception rules are not wired up.
      </div>
    );
  }

  return (
    <Card>
      <div>
        <Toolbar>
          <Checkbox
            checked={active}
            onCheckedChange={(checked) => {
              setActive(checked);
              setDirty(true);
            }}
            label={`Hold ${noun}s matching these rules`}
          />
          <span className="field-hint">{describeRules(active, rules, noun)}</span>
          <span style={{ flex: 1 }} />
          <Button
            variant="outline"
            size="small"
            onClick={() =>
              update((list) => [...list, defaultRule(direction)])
            }
          >
            <Plus size={13} />
            Add rule
          </Button>
          <Button size="small" onClick={onSave} disabled={!dirty || save.isPending}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </Toolbar>
      </div>
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>
      <div className="table-frame" ref={tableRef}>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                {/* Percentages so the columns track the table's own width; fixed
                    pixels do not scale under table-layout: fixed. */}
                <th style={{ width: "8%" }}>On</th>
                <th style={{ width: "18%" }}>Field</th>
                <th>Match</th>
                <th style={{ width: "12%" }}>Kind</th>
                <th style={{ width: "18%" }}>Comment</th>
                <th style={{ width: "10%" }}>Order</th>
                <th style={{ width: "6%" }} />
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="cell-dim">
                    no rules — every {noun} is held while this list is on
                  </td>
                </tr>
              ) : (
                rules.map((rule, index) => (
                  <tr key={index}>
                    <td>
                      <Checkbox
                        checked={rule.enabled}
                        onCheckedChange={(checked) =>
                          update((list) => list.map((r, i) => (i === index ? { ...r, enabled: checked } : r)))
                        }
                        label="On"
                      />
                    </td>
                    <td>
                      <Select
                        aria-label={`Field for rule ${index + 1}`}
                        value={rule.field}
                        onChange={(event) =>
                          update((list) =>
                            list.map((r, i) => (i === index ? { ...r, field: event.target.value as InterceptRuleSpec["field"] } : r)),
                          )
                        }
                      >
                        {FIELDS.map((f) => (
                          <option key={f.value} value={f.value}>
                            {f.label}
                          </option>
                        ))}
                      </Select>
                    </td>
                    <td>
                      <Input
                        aria-label={`Match pattern for rule ${index + 1}`}
                        value={rule.string_match}
                        placeholder="pattern to match"
                        onChange={(event) =>
                          update((list) => list.map((r, i) => (i === index ? { ...r, string_match: event.target.value } : r)))
                        }
                      />
                    </td>
                    <td>
                      <Select
                        aria-label={`Match kind for rule ${index + 1}`}
                        value={rule.category}
                        onChange={(event) =>
                          update((list) =>
                            list.map((r, i) => (i === index ? { ...r, category: event.target.value as InterceptRuleSpec["category"] } : r)),
                          )
                        }
                      >
                        {CATEGORIES.map((c) => (
                          <option key={c.value} value={c.value}>
                            {c.label}
                          </option>
                        ))}
                      </Select>
                    </td>
                    <td>
                      <Input
                        aria-label={`Comment for rule ${index + 1}`}
                        value={rule.comment}
                        placeholder="label"
                        onChange={(event) =>
                          update((list) => list.map((r, i) => (i === index ? { ...r, comment: event.target.value } : r)))
                        }
                      />
                    </td>
                    <td>
                      <div className="chip-row">
                        <IconButton
                          label={`Move rule ${index + 1} up`}
                          size="small"
                          disabled={index === 0}
                          onClick={() => move(index, -1)}
                        >
                          <ArrowUp size={13} />
                        </IconButton>
                        <IconButton
                          label={`Move rule ${index + 1} down`}
                          size="small"
                          disabled={index === rules.length - 1}
                          onClick={() => move(index, 1)}
                        >
                          <ArrowDown size={13} />
                        </IconButton>
                      </div>
                    </td>
                    <td>
                      <IconButton
                        label={`Remove rule ${index + 1}`}
                        size="small"
                        onClick={() => update((list) => list.filter((_, i) => i !== index))}
                      >
                        <Trash2 size={13} />
                      </IconButton>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  );
}

export function InterceptPage(): JSX.Element {
  const { data, error, isFetching, refetch } = useInterceptDetailed();
  // Enable and drop come from the shared controls; forward has its own hook because the shared one
  // hard-codes fix_content_length and this page offers it as a toggle.
  const controls = useInterceptControls();
  const forwardHeld = useForwardHeld();

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [raw, setRaw] = useState("");
  const [fixContentLength, setFixContentLength] = useState(true);
  const [directionFilter, setDirectionFilter] = useState<"all" | "request" | "response">("all");

  const heldAll = data?.held ?? [];
  // Apply direction filter to the held queue — the operator can focus on
  // just requests or just responses without losing the other half.
  const held = directionFilter === "all" ? heldAll : heldAll.filter((h) => h.direction === directionFilter);
  // Selection is held by id, not object identity, so a poll that rebuilds every row cannot silently
  // drop the operator's selection.
  const selected = useMemo(() => held.find((h) => h.id === selectedId) ?? null, [held, selectedId]);

  // The edit buffer resets only when the *selected id* changes, never on a background refresh of the
  // same message — otherwise every 1.5s poll would overwrite an operator's in-progress edit.
  useEffect(() => {
    setRaw(selected?.raw ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional: keyed on id, not on `selected`'s contents
  }, [selectedId]);

  // A held message can resolve elsewhere (another operator, or a client that gave up waiting); drop a
  // selection that no longer exists in the queue rather than let the editor go stale.
  useEffect(() => {
    if (selectedId !== null && data && !held.some((h) => h.id === selectedId)) setSelectedId(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const toggle = () => {
    if (!data?.wired) {
      toast.error("Interception is not wired up on this server");
      return;
    }
    controls.setEnabled.mutate(!data.enabled, { onError: (err) => toast.error(err instanceof Error ? err.message : String(err)) });
  };

  const forward = () => {
    if (!selected) return;
    forwardHeld.mutate(
      { id: selected.id, raw, fixContentLength },
      {
        onSuccess: () => {
          setSelectedId(null);
          toast.success(`Held message #${selected.id} forwarded`);
        },
        onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  const drop = () => {
    if (!selected) return;
    controls.drop.mutate(selected.id, {
      onSuccess: () => {
        setSelectedId(null);
        toast.success(`Held message #${selected.id} dropped`);
      },
      onError: (err) => toast.error(err instanceof Error ? err.message : String(err)),
    });
  };

  // Burp's proxy bindings. ctrl+F forwards — in Burp that is Forward, not Find, and
  // the editor's search lives on ctrl+S to match. alt+T stands in for Burp's ctrl+T
  // because Chrome and Firefox reserve ctrl+T for a new tab and a page cannot claim it.
  useHotkeys(
    "mod+f",
    (event) => {
      if (!selected) return;
      event.preventDefault();
      forward();
    },
    { enableOnFormTags: true, enableOnContentEditable: true },
    [selected],
  );
  useHotkeys(
    "alt+t",
    (event) => {
      event.preventDefault();
      toggle();
    },
    { enableOnFormTags: true },
    [data],
  );

  const columns = useMemo<Column<HeldMessageDetail>[]>(
    () => [
      { accessorKey: "id", header: "#", size: 56, cell: (info) => <span className="cell-num">{info.getValue<number>()}</span> },
      {
        accessorKey: "direction",
        header: "Dir",
        size: 76,
        cell: (info) => <Badge tone={info.getValue<string>() === "request" ? "info" : "good"}>{info.getValue<string>()}</Badge>,
      },
      { accessorKey: "method", header: "Method", size: 74 },
      {
        id: "authority",
        header: "Host",
        size: 180,
        accessorFn: (row) => `${row.host}:${row.port}${row.tls ? " (tls)" : ""}`,
        cell: (info) => <span title={info.getValue<string>()}>{info.getValue<string>()}</span>,
      },
      { accessorKey: "path", header: "Path", size: 260, cell: (info) => <code title={info.getValue<string>()}>{info.getValue<string>()}</code> },
      {
        accessorKey: "status",
        header: "Status",
        size: 70,
        cell: (info) => {
          const value = info.getValue<number | null>();
          return value === null ? <span className="cell-dim">—</span> : <Badge>{value}</Badge>;
        },
      },
      { accessorKey: "held_ms", header: "Held", size: 80, cell: (info) => <span className="cell-num">{formatDuration(info.getValue<number>())}</span> },
      { accessorKey: "len", header: "Len", size: 76, cell: (info) => <span className="cell-num">{formatBytes(info.getValue<number>())}</span> },
    ],
    [],
  );

  const detail = selected ? (
    <div className="tabs-fill">
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">HELD #{selected.id}</span>
          <strong>
            {selected.direction === "response" ? `${selected.status ?? "?"} response to ` : ""}
            {selected.method} {selected.host}:{selected.port}
            {selected.path}
          </strong>
        </div>
        <div className="detail-actions">
          <Badge tone={selected.direction === "request" ? "info" : "good"}>{selected.direction}</Badge>
          <IconButton label="Clear selection" size="small" onClick={() => setSelectedId(null)}>
            <X size={13} />
          </IconButton>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateRows: "minmax(0, 1fr) auto", minHeight: 0 }}>
        <HttpEditor label="Held bytes" value={raw} onChange={setRaw} filename={`held-${selected.id}.txt`} />
        <Toolbar style={{ borderTop: "1px solid var(--line)" }}>
          <Checkbox
            checked={fixContentLength}
            onCheckedChange={setFixContentLength}
            label="Fix Content-Length when forwarding"
          />
          <span style={{ flex: 1 }} />
          <Button onClick={forward} disabled={forwardHeld.isPending}>
            <Send size={14} />
            Forward
          </Button>
          <Button variant="danger" onClick={drop} disabled={controls.drop.isPending}>
            <Trash2 size={14} />
            Drop
          </Button>
        </Toolbar>
      </div>
    </div>
  ) : (
    <Empty title="Nothing selected" detail="Select a held message to view and edit its exact bytes before forwarding or dropping it." />
  );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Intercept"
          actions={
            <>
              <Badge tone={data?.wired ? "good" : "warn"}>{data?.wired ? "wired" : "not wired"}</Badge>
              <Switch
                checked={data?.enabled ?? false}
                onCheckedChange={toggle}
                label="Intercept is on"
              />
              <span className="field-hint">Intercept is {data?.enabled ? "on" : "off"}</span>
            </>
          }
        />
        {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
        {data && !data.wired ? (
          <div className="notice notice-warn">{data.hint ?? "interception is not wired up"}</div>
        ) : null}
        <div className="metric-grid compact" style={{ marginTop: 10 }}>
          <Metric accent label="Pending" value={data?.pending ?? 0} />
          <Metric label="Mode" value={data?.enabled ? "Holding" : "Passing"} />
          <Metric label="Transport" value={data?.wired ? "Connected" : "Unavailable"} />
          <Metric label="Queue depth" value={heldAll.length} />
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <label htmlFor="direction-filter" style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>Show:</label>
            <Select
              id="direction-filter"
              aria-label="Filter by direction"
              value={directionFilter}
              onChange={(e) => setDirectionFilter(e.target.value as "all" | "request" | "response")}
              style={{ width: "auto" }}
            >
              <option value="all">All messages</option>
              <option value="request">Requests only</option>
              <option value="response">Responses only</option>
            </Select>
          </div>
        </div>
      </div>

      <Tabs defaultValue="queue" className="tabs-fill">
        <TabsList>
          <TabsTrigger value="queue">Queue</TabsTrigger>
          <TabsTrigger value="rules">Interception rules</TabsTrigger>
        </TabsList>
        <TabsContent value="queue" style={{ display: "grid", minHeight: 0 }}>
          <SplitPane
            storageId="intercept"
            orientation="vertical"
            defaultMasterSize="50"
            master={
              <VirtualTable
                ariaLabel="Held messages"
                data={held}
                columns={columns}
                getRowId={(row) => String(row.id)}
                selectedId={selectedId === null ? null : String(selectedId)}
                onSelect={(row) => setSelectedId(row.id)}
                loading={isFetching && !data}
                empty={
                  <Empty
                    title="Queue is clear"
                    detail={data?.enabled ? "Requests will stop here when a rule matches." : "Enable interception to hold matching traffic."}
                  />
                }
              />
            }
            detail={detail}
          />
        </TabsContent>
        <TabsContent value="rules" style={{ overflowY: "auto", padding: 10 }}>
          <div className="two-col">
            <RuleEditor direction="requests" />
            <RuleEditor direction="responses" />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
