import { useState } from "react";
import { ArrowDown, ArrowUp, Play, Power, PowerOff } from "lucide-react";
import { toast } from "sonner";
import { formatCount, formatDuration } from "../lib/api";
import {
  useExtensionApis,
  useExtensionConsole,
  useExtensions,
  useInvokeExtension,
  useLoadExtension,
  useMoveExtension,
  useUnloadExtension,
} from "../lib/data.extensions";
import { cn } from "../lib/cn";
import type { ConsoleLine, ExtensionView, Registration } from "../lib/types.extensions";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, IconButton, Metric, Tooltip } from "../ui/primitives";
import { SimpleTable } from "../ui/table";
import type { Tone } from "../ui/primitives";

/**
 * The EXTENDER tool: Extensions, Options and APIs.
 *
 * There is no BApp Store sub-tab, and its absence is the design decision this file is most careful
 * about. Burp's store is a hosted catalogue; nothing in burpsy fetches, resolves or installs anything,
 * so a fourth tab listing zero extensions would tell an operator that a catalogue exists and happens
 * to be empty. Instead every tab here says what a plugin actually is — a local executable the operator
 * names on the command line, speaking JSON-RPC over its own stdin and stdout — and the Options tab
 * carries the server's own `registry: null` with the reason next to it.
 */

/** What each state should look like at a glance, and what to say about it. */
const STATE_TONE: Record<ExtensionView["state"], Tone> = {
  loaded: "good",
  loading: "info",
  unloaded: "neutral",
  failed: "bad",
  crashed: "bad",
};

/** The five states in words. A boolean "loaded" would render the four not-loaded cases identically. */
const STATE_LABEL: Record<ExtensionView["state"], string> = {
  loaded: "loaded",
  loading: "loading",
  unloaded: "not loaded",
  failed: "failed to load",
  crashed: "exited on its own",
};

function stateBadge(row: ExtensionView): JSX.Element {
  return <Badge tone={STATE_TONE[row.state]}>{STATE_LABEL[row.state]}</Badge>;
}

/** The plugin's own words for a registration kind. */
const KIND_LABEL: Record<Registration["kind"], string> = {
  "context-menu": "Context-menu item",
  menu: "Menu action",
  "editor-tab": "Message-editor tab",
};

function timeOf(atMs: number): string {
  if (!Number.isFinite(atMs) || atMs <= 0) return "—";
  return new Date(atMs).toLocaleTimeString();
}

/** How a console line is attributed. The whole point of the field, so it is a badge and not a word. */
const SOURCE_TONE: Record<ConsoleLine["source"], Tone> = {
  plugin: "info",
  stderr: "warn",
  host: "neutral",
  protocol: "bad",
};

function ConsolePane({
  title,
  detail,
  lines,
  dropped,
  emptyDetail,
}: {
  title: string;
  detail: string;
  lines: ConsoleLine[];
  dropped: number;
  emptyDetail: string;
}): JSX.Element {
  return (
    <div>
      <SectionHeading
        title={title}
        detail={detail}
        actions={
          dropped > 0 ? (
            <Badge tone="warn">
              {formatCount(dropped)} older {dropped === 1 ? "line" : "lines"} dropped
            </Badge>
          ) : null
        }
      />
      {lines.length === 0 ? (
        <Empty title={`Nothing on the ${title.toLowerCase()}`} detail={emptyDetail} />
      ) : (
        <SimpleTable headers={["Time", "From", "Line"]}>
          {lines.map((line, index) => (
            <tr key={`${line.at_ms}-${index}`}>
              <td>
                <span className="cell-dim">{timeOf(line.at_ms)}</span>
              </td>
              <td>
                <Badge tone={SOURCE_TONE[line.source]}>{line.source}</Badge>
              </td>
              <td>
                <code>{line.text}</code>
              </td>
            </tr>
          ))}
        </SimpleTable>
      )}
    </div>
  );
}

function RegistrationTable({ plugin }: { plugin: ExtensionView }): JSX.Element {
  const invoke = useInvokeExtension();
  const [lastResult, setLastResult] = useState<{ registration: string; text: string } | null>(null);

  if (plugin.registrations.length === 0) {
    return (
      <Empty
        title="This plugin registered nothing"
        detail={
          plugin.state === "loaded"
            ? `${plugin.name} completed the handshake and declared no context-menu item, menu action or editor tab. It can still log to its consoles.`
            : "Registrations are declared at the handshake, so there are none until the plugin is loaded."
        }
      />
    );
  }

  const run = (registration: string) =>
    invoke.mutate(
      { name: plugin.name, registration },
      {
        onSuccess: (response) => {
          const text = response.result.output ?? response.result.text ?? "";
          // An empty answer is reported as an empty answer. A menu action whose whole effect was to
          // log something has nothing to return, and inventing "done" for it would be a fabricated
          // result — the plugin's console is where the effect shows.
          setLastResult({
            registration,
            text: text || "The plugin answered with no text. Anything it did is on its consoles.",
          });
          toast.success(`Ran ${registration}`);
        },
        onError: (failure: unknown) =>
          toast.error(failure instanceof Error ? failure.message : `Invoking ${registration} failed`),
      },
    );

  return (
    <>
      <SimpleTable headers={["Kind", "Label", "Id", "Hint", ""]}>
        {plugin.registrations.map((registration) => (
          <tr key={registration.id}>
            <td>{KIND_LABEL[registration.kind]}</td>
            <td>{registration.label}</td>
            <td>
              <code>{registration.id}</code>
            </td>
            <td>
              <span className="cell-dim">{registration.hint ?? "—"}</span>
            </td>
            <td>
              {registration.kind === "menu" ? (
                <Button
                  variant="outline"
                  size="small"
                  disabled={plugin.state !== "loaded" || invoke.isPending}
                  onClick={() => run(registration.id)}
                >
                  <Play size={13} />
                  Run
                </Button>
              ) : (
                // Not offered rather than offered and broken: both other kinds are invoked with a
                // message, and this tab selects none. They are reachable from POST
                // /api/extensions/invoke with an exchange or a message id.
                <Tooltip content="This kind is invoked with a message, which this tab does not select. Use POST /api/extensions/invoke with an exchange or message id.">
                  <span className="cell-dim">needs a message</span>
                </Tooltip>
              )}
            </td>
          </tr>
        ))}
      </SimpleTable>
      {lastResult ? (
        <div className="notice">
          <span>
            <code>{lastResult.registration}</code> answered: {lastResult.text}
          </span>
        </div>
      ) : null}
    </>
  );
}

function ExtensionDetail({ plugin }: { plugin: ExtensionView }): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useExtensionConsole(plugin.name);

  return (
    <Card>
      <SectionHeading
        title={plugin.declared_name ? `${plugin.name} — ${plugin.declared_name}` : plugin.name}
        detail={plugin.detail || `${plugin.path} · ${STATE_LABEL[plugin.state]}`}
        actions={
          <>
            {stateBadge(plugin)}
            {plugin.registrations_refused > 0 ? (
              <Badge tone="warn">
                {formatCount(plugin.registrations_refused)} refused
              </Badge>
            ) : null}
            <RefreshButton onClick={() => void refetch()} loading={isFetching} label="Refresh consoles" />
          </>
        }
      />

      <div className="metric-grid wide">
        <Metric label="Registrations" value={formatCount(plugin.registrations.length)} detail="Accepted at the handshake" />
        <Metric
          label="Refused"
          value={formatCount(plugin.registrations_refused)}
          detail="Declared and not usable — the reasons are on the error console"
          tone={plugin.registrations_refused > 0 ? "warn" : undefined}
        />
        <Metric label="Invocations" value={formatCount(plugin.invocations)} />
        <Metric
          label="Failed invocations"
          value={formatCount(plugin.invocation_failures)}
          tone={plugin.invocation_failures > 0 ? "bad" : undefined}
        />
        <Metric
          label="Protocol errors"
          value={formatCount(plugin.protocol_errors)}
          detail="Lines on stdout that were not JSON-RPC"
          tone={plugin.protocol_errors > 0 ? "warn" : undefined}
        />
      </div>

      {plugin.exit ? (
        <div className={plugin.state === "crashed" ? "notice notice-warn" : "notice"}>
          <span>
            The process ended at {timeOf(plugin.exit.at_ms)}:{" "}
            {plugin.exit.detail || plugin.exit.signal || `exit status ${plugin.exit.code}`}.
          </span>
        </div>
      ) : null}

      <SectionHeading title="Registrations" detail="What this plugin declared it can do." />
      <RegistrationTable plugin={plugin} />

      {error ? <ErrorNotice error={error} title="Could not read the consoles" onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading consoles" /> : null}
      {data ? (
        <>
          <ConsolePane
            title="Output console"
            detail={`What the plugin logged, plus this host's own notes. The last ${formatCount(data.limit)} lines are kept.`}
            lines={data.output}
            dropped={data.output_dropped}
            emptyDetail={
              plugin.state === "loaded"
                ? "The plugin has sent no log notification on the output stream since it was loaded."
                : "Consoles are cleared by neither a load nor an unload; this plugin has simply logged nothing."
            }
          />
          <ConsolePane
            title="Error console"
            detail="Anything on stderr, every protocol violation, and this host's failure notes — kept apart by the From column."
            lines={data.error}
            dropped={data.error_dropped}
            emptyDetail="Nothing has been written to stderr, and no line has failed to parse as JSON-RPC."
          />
          {data.truncated > 0 ? (
            <p className="field-hint">
              {formatCount(data.truncated)} {data.truncated === 1 ? "line was" : "lines were"} cut at the
              per-line byte bound. A cut line is marked in place, not silently shortened.
            </p>
          ) : null}
        </>
      ) : null}
    </Card>
  );
}

export function ExtensionsPage(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useExtensions();
  const load = useLoadExtension();
  const unload = useUnloadExtension();
  const move = useMoveExtension();
  const [selected, setSelected] = useState<string | null>(null);

  const rows = data?.extensions ?? [];
  const active = rows.find((row) => row.name === selected) ?? rows[0] ?? null;
  const busy = load.isPending || unload.isPending;

  // The order is the sequence the console offers a plugin's registrations in — the palette group,
  // the exchange context menu, the editor's plugin tabs — so this is not a table preference. The
  // server owns it: the answer is the whole reordered list, and the query cache is refreshed from it
  // rather than the row order being guessed at here while the request is in flight.
  const moveRow = (name: string, direction: "up" | "down") => {
    setSelected(name);
    move.mutate(
      { name, direction },
      {
        onSuccess: () => toast.success(`Moved ${name} ${direction}`),
        // The server's own refusal, verbatim: "already first" and "not on the allowlist" are
        // different problems, and the edges are refused rather than clamped precisely so a caller
        // that asked anyway is told which.
        onError: (failure: unknown) =>
          toast.error(failure instanceof Error ? failure.message : `Could not move ${name} ${direction}`),
      },
    );
  };

  const toggle = (row: ExtensionView, wanted: boolean) => {
    setSelected(row.name);
    const action = wanted ? load : unload;
    action.mutate(row.name, {
      onSuccess: () => toast.success(wanted ? `Loaded ${row.name}` : `Unloaded ${row.name}`),
      onError: (failure: unknown) =>
        // The server's own reason, verbatim: "no such file", "handshake failed", "speaks protocol 99"
        // and "already loaded" are four different problems and a generic message hides which.
        toast.error(failure instanceof Error ? failure.message : `Could not ${wanted ? "load" : "unload"} ${row.name}`),
    });
  };

  return (
    <div className="page">
      <PageHeader
        title="Extensions"
        description="A plugin is a local executable that speaks newline-delimited JSON-RPC on its stdin and stdout. There is no store to browse and nothing is downloaded: the operator names each one on the command line."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />
      {error ? <ErrorNotice error={error} title="Could not read the plugin list" onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading extensions" /> : null}

      {data ? (
        <Card>
          <SectionHeading title="Allowlist" detail={data.detail} />
          <div className="metric-grid wide">
            <Metric label="Allowlisted" value={formatCount(data.allowlisted)} detail="Named with -plugins" />
            <Metric label="Loaded" value={formatCount(data.loaded)} tone={data.loaded > 0 ? "good" : undefined} />
            <Metric label="Not loaded" value={formatCount(data.unloaded)} />
            <Metric
              label="Failed to load"
              value={formatCount(data.failed)}
              detail="Never completed the handshake"
              tone={data.failed > 0 ? "bad" : undefined}
            />
            <Metric
              label="Exited on their own"
              value={formatCount(data.crashed)}
              detail="Loaded, then the process ended unasked"
              tone={data.crashed > 0 ? "bad" : undefined}
            />
          </div>

          {rows.length === 0 ? (
            <Empty
              title="No plugin is allowlisted"
              detail={`${data.detail} Loading a plugin runs operator-supplied code in this process, so nothing can be admitted from the browser.`}
            />
          ) : (
            <SimpleTable headers={["Order", "Loaded", "Name", "Type", "Version", "State", "Registrations", "Console", ""]}>
              {rows.map((row, index) => (
                <tr
                  key={row.name}
                  onClick={() => setSelected(row.name)}
                  // The same three classes VirtualTable's rows carry, so a selected row here looks
                  // like a selected row everywhere else. No aria-selected: this is a plain table, not
                  // a grid, and the attribute is not allowed on a row outside one.
                  className={cn("data-row", "clickable", active?.name === row.name && "selected-row")}
                >
                  {/* Burp's Extender list is an ordered list and its Up/Down buttons move a plugin
                      within it. This column is that control. The edges are disabled with a hint
                      rather than left live: the route refuses them with 409, and a button that can
                      only fail is worse than one that says why it cannot act. */}
                  <td onClick={(event) => event.stopPropagation()}>
                    <div className="toolbar">
                      <span className="cell-num">{index + 1}</span>
                      <IconButton
                        label={
                          index === 0
                            ? `${row.name} is already first`
                            : `Move ${row.name} before ${rows[index - 1]?.name ?? "the plugin above"}`
                        }
                        size="small"
                        disabled={index === 0 || move.isPending}
                        onClick={() => moveRow(row.name, "up")}
                      >
                        <ArrowUp size={13} />
                      </IconButton>
                      <IconButton
                        label={
                          index === rows.length - 1
                            ? `${row.name} is already last`
                            : `Move ${row.name} after ${rows[index + 1]?.name ?? "the plugin below"}`
                        }
                        size="small"
                        disabled={index === rows.length - 1 || move.isPending}
                        onClick={() => moveRow(row.name, "down")}
                      >
                        <ArrowDown size={13} />
                      </IconButton>
                    </div>
                  </td>
                  <td>
                    <Checkbox
                      checked={row.state === "loaded"}
                      onCheckedChange={(next) => toggle(row, next)}
                      label={<span className="sr-only">{row.state === "loaded" ? `Unload ${row.name}` : `Load ${row.name}`}</span>}
                    />
                  </td>
                  <td>
                    <code>{row.name}</code>
                  </td>
                  <td>{row.type ? row.type : <span className="cell-dim">not declared yet</span>}</td>
                  <td>
                    <span className="cell-dim">{row.version || "—"}</span>
                  </td>
                  <td>{stateBadge(row)}</td>
                  <td>
                    <span className="cell-num">{formatCount(row.registrations.length)}</span>
                    {row.registrations_refused > 0 ? (
                      <span className="cell-dim"> ({formatCount(row.registrations_refused)} refused)</span>
                    ) : null}
                  </td>
                  <td>
                    <span className="cell-num">{formatCount(row.output_lines)}</span>
                    <span className="cell-dim"> out / </span>
                    <span className="cell-num">{formatCount(row.error_lines)}</span>
                    <span className="cell-dim"> err</span>
                  </td>
                  <td>
                    <Button
                      variant="outline"
                      size="small"
                      disabled={busy}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggle(row, row.state !== "loaded");
                      }}
                    >
                      {row.state === "loaded" ? <PowerOff size={13} /> : <Power size={13} />}
                      {row.state === "loaded" ? "Unload" : "Load"}
                    </Button>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          )}
        </Card>
      ) : null}

      {active ? <ExtensionDetail plugin={active} /> : null}
    </div>
  );
}

export function ExtenderOptionsPage(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useExtensions();
  const policy = data?.policy;

  return (
    <div className="page">
      <PageHeader
        title="Extender options"
        description="How a plugin is admitted, and every bound this process holds it to. These are the values in force here, read from the running server rather than the defaults in the source."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />
      {error ? <ErrorNotice error={error} title="Could not read the plugin policy" onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading options" /> : null}

      {policy ? (
        <>
          <Card>
            <SectionHeading
              title="Admission"
              detail="A plugin runs only if the operator named it on the command line. There is no path in any request body: every route takes an allowlist name, and a name that is not on the list cannot be loaded."
            />
            <SimpleTable headers={["Setting", "Value", "Why"]}>
              <tr>
                <td>Allowlist flag</td>
                <td>
                  <code>{policy.flag}</code>
                </td>
                <td>The only way a plugin is admitted. Restart burpsy to change it.</td>
              </tr>
              <tr>
                <td>Plugins allowlisted</td>
                <td>
                  <span className="cell-num">{formatCount(policy.allowlisted)}</span>
                </td>
                <td>Nothing is started at boot; a load is an act the operator performs.</td>
              </tr>
              <tr>
                <td>Shell</td>
                <td>
                  <Badge tone={policy.shell ? "bad" : "good"}>{policy.shell ? "used" : "never used"}</Badge>
                </td>
                <td>
                  The executable is run directly, so an argument containing shell metacharacters is data.
                </td>
              </tr>
              <tr>
                <td>Environment passed to a plugin</td>
                <td>
                  <code>{policy.environment_passed.join(" ") || "nothing"}</code>
                </td>
                <td>
                  What a language runtime needs to start, and no more — an operator&apos;s shell routinely
                  holds credentials for services that have nothing to do with the engagement.
                </td>
              </tr>
              <tr>
                <td>Protocol version</td>
                <td>
                  <span className="cell-num">{formatCount(policy.protocol_version)}</span>
                </td>
                <td>
                  A plugin answering with a different number is refused rather than half-supported.
                </td>
              </tr>
            </SimpleTable>
          </Card>

          <Card>
            <SectionHeading
              title="Bounds"
              detail="A plugin is code this process cannot reason about, so nothing it produces is unbounded. Every limit here is enforced and every overflow is counted, never silently dropped."
            />
            <div className="metric-grid wide">
              <Metric
                label="Load timeout"
                value={formatDuration(policy.load_timeout_ms)}
                detail="Spawn plus handshake"
              />
              <Metric label="Call timeout" value={formatDuration(policy.call_timeout_ms)} detail="One invocation" />
              <Metric
                label="Shutdown grace"
                value={formatDuration(policy.shutdown_grace_ms)}
                detail="Then stdin closes, then the process is killed"
              />
              <Metric
                label="Console lines"
                value={formatCount(policy.max_console_lines)}
                detail="Per stream, per plugin; oldest evicted and counted"
              />
              <Metric
                label="Console line bytes"
                value={formatCount(policy.max_console_line_bytes)}
                detail="A longer line is cut and marked"
              />
              <Metric
                label="Message bytes"
                value={formatCount(policy.max_message_bytes)}
                detail="One JSON-RPC line, either direction"
              />
              <Metric
                label="Registrations"
                value={formatCount(policy.max_registrations)}
                detail="Per plugin; the excess is refused"
              />
            </div>
          </Card>

          <Card>
            <SectionHeading title="There is no store" detail="Burp's fourth Extender tab has no counterpart here, deliberately." />
            <div className="notice notice-warn">
              <span>{policy.registry_detail}</span>
            </div>
            <p className="field-hint">
              The server reports <code>registry: null</code> on this surface rather than leaving the
              absence to be inferred from a missing field — so a caller can tell &ldquo;no store&rdquo;
              from &ldquo;a store this build did not ask about&rdquo;.
            </p>
          </Card>
        </>
      ) : null}
    </div>
  );
}

export function ExtenderApisPage(): JSX.Element {
  const { data, error, isFetching, isLoading, refetch } = useExtensionApis();

  return (
    <div className="page">
      <PageHeader
        title="Extender APIs"
        description="The contract a plugin is written against, served from the same method table the host dispatches on — so this page cannot drift away from what the code does."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />
      {error ? <ErrorNotice error={error} title="Could not read the protocol contract" onRetry={() => void refetch()} /> : null}
      {isLoading ? <LoadingPanel label="Loading the protocol contract" /> : null}

      {data ? (
        <>
          <Card>
            <SectionHeading title="Transport" detail={`Protocol version ${data.protocol_version}.`} />
            <SimpleTable headers={["", "How it works"]}>
              <tr>
                <td>Process</td>
                <td>{data.transport}</td>
              </tr>
              <tr>
                <td>Framing</td>
                <td>{data.framing}</td>
              </tr>
              <tr>
                <td>Handshake</td>
                <td>{data.handshake}</td>
              </tr>
            </SimpleTable>
          </Card>

          <Card>
            <SectionHeading
              title="Registration points"
              detail="Three, and only three. Of Montoya's thirteen userInterface() registration points, ten hand Burp a Swing object and have no honest web analogue; a JSON schema for a component whose only consumer is the thing that defined it would be a fiction, so they are absent rather than approximated."
            />
            <SimpleTable headers={["Kind", "Invoked by", "What it is", "Burp's equivalent"]}>
              {data.kinds.map((kind) => (
                <tr key={kind.kind}>
                  <td>
                    <code>{kind.kind}</code>
                  </td>
                  <td>
                    <code>{kind.method}</code>
                  </td>
                  <td>{kind.label}</td>
                  <td>
                    <span className="cell-dim">{kind.montoya}</span>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          </Card>

          <Card>
            <SectionHeading
              title="Methods"
              detail={`${data.methods.length} ${data.methods.length === 1 ? "method" : "methods"}, generated from the host's own table. A Go test parses the dispatcher's source and fails if either side names a method the other does not.`}
            />
            <SimpleTable headers={["Method", "Direction", "Call", "Params", "Result", "Why"]}>
              {data.methods.map((method) => (
                <tr key={method.name}>
                  <td>
                    <code>{method.name}</code>
                  </td>
                  <td>
                    <Badge tone={method.direction === "host-to-plugin" ? "info" : "accent"}>{method.direction}</Badge>
                  </td>
                  <td>{method.call}</td>
                  <td>
                    <code>{method.params}</code>
                  </td>
                  <td>
                    <code>{method.result}</code>
                  </td>
                  <td>{method.why}</td>
                </tr>
              ))}
            </SimpleTable>
          </Card>

          <Card>
            <SectionHeading
              title="What a plugin cannot do"
              detail="Named rather than left to be discovered. An absent capability that is stated is a decision; an absent capability that is silent is a bug."
            />
            <SimpleTable headers={["Not offered", "Why"]}>
              {data.unsupported.map((item) => (
                <tr key={item.what}>
                  <td>{item.what}</td>
                  <td>
                    <span className="cell-dim">{item.why}</span>
                  </td>
                </tr>
              ))}
            </SimpleTable>
          </Card>
        </>
      ) : null}
    </div>
  );
}
