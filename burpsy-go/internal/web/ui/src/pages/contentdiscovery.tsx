import { AlertTriangle, Copy, ExternalLink, FolderTree, Globe, Link2, Play, Repeat2, Terminal } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { copyToClipboard, formatBytes, formatCount, templateRequest } from "../lib/api";
import { takeSeed } from "../lib/page-seed";
import { useApp } from "../lib/store";
import {
  useDiscoveryRuns,
  useStartDiscovery,
  type Discovery,
  type DiscoveryRun,
  type DiscoveryToolState,
} from "../lib/data.discovery";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { MenuRow, SimpleTable } from "../ui/table";
import type { MenuGroup } from "../ui/menu";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNotice,
  Field,
  Input,
  Metric,
  Toolbar,
  type Tone,
} from "../ui/primitives";

/**
 * Content discovery — Burp's "Discover content" engagement tool.
 *
 * # Why this page exists
 *
 * The engine has been here all along: `internal/extscan` wraps ffuf,
 * `internal/web/api_discovery.go` exposes it, the route is registered, the tests
 * pass. Nothing in the console called it. An operator working in the browser had
 * no way to launch a sweep, watch one, or read its results — the only route was
 * `burpsy extscan` on the command line. That is issue 519, and it is the same
 * failure shape as match/replace rules that installed and rewrote nothing:
 * complete, covered, and unreachable. Backend tests are exactly what makes this
 * class of gap invisible.
 *
 * # Why it is not on the Discover tab
 *
 * Two different Burp features share the word. Burp's DISCOVER *tab* is a farm of
 * outbound links, and `pages/discover.tsx` deliberately replaced it with an
 * in-app reference — see the argument in that file. Burp's "Discover content" is
 * an engagement tool opened from a site-map right-click, which is why this sits
 * under Target next to the site map instead.
 *
 * # What this page refuses to smooth over
 *
 * The endpoint is careful about the difference between "swept and found nothing"
 * and "never swept", and the easy version of this page would erase it by
 * rendering `discoveries` and nothing else. So:
 *
 *   - A finished run with no discoveries shows its `outcome` and whether the tool
 *     `looked`. "0 paths" is not an answer on its own.
 *   - `counts.out_of_scope` is always shown when non-zero, because a sweep that
 *     matched forty paths and discarded thirty-nine would otherwise look like a
 *     sweep that matched one.
 *   - The server's own `summary` is printed verbatim rather than reworded here.
 *     One wording of the caveat, next to the logic that knows it.
 *   - When ffuf is not allowlisted the page says so where the results would be.
 *     The server refuses rather than answering 200 with an empty list for this
 *     reason, and a console that showed an empty table would undo that.
 *   - The argv is shown for every run. These paths were never fetched by burpsy,
 *     so they are absent from history and the site map by design; the command is
 *     the only record of what actually hit the target.
 */

/** Run state to a badge tone. `stopped` is warn rather than bad: it was cancelled, not broken. */
const STATE_TONE: Record<string, Tone> = {
  running: "info",
  done: "good",
  stopped: "warn",
  failed: "bad",
};

/**
 * Status code to tone, for the discovery rows.
 *
 * 401 and 403 are `warn` rather than `bad`: on a content-discovery sweep a 403 is
 * usually the most interesting row on the page — something is there and it is
 * refusing you — and colouring it as a failure buries the find.
 */
function statusTone(status: number): Tone {
  if (status >= 500) return "bad";
  if (status === 401 || status === 403) return "warn";
  if (status >= 400) return "neutral";
  if (status >= 300) return "info";
  return "good";
}

function startedAt(run: DiscoveryRun): string {
  const at = new Date(run.started);
  return Number.isNaN(at.getTime()) ? run.started : at.toLocaleTimeString();
}

/**
 * The reason panel for a server that cannot run a sweep.
 *
 * Rendered where the form would be, not as a dismissible aside: with no
 * allowlisted binary there is nothing to submit, and a form that accepted input
 * and then failed would waste the operator's typing to say what is already known.
 */
function ToolUnavailable({ tool }: { tool: DiscoveryToolState }): JSX.Element {
  return (
    <Card className="stack">
      <div className="notice-row">
        <AlertTriangle size={15} aria-hidden="true" />
        <div>
          <strong>Content discovery is not available on this server</strong>
          <p className="cell-dim">
            {tool.reason ??
              `${tool.name} is not allowlisted. Pass -tools ${tool.name}=/path/to/${tool.name} when starting burpsy.`}
          </p>
          <p className="cell-dim">
            Which binary may be executed is operator policy set on the command line, never by this
            page — a console that could name its own executable would make the flag decorative.
          </p>
        </div>
      </div>
    </Card>
  );
}

/** The launch form. Only target and wordlist are required; the rest fall through to ffuf's defaults. */
function StartSweep({ tool }: { tool: DiscoveryToolState }): JSX.Element {
  const start = useStartDiscovery();
  // Seeded when this page was opened from the site map's Engagement tools › Discover content
  // (burpsy-react-ui-gupj), blank otherwise. Read once at mount and cleared, so the seed cannot
  // overwrite a target the operator has since typed — see lib/page-seed.ts.
  const [target, setTarget] = useState(() => takeSeed("discovery-target") ?? "");
  const [wordlist, setWordlist] = useState("");
  const [extensions, setExtensions] = useState("");
  const [matchCodes, setMatchCodes] = useState("");
  const [rate, setRate] = useState("");

  const ready = target.trim() !== "" && wordlist.trim() !== "";

  const submit = () => {
    if (!ready) return;
    const parsedRate = Number.parseInt(rate, 10);
    start.mutate(
      {
        target: target.trim(),
        wordlist: wordlist.trim(),
        extensions: extensions.trim() || undefined,
        match_codes: matchCodes.trim() || undefined,
        // Only sent when it parses to a positive number. Zero is ffuf's uncapped
        // default, and sending 0 for an unparseable field would silently mean
        // "no limit" on an engagement that asked for one.
        rate: Number.isFinite(parsedRate) && parsedRate > 0 ? parsedRate : undefined,
      },
      {
        onSuccess: (response) => toast.success(`Sweep #${response.task_id} started against ${response.target}`),
        // The server refuses an out-of-scope or partly-in-scope target with 403 and
        // explains which check failed; surface that text rather than a generic failure.
        onError: (failure) => toast.error(failure instanceof Error ? failure.message : "Starting the sweep failed"),
      },
    );
  };

  return (
    <Card className="stack">
      <SectionHeading
        title="New sweep"
        detail={`Delegated to ${tool.name}. FUZZ is appended to the target path, so point it at the directory to sweep.`}
      />
      <div className="field-grid">
        <Field label="Target URL" hint="e.g. https://target.test/app/ — the path space swept beneath it">
          {(id) => (
            <Input
              id={id}
              value={target}
              placeholder="https://target.test/app/"
              onChange={(event) => setTarget(event.target.value)}
            />
          )}
        </Field>
        <Field label="Wordlist path" hint="A path on the burpsy host. Required: ffuf with no wordlist is no sweep.">
          {(id) => (
            <Input
              id={id}
              value={wordlist}
              placeholder="/usr/share/wordlists/dirb/common.txt"
              onChange={(event) => setWordlist(event.target.value)}
            />
          )}
        </Field>
        <Field label="Extensions" hint="Optional. Extends every word, e.g. php,bak">
          {(id) => (
            <Input id={id} value={extensions} placeholder="php,bak" onChange={(event) => setExtensions(event.target.value)} />
          )}
        </Field>
        <Field label="Match status codes" hint={`Optional. Empty takes ${tool.name}'s own default, which already excludes 404.`}>
          {(id) => (
            <Input id={id} value={matchCodes} placeholder="200,204,301,302,401,403" onChange={(event) => setMatchCodes(event.target.value)} />
          )}
        </Field>
        <Field label="Rate limit" hint="Optional, requests per second. Empty is uncapped; set it if the engagement agreed a rate.">
          {(id) => (
            <Input id={id} value={rate} inputMode="numeric" placeholder="uncapped" onChange={(event) => setRate(event.target.value)} />
          )}
        </Field>
      </div>
      <Toolbar>
        <Button onClick={submit} disabled={!ready || start.isPending}>
          <Play size={13} />
          {start.isPending ? "Starting…" : "Start sweep"}
        </Button>
        <span className="cell-dim">
          Scope is checked before the run and again on every result. A host whose subtree is only
          partly in scope is refused outright, because a wordlist picks its own paths.
        </span>
      </Toolbar>
      {start.error ? <ErrorNotice title="Could not start the sweep" error={start.error} /> : null}
    </Card>
  );
}

/** The honest-counting strip for one run: what is shown, what was dropped, and whether it looked. */
function RunCounts({ run }: { run: DiscoveryRun }): JSX.Element {
  return (
    <div className="metric-row">
      <Metric label="Paths reported" value={formatCount(run.counts.discovered)} />
      <Metric
        label="Dropped: out of scope"
        value={formatCount(run.counts.out_of_scope)}
        tone={run.counts.out_of_scope > 0 ? "warn" : undefined}
        detail={run.counts.out_of_scope > 0 ? "reported by the tool, refused by the engagement scope" : undefined}
      />
      <Metric
        label="Examined the target"
        value={run.looked ? "yes" : "no"}
        tone={run.looked ? "good" : "bad"}
        detail={run.looked ? undefined : "an empty result here means nothing was checked, not that nothing is there"}
      />
      <Metric label="Outcome" value={run.outcome} detail={run.exit_code >= 0 ? `exit ${run.exit_code}` : undefined} />
    </div>
  );
}

/**
 * The discovered-path context menu.
 *
 * # Why Send to Repeater builds a request instead of fetching one
 *
 * A discovered path is not an exchange. The sweep is an external tool reporting that a URL exists
 * with a status and a length; nothing captured the request, so there are no bytes to send anywhere.
 * The Repeater entry therefore synthesises the request the sweep implies — `templateRequest`, the
 * same builder Repeater's own "new tab" uses — and the toast says so, because handing the operator
 * a hand-built GET while implying it is the captured one would be the dishonest version.
 *
 * "Add to site map" is not offered for the same reason and cannot be faked: the site map is built
 * from captured traffic, and there is no endpoint that injects a path into it.
 */
function DiscoveryRows({ rows }: { rows: Discovery[] }): JSX.Element {
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const setRoute = useApp((state) => state.setRoute);
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);

  const menuFor = (row: Discovery): MenuGroup[] => [
    {
      id: "send",
      actions: [
        {
          id: "repeater",
          label: "Send to Repeater (built from this URL)",
          icon: Repeat2,
          onSelect: () => {
            const scheme = row.url.startsWith("http://") ? "http" : "https";
            openRepeaterTab({
              name: `discovered ${row.path || "/"}`.slice(0, 42),
              target: `${scheme}://${row.host}`,
              protocol: scheme,
              request: templateRequest(row.host, row.path || "/"),
            });
            setRoute("repeater");
            toast.success("A GET for this path was built and opened in Repeater — the sweep captured no request bytes");
          },
        },
        {
          id: "browser",
          label: "Open URL in browser",
          icon: Globe,
          onSelect: () => {
            window.open(row.url, "_blank", "noopener");
            toast.info("Opened in your browser — it is captured only if that browser uses burpsy's proxy");
          },
        },
      ],
    },
    {
      id: "copy",
      actions: [
        {
          id: "url",
          label: "Copy URL",
          icon: Link2,
          onSelect: () => {
            void copyToClipboard(row.url);
            toast.success("URL copied");
          },
        },
        {
          id: "path",
          label: "Copy path",
          icon: Copy,
          onSelect: () => void copyToClipboard(row.path || "/"),
        },
        ...(row.redirect
          ? [
              {
                id: "redirect",
                label: "Copy redirect target",
                icon: ExternalLink,
                onSelect: () => void copyToClipboard(row.redirect ?? ""),
              },
            ]
          : []),
      ],
    },
    {
      id: "history",
      actions: [
        {
          id: "filter",
          label: `Filter history by ${row.path || "/"}`,
          icon: FolderTree,
          onSelect: () => {
            setHistoryQuery(`host = ${row.host} AND path ~ "${(row.path || "/").replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`);
            setRoute("history");
          },
        },
      ],
    },
  ];

  return (
    <SimpleTable headers={["Status", "Path", "Length", "Words", "Lines", "Type", "Redirects to"]}>
      {rows.map((row) => (
        <MenuRow key={row.url} groups={menuFor(row)}>
          <td>
            <Badge tone={statusTone(row.status)}>{row.status}</Badge>
          </td>
          <td>
            <code title={row.url}>{row.path || "/"}</code>
          </td>
          <td className="cell-num">{formatBytes(row.length)}</td>
          <td className="cell-num">{formatCount(row.words)}</td>
          <td className="cell-num">{formatCount(row.lines)}</td>
          <td className="cell-dim">{row.content_type ?? "—"}</td>
          <td className="cell-dim">
            {row.redirect ? (
              <span className="chip-row">
                <ExternalLink size={12} aria-hidden="true" />
                <code>{row.redirect}</code>
              </span>
            ) : (
              "—"
            )}
          </td>
        </MenuRow>
      ))}
    </SimpleTable>
  );
}

function RunCard({ run }: { run: DiscoveryRun }): JSX.Element {
  const byStatus = useMemo(
    () => run.counts.by_status.slice().sort((a, b) => a.status - b.status),
    [run.counts.by_status],
  );

  return (
    <Card className="stack">
      <SectionHeading
        title={`#${run.task_id} — ${run.target}`}
        detail={`started ${startedAt(run)} · wordlist ${run.wordlist}${run.extensions ? ` · extensions ${run.extensions}` : ""}${
          run.match_codes ? ` · match ${run.match_codes}` : ""
        }`}
        actions={<Badge tone={STATE_TONE[run.state] ?? "neutral"}>{run.state}</Badge>}
      />

      {/* The server's own sentence, verbatim. It is the one place the caveats are worded. */}
      <p className="cell-dim">{run.summary}</p>

      {run.error ? <ErrorNotice title="The sweep reported an error" error={run.error} /> : null}

      <RunCounts run={run} />

      {byStatus.length > 0 ? (
        <div className="chip-row">
          {byStatus.map((group) => (
            <Badge key={group.status} tone={statusTone(group.status)}>
              {group.count} × {group.status}
            </Badge>
          ))}
        </div>
      ) : null}

      {run.command && run.command.length > 0 ? (
        <details>
          <summary className="cell-dim">
            <Terminal size={12} aria-hidden="true" /> Command that ran
          </summary>
          {/* These requests never passed through burpsy, so they are in no history row and no
              site-map node. This argv is the only record of what reached the target. */}
          <pre className="code-block">{run.command.join(" ")}</pre>
        </details>
      ) : null}

      {run.discoveries.length > 0 ? (
        <DiscoveryRows rows={run.discoveries} />
      ) : run.state === "running" ? (
        <Empty title="Sweeping" detail="Nothing has been reported yet. An empty list here means not-yet, not nothing." />
      ) : run.looked ? (
        <Empty
          title="No paths matched"
          detail={`${run.outcome}: the wordlist was swept and nothing matched. This is a result about the target.`}
        />
      ) : (
        <Empty
          title="Nothing was examined"
          detail={`${run.outcome}: this run never checked the target, so it says nothing about what is there.`}
        />
      )}
    </Card>
  );
}

export function ContentDiscoveryPage(): JSX.Element {
  const { data, error, isLoading, isFetching, refetch } = useDiscoveryRuns();

  if (isLoading) return <LoadingPanel label="Loading content discovery" />;

  return (
    <div className="page stack">
      <PageHeader
        title="Content discovery"
        eyebrow="Target"
        description="Burp's Discover content, delegated to ffuf. These requests do not pass through burpsy, so they appear in no history row and no site-map node — the command and the run record are the whole account of them."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} label="Refresh runs" />}
      />

      {error ? <ErrorNotice title="Could not load content-discovery runs" error={error} onRetry={() => void refetch()} /> : null}

      {data ? (
        <>
          {data.tool.available ? <StartSweep tool={data.tool} /> : <ToolUnavailable tool={data.tool} />}

          {data.runs.length === 0 ? (
            <Empty
              title="No sweeps recorded"
              detail={
                data.tool.available
                  ? `The server retains the last ${data.retained} runs. Nothing has been started yet.`
                  : "No sweep can be started until the tool is allowlisted, so there is nothing to show."
              }
            />
          ) : (
            <>
              <SectionHeading
                title="Runs"
                detail={`Most recent first. The server retains ${data.retained}; older runs are gone rather than hidden.`}
              />
              {data.runs.map((run) => (
                <RunCard key={run.task_id} run={run} />
              ))}
            </>
          )}
        </>
      ) : null}
    </div>
  );
}
