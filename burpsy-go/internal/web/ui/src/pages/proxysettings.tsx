/**
 * The Proxy settings leaf: Burp's response-modification switches plus the
 * strip-Accept-Encoding knob, over /api/proxy/options. Every switch here is
 * live — the relay reads the same option set on the next response, no restart
 * — and the counters answer the question a bare switch list cannot: did these
 * rules actually change anything?
 *
 * The labels and descriptions are this build's own wording for what each rule
 * rewrites (proxy/options.go is the authority); they live here because the wire
 * carries keys, not prose.
 */
import { toast } from "sonner";
import { Badge, Card, ErrorNotice, Metric, Switch } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { formatCount } from "../lib/api";
import { useProxyOptions, useSetProxyOptions } from "../lib/data.proxyoptions";

// One row of the panel: key, label, what it does. Order matches proxy.OptionKeys.
const SWITCHES: { key: string; label: string; detail: string }[] = [
  {
    key: "unhide_hidden_form_fields",
    label: "Unhide hidden form fields",
    detail: 'Rewrite type="hidden" inputs to type="text" so a hidden field can be edited in the browser.',
  },
  {
    key: "remove_object_tags",
    label: "Remove object tags",
    detail: "Strip <object>…</object> elements and everything inside them.",
  },
  {
    key: "remove_javascript_form_validation",
    label: "Remove JavaScript form validation",
    detail: "Remove onsubmit/onreset handler attributes — the two hooks client-side validation runs from.",
  },
  {
    key: "remove_all_javascript",
    label: "Remove all JavaScript",
    detail: "Remove <script> elements, every inline on* handler, and javascript: hrefs.",
  },
  {
    key: "convert_https_links_to_http",
    label: "Convert HTTPS links to HTTP",
    detail: "Rewrite https:// to http:// inside href, src and action attribute values.",
  },
  {
    key: "strip_accept_encoding",
    label: "Strip Accept-Encoding from requests",
    detail: "Ask the origin for plaintext: with no decompressor on the proxy path, compressed responses are exactly the ones these rules cannot rewrite.",
  },
];

export function ProxySettingsPage(): JSX.Element {
  const state = useProxyOptions();
  const setOptions = useSetProxyOptions();

  if (state.isLoading) return <LoadingPanel label="Loading proxy options" />;
  if (state.error || !state.data)
    return <ErrorNotice error={state.error ?? new Error("Proxy options unavailable")} onRetry={() => void state.refetch()} />;

  const d = state.data;
  const c = d.counters;

  return (
    <div className="stack">
      <PageHeader
        title="Proxy settings"
        description="Response-modification rules the relay applies live, and the counters that say whether they changed anything."
        actions={<RefreshButton onClick={() => void state.refetch()} loading={state.isFetching} />}
      />
      <Card>
        <SectionHeading
          title="Response modification"
          detail="These rules rewrite matched responses as they pass through the proxy — live, no restart. The counters below say whether a switch that is on has actually changed anything yet."
        />
        <div className="switch-grid">
          {SWITCHES.map((sw) => (
            <label key={sw.key} className="switch-row" htmlFor={`proxy-opt-${sw.key}`}>
              <span>
                <span>{sw.label}</span>
                <span className="cell-dim" style={{ display: "block" }}>{sw.detail}</span>
              </span>
              <Switch
                id={`proxy-opt-${sw.key}`}
                label={sw.label}
                checked={d.options[sw.key] === true}
                disabled={setOptions.isPending}
                onCheckedChange={(on) =>
                  setOptions.mutate(
                    { [sw.key]: on },
                    {
                      onSuccess: () => toast.success(`${sw.label} ${on ? "on" : "off"} — applies from the next matching response`),
                      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
                    },
                  )
                }
              />
            </label>
          ))}
        </div>
      </Card>

      <Card>
        <SectionHeading title="Outcome counters" detail="What the rules did across every response considered since this process started." />
        <div className="metric-grid wide">
          <Metric label="Considered" value={c.responses_considered} />
          <Metric label="Modified" value={c.responses_modified} tone={c.responses_modified > 0 ? "good" : undefined} />
          <Metric label="Unchanged" value={c.responses_unchanged} />
          <Metric label="Skipped: compressed" value={c.skipped_compressed} detail="turn on strip-Accept-Encoding to reach these" />
          <Metric label="Skipped: not HTML" value={c.skipped_not_html} />
          <Metric label="Skipped: unframed" value={c.skipped_unframed} />
        </div>
        {c.responses_considered > 0 && c.responses_modified === 0 ? (
          <p className="cell-dim" style={{ marginTop: "var(--gap)" }}>
            Rules have looked at {formatCount(c.responses_considered)}{" "}
            {c.responses_considered === 1 ? "response" : "responses"} and changed none — either nothing matches or every
            switch is off. That is stated rather than left to look like a clean pass.
          </p>
        ) : null}
      </Card>

      <Card>
        <SectionHeading title="Transport adjustments" detail="Not response rules, but part of the same knob set." />
        <SimpleTable headers={["Adjustment", "Count"]}>
          <tr>
            <td>Accept-Encoding stripped from requests</td>
            <td><Badge>{formatCount(c.accept_encoding_stripped)}</Badge></td>
          </tr>
          <tr>
            <td>Responses dechunked before rule matching</td>
            <td><Badge>{formatCount(c.dechunked)}</Badge></td>
          </tr>
          <tr>
            <td>HTTP/2 responses relayed without rewriting</td>
            <td><Badge>{formatCount(c.relayed_http2)}</Badge></td>
          </tr>
        </SimpleTable>
      </Card>
    </div>
  );
}
