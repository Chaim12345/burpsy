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
import { useState } from "react";
import { toast } from "sonner";
import { Badge, Button, Card, ErrorNotice, Field, Input, Metric, Switch } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { formatCount } from "../lib/api";
import { useProxyOptions, useSetProxyOptions } from "../lib/data.proxyoptions";
import { useProxyListener, useRebindProxyListener } from "../lib/data.proxylistener";

// One row of the panel: key, label, what it does. Order matches proxy.OptionKeys.
const SWITCHES: { key: string; label: string; detail: string }[] = [
 {
  key: "unhide_hidden_form_fields",
  label: "Unhide hidden form fields",
  detail: 'Rewrite type="hidden" inputs to type="text" so a hidden field can be edited in the browser.',
 },
 {
  key: "enable_disabled_form_fields",
  label: "Enable disabled form fields",
  detail:
   "Remove the disabled attribute from form controls — input, textarea, select, option, button, fieldset — so a greyed-out control can be used.",
 },
 {
  key: "remove_input_field_length_limits",
  label: "Remove input field length limits",
  detail: "Remove maxlength attributes from inputs and textareas, so an over-long value can be submitted.",
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
  key: "remove_secure_flag_from_cookies",
  label: "Remove secure flag from cookies",
  detail:
   "Remove the Secure attribute from Set-Cookie headers, so an HTTPS-only cookie is also sent over plaintext HTTP and can be captured. A header rule: it reaches every response, whatever the body is.",
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
    <div className="switch-grid" style={{ marginBottom: "var(--gap)" }}>
     <label className="switch-row" htmlFor="proxy-opt-strip_sec_websocket_extensions">
      <span>
       <span>Strip Sec-WebSocket-Extensions from handshakes</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Remove the client's permessage-deflate offer before an upgrade is forwarded, so the origin cannot negotiate
        compression and frames are captured in the clear. On by default; turn it off for an origin that requires the
        extension — compressed frames are then recorded with a note. Applies from the next WebSocket handshake.
       </span>
      </span>
      <Switch
       id="proxy-opt-strip_sec_websocket_extensions"
       label="Strip Sec-WebSocket-Extensions from handshakes"
       checked={d.options["strip_sec_websocket_extensions"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { strip_sec_websocket_extensions: on },
         {
          onSuccess: () =>
           toast.success(
            `Sec-WebSocket-Extensions stripping ${on ? "on" : "off"} — applies from the next WebSocket handshake`,
           ),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-dont_log_out_of_scope">
      <span>
       <span>Don't log out-of-scope traffic</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Keep the history panel free of traffic the scope excludes: the request is still forwarded and the response is
        still delivered to the browser, only the record is dropped, and each drop is counted below. On by default —
        this store has never held out-of-scope exchanges. Turn it off to log everything the proxy sees, including the
        excluded traffic.
       </span>
      </span>
      <Switch
       id="proxy-opt-dont_log_out_of_scope"
       label="Don't log out-of-scope traffic"
       checked={d.options["dont_log_out_of_scope"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { dont_log_out_of_scope: on },
         {
          onSuccess: () =>
           toast.success(
            `Out-of-scope logging ${on ? "suppressed" : "kept"} — applies from the next exchange`,
           ),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-strip_proxy_headers">
      <span>
       <span>Strip Proxy-* headers from requests</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Remove every Proxy-Connection / Proxy-Authorization / … header before the request is forwarded — the family
        talks to proxies, not to origins, and Burp strips it for the same reason. On by default; turn it off to send
        them, which is occasionally what testing an origin's own Proxy-header handling needs. Applies from the next
        request.
       </span>
      </span>
      <Switch
       id="proxy-opt-strip_proxy_headers"
       label="Strip Proxy-* headers from requests"
       checked={d.options["strip_proxy_headers"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { strip_proxy_headers: on },
         {
          onSuccess: () => toast.success(`Proxy-* stripping ${on ? "on" : "off"} — applies from the next request`),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-set_connection_close">
      <span>
       <span>Set &quot;Connection: close&quot; on requests and responses</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Rewrite the request's Connection header to close and set it on the response, so both directions end after one
        exchange. Off by default — the relay already honours whatever the client asked for; forcing close trades
        keep-alive throughput for determinism. Applies from the next request.
       </span>
      </span>
      <Switch
       id="proxy-opt-set_connection_close"
       label="Set Connection: close on requests and responses"
       checked={d.options["set_connection_close"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { set_connection_close: on },
         {
          onSuccess: () => toast.success(`Connection: close ${on ? "forced" : "left to the client"} — applies from the next request`),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
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
      <tr>
       <td>Out-of-scope exchanges not logged</td>
       <td>
        <Badge>{formatCount(c.exchanges_dropped_out_of_scope)}</Badge>
       </td>
      </tr>
     </SimpleTable>
    </div>
   </Card>

   <ProxyListenerSection />
  </div>
 );
}

/**
 * The listener's bind address, live (burpsy-react-ui-77m, scope (1): one
 * re-bindable listener, not a listener list). Burp's "Proxy listeners" panel
 * starts with Binding; here the address is what the accept loop actually serves
 * — an ephemeral bind is shown resolved — and Rebind moves it without a
 * restart: the engine opens the new socket before closing the old one, so a
 * typo'd port is an error toast, not an outage.
 *
 * The bind is deliberately not persisted. A restart reverts to -proxy-bind; a
 * saved port that disagreed with the flag would leave this panel describing a
 * listener that exists only in a durable store.
 */
function ProxyListenerSection(): JSX.Element {
 const listener = useProxyListener();
 const rebind = useRebindProxyListener();
 const options = useProxyOptions();
 const setOptions = useSetProxyOptions();
 const [draft, setDraft] = useState("");

 if (listener.isLoading) return <LoadingPanel label="Loading proxy listener" />;
 if (listener.error || !listener.data)
  return (
   <Card>
    <ErrorNotice error={listener.error ?? new Error("Proxy listener unavailable")} onRetry={() => void listener.refetch()} />
   </Card>
  );

 const d = listener.data;
 const current = d.bind;
 const invisible = options.data?.options["invisible_proxy"];
 const setInvisible = (on: boolean) =>
  setOptions.mutate(
   { invisible_proxy: on },
   {
    onSuccess: () => toast.success(`Invisible proxying ${on ? "on" : "off"} — applies from the next request`),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
   },
  );

 return (
  <Card>
   <SectionHeading
    title="Proxy listener"
    detail="The address the proxy is bound to right now, and the invisible-proxying switch for clients that do not speak to a proxy. Both are live: no restart."
    actions={<RefreshButton onClick={() => void listener.refetch()} loading={listener.isFetching} />}
   />
   <div className="metric-grid wide">
    <Metric label="Bound to" value={current} />
    {d.previous_bind ? <Metric label="Previous bind" value={d.previous_bind} /> : null}
   </div>
   <div className="stack" style={{ marginTop: "var(--gap)" }}>
    <Field
     label="Re-bind listener"
     hint="host:port — for example 127.0.0.1:8080, or 0.0.0.0:8080 for every interface. Port 0 picks an ephemeral port. Applies immediately; reverts to -proxy-bind on restart."
    >
     {(id) => (
      <div className="toolbar">
       <Input
        id={id}
        name="proxy_listener_bind"
        value={draft}
        placeholder={current}
        onChange={(e) => setDraft(e.target.value)}
        style={{ maxWidth: "22rem" }}
       />
       <Button
        variant="outline"
        disabled={!draft.trim() || draft.trim() === current || rebind.isPending}
        onClick={() =>
         rebind.mutate(draft.trim(), {
          onSuccess: (next) => {
           toast.success(`Proxy listener moved to ${next.bind}`);
           setDraft("");
          },
          onError: (failure: unknown) =>
           // A failed rebind leaves the old listener serving — say so, because
           // "the change did not happen" and "the proxy is down" need telling apart.
           toast.error(failure instanceof Error ? `${failure.message} — the previous listener is still serving` : "Re-binding the listener failed"),
         })
        }
       >
        Re-bind
       </Button>
      </div>
     )}
    </Field>
   </div>
   <div className="switch-grid" style={{ marginTop: "var(--gap)" }}>
    <label className="switch-row" htmlFor="proxy-opt-invisible_proxy">
     <span>
      <span>Support invisible proxying</span>
      <span className="cell-dim" style={{ display: "block" }}>
       For clients that were never told about the proxy: accept an origin-form request (GET /path) whose only authority
       is the Host header, instead of refusing it. On by default — this engine has always honoured the header — so the
       switch exists to tighten a listener, and applies from the next request.
      </span>
     </span>
     <Switch
      id="proxy-opt-invisible_proxy"
      label="Support invisible proxying"
      checked={invisible === true}
      onCheckedChange={(on) => setInvisible(on)}
     />
    </label>
   </div>
  </Card>
 );
}
