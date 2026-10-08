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
import { Fragment, useState } from "react";
import { toast } from "sonner";
import { Badge, Button, Card, ErrorNotice, Field, Input, Metric, Select, Switch } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { formatCount } from "../lib/api";
import { useProxyOptions, useSetProxyOptions } from "../lib/data.proxyoptions";
import type { ProxyListenerRow } from "../lib/data.proxylistener";
import {
 useAddProxyListener,
 useProxyListener,
 useRemoveProxyListener,
 useUpdateProxyListener,
} from "../lib/data.proxylistener";
import type { InvisibleChoice, ListenerDraft } from "../lib/proxy-listener";
import {
 REDIRECT_CAVEAT,
 describeListener,
 draftFromListener,
 emptyListenerDraft,
 listenerDraftToBody,
} from "../lib/proxy-listener";
import { TlsPassthroughSection } from "./settings";

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

   <TlsPassthroughSection />

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
     <label className="switch-row" htmlFor="proxy-opt-use_http10_to_server">
      <span>
       <span>Use HTTP/1.0 in requests to server</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Send every forwarded request with an HTTP/1.0 request line, for a legacy origin that mishandles HTTP/1.1. Only the version token changes. Applies from the next request.
       </span>
      </span>
      <Switch
       id="proxy-opt-use_http10_to_server"
       label="Use HTTP/1.0 in requests to server"
       checked={d.options["use_http10_to_server"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { use_http10_to_server: on },
         {
          onSuccess: () => toast.success(`HTTP/1.0 to the server ${on ? "on" : "off"}`),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-use_http10_to_client">
      <span>
       <span>Use HTTP/1.0 in responses to client</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Answer the browser with an HTTP/1.0 status line. History records the response as the browser received it. Applies from the next response.
       </span>
      </span>
      <Switch
       id="proxy-opt-use_http10_to_client"
       label="Use HTTP/1.0 in responses to client"
       checked={d.options["use_http10_to_client"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { use_http10_to_client: on },
         {
          onSuccess: () => toast.success(`HTTP/1.0 to the client ${on ? "on" : "off"}`),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-suppress_error_messages">
      <span>
       <span>Suppress burpsy error messages in browser</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Close the connection instead of sending burpsy's own explanatory error page (a refused scope, a failed CONNECT, an unattributable request). The event is still logged and counted.
       </span>
      </span>
      <Switch
       id="proxy-opt-suppress_error_messages"
       label="Suppress burpsy error messages in browser"
       checked={d.options["suppress_error_messages"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { suppress_error_messages: on },
         {
          onSuccess: () => toast.success(`Error messages ${on ? "suppressed" : "shown"}`),
          onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Setting the option failed"),
         },
        )}
      />
     </label>
     <label className="switch-row" htmlFor="proxy-opt-disable_web_interface">
      <span>
       <span>Disable web interface at http://burpsy</span>
       <span className="cell-dim" style={{ display: "block" }}>
        Stop the listener answering http://burpsy, http://burpsuite and its own address with the welcome page and CA certificate. Useful on a listener bound to an unprotected interface.
       </span>
      </span>
      <Switch
       id="proxy-opt-disable_web_interface"
       label="Disable web interface at http://burpsy"
       checked={d.options["disable_web_interface"] === true}
       onCheckedChange={(on) =>
        setOptions.mutate(
         { disable_web_interface: on },
         {
          onSuccess: () => toast.success(`Web interface ${on ? "disabled" : "enabled"}`),
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
 * Burp's "Proxy listeners" panel: the LIST of listeners the engine is serving, each with its
 * own bind address, redirect target, force-TLS setting and invisible-proxying tick
 * (burpsy-react-ui-pfeg). It replaces the single bound address this page showed when the
 * decision on burpsy-react-ui-77m scoped it to one re-bindable listener, because the controls
 * Burp's page is primarily for — pointing a non-proxy-aware client at a listener that
 * forwards somewhere else, over TLS — cannot be expressed by one socket.
 *
 * Three things this panel states rather than leaves to be discovered, because each is a way
 * an operator could otherwise be misled:
 *
 *   - Every row is a socket the accept loop is serving. A listener that cannot bind is
 *     refused with the reason and never appears, so there is no such thing as a dead row.
 *   - The boot listener (-proxy-bind) can be re-bound but not removed: it is the one the
 *     in-browser panel and the startup banner report, and the collection must not become
 *     empty. The Remove button is absent on it and the endpoint refuses it too.
 *   - Nothing is persisted. A restart reverts to -proxy-bind and a single listener.
 */
function ProxyListenerSection(): JSX.Element {
 const listener = useProxyListener();
 const add = useAddProxyListener();
 const update = useUpdateProxyListener();
 const remove = useRemoveProxyListener();
 const options = useProxyOptions();
 const setOptions = useSetProxyOptions();
 // `null` is "not editing"; "new" is the add form; anything else is a listener id.
 const [editing, setEditing] = useState<string | null>(null);
 const [draft, setDraft] = useState<ListenerDraft>(emptyListenerDraft());

 if (listener.isLoading) return <LoadingPanel label="Loading proxy listeners" />;
 if (listener.error || !listener.data)
  return (
   <Card>
    <ErrorNotice error={listener.error ?? new Error("Proxy listeners unavailable")} onRetry={() => void listener.refetch()} />
   </Card>
  );

 const d = listener.data;
 const rows = d.listeners ?? [];
 const globalInvisible = options.data?.options["invisible_proxy"] === true;
 const anyRedirect = rows.some((row) => row.redirect_host !== "" || row.redirect_port !== 0);

 const openAdd = () => {
  setDraft(emptyListenerDraft());
  setEditing("new");
 };
 const openEdit = (row: ProxyListenerRow) => {
  setDraft(draftFromListener(row));
  setEditing(row.id);
 };
 const failureText = (failure: unknown, fallback: string) =>
  failure instanceof Error ? failure.message : fallback;

 const submit = () => {
  const parsed = listenerDraftToBody(draft);
  if (!parsed.ok) {
   toast.error(parsed.error);
   return;
  }
  if (editing === "new") {
   add.mutate(parsed.body, {
    onSuccess: (row) => {
     toast.success(`Listener ${row.id} bound to ${row.bound_addr}`);
     setEditing(null);
    },
    // A bind that failed added nothing — say so, because "the listener is not there" and
    // "the listener is there and dead" are the two states this panel exists to tell apart.
    onError: (failure: unknown) => toast.error(`${failureText(failure, "Adding the listener failed")} — no listener was added`),
   });
   return;
  }
  if (!editing) return;
  update.mutate(
   { id: editing, body: parsed.body },
   {
    onSuccess: (row) => {
     toast.success(`Listener ${row.id} now bound to ${row.bound_addr}`);
     setEditing(null);
    },
    onError: (failure: unknown) =>
     toast.error(`${failureText(failure, "Updating the listener failed")} — the listener is still serving where it was`),
   },
  );
 };

 const form = (submitLabel: string) => (
  <tr>
   <td colSpan={6}>
    <div className="stack">
     <Field
      label="Bind address"
      hint="host:port — for example 127.0.0.1:8081, or 0.0.0.0:8081 for every interface. Port 0 picks an ephemeral port. Applies immediately; reverts to -proxy-bind on restart."
     >
      {(id) => (
       <Input
        id={id}
        name="proxy_listener_bind"
        value={draft.bind}
        placeholder="127.0.0.1:8081"
        onChange={(e) => setDraft({ ...draft, bind: e.target.value })}
        style={{ maxWidth: "22rem" }}
       />
      )}
     </Field>
     <Field
      label="Redirect to host"
      hint="Send every request this listener accepts to this host instead of the one the client named. Leave blank to keep the client's host. The Host header is not rewritten, so a vhost on the redirect target still answers."
     >
      {(id) => (
       <Input
        id={id}
        name="proxy_listener_redirect_host"
        value={draft.redirectHost}
        placeholder="(keep the host the client asked for)"
        onChange={(e) => setDraft({ ...draft, redirectHost: e.target.value })}
        style={{ maxWidth: "22rem" }}
       />
      )}
     </Field>
     <Field label="Redirect to port" hint="Leave blank to keep the port the client asked for.">
      {(id) => (
       <Input
        id={id}
        name="proxy_listener_redirect_port"
        value={draft.redirectPort}
        placeholder="(keep the port the client asked for)"
        onChange={(e) => setDraft({ ...draft, redirectPort: e.target.value })}
        style={{ maxWidth: "12rem" }}
       />
      )}
     </Field>
     <Field
      label="Support invisible proxying"
      hint="Inherit follows the switch below, which is the whole-process default; on and off decide for this listener alone."
     >
      {(id) => (
       <Select
        id={id}
        name="proxy_listener_invisible"
        value={draft.invisible}
        onChange={(e) => setDraft({ ...draft, invisible: e.target.value as InvisibleChoice })}
        style={{ maxWidth: "22rem" }}
       >
        <option value="inherit">Inherit the switch below ({globalInvisible ? "currently on" : "currently off"})</option>
        <option value="on">On for this listener</option>
        <option value="off">Off for this listener</option>
       </Select>
      )}
     </Field>
     <label className="switch-row" htmlFor="proxy-listener-force-tls">
      <span>
       <span>Force use of TLS</span>
       <span className="cell-dim" style={{ display: "block" }}>
        The connection this proxy opens to the destination uses TLS whatever the client used to reach the listener — the
        setup a plaintext client in front of an HTTPS origin needs. It changes the leg to the destination only: traffic
        that arrives through CONNECT is already TLS upstream, so this setting is already satisfied for it.
       </span>
      </span>
      <Switch
       id="proxy-listener-force-tls"
       label="Force use of TLS"
       checked={draft.forceTLS}
       onCheckedChange={(on) => setDraft({ ...draft, forceTLS: on })}
      />
     </label>
     <div className="toolbar">
      <Button onClick={submit} disabled={add.isPending || update.isPending}>
       {submitLabel}
      </Button>
      <Button variant="outline" onClick={() => setEditing(null)}>
       Cancel
      </Button>
     </div>
    </div>
   </td>
  </tr>
 );

 return (
  <Card>
   <SectionHeading
    title="Proxy listeners"
    detail="Every row is a socket the accept loop is serving right now, with the redirect, force-TLS and invisible-proxying settings its traffic is relayed under. All of it is live: no restart. None of it is persisted — a restart reverts to the single listener -proxy-bind names."
    actions={
     <div className="toolbar">
      <Button variant="outline" onClick={openAdd} disabled={editing === "new"}>
       Add listener
      </Button>
      <RefreshButton onClick={() => void listener.refetch()} loading={listener.isFetching} />
     </div>
    }
   />
   <SimpleTable headers={["Listener", "Bound to", "Redirect", "Force TLS", "Invisible", ""]}>
    {rows.map((row) => (
     <Fragment key={row.id}>
      <tr>
       <td>
        <span>{row.id === "default" ? "default (-proxy-bind)" : row.id}</span>
        <span className="cell-dim" style={{ display: "block" }}>{describeListener(row, globalInvisible)}</span>
       </td>
       <td>{row.bound_addr || "—"}</td>
       <td>
        {row.redirect_host || row.redirect_port
         ? `${row.redirect_host || "(client's host)"}:${row.redirect_port || "(client's port)"}`
         : "—"}
       </td>
       <td>{row.force_tls ? <Badge tone="warn">Forced</Badge> : "—"}</td>
       <td>
        {row.invisible === null
         ? `Inherit (${globalInvisible ? "on" : "off"})`
         : row.invisible
           ? "On"
           : "Off"}
       </td>
       <td>
        <div className="toolbar">
         <Button variant="outline" onClick={() => openEdit(row)} disabled={editing === row.id}>
          Edit
         </Button>
         {row.removable ? (
          <Button
           variant="outline"
           disabled={remove.isPending}
           onClick={() =>
            remove.mutate(row.id, {
             onSuccess: () => {
              toast.success(`Listener ${row.id} removed — it stopped accepting, and the exchanges it was relaying finish`);
              if (editing === row.id) setEditing(null);
             },
             onError: (failure: unknown) => toast.error(failureText(failure, "Removing the listener failed")),
            })
           }
          >
           Remove
          </Button>
         ) : (
          <span className="cell-dim">Re-bind only</span>
         )}
        </div>
       </td>
      </tr>
      {editing === row.id ? form("Save") : null}
     </Fragment>
    ))}
    {editing === "new" ? form("Add listener") : null}
   </SimpleTable>
   <p className="cell-dim" style={{ marginTop: "var(--gap)" }}>
    The <strong>default</strong> listener is the one <code>-proxy-bind</code> opened. It can be re-bound but not removed:
    it is the address the in-browser panel and the startup banner report, and an empty collection would be a proxy with no
    way in. Removing any other listener stops it accepting immediately; the exchanges it is already relaying run to
    completion.
   </p>
   {anyRedirect ? (
    <p className="cell-dim" style={{ marginTop: "var(--gap)" }}>{REDIRECT_CAVEAT}</p>
   ) : null}
   <div className="switch-grid" style={{ marginTop: "var(--gap)" }}>
    <label className="switch-row" htmlFor="proxy-opt-invisible_proxy">
     <span>
      <span>Support invisible proxying (every listener set to inherit)</span>
      <span className="cell-dim" style={{ display: "block" }}>
       For clients that were never told about the proxy: accept an origin-form request (GET /path) whose only authority
       is the Host header, instead of refusing it. On by default — this engine has always honoured the header. This is
       the process-wide default; a listener above can override it in either direction, and applies from the next request.
      </span>
     </span>
     <Switch
      id="proxy-opt-invisible_proxy"
      label="Support invisible proxying"
      checked={globalInvisible}
      onCheckedChange={(on) =>
       setOptions.mutate(
        { invisible_proxy: on },
        {
         onSuccess: () => toast.success(`Invisible proxying ${on ? "on" : "off"} for inheriting listeners — applies from the next request`),
         onError: (failure: unknown) => toast.error(failureText(failure, "Setting the option failed")),
        },
       )
      }
     />
    </label>
   </div>
  </Card>
 );
}
