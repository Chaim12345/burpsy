// A loaded plugin's editor-tab registrations as message-editor tabs (burpsy-react-ui-ww5).
//
// # What this is the other half of
//
// The host has three registration points with an honest web analogue (internal/extension/
// views.go): context-menu (surfaced by lib/plugin-exchange-actions.ts), menu (the palette,
// lib/palette-commands.ts), and editor-tab — this module. KindEditorTab is the read-only half
// of Burp's registerHttpRequestEditorProvider: a *named, read-only* tab over one whole
// message. The caret/selection half is deliberately out of scope because a request/response
// round trip cannot carry either (protocol.go's MethodSpecs say so), and the invoke contract
// matches: `editor.render` takes {registration, message, raw} and answers {text}.
//
// # The wire, and why raw is fetched here
//
// A plugin has no route to this process's traffic store (the same fact plugin-exchange-actions
// records for contextMenu.invoke), so the caller must hand the bytes with the id. The editor
// owns its message's id but its `value` may be a derived reading (Pretty, a charset override)
// rather than the stored bytes, so the tab fetches through fetchRaw at open time, exactly as
// the context-menu path does, and reports a fetch failure rather than invoking with an empty
// raw the plugin would read as "this message was empty".
//
// # Caching, and why the cache is keyed the way it is
//
// pluginTabKey (plugin-registrations.ts) is messageId + plugin + registration id: a tab's
// content depends on the exact message the operator is looking at, and caching per key means
// stepping to another row does not flash a previous row's derived view. No TTL and no
// revalidation: a message id names the same bytes for the life of the store, so the first
// render is the honest answer every time. Expiring the cache would re-invoke a plugin for a
// message it already answered, charging the plugin's invocation counter for a re-read the
// operator did not ask for.
import { useCallback, useMemo, useRef, useState } from "react";
import { fetchRaw } from "./actions";
import { useExtensions, useInvokeExtension } from "./data.extensions";
import { pluginInvocations, pluginTabKey, type PluginInvocation } from "./plugin-registrations";

/** One openable plugin tab, reduced to what the strip renders. */
export interface PluginTabEntry {
 /** The registration and the plugin that declared it. */
 invocation: PluginInvocation;
 /** Stable identity for React's key and the content cache. */
 key: string;
}

/** The rendered content of the open tab, wherever it stands. */
export interface PluginTabContent {
 /** The plugin's rendered text once editor.render answered. */
 text?: string;
 /** True while the invoke is in flight. A tab body that says nothing would read as empty. */
 loading: boolean;
 /** Why the render failed, when it did. Shown in the tab rather than only toasted, because a
  * toast is gone before the operator looks at the tab they just opened. */
 error?: string;
}

/** What the editor needs to render the plugin tabs. */
export interface PluginTabs {
 /** One per loaded editor-tab registration, in the served order (the plugin list's own). */
 entries: PluginTabEntry[];
 /** The open tab's key, or null when none is. */
 openKey: string | null;
 /** Open one tab (fetching and invoking on first open), or close the open one. */
 open: (key: string) => void;
 close: () => void;
 /** The open tab's content. Undefined matches openKey === null. */
 content: PluginTabContent | undefined;
}

/**
 * The loaded plugins' editor-tab registrations for one message.
 *
 * `messageId` is the id of the message the editor is showing, not the exchange: editor.render
 * is per-message, and the request and response panes of one exchange are different messages
 * with different ids. An undefined messageId (a pane with no stored message behind it) still
 * offers the tabs — the strip is honest about the plugin's existence — but opening one reports
 * the missing id rather than invoking against nothing.
 */
export function usePluginEditorTabs(messageId: number | undefined): PluginTabs {
 const extensions = useExtensions();
 const invoke = useInvokeExtension();
 const mutate = invoke.mutate;

 // Content cache across tab opens and switches. Keyed by pluginTabKey; see the module doc
 // for why it never expires. A ref rather than state: the cache is the tab's own plumbing,
 // and the visible state below is what re-renders.
 const cacheRef = useRef<Map<string, string>>(new Map());

 const entries = useMemo(
  () =>
   pluginInvocations(extensions.data, "editor-tab").map((invocation) => ({
    invocation,
    key: pluginTabKey(messageId ?? -1, invocation),
   })),
  [extensions.data, messageId],
 );

 const byKey = useMemo(() => new Map(entries.map((entry) => [entry.key, entry.invocation])), [entries]);

 const [openKey, setOpenKey] = useState<string | null>(null);
 const [states, setStates] = useState<Record<string, PluginTabContent>>({});

 const open = useCallback(
  (key: string) => {
   const invocation = byKey.get(key);
   if (!invocation) return;
   setOpenKey(key);
   const cached = cacheRef.current.get(key);
   if (cached !== undefined || states[key]?.loading) return;
   if (messageId === undefined) {
    setStates((current) => ({
     ...current,
     [key]: { loading: false, error: "this pane has no stored message to hand the plugin" },
    }));
    return;
   }
   setStates((current) => ({ ...current, [key]: { loading: true } }));
   void (async () => {
    let raw: string;
    try {
     raw = await fetchRaw(messageId);
    } catch (failure: unknown) {
     setStates((current) => ({
      ...current,
      [key]: {
       loading: false,
       error: `could not read the message to hand ${invocation.plugin}: ${failure instanceof Error ? failure.message : "fetch failed"
        }`,
      },
     }));
     return;
    }
    mutate(
     { name: invocation.plugin, registration: invocation.registration.id, message: messageId, raw },
     {
      onSuccess: (response) => {
       // editor.render fills `text`; `output` is the menu methods' field. Reading text
       // only would silently drop nothing — but a plugin that answered with output
       // instead broke its own contract, and showing it is more useful than an empty tab.
       const text = response.result.text ?? response.result.output ?? "";
       cacheRef.current.set(key, text);
       setStates((current) => ({ ...current, [key]: { loading: false } }));
      },
      onError: (failure: unknown) => {
       setStates((current) => ({
        ...current,
        [key]: { loading: false, error: failure instanceof Error ? failure.message : "the invoke failed" },
       }));
      },
     },
    );
   })();
  },
  [byKey, messageId, mutate, states],
 );

 const close = useCallback(() => setOpenKey(null), []);

 // The content the open tab shows. Cached text first, so reopening a tab is instant; then the
 // live state, which carries loading and error.
 const content =
  openKey === null
   ? undefined
   : cacheRef.current.has(openKey)
    ? { text: cacheRef.current.get(openKey), loading: false }
    : states[openKey];

 return { entries, openKey, open, close, content };
}
