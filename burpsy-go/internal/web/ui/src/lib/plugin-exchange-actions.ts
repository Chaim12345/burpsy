// The exchange context menu with a loaded plugin's context-menu items in it (burpsy-react-ui-ww5).
//
// # Why this wraps useExchangeActions instead of living inside it
//
// lib/actions.ts's `menu(exchange, extra?)` already appends a caller's own groups, so every page
// gets the plugin group by taking its actions from here instead of from there. The alternative —
// building the group inside actions.ts — is the same behaviour and a worse dependency: actions.ts is
// imported by lib/palette-recency's tests and by every table page, and putting a react-query read of
// /api/extensions in it would make the plugin list a prerequisite for the whole action layer.
//
// # What a plugin is handed, and why it is not just an id
//
// MethodSpecs' entry for contextMenu.invoke reads: *"The exchange id and its bytes are passed in,
// because a plugin has no route to this process's traffic store."* An `Exchange` row does not carry
// its bytes (lib/actions.ts:496 says so), so this fetches the request through /api/message/:id
// before invoking. Sending the id alone would satisfy the schema and hand the plugin a number it
// cannot dereference — a menu item that runs and can do nothing, which is the shape of defect this
// tree counts as worse than an absent control.
//
// The fetch failing is reported as the fetch failing. The plugin is not invoked with an empty `raw`
// that it would have to read as "this exchange had no request".
import { useMemo } from "react";
import { toast } from "sonner";
import { fetchRaw } from "./actions";
import { useExchangeActions } from "./actions";
import { useExtensions, useInvokeExtension } from "./data.extensions";
import { pluginMenuItems, type PluginInvocation, type PluginTarget } from "./plugin-registrations";
import type { MenuGroup } from "../ui/menu";

/**
 * useExchangeActions with the loaded plugins' context-menu registrations appended to `menu()`.
 *
 * Every other action is passed through untouched, so a page swapping to this hook keeps the menu it
 * had and gains a group at the bottom. The plugin group goes last, after the caller's own `extra`:
 * Burp puts extension-contributed items at the end of the context menu, and an operator's muscle
 * memory for "Send to Repeater" must not move because a plugin was loaded.
 *
 * The group is absent, not empty, when no loaded plugin declares a context-menu item —
 * `pluginMenuItems` returns [] and the menu renders exactly as it did before. On a stock build
 * /api/extensions reports `allowlisted: 0`, so that is the normal case and it is an honest absence
 * rather than a heading that opens onto nothing.
 */
export function usePluginExchangeActions(): ReturnType<typeof useExchangeActions> {
 const base = useExchangeActions();
 const extensions = useExtensions();
 const invoke = useInvokeExtension();

 // The mutation object is new on every render, so the callback is memoised on `mutate` — which is
 // stable — rather than on `invoke`. Without that, `menu` would change identity every render and
 // every page's memoised menu groups would rebuild on every keystroke elsewhere in the page.
 const mutate = invoke.mutate;
 const run = useMemo(
  () => (call: PluginInvocation, target: PluginTarget) => {
   void (async () => {
    let raw = target.raw;
    if (raw === undefined && target.message !== undefined) {
     try {
      raw = await fetchRaw(target.message);
     } catch (failure: unknown) {
      toast.error(
       failure instanceof Error
        ? `Could not read the request to hand ${call.plugin}: ${failure.message}`
        : `Could not read the request to hand ${call.plugin}`,
      );
      return;
     }
    }
    mutate(
     {
      name: call.plugin,
      registration: call.registration.id,
      exchange: target.exchange,
      raw,
     },
     {
      onSuccess: (response) => {
       const text = response.result.output ?? response.result.text ?? "";
       // The same rule the Extender page's Run button follows: an empty answer is reported as
       // an empty answer. A plugin whose whole effect was to log something has nothing to
       // return, and inventing "done" for it would be a fabricated result.
       toast.success(text || `${call.registration.label} answered with no text. Anything it did is on ${call.plugin}'s consoles.`);
      },
      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : `Invoking ${call.registration.label} failed`),
     },
    );
   })();
  },
  [mutate],
 );

 const list = extensions.data;
 const baseMenu = base.menu;
 const menu = useMemo(
  () =>
   (exchange: Parameters<typeof baseMenu>[0], extra: MenuGroup[] = []): MenuGroup[] =>
    baseMenu(exchange, [
     ...extra,
     ...pluginMenuItems(list, exchange.id, (call, target) =>
      // The row's request message is what a context-menu plugin acts on: Burp's own
      // ContextMenuItemsProvider is handed the selected request/response pair, and the request is
      // the half every such plugin reads first. `target.exchange` still travels, so a plugin that
      // only wants the id has it.
      //
      // OMITTED rather than zero when the row has no request. A blind CONNECT tunnel has no
      // request bytes, and handing a plugin `message: 0` would point it at the first request the
      // project ever captured — a different exchange's bytes, acted on under this row's name
      // (burpsy-react-ui-wtov). A plugin that needs the message reads `undefined` and can say so;
      // one that only wants the id still has `target.exchange`.
      run(call, exchange.request === null ? { ...target, message: undefined } : { ...target, message: exchange.request }),
     ),
    ]),
  [baseMenu, list, run],
 );

 return { ...base, menu };
}
