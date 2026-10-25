// ISOLATED-world relay (burpsy-react-ui-wl94, k13f).
//
// The MAIN-world instrumentation cannot reach the extension's messaging (it runs in the page's own
// world), and a content script cannot fetch an http:// origin from an https page without tripping
// mixed-content. So the flow is three hops: MAIN dispatches a DOM event, this relay (which does have
// chrome.runtime) forwards it to the service worker, and the worker — whose fetch is not subject to
// the page's mixed-content rules — posts it to burpsy. This file carries no config; the worker holds
// the report URL and the capability.
//
// Everything arriving from MAIN is page-tamperable and is forwarded only as an untrusted observation.
// A decision comes back from the worker (extension-internal message, not a page event) and is handed
// to MAIN as a DOM event; the page can tamper with or ignore it, so delivery is never proof of effect.
(function () {
  "use strict";
  try { chrome.runtime.sendMessage({ type: "burpsy-di-frame-open" }); } catch (e) {}
  document.addEventListener("__burpsyDI_hit", function (ev) {
    try {
      var hit = JSON.parse(ev.detail);
      chrome.runtime.sendMessage({ type: "burpsy-di-hit", hit: hit });
    } catch (e) {}
  }, true);
  document.addEventListener("__burpsyDI_msg", function (ev) {
    try {
      var m = JSON.parse(ev.detail);
      chrome.runtime.sendMessage({ type: "burpsy-di-msg", msg: { body: m.body, origin: m.origin, hasPorts: !!m.hasPorts } });
    } catch (e) {}
  }, true);
  chrome.runtime.onMessage.addListener(function (msg, sender) {
    if (!msg || msg.type !== "burpsy-di-decision" || sender.id !== chrome.runtime.id || sender.tab) return;
    document.dispatchEvent(new CustomEvent("__burpsyDI_decision", { detail: JSON.stringify(msg.decision) }));
  });
})();
