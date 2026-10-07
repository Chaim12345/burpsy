// ISOLATED-world relay (burpsy-react-ui-wl94).
//
// The MAIN-world instrumentation cannot reach the extension's messaging (it runs in the page's own
// world), and a content script cannot fetch an http:// origin from an https page without tripping
// mixed-content. So the flow is three hops: MAIN dispatches a DOM event, this relay (which does have
// chrome.runtime) forwards it to the service worker, and the worker — whose fetch is not subject to
// the page's mixed-content rules — posts it to burpsy. This file carries no config; the worker holds
// the report URL.
(function () {
  "use strict";
  document.addEventListener("__burpsyDI_hit", function (ev) {
    try {
      var hit = JSON.parse(ev.detail);
      chrome.runtime.sendMessage({ type: "burpsy-di-hit", hit: hit });
    } catch (e) {}
  }, true);
})();
