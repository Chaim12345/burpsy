// Service worker (burpsy-react-ui-wl94): the one hop with a fetch that is not bound by the page's
// mixed-content policy, so it is where a hit on an https page reaches burpsy's http loopback API.
//
// burpsy bypasses its own web host in the browser's proxy settings (see internal/browser), so this
// POST is a direct loopback request and never appears in HTTP history or loops back through the
// proxy it is meant to observe.
importScripts("config.js");

var cfg = self.__burpsyDI_config || {};

chrome.runtime.onMessage.addListener(function (msg) {
  if (!msg || msg.type !== "burpsy-di-hit" || !cfg.report) return;
  try {
    fetch(cfg.report, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(msg.hit)
    }).catch(function () {});
  } catch (e) {}
});
