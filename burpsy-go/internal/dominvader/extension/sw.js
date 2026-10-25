// Service worker (burpsy-react-ui-wl94, k13f): the one hop with a fetch that is not bound by the page's
// mixed-content policy, so it is where a hit on an https page reaches burpsy's http loopback API.
//
// burpsy bypasses its own web host in the browser's proxy settings (see internal/browser), so this
// POST is a direct loopback request and never appears in HTTP history or loops back through the
// proxy it is meant to observe.
//
// TRUST: the worker derives tab and frame ONLY from chrome.runtime sender metadata of this extension's
// own content scripts, never from a message payload. The per-launch capability lives only in
// worker-config.js (not web-accessible, not in MAIN-world config). A compromised worker, or MAIN-world
// code that tampers with the page side, is NOT defended against; observations are never trusted proof.
importScripts("config.js");
try { importScripts("worker-config.js"); } catch (e) {}

var cfg = self.__burpsyDI_config || {};
var capability = self.__burpsyDI_workerCapability || "";
var DECISION_POLL_MS = 250;
var DECISION_WAIT_MS = 35000;

function origin() {
  try { return new URL(cfg.report).origin; } catch (e) { return ""; }
}

function post(path, body) {
  return fetch(origin() + path, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Burpsy-DOM-Worker": capability },
    body: JSON.stringify(body)
  }).then(function (r) {
    if (!r.ok) { var err = new Error("status " + r.status); err.status = r.status; throw err; }
    return r.json();
  });
}

// Sender metadata is the only source of tab/frame. A sender that is not one of this extension's own
// content scripts in a tab frame is refused.
function senderFrame(sender) {
  if (!sender || sender.id !== chrome.runtime.id || !sender.tab || typeof sender.tab.id !== "number" ||
      typeof sender.frameId !== "number") return null;
  return { tab: sender.tab.id, frame: String(sender.frameId), key: sender.tab.id + ":" + sender.frameId };
}

// Per-document server-issued frame tokens. Held in worker memory only; a worker restart simply
// re-registers on the next frame-open or after a refused report.
var tokens = {};

function register(f) {
  return post("/api/dominvader/messages/register", { tab: f.tab, frame: f.frame }).then(function (r) {
    tokens[f.key] = r.frame_token;
    return r.frame_token;
  });
}

function deliver(f, decision) {
  return new Promise(function (resolve) {
    try {
      chrome.tabs.sendMessage(f.tab, { type: "burpsy-di-decision", decision: decision }, { frameId: Number(f.frame) }, function () {
        resolve(!chrome.runtime.lastError);
      });
    } catch (e) { resolve(false); }
  });
}

function awaitDecision(f, token, holdId) {
  var deadline = Date.now() + DECISION_WAIT_MS;
  function step() {
    if (Date.now() > deadline) return Promise.resolve();
    return post("/api/dominvader/messages/poll", { frame_token: token }).then(function (list) {
      var mine = (list || []).filter(function (d) { return d.hold_id === holdId; });
      if (mine.length === 0) return new Promise(function (r) { setTimeout(r, DECISION_POLL_MS); }).then(step);
      return deliver(f, mine[0]).then(function (ok) {
        return post("/api/dominvader/messages/ack", { frame_token: token, hold_id: holdId, outcome: ok ? "dispatched" : "failed" });
      });
    });
  }
  return step();
}

function report(f, m, retried) {
  var token = tokens[f.key];
  var ensure = token ? Promise.resolve(token) : register(f);
  return ensure.then(function (t) {
    // State/hold fields are never sent: the server decides them.
    return post("/api/dominvader/messages/report", {
      frame_token: t,
      message: { body: m.body, origin: m.origin || "", has_ports: !!m.hasPorts }
    }).then(function (rec) {
      if (rec && rec.state === "held" && rec.hold_id) return awaitDecision(f, t, rec.hold_id);
    });
  }).catch(function (e) {
    if (!retried && e && e.status === 400) { delete tokens[f.key]; return report(f, m, true); }
  });
}

chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (!msg) return;
  if (msg.type === "burpsy-di-hit") {
    if (!cfg.report) return;
    try {
      fetch(cfg.report, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(msg.hit)
      }).catch(function () {});
    } catch (e) {}
    return;
  }
  if (!cfg.enabled || !capability || !origin()) return;
  var f = senderFrame(sender);
  if (!f) return;
  if (msg.type === "burpsy-di-frame-open") {
    delete tokens[f.key];
    register(f).catch(function () {});
  } else if (msg.type === "burpsy-di-msg" && msg.msg && typeof msg.msg.body === "string") {
    report(f, msg.msg, false);
  }
});
