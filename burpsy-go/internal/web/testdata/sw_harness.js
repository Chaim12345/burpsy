// Drives the REAL extension sw.js (materialised by the Go test) under Node with a mocked chrome API
// and Node's real fetch against a real burpsy server. This verifies the worker<->server protocol and
// sender-metadata binding. It is NOT a browser test: no Chrome, no content-script/MAIN-world behaviour.
const fs = require("fs"), path = require("path"), vm = require("vm");
const dir = process.env.BURPSY_EXT_DIR;
const listeners = [], deliveries = [];
const EXT = "ext-own-id";
const ctx = {
  console, setTimeout, clearTimeout, fetch, URL, Date, JSON, Promise,
  chrome: {
    runtime: { id: EXT, lastError: null, onMessage: { addListener: (f) => listeners.push(f) } },
    tabs: { sendMessage: (tab, msg, opts, cb) => { deliveries.push({ tab, frameId: opts.frameId, decision: msg.decision }); cb && cb(); } },
  },
};
ctx.self = ctx;
ctx.importScripts = (...files) => files.forEach((f) => vm.runInContext(fs.readFileSync(path.join(dir, f), "utf8"), ctx, { filename: f }));
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(dir, "sw.js"), "utf8"), ctx, { filename: "sw.js" });
const fire = (msg, sender) => listeners.forEach((l) => l(msg, sender));
const good = { id: EXT, tab: { id: 4 }, frameId: 7 };
(async () => {
  fire({ type: "burpsy-di-frame-open" }, good);
  // forged: wrong extension id, no tab (not a content script), payload-claimed tab/frame
  fire({ type: "burpsy-di-msg", msg: { body: '"wrong-id"' } }, { id: "other-ext", tab: { id: 4 }, frameId: 7 });
  fire({ type: "burpsy-di-msg", msg: { body: '"no-tab"' } }, { id: EXT });
  fire({ type: "burpsy-di-msg", tab: 99, frame: "0", msg: { body: '"payload-claims-frame"', state: "held", hold_id: "forged", tab: 99, frame: "0" } }, good);
  const t0 = Date.now();
  while (Date.now() - t0 < 15000 && deliveries.length < 1) await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => setTimeout(r, 800));
  console.log(JSON.stringify({ deliveries, capabilityOnPageGlobals: typeof ctx.__burpsyDI_workerCapability }));
  process.exit(0);
})();
