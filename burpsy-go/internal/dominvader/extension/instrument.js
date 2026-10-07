// MAIN-world DOM taint instrumentation (burpsy-react-ui-wl94).
//
// Runs in the page's own JavaScript world at document_start, so it wraps sinks before the page's
// scripts run. It watches the operator's canary: where it enters the page (sources) and every sink
// it reaches at runtime. A hit is dispatched as a DOM CustomEvent, which the ISOLATED-world relay
// (relay.js) forwards to the extension's service worker and on to burpsy — the two worlds share the
// DOM but not their globals, so an event on `document` is the one channel between them.
//
// The sink list is deliberately the same vocabulary burpsy's scanner-side analyser uses
// (internal/domexec/taint.go sinkTags); the operator and the scanner then speak of the same sinks.
(function () {
  "use strict";
  var cfg = window.__burpsyDI_config;
  if (!cfg || !cfg.enabled || !cfg.canary) return;
  var CANARY = String(cfg.canary);

  // A short, non-reversible identity for one hit, so the relay and burpsy can drop the duplicates a
  // busy page produces (the same sink hit on every keystroke) without carrying the value that made
  // them. Not the canary and not the whole argument — just enough to collapse repeats.
  function dedupe(sink, arg, stack) {
    var s = sink + "|" + arg.length + "|" + (stack || "").slice(0, 120);
    var h = 0;
    for (var i = 0; i < s.length; i++) {
      h = (h * 31 + s.charCodeAt(i)) | 0;
    }
    return String(h);
  }

  // Which of the browser-readable sources currently carry the canary. This is the source->sink story
  // DOM Invader tells: not a byte-exact taint trace, but "the canary is in these places, and it
  // reached this sink". postMessage is added dynamically when a message carrying the canary arrives.
  var pmCarried = false;
  function sourcesCarrying() {
    var out = [];
    try { if (String(location.hash).indexOf(CANARY) >= 0) out.push("location.hash"); } catch (e) {}
    try { if (String(location.search).indexOf(CANARY) >= 0) out.push("location.search"); } catch (e) {}
    try { if (String(location.href).indexOf(CANARY) >= 0 && out.indexOf("location.hash") < 0 && out.indexOf("location.search") < 0) out.push("location.href"); } catch (e) {}
    try { if (String(document.referrer).indexOf(CANARY) >= 0) out.push("document.referrer"); } catch (e) {}
    try { if (String(window.name).indexOf(CANARY) >= 0) out.push("window.name"); } catch (e) {}
    if (pmCarried) out.push("postMessage");
    return out;
  }

  function excerpt(v) {
    var s;
    try { s = String(v); } catch (e) { return "[unstringable]"; }
    // Keep the context around the canary so the operator sees how it was framed, bounded so a whole
    // document written to innerHTML is not shipped back.
    var at = s.indexOf(CANARY);
    if (at < 0) return s.slice(0, 200);
    var start = Math.max(0, at - 80);
    return (start > 0 ? "..." : "") + s.slice(start, at + CANARY.length + 80);
  }

  function report(kind, sink, value) {
    var arg = "";
    try { arg = String(value); } catch (e) { return; }
    if (arg.indexOf(CANARY) < 0) return;
    var stack = "";
    try { stack = (new Error()).stack || ""; } catch (e) {}
    var hit = {
      kind: kind,
      sink: sink,
      sources: sourcesCarrying(),
      excerpt: excerpt(arg),
      stack: stack,
      url: location.href,
      frame: (window.top === window) ? "top" : "iframe",
      dedupe: dedupe(sink, arg, stack),
      ts: Date.now()
    };
    try {
      document.dispatchEvent(new CustomEvent("__burpsyDI_hit", { detail: JSON.stringify(hit) }));
    } catch (e) {}
  }

  // --- sink wrappers (same vocabulary as domexec) --------------------------------------------------
  function wrapMethod(obj, name, sink, argIndex) {
    try {
      var orig = obj[name];
      if (typeof orig !== "function") return;
      obj[name] = function () {
        try { report("sink", sink, arguments[argIndex]); } catch (e) {}
        return orig.apply(this, arguments);
      };
    } catch (e) {}
  }
  function wrapSetter(proto, prop, sink) {
    try {
      var orig = Object.getOwnPropertyDescriptor(proto, prop);
      if (!orig || !orig.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: orig.enumerable,
        get: orig.get,
        set: function (v) {
          try { report("sink", sink, v); } catch (e) {}
          return orig.set.call(this, v);
        }
      });
    } catch (e) {}
  }

  wrapMethod(window, "eval", "eval", 0);
  try {
    var OrigFunction = window.Function;
    var wrappedFunction = function () {
      try { report("sink", "function-ctor", Array.prototype.join.call(arguments, ",")); } catch (e) {}
      return OrigFunction.apply(this, arguments);
    };
    wrappedFunction.prototype = OrigFunction.prototype;
    window.Function = wrappedFunction;
  } catch (e) {}
  wrapMethod(window, "setTimeout", "settimeout-string", 0);
  wrapMethod(Document.prototype, "write", "document-write", 0);
  wrapSetter(Element.prototype, "innerHTML", "innerHTML");
  wrapSetter(Element.prototype, "outerHTML", "outerHTML");
  wrapSetter(HTMLScriptElement.prototype, "src", "script-src");
  wrapSetter(HTMLAnchorElement.prototype, "href", "anchor-href");
  wrapMethod(Document.prototype, "evaluate", "document-evaluate", 0);
  try { wrapMethod(JSON, "parse", "json-parse", 0); } catch (e) {}
  wrapMethod(window, "postMessage", "postmessage", 0);
  wrapMethod(XMLHttpRequest.prototype, "open", "xhr-open", 1);
  wrapSetter(Document.prototype, "cookie", "cookie");
  try {
    var origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      try {
        var sink = (this === window.localStorage) ? "localStorage" : (this === window.sessionStorage ? "sessionStorage" : "localStorage");
        report("sink", sink, value);
      } catch (e) {}
      return origSetItem.call(this, key, value);
    };
  } catch (e) {}

  // --- sources ------------------------------------------------------------------------------------
  // A source observation on its own is worth reporting: it tells the operator the canary reached the
  // page even before any script touched it, and it is how DOM Invader shows "carried by" with no sink.
  function noteSource(which, value) {
    try {
      if (String(value).indexOf(CANARY) < 0) return;
    } catch (e) { return; }
    report("source", which, value);
  }
  try { noteSource("location.hash", location.hash); } catch (e) {}
  try { noteSource("location.search", location.search); } catch (e) {}
  try { noteSource("document.referrer", document.referrer); } catch (e) {}
  try { noteSource("window.name", window.name); } catch (e) {}
  window.addEventListener("message", function (ev) {
    try {
      var data = typeof ev.data === "string" ? ev.data : JSON.stringify(ev.data);
      if (data.indexOf(CANARY) >= 0) {
        pmCarried = true;
        report("source", "postMessage", data);
      }
    } catch (e) {}
  }, true);
})();
