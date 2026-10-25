// Probe-only instrumentation. The operator browser remains untouched unless a
// dedicated, scope-fenced context supplies a fresh per-probe configuration.
(function () {
  "use strict";
  var p = window.__burpsyDI_probe;
  if (!p || !p.marker || !p.proof || !p.property) return;
  var sourceReported = false;
  function proven() {
    return Object.prototype.hasOwnProperty.call(Object.prototype, p.proof) &&
      Object.prototype[p.proof] === p.marker;
  }
  function emit(kind, sink, value) {
    var h = {kind: kind, sink: sink, sources: [p.technique], excerpt: String(value).slice(0, 240),
      stack: (new Error()).stack || "", url: location.href,
      frame: window.top === window ? "top" : "iframe", ts: Date.now(),
      property: p.property, technique: p.technique, probe: p.marker};
    document.dispatchEvent(new CustomEvent("__burpsyDI_hit", {detail: JSON.stringify(h)}));
  }
  function checkSource() {
    if (!proven()) return false;
    if (!sourceReported) {
      sourceReported = true;
      emit("pollution-source", "Object.prototype." + p.proof, p.marker);
    }
    return true;
  }
  function observe(sink, value) {
    if (String(value).indexOf(p.marker) < 0 || !checkSource()) return;
    emit("pollution-gadget", sink, value);
  }
  function setter(type, prop, sink) {
    if (!type) return;
    var orig = Object.getOwnPropertyDescriptor(type.prototype, prop);
    if (!orig || !orig.set) return;
    Object.defineProperty(type.prototype, prop, {configurable: true, enumerable: orig.enumerable,
      get: orig.get, set: function (v) { observe(sink, v); return orig.set.call(this, v); }});
  }
  function method(obj, name, sink, index) {
    if (!obj || typeof obj[name] !== "function") return;
    var orig = obj[name];
    obj[name] = function () { observe(sink, arguments[index]); return orig.apply(this, arguments); };
  }
  setter(window.Element, "innerHTML", "innerHTML");
  setter(window.Element, "outerHTML", "outerHTML");
  setter(window.HTMLScriptElement, "src", "script-src");
  method(window, "eval", "eval", 0);
  method(window, "setTimeout", "settimeout-string", 0);
  method(window.Document && Document.prototype, "write", "document-write", 0);
  method(window, "fetch", "fetch", 0);
  // JSON mode changes only the input the page itself parses. It does not pollute
  // Object.prototype directly: only an unsafe downstream merge can prove a source.
  if (p.technique === "json") {
    var parse = JSON.parse;
    JSON.parse = function (text, reviver) {
      var obj = parse.call(this, text, reviver);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        var payload = {}; payload[p.proof] = p.marker; payload[p.property] = p.marker;
        Object.defineProperty(obj, "__proto__", {value: payload, enumerable: true, configurable: true});
        if (p.nested) Object.defineProperty(obj, "constructor", {value: {prototype: payload}, enumerable: true, configurable: true});
      }
      return obj;
    };
  }
  if (document.readyState !== "loading") checkSource();
  document.addEventListener("DOMContentLoaded", checkSource, true);
  window.__burpsyDI_checkPollution = checkSource;
})();
