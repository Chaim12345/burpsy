// /ui2/app.js — the entire client-side behaviour of the server-rendered console.
// No framework beyond htmx itself; this file is plain JS so the html/template parser
// never has to see inside it.

// Live refresh: /api/events frames carry {"kind":"history"|"issues",...}; on a change for
// the open view, re-issue the current filter form into the rows target. The SSE ext fires
// htmx:sseMessage events; translated here.
document.body.addEventListener('htmx:sseMessage', function (e) {
  var kind = '';
  try { kind = JSON.parse(e.detail.data).kind || ''; } catch (_) { /* ignore non-JSON frames */ }
  if (kind === 'ping' || kind === 'hello') return;
  var view = document.querySelector('header nav a.active');
  var want = (view && view.textContent.trim() === 'History') ? 'history' : 'issues';
  if (kind === want) {
    var form = document.querySelector('header form');
    if (form) { htmx.trigger(form, 'submit'); }
    else { htmx.ajax('GET', '/ui2/' + want, { target: '#rows', swap: 'outerHTML' }); }
  }
});

// After any swap into the rows, keep only the NEWEST sentinel: older sentinel rows from
// earlier pages must not fire 'revealed' and re-fetch a stale offset.
document.body.addEventListener('htmx:afterSwap', function (e) {
  if (!e.detail.target || e.detail.target.id !== 'rows-body') return;
  var sentinels = document.querySelectorAll('.sentinel-row');
  for (var i = 0; i < sentinels.length - 1; i++) sentinels[i].remove();
});

// Row click: mark the selected row so the detail pane and the list agree.
document.body.addEventListener('click', function (e) {
  var tr = e.target.closest && e.target.closest('#rows-body tr[hx-get]');
  if (!tr) return;
  document.querySelectorAll('#rows-body tr.selected').forEach(function (r) { r.classList.remove('selected'); });
  tr.classList.add('selected');
});
// ---- Theme (persisted, prefers-color-scheme default) ----
(function () {
  var KEY = 'burpsy.ui2.theme';
  var apply = function (t) {
    document.documentElement.dataset.theme = t;
    var b = document.getElementById('theme-toggle');
    if (b) b.textContent = t === 'dark' ? '☀' : '◐';
  };
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (_) {}
  apply(saved || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'theme-toggle') {
      var next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem(KEY, next); } catch (_) {}
      apply(next);
    }
  });
})();

// ---- Keyboard shortcuts (alt+1..0 tools, alt+T intercept, ? shortcuts) ----
(function () {
  var TOOLS = ['dashboard', 'sitemap', 'scope', 'scanner', 'issues', 'intercept', 'history', 'ws', 'proxy', 'settings'];
  var HELP = [
    'alt+1..0 — switch tool (1=dashboard … 0=settings)',
    'alt+T — toggle interception',
    'j/k or ↑/↓ — move row selection, Enter — open detail',
    'mod+A (in table) — select all rows',
    '? — this list'
  ];
  var sel = -1;
  function rows() { return Array.prototype.slice.call(document.querySelectorAll('#rows-body tr[hx-get]')); }
  function move(d) {
    var r = rows(); if (!r.length) return;
    sel = Math.max(0, Math.min(r.length - 1, sel + d));
    r.forEach(function (x, i) { x.classList.toggle('selected', i === sel); });
    r[sel].scrollIntoView({ block: 'nearest' });
  }
  function openSelected() {
    var r = rows(); if (sel >= 0 && r[sel]) r[sel].dispatchEvent(new MouseEvent('click', { bubbles: true }));
  }
  document.addEventListener('keydown', function (e) {
    if (e.target && /^(input|textarea|select)$/i.test(e.target.tagName)) return;
    if (e.altKey && !e.ctrlKey && !e.metaKey && /^[0-9]$/.test(e.key)) {
      var i = e.key === '0' ? 9 : parseInt(e.key, 10) - 1;
      if (TOOLS[i]) { location.href = '/ui2/' + TOOLS[i]; e.preventDefault(); }
      return;
    }
    if (e.altKey && e.key.toLowerCase() === 't') {
      var on = document.querySelector('#rows .meta');
      var enable = on && /interception OFF/.test(on.textContent);
      fetch('/ui2/intercept/' + (enable ? 'enable' : 'disable'), { method: 'POST' }).then(function () {
        htmx.ajax('GET', '/ui2/intercept', { target: '#rows', swap: 'outerHTML' });
      });
      e.preventDefault(); return;
    }
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) { alert(HELP.join('\n')); e.preventDefault(); return; }
    if ((e.key === 'j' || e.key === 'ArrowDown') && !e.ctrlKey && !e.metaKey) { move(1); e.preventDefault(); return; }
    if ((e.key === 'k' || e.key === 'ArrowUp') && !e.ctrlKey && !e.metaKey) { move(-1); e.preventDefault(); return; }
    if (e.key === 'Enter') { openSelected(); e.preventDefault(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && document.querySelector('#rows-body')) {
      document.querySelectorAll('#rows-body tr[hx-get]').forEach(function (r) { r.classList.add('checked'); });
      e.preventDefault();
    }
  });
})();

// ---- Row multi-select (checkbox column driven by .checked class) ----
(function () {
  function count() {
    var n = document.querySelectorAll('#rows-body tr.checked').length;
    var el = document.getElementById('sel-count');
    if (el) el.textContent = n ? n + ' selected' : '';
  }
  document.addEventListener('click', function (e) {
    var tr = e.target.closest && e.target.closest('#rows-body tr[hx-get]');
    if (tr && (e.shiftKey || e.target.classList.contains('selbox'))) { tr.classList.toggle('checked'); count(); e.preventDefault(); }
  });
  document.body.addEventListener('htmx:afterSwap', function () { count(); });
})();
