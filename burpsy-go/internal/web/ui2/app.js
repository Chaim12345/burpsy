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
