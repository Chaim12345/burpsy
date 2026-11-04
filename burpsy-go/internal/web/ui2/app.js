// /ui2/app.js — the entire client-side behaviour of the server-rendered console.
// No framework beyond htmx itself; this file is plain JS so the html/template parser
// never has to see inside it.

// Live event stream: ONE EventSource per page, dispatching the server's coarse change
// frames to the view on screen. /api/events frames are unnamed "message" events and the
// vendored sse extension only fires for event types named in sse-swap, so this is the
// only consumer of the stream - the layout no longer wires the extension, and one
// connection serves every consumer below.
//
// A frame is {"kind": ...} and says "this kind changed", never what. Consumers:
//  - the crawl-watch view (on any page): history + dashboard frames re-fetch its
//    fragment (a working crawl produces both, including the dashboard frame the crawl
//    goroutine sends when the run ends);
//  - the History view: history frames re-fetch the rows with the operator's current
//    filter values (the filter form lives in the header, outside #rows, so filter text
//    and focus survive every swap);
//  - the Issues view: issues frames re-fetch its rows.
//  - the Intercept view: intercept frames re-fetch the queue and switch state.
//  - the Logger view: toollog frames re-fetch its rows, carrying the current search.
//  - the WebSockets view: ws frames re-fetch its connections and frames tables.
// Refresh discipline: one refresh in flight, one armed trailing refresh, so a
// saturated capture cannot build a backlog and two responses can never render out of
// order. Every operator-initiated request bumps a generation; a live answer from an
// older generation is dropped before it swaps, so a live refresh can never overwrite a
// newer operator action. List views auto-refresh only at their top - scrolled-down
// operators get a pill they can refresh or dismiss, so scroll position and loaded
// older pages are never taken away. Selection is re-marked by row id after a swap; the
// detail pane lives outside #rows and is untouched. On Intercept and Logger an open
// held-message editor or any unsaved field edit inside #rows also arms the pill, and
// a manual refresh re-applies those edits across the swap instead of discarding them.
// The same capture-and-re-apply covers successful operator swaps on those views, so
// forwarding one held message no longer wipes an unsaved edit in another; the submitted
// item's own draft is never resurrected, because its form is gone from the new fragment.
// The stream and all of this state
// die with the page; nothing is submitted and no mutating request is ever retried.
var liveES = null, liveBusy = false, liveTrailing = '', liveGen = 0, livePillCount = 0,
    liveOpFlight = 0, liveDirtySaved = null;

function liveTag(e) {
  var h = e.detail && e.detail.requestConfig && e.detail.requestConfig.headers;
  return h && h['X-Live-Refresh'] ? String(h['X-Live-Refresh']) : '';
}

function liveStream() {
  if (liveES) return;
  liveES = new EventSource('/api/events');
  liveES.onmessage = function (e) {
    var kind = '';
    try { kind = JSON.parse(e.data).kind || ''; } catch (_) { return; }
    if (kind === 'ping' || kind === 'hello') return;
    var view = (document.body.dataset || {}).view || '';
    if (document.getElementById('crawlwatch') && (kind === 'history' || kind === 'dashboard')) {
      liveRefresh('crawlwatch');
    } else if (view === 'history' && kind === 'history') {
      liveRefresh('history');
    } else if (view === 'issues' && kind === 'issues') {
      liveRefresh('issues');
    } else if (view === 'intercept' && kind === 'intercept') {
      liveRefresh('intercept');
    } else if (view === 'logger' && kind === 'toollog') {
      liveRefresh('logger');
    } else if (view === 'ws' && kind === 'ws') {
      liveRefresh('ws');
    } else if (view === 'organizer' && kind === 'organizer') {
      liveRefresh('organizer');
    } else if (view === 'proxy' && kind === 'proxy') {
      liveRefresh('proxy');
    } else if (view === 'session' && kind === 'session') {
      // Pending browser-recovery prompts announce on register, resolve and expiry. The page is
      // NOT read-only any more (rules editing): liveGuarded covers focused/dirty fields and an
      // open edit box, and the session branch below holds the refresh for a pending review
      // sheet or a rendered outcome note - the pill announces the update instead of erasing
      // the operator's state.
      liveRefresh('session');
    } else if (view === 'sequencer' && kind === 'dashboard') {
      // Captures announce their lifecycle (started/finished) through the task registry's
      // dashboard kind; per-token ticks deliberately stay silent - one event per token
      // would flood the stream. The start form is real operator state, so a focused or
      // dirty field falls back to the pill like the other form pages.
      liveRefresh('sequencer');
    } else if (view === 'scope' && kind === 'scope') {
      // Scope edits from any surface announce; the page's add-rule and library forms are real
      // operator state, so a focused or dirty field falls back to the pill like intercept/logger.
      liveRefresh('scope');
    } else if (view === 'dashboard' && (kind === 'dashboard' || kind === 'history' || kind === 'toollog' || kind === 'issues')) {
      // The dashboard is four feeds on one page: the event feed and task table ride
      // dashboard, the counters line rides history, the activity table rides toollog, and
      // the Coverage table's finding rows (Issues, Passive checks, Live audit) ride issues.
      liveRefresh('dashboard');
    }
  };
}
liveStream();

// The list scrolls inside main (split view: #list), never the window - measure that
// element, or the pill rule would never engage.
function liveScrolled() {
  var el = document.querySelector('main.split #list') || document.querySelector('main');
  return el ? el.scrollTop >= 150 : false;
}

// Unsaved edits inside #rows: any field whose current state differs from the state the
// server rendered. value/defaultValue and checked/defaultChecked comparisons catch a
// blurred field and a closed held-message editor, which a focus check alone would miss.
// Each dirty field is keyed by its form's hx-post action plus its name (and its value
// for checkboxes, which share a name), so it can be re-applied after a manual refresh.
function liveDirtyFields(rows) {
  var out = [];
  var fields = rows.querySelectorAll('input, textarea, select');
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    var t = (f.type || '').toLowerCase();
    if (t === 'hidden' || t === 'submit' || t === 'button') continue;
    // A password field's typed value is never carried across a swap: dirty capture + re-apply
    // would keep the secret alive in page state after the sheet that asked for it is gone
    // (triage settings' API key), and re-applying it could silently repopulate a DIFFERENT
    // password field the swap rendered. The operator retypes secrets on the sheet that wants
    // them - exactly once.
    if (t === 'password') continue;
    var checkable = t === 'checkbox' || t === 'radio';
    var isSelect = f.tagName === 'SELECT';
    // A select has no defaultValue: its rendered state lives on the options. And when NO option
    // carries the selected attribute, the browser's default is the first option - comparing
    // selected against defaultSelected alone would read that untouched select as dirty forever,
    // which is exactly how the Scope page's kind picker rendered before this case existed.
    if (isSelect ? (function () {
        var anyDefault = Array.prototype.some.call(f.options, function (o) { return o.defaultSelected; });
        // Untouched defaults differ by arity: a single-select with no selected attribute defaults
        // to its FIRST option; a multiple-select defaults to NOTHING selected.
        if (!anyDefault) {
          if (f.multiple) return !Array.prototype.some.call(f.options, function (o) { return o.selected; });
          return f.options.length === 0 || f.options[0].selected;
        }
        return !Array.prototype.some.call(f.options, function (o) { return o.selected !== o.defaultSelected; });
      })()
        : checkable ? f.checked === f.defaultChecked : f.value === f.defaultValue) continue;
    var form = f.closest('form');
    out.push({
      form: form ? (form.getAttribute('hx-post') || form.getAttribute('action') || '') : '',
      name: f.name, fvalue: f.value, checked: f.checked, checkable: checkable
    });
  }
  return out;
}

// Re-apply captured dirty fields after a #rows swap: the same field in the new fragment
// gets the operator's unsaved value back; a field that no longer exists (a held item
// that was forwarded or dropped) is left alone.
function liveReapplyDirty(saved) {
  var rows = document.getElementById('rows');
  if (!rows || !saved) return;
  for (var i = 0; i < saved.length; i++) {
    var d = saved[i];
    var forms = rows.querySelectorAll('form');
    for (var j = 0; j < forms.length; j++) {
      var action = forms[j].getAttribute('hx-post') || forms[j].getAttribute('action') || '';
      if (action !== d.form) continue;
      var cand = forms[j].querySelectorAll('[name="' + d.name + '"]');
      for (var k = 0; k < cand.length; k++) {
        if (d.checkable) { if (cand[k].value === d.fvalue) cand[k].checked = d.checked; }
        else { cand[k].value = d.fvalue; }
      }
    }
  }
}

// A swap must never take away something the operator is doing: scrolled position and
// loaded older pages, an open held-message editor on Intercept, a focused field, or any
// unsaved edit inside #rows (the Logger capture filter lives there). Any of those arms
// the pill instead of refreshing; the pill's own refresh re-applies the edits it crosses.
function liveGuarded(what) {
  if (liveScrolled()) return true;
  if (what === 'intercept' || what === 'logger' || what === 'scope' || what === 'sequencer' || what === 'session' || what === 'organizer' || what === 'dashboard') {
    var rows = document.getElementById(what === 'scope' ? 'srows' : 'rows');
    if (!rows) return false;
    if (rows.querySelector('details.held-editor[open], details.scope-edit[open], details.collection-edit[open]')) return true;
    var ae = document.activeElement;
    if (ae && rows.contains(ae) && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName)) return true;
    if (liveDirtyFields(rows).length) return true;
    if (what === 'organizer') {
      if (rows.dataset.review === '1' || rows.querySelector('#organizer-note')) return true;
    }
    if (what === 'session') {
      // Operator state beyond form fields: a pending review sheet (its one-time token exists
      // only in this DOM - a swap strands the review) and a rendered outcome note. Both hold
      // the refresh to the pill until the operator asks for it.
      if (rows.dataset.review === '1') return true;
      if (rows.querySelector('#session-note')) return true;
    }
    if (what === 'dashboard') {
      // A pending review sheet (live audit, clear event log) holds its one-time token only in
      // this DOM, and the outcome note is the record of what a button just did: the pill
      // announces the update instead of erasing either.
      if (rows.dataset.review === '1') return true;
      if (rows.querySelector('#dash-note')) return true;
      if (rows.querySelector('details#dash-new-live[open]')) return true;
    }
    if (what === 'scope') {
      // The scope review sheet is the same stranded-token state as the session one (its
      // content-bound digests also exist only in this DOM), and the outcome note is the
      // record of what a load or save just did - a refresh must not erase either mid-read.
      if (rows.dataset.review === '1') return true;
      if (rows.querySelector('#scope-note')) return true;
    }
  }
  return false;
}

function liveRefresh(what) {
  // "Follow new rows": history is newest-first, so following means jumping to the top.
  if (what === 'history') {
    var fol = document.getElementById('hfollow');
    var lst = document.querySelector('main.split #list');
    if (fol && fol.checked && lst) lst.scrollTop = 0;
  }
  if (what !== 'crawlwatch' && liveGuarded(what)) { livePillShow(what); return; }
  if (liveBusy || liveOpFlight > 0) { liveTrailing = what; return; }
  liveIssue(what);
}

function liveIssue(what) {
  var url = '', target = '';
  if (what === 'crawlwatch') {
    var cw = document.getElementById('crawlwatch');
    if (!cw || !cw.dataset.task) return;
    url = '/ui2/scanner/crawl-watch?task=' + encodeURIComponent(cw.dataset.task);
    target = '#crawlwatch';
  } else if (what === 'history') {
    // The header query/search and the toolbar filters together are the view's state.
    var hp = histParams().toString();
    url = '/ui2/history' + (hp ? '?' + hp : '');
    target = '#rows';
  } else if (what === 'issues') {
    url = '/ui2/issues';
    target = '#rows';
  } else if (what === 'intercept') {
    url = '/ui2/intercept';
    target = '#rows';
  } else if (what === 'logger') {
    var carried = document.querySelector('#rows input[name="search"]');
    url = '/ui2/logger' + (carried && carried.value ? '?search=' + encodeURIComponent(carried.value) : '');
    target = '#rows';
  } else if (what === 'ws') {
    url = '/ui2/ws';
    target = '#rows';
  } else if (what === 'organizer') {
    url = '/ui2/organizer';
    target = '#rows';
  } else if (what === 'proxy') {
    url = '/ui2/proxy';
    target = '#rows';
  } else if (what === 'dashboard') {
    // The dashboard and a task's detail page share this view; each names its own refresh URL
    // (filter, tab and event-log filters included) in #dash-live, so a refresh keeps them.
    var dl = document.getElementById('dash-live');
    url = (dl && dl.getAttribute('data-live')) || '/ui2/dashboard';
    if (url.indexOf('/ui2/dashboard') !== 0) url = '/ui2/dashboard';
    target = '#rows';
  } else if (what === 'session') {
    url = '/ui2/session';
    target = '#rows';
  } else if (what === 'scope') {
    url = '/ui2/scope';
    target = '#srows';
  } else if (what === 'sequencer') {
    url = '/ui2/sequencer';
    target = '#rows';
  } else { return; }
  liveBusy = true;
  htmx.ajax('GET', url, { target: target, swap: 'outerHTML', headers: { 'X-Live-Refresh': what + ':' + liveGen } });
}

// An operator request bumps the generation and counts as in flight until its terminal
// event; live requests carry their generation in the tag and are answered only if it is
// still current. The in-flight count keeps a live refresh from being ISSUED while an
// operator request is outstanding - without it, a live answer read from before the
// operator's change could swap in after the operator's own fresher answer.
// Session add form: each action kind's fields live in a span.kind-fields that starts hidden
// with its controls disabled, so a plain form post carries only the chosen kind's fields (a
// disabled control is never submitted). Ticking a kind's radio shows its block and enables
// exactly its controls; the server still refuses a field that arrives for the wrong kind,
// because that post did not come from the form the operator saw. Delegated, because the form
// is swapped by htmx and listeners on it would not survive.
document.addEventListener('change', function (e) {
  var radio = e.target && e.target.closest ? e.target.closest('#session-rule-controls input[name="action"], .session-action-append input[name="action"]') : null;
  if (!radio || !radio.form) return;
  var spans = radio.form.querySelectorAll('.kind-fields');
  for (var i = 0; i < spans.length; i++) {
    var on = spans[i].getAttribute('data-kind') === radio.value;
    spans[i].hidden = !on;
    var ctrls = spans[i].querySelectorAll('input, select, textarea');
    for (var j = 0; j < ctrls.length; j++) ctrls[j].disabled = !on;
  }
});

document.body.addEventListener('htmx:beforeRequest', function (e) {
  if (!liveTag(e)) { liveGen++; liveOpFlight++; }
});

// Stale live answers are dropped before they can swap over a newer operator action.
document.body.addEventListener('htmx:beforeSwap', function (e) {
  var tag = liveTag(e);
  if (!tag) return;
  var gen = parseInt(tag.split(':')[1], 10);
  if (gen !== liveGen) { e.detail.shouldSwap = false; }
});

// Busy bookkeeping keys on the live tag in requestConfig, not on detail.target (which
// is not reliably an element on error events). Any terminal event of a live request
// frees the slot; a successful answer replays one armed trailing refresh, an error
// stands the follow down - the next frame re-arms it.
// htmx:targetError is deliberately NOT in this list: it fires before any send and its detail
// carries only the hx-target string - no requestConfig - so it can never be matched to a live
// request here. It is also unreachable from liveIssue, whose callers guard that their target
// exists before issuing; a live request that was never sent never set liveBusy either.
['htmx:afterRequest', 'htmx:responseError', 'htmx:sendError', 'htmx:timeout', 'htmx:abort'].forEach(function (name) {
  document.body.addEventListener(name, function (e) {
    var tag = liveTag(e);
    if (!tag) {
      // An operator request settled. htmx:targetError is NOT counted here on purpose:
      // it fires before any send, without a preceding beforeRequest, so counting it
      // would unpair the in-flight count. When the last operator request settles, a
      // refresh deferred behind it runs - its fetch reads state with the change in it.
      if (liveOpFlight > 0) liveOpFlight--;
      if (liveOpFlight === 0 && liveTrailing) {
        var w0 = liveTrailing;
        liveTrailing = '';
        liveRefresh(w0);
      }
      return;
    }
    liveBusy = false;
    if (name === 'htmx:afterRequest' && liveTrailing) {
      var w = liveTrailing;
      liveTrailing = '';
      liveRefresh(w);
    } else if (name !== 'htmx:afterRequest') {
      liveTrailing = '';
    }
  });
});

// Selection survives a live rows swap: re-mark the row by its exchange id.
// The views whose #rows carries operator-editable fields; on those, successful operator
// swaps get the same dirty capture as live ones.
function liveDirtyView() {
  var v = (document.body.dataset || {}).view || '';
  return v === 'intercept' || v === 'logger' || v === 'sequencer';
}

document.body.addEventListener('htmx:beforeSwap', function (e) {
  var tag = liveTag(e);
  if (!e.detail.target || e.detail.target.id !== 'rows') return;
  if (!tag && !liveDirtyView()) return;
  if (tag) {
    var sel = document.querySelector('#rows-body tr.selected');
    if (sel && sel.dataset.id) e.detail.target.dataset.liveReselect = sel.dataset.id;
  }
  // Captured at the last moment before replacement, so edits typed after the pill's
  // refresh was tapped are kept too. A no-op when the auto-refresh guard did its job.
  var rows = document.getElementById('rows');
  var captured = rows ? liveDirtyFields(rows) : [];
  // A transient sheet with no operator-editable fields at all (the Sequencer review
  // sheet sits between the start form and the list) captures nothing; keep the edits
  // from the form it replaced so the NEXT swap back still re-applies them.
  var hasEditable = rows && rows.querySelector('form input:not([type="hidden"]):not([type="submit"]):not([type="button"]), form textarea, form select');
  if (captured.length) liveDirtySaved = captured;
  else if (hasEditable) liveDirtySaved = null;
});
document.body.addEventListener('htmx:afterSwap', function (e) {
  var tag = liveTag(e);
  if (!e.detail.target || e.detail.target.id !== 'rows') return;
  // Operator-initiated swap (a click, never a live refresh): when the operator submitted from
  // mid-page, the browser keeps the scroll offset, and a fresh sheet SHORTER than the header
  // band then renders entirely behind the sticky header - a blank-looking page (film-caught:
  // the triage settings refusal hidden after a mid-page submit). Scroll up only in exactly
  // that case; long sheets keep the operator's scroll position, and live refreshes never move
  // it at all.
  // Session action reviews start at their named change, never underneath the sticky header.
  if (!tag && document.body.dataset.view === 'organizer' && document.querySelector('#rows[data-review]')) {
    window.scrollTo(0, 0);
    var organizerMain = document.querySelector('main');
    if (organizerMain) organizerMain.scrollTop = 0;
  }
  if (!tag && document.body.dataset.view === 'session' && document.querySelector('#rows[data-review]')) {
    window.scrollTo(0, 0);
    var sessionMain = document.querySelector('main');
    if (sessionMain) sessionMain.scrollTop = 0;
  }
  if (!tag && window.scrollY > 0) {
    var rowsEl = document.getElementById('rows');
    var headEl = document.querySelector('header');
    if (rowsEl && headEl) {
      var headBottom = headEl.getBoundingClientRect().bottom;
      if (rowsEl.getBoundingClientRect().top < headBottom && rowsEl.offsetHeight + headBottom < window.innerHeight) {
        window.scrollTo(0, 0);
      }
    }
  }
  if (!tag && !liveDirtyView()) return;
  if (tag) {
    var id = e.detail.target.dataset.liveReselect;
    if (id) {
      var tr = document.querySelector('#rows-body tr[data-id="' + id + '"]');
      if (tr) tr.classList.add('selected');
      delete e.detail.target.dataset.liveReselect;
    }
    livePillHide();
  }
  // A transient sheet with no editable fields (the Sequencer review sheet) applies
  // nothing; keep the saved edits for the swap that brings the form back instead of
  // dropping them here.
  var rows2 = document.getElementById('rows');
  var hasEditable2 = rows2 && rows2.querySelector('form input:not([type="hidden"]):not([type="submit"]):not([type="button"]), form textarea, form select');
  if (hasEditable2 || !liveDirtySaved) {
    liveReapplyDirty(liveDirtySaved);
    liveDirtySaved = null;
  }
});

// The pill: shown when frames arrive for a list the operator has scrolled into. Tap
// refresh to reload the first page (their choice), or dismiss.
function livePillShow(what) {
  livePillCount++;
  var p = document.getElementById('livepill');
  if (!p) {
    p = document.createElement('div');
    p.id = 'livepill';
    p.setAttribute('role', 'status');
    var label = document.createElement('span');
    label.id = 'livepill-label';
    var b = document.createElement('button');
    b.type = 'button';
    b.textContent = 'refresh';
    b.addEventListener('click', function () {
      var w = p.dataset.what;
      livePillHide();
      liveGen++;
      if (liveBusy || liveOpFlight > 0) { liveTrailing = w; } else { liveIssue(w); }
    });
    var x = document.createElement('button');
    x.type = 'button';
    x.textContent = 'dismiss';
    x.addEventListener('click', livePillHide);
    p.appendChild(label);
    p.appendChild(b);
    p.appendChild(x);
    document.body.appendChild(p);
  }
  p.dataset.what = what;
  livePillDock();
  var noun = what === 'issues' ? 'New findings' : what === 'intercept' ? 'Held traffic changed' : what === 'scope' ? 'Scope changed' : what === 'sequencer' ? 'Captures changed' : 'New traffic';
  document.getElementById('livepill-label').textContent = noun + ' (' + livePillCount + ') - the list stays put while you are scrolled or editing.';
}
// The scope rule editor docks as a bottom sheet on every viewport; a bottom pill would
// cover its fields, so while that sheet is open the pill docks to the top instead.
function livePillDock() {
  var p = document.getElementById('livepill');
  if (p) p.classList.toggle('livepill-top', !!document.querySelector('details.scope-edit[open], details.collection-edit[open]'));
}
// Opening or closing the scope editor while a pill is pending re-docks it: the toggle
// event does not bubble, so this listens in the capture phase.
document.addEventListener('toggle', livePillDock, true);
// A swap that replaces the scope fragment removes an open rule editor WITHOUT a toggle
// event - the node is discarded, not closed - which would leave a pending pill docked to
// the top over nothing. Re-evaluate the dock after every swap.
document.body.addEventListener('htmx:afterSwap', livePillDock);

function livePillHide() {
  var p = document.getElementById('livepill');
  if (p) p.remove();
  livePillCount = 0;
}

// Operator-facing request feedback: a header badge counts in-flight requests and a polite
// live region reports failures. Pairing follows htmx's own guarantees - beforeSend fires
// exactly once per issued request, afterRequest exactly once per finished one, whatever the
// outcome - so the counter cannot leak. Live refresh traffic is excluded: it is background
// read-only work the operator did not start, and its failures are re-armed by the next frame.
// Failure wording stays neutral: a lost or refused answer says nothing about whether the
// server applied a change, so the notice never claims nothing was applied, and nothing is
// retried automatically. The badge and notice live outside every swap target, so feedback
// never replaces gate-review content; the notice is written with textContent only.
var busyPending = 0;
function busyRender() {
  var b = document.getElementById('busybadge');
  if (!b) return;
  b.hidden = busyPending === 0;
  b.textContent = busyPending <= 1 ? 'working…' : 'working (' + busyPending + ')…';
}
function noticeSay(text) {
  var n = document.getElementById('notice');
  if (n) n.textContent = text;
}
function noticeClear() {
  var n = document.getElementById('notice');
  if (n) n.textContent = '';
}
document.body.addEventListener('htmx:beforeSend', function (e) {
  if (liveTag(e)) return;
  busyPending++;
  busyRender();
  noticeClear();
});
document.body.addEventListener('htmx:afterRequest', function (e) {
  if (liveTag(e)) return;
  if (busyPending > 0) busyPending--;
  busyRender();
});
['htmx:responseError', 'htmx:sendError', 'htmx:timeout', 'htmx:targetError'].forEach(function (name) {
  document.body.addEventListener(name, function (e) {
    if (liveTag(e)) return;
    // A sentinel whose fetch failed keeps its row. `intersect once` has already disconnected
    // its observer and htmx skips already-initialized elements, so re-arming means a fresh
    // clone on the NEXT user scroll (one retry per gesture, never a hot retry loop). The fired
    // flag comes off so a successful retry still cleans the row up.
    var tr = e.detail.elt && e.detail.elt.closest ? e.detail.elt.closest('.sentinel-row') : null;
    if (tr) {
      tr.removeAttribute('data-fired');
      tr.setAttribute('data-rearm', '1');
    }
    noticeSay("Couldn't confirm the result. Check the current state before retrying.");
  });
});

// A sentinel that fired is spent: its `intersect once` observer has disconnected, so it can
// never fetch again, and on the LAST page no newer sentinel arrives to supersede it - without
// removal it would sit at the end of the list reading "loading more..." forever.
document.body.addEventListener('htmx:beforeRequest', function (e) {
  var tr = e.detail.elt && e.detail.elt.closest ? e.detail.elt.closest('.sentinel-row') : null;
  if (tr) tr.setAttribute('data-fired', '1');
});
// Re-arm failed sentinels on the next user scroll of any pane (capture phase sees element
// scrolls, not just window scroll): clone the row so htmx initializes a fresh observer on it.
var rearmTimer = null;
document.addEventListener('scroll', function () {
  if (rearmTimer) return;
  rearmTimer = setTimeout(function () {
    rearmTimer = null;
    document.querySelectorAll('.sentinel-row[data-rearm]').forEach(function (tr) {
      tr.removeAttribute('data-rearm');
      var clone = tr.cloneNode(true);
      tr.replaceWith(clone);
      if (window.htmx) htmx.process(clone);
    });
  }, 300);
}, true);

// After any swap into the rows, keep only the NEWEST sentinel: older sentinel rows from
// earlier pages must not fire their lazy-load trigger and re-fetch a stale offset.
document.body.addEventListener('htmx:afterSwap', function (e) {
  if (!e.detail.target || e.detail.target.id !== 'rows-body') return;
  document.querySelectorAll('.sentinel-row[data-fired]').forEach(function (tr) { tr.remove(); });
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

// Scope edit panel: the close control only collapses the panel - typed values stay in the
// form, nothing is submitted or reset; tapping the row's "edit" summary reopens it as left.
document.addEventListener('click', function (e) {
  var b = e.target && e.target.closest && e.target.closest('.scope-edit-close');
  if (!b) return;
  var d = b.closest('details');
  if (d) d.removeAttribute('open');
});

// ---- Mobile nav (burger toggles the wrapped nav below 600px) ----
(function () {
  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'nav-burger') {
      var h = document.querySelector('header');
      var open = h.classList.toggle('nav-open');
      e.target.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
  });
})();
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
    'mod+K — command palette: every page and settings section, fuzzy filter, Enter opens, Esc closes',
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
      var st = document.getElementById('intercept-state');
      if (!st) { location.href = '/ui2/intercept'; e.preventDefault(); return; }
      fetch('/ui2/intercept/' + (st.dataset.on === 'true' ? 'disable' : 'enable'), { method: 'POST' }).then(function () {
        htmx.ajax('GET', '/ui2/intercept', { target: '#rows', swap: 'outerHTML' });
      });
      e.preventDefault(); return;
    }
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) { alert(HELP.join('\n')); e.preventDefault(); return; }
    if ((e.key === 'j' || e.key === 'ArrowDown') && !e.ctrlKey && !e.metaKey) { move(1); e.preventDefault(); return; }
    if ((e.key === 'k' || e.key === 'ArrowUp') && !e.ctrlKey && !e.metaKey) { move(-1); e.preventDefault(); return; }
    if (e.key === 'Enter') { openSelected(); e.preventDefault(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && document.querySelector('#rows-body')) {
      document.dispatchEvent(new CustomEvent('ui2:selectall'));
      e.preventDefault();
    }
  });
})();

// ---- Row multi-select (shift/ctrl/cmd-click or the row checkbox) ----
// The selection is a list of row ids kept here, so it survives live rows swaps and paging; the
// rows are re-marked after every swap. It feeds the History bulk-action forms (.hbulk-ids) and
// enables their buttons (data-needs-sel = minimum count). Nothing is ever submitted from here.
(function () {
  var sel = [];
  function sync() {
    document.querySelectorAll('#rows-body tr[data-id]').forEach(function (tr) {
      var on = sel.indexOf(tr.dataset.id) >= 0;
      tr.classList.toggle('checked', on);
      var b = tr.querySelector('.selbox');
      if (b) b.checked = on;
    });
    var el = document.getElementById('sel-count');
    if (el) el.textContent = sel.length ? sel.length + ' selected' : '';
    document.querySelectorAll('.hbulk-ids').forEach(function (i) { i.value = sel.join(','); });
    document.querySelectorAll('[data-needs-sel]').forEach(function (b) {
      b.disabled = sel.length < parseInt(b.getAttribute('data-needs-sel'), 10);
    });
  }
  function toggle(id, on) {
    var i = sel.indexOf(id);
    if (on && i < 0) sel.push(id);
    if (!on && i >= 0) sel.splice(i, 1);
  }
  document.addEventListener('click', function (e) {
    var tr = e.target.closest && e.target.closest('#rows-body tr[data-id]');
    if (!tr) return;
    if (e.target.classList.contains('selbox')) { toggle(tr.dataset.id, e.target.checked); sync(); return; }
    if (e.shiftKey || e.ctrlKey || e.metaKey) {
      toggle(tr.dataset.id, sel.indexOf(tr.dataset.id) < 0);
      sync();
      e.preventDefault();
    }
  });
  document.addEventListener('ui2:selectall', function () {
    document.querySelectorAll('#rows-body tr[data-id]').forEach(function (tr) { toggle(tr.dataset.id, true); });
    sync();
  });
  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'hsel-clear') { sel = []; sync(); }
  });
  // Deleted or cleared rows are gone: drop the selection with them.
  document.body.addEventListener('burpsy-history-changed', function () { sel = []; sync(); });
  document.body.addEventListener('htmx:afterSwap', sync);
  document.addEventListener('DOMContentLoaded', sync);
})();

// ---- History toolbar: view state, export link, columns, presets, follow, go-to ----
// histParams is the History view's state as query fields: the header query/search form plus the
// toolbar filter form. Live refresh, CSV export and presets all read it from here.
function histParams() {
  var out = new URLSearchParams();
  ['hq', 'hfilter'].forEach(function (id) {
    var f = document.getElementById(id);
    if (!f) return;
    new FormData(f).forEach(function (v, k) { if (v !== '') out.append(k, v); });
  });
  return out;
}
(function () {
  function store(key, val) {
    try {
      if (val === undefined) return JSON.parse(localStorage.getItem(key) || 'null');
      localStorage.setItem(key, JSON.stringify(val));
    } catch (_) { return null; }
    return null;
  }
  // Export: the link carries the view's current state at click time.
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('#hexport');
    if (!a) return;
    var hp = histParams().toString();
    a.setAttribute('href', '/ui2/history/export.csv' + (hp ? '?' + hp : ''));
  });
  // Column chooser: hidden column keys live in localStorage; #list (outside every swap)
  // carries one hc-<key> class per hidden column, matched by a generated style rule.
  var COLS = 'burpsy.ui2.history.hiddencols';
  function applyCols() {
    var boxes = document.querySelectorAll('[data-hcol]');
    var list = document.getElementById('list');
    if (!boxes.length || !list) return;
    var hidden = store(COLS);
    var css = '';
    boxes.forEach(function (b) {
      var key = String(b.getAttribute('data-hcol')).replace(/[^a-z0-9-]/g, '');
      var off = hidden ? hidden.indexOf(key) >= 0 : !b.hasAttribute('data-default');
      b.checked = !off;
      list.classList.toggle('hc-' + key, off);
      css += '#list.hc-' + key + ' .c-' + key + '{display:none}';
    });
    var st = document.getElementById('hcols-css');
    if (!st) { st = document.createElement('style'); st.id = 'hcols-css'; document.head.appendChild(st); }
    st.textContent = css;
  }
  document.addEventListener('change', function (e) {
    if (e.target && e.target.hasAttribute && e.target.hasAttribute('data-hcol')) {
      var hidden = [];
      document.querySelectorAll('[data-hcol]').forEach(function (b) { if (!b.checked) hidden.push(b.getAttribute('data-hcol')); });
      store(COLS, hidden);
      applyCols();
    }
    if (e.target && e.target.id === 'hfollow') store('burpsy.ui2.history.follow', e.target.checked);
    if (e.target && e.target.id === 'hpreset' && e.target.value) {
      var all = store(PRE) || {};
      if (all[e.target.value] !== undefined) applyPreset(all[e.target.value]);
    }
  });
  // Filter presets: name -> query string, per browser.
  var PRE = 'burpsy.ui2.history.presets';
  function fillPresets() {
    var s = document.getElementById('hpreset');
    if (!s) return;
    var all = store(PRE) || {};
    while (s.options.length > 1) s.remove(1);
    Object.keys(all).sort().forEach(function (n) { var o = document.createElement('option'); o.value = n; o.textContent = n; s.appendChild(o); });
  }
  function applyPreset(qs) {
    var p = new URLSearchParams(qs);
    ['hq', 'hfilter'].forEach(function (id) {
      var f = document.getElementById(id);
      if (!f) return;
      Array.prototype.forEach.call(f.elements, function (el) {
        if (!el.name) return;
        if (el.type === 'checkbox') el.checked = p.getAll(el.name).indexOf(el.value) >= 0;
        else if (el.tagName === 'SELECT') {
          var want = p.get(el.name);
          Array.prototype.forEach.call(el.options, function (o) {
            o.selected = want !== null ? (o.value === want) : o.hasAttribute('data-default') || (o.index === 0 && !el.querySelector('[data-default]'));
          });
        } else if (el.type !== 'hidden' && el.type !== 'file') el.value = p.get(el.name) || '';
      });
    });
    var f = document.getElementById('hfilter');
    if (f && window.htmx) htmx.trigger(f, 'submit');
  }
  document.addEventListener('click', function (e) {
    var id = e.target && e.target.id;
    if (id === 'hpreset-save') {
      var name = (window.prompt('Name this filter preset') || '').trim();
      if (!name) return;
      var all = store(PRE) || {};
      all[name] = histParams().toString();
      store(PRE, all);
      fillPresets();
      document.getElementById('hpreset').value = name;
    } else if (id === 'hpreset-del') {
      var s = document.getElementById('hpreset');
      var cur = store(PRE) || {};
      if (s && s.value) { delete cur[s.value]; store(PRE, cur); fillPresets(); }
    } else if (id === 'hpreset-reset') {
      applyPreset('');
    }
  });
  function init() {
    applyCols();
    fillPresets();
    var fol = document.getElementById('hfollow');
    if (fol) fol.checked = store('burpsy.ui2.history.follow') === true;
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  // A delete, clear or import changed the rows: refresh them like a live frame would.
  document.body.addEventListener('burpsy-history-changed', function () {
    if ((document.body.dataset || {}).view === 'history') liveRefresh('history');
  });
  // Go to entry: mark and reveal the row when the current list holds it.
  document.body.addEventListener('htmx:afterSwap', function (e) {
    var g = e.detail.target && e.detail.target.querySelector && e.detail.target.querySelector('[data-goto]');
    if (!g) return;
    var tr = document.querySelector('#rows-body tr[data-id="' + g.getAttribute('data-goto') + '"]');
    document.querySelectorAll('#rows-body tr.selected').forEach(function (r) { r.classList.remove('selected'); });
    if (tr) { tr.classList.add('selected'); tr.scrollIntoView({ block: 'nearest' }); }
  });
})();

// ---- Confirm-gate readiness (armed only after htmx has bound the fragment) ----
// Destructive two-step confirmations (attack launch, payload mint) render their submit
// button disabled with data-arm-on-load. A click before htmx has bound the swapped-in
// hx-post form would otherwise submit NATIVELY — historically a silent GET to the page
// URL that dropped the launch and put the minted token and payloads into the URL
// (browser history, access logs); the forms now also declare method="post" so even a
// native submit is an explicit 405 on the GET-only page route, not a silent re-render.
//
// The readiness signal is htmx:load armed on descendants, and the topology is verified
// in htmx.min.js and pinned by TestUI2IntruderLaunchBrowserFinalClick's event probe:
// htmx pushes one deferred task per TOP-LEVEL swapped node which first processes
// (binds) that whole subtree and only then fires htmx:load on the node — descendants
// (the button) never get their own htmx:load, and afterSwap/afterSettle of OTHER
// in-flight swaps can interleave before this fragment's task runs (observed: a
// points-out afterSettle firing between the confirm fragment's insertion and its
// binding). So: arm controls INSIDE an element whose htmx:load fired — by then its
// subtree is bound — and never from afterSwap or a foreign swap's afterSettle.
// A control whose swap task never ran stays disabled: inert rather than clickable-unbound.
(function () {
  function arm(root) {
    if (root.hasAttribute && root.hasAttribute('data-arm-on-load') && root.disabled) {
      root.disabled = false;
      root.removeAttribute('title');
    }
    if (root.querySelectorAll) {
      root.querySelectorAll('[data-arm-on-load][disabled]').forEach(function (b) {
        b.disabled = false;
        b.removeAttribute('title');
      });
    }
  }
  document.body.addEventListener('htmx:load', function (e) {
    if (e.target) arm(e.target);
  });
})();

// ---- Copy buttons (structured results, e.g. minted collaborator payloads) ----
// data-copy carries the exact text (html/template-escaped into the attribute); the
// button never re-reads the DOM around it, so what the operator copies is what the
// server rendered. navigator.clipboard needs a secure context; the execCommand
// fallback keeps the button working on plain-http LAN installs.
(function () {
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest && e.target.closest('.copy-btn');
    if (!b) return;
    var text = b.getAttribute('data-copy') || '';
    var report = function (ok) {
      // Never claim a copy that did not happen: on rejection the address is still
      // select-all in its <code> block, so point the operator at the manual path.
      b.textContent = ok ? 'Copied' : 'Select text';
      setTimeout(function () { b.textContent = 'Copy'; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { report(true); }, function () { report(false); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
      report(ok);
    }
  });
})();

// Tap-to-expand for truncated table cells. Fixed-layout tables at narrow widths
// truncate every cell with an ellipsis; tapping a TRUNCATED cell expands it in
// place so the full content wraps visibly, and tapping the expanded cell
// collapses it. Rows with their own tap action (history/logger: tr[hx-get])
// ask for a second tap — the first selects the row and loads its detail — so
// one tap never both navigates and expands; every other row expands on the
// first tap. Links, buttons and form controls inside cells keep their own
// behavior.
document.addEventListener('click', (e) => {
  const td = e.target.closest('td');
  if (!td || e.target.closest('a,button,input,select,textarea,label')) return;
  if (td.classList.contains('cell-x')) {
    td.classList.remove('cell-x');
    return;
  }
  const tr = td.parentElement;
  if (!tr) return;
  const truncated = td.scrollWidth > td.clientWidth + 1;
  if (truncated && (tr.classList.contains('selected') || !tr.hasAttribute('hx-get'))) {
    td.classList.add('cell-x');
  }
});

// Truncated column headers expand in place the same way body cells do: on
// phone the fixed table layout clips headings (for example the WebSocket
// connections Exchange heading), and a tap - or Enter/Space on the focused
// header - wraps the full heading visibly; a second tap collapses it. Headers
// are made focusable only while they actually truncate, so the desktop tab
// order is unchanged, and a header carrying its own hx-get/hx-post keeps its
// own behavior. cell-x styling for th lives in the phone media query, so
// desktop rendering is unchanged.
// Header expansion exists only inside the phone media query: the cell-x style
// for th lives there, so a desktop header clipped by the 340px cap must not
// gain a tab stop or toggle it cannot show. ui2HeaderMedia mirrors that query.
const ui2HeaderMedia = window.matchMedia('(max-width: 640px)');
function ui2HeaderTruncated(th) {
  return ui2HeaderMedia.matches && th.scrollWidth > th.clientWidth + 1;
}
function ui2SyncExpandableHeaders(root) {
  root.querySelectorAll('th').forEach((th) => {
    if (ui2HeaderTruncated(th)) {
      th.setAttribute('tabindex', '0');
      th.setAttribute('aria-expanded', th.classList.contains('cell-x') ? 'true' : 'false');
    } else {
      th.removeAttribute('tabindex');
      th.removeAttribute('aria-expanded');
      th.classList.remove('cell-x');
    }
  });
}
function ui2ToggleHeader(th) {
  const open = th.classList.toggle('cell-x');
  th.setAttribute('aria-expanded', open ? 'true' : 'false');
}
document.addEventListener('click', (e) => {
  const th = e.target.closest('th');
  if (!th || e.target.closest('a,button,input,select,textarea,label')) return;
  if (th.hasAttribute('hx-get') || th.hasAttribute('hx-post')) return;
  if (ui2HeaderTruncated(th) || th.classList.contains('cell-x')) ui2ToggleHeader(th);
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const th = e.target.closest && e.target.closest('th');
  if (!th || !th.hasAttribute('tabindex')) return;
  e.preventDefault();
  ui2ToggleHeader(th);
});
document.addEventListener('htmx:load', (e) => {
  const elt = e.detail && e.detail.elt;
  if (elt && elt.querySelectorAll) ui2SyncExpandableHeaders(elt);
});
document.addEventListener('DOMContentLoaded', () => ui2SyncExpandableHeaders(document));
let ui2HeaderScanTimer = null;
window.addEventListener('resize', () => {
  if (ui2HeaderScanTimer) clearTimeout(ui2HeaderScanTimer);
  ui2HeaderScanTimer = setTimeout(() => ui2SyncExpandableHeaders(document), 150);
});
ui2HeaderMedia.addEventListener('change', () => ui2SyncExpandableHeaders(document));

// ---- Shell: status bar, File/Project menus, bundle file picker ----
// The status bar's data segment is server-rendered (/ui2/shell/status) and fetched with plain
// fetch, NOT htmx: an htmx request would count as an operator request above and bump the live
// generation, dropping a view's in-flight live refresh. Stream state and the last-event time
// are facts only this page knows, so they are set here from the one EventSource.
(function () {
  var stream = document.getElementById('sb-stream');
  var last = document.getElementById('sb-last');
  var data = document.getElementById('sb-data');
  if (!stream || !data) return;
  function setStream(on) {
    stream.textContent = on ? 'stream: live' : 'stream: offline';
    stream.className = on ? 'sb-live' : 'sb-off';
  }
  var inFlight = false, again = false, timer = null;
  function refresh() {
    if (inFlight) { again = true; return; }
    inFlight = true;
    fetch('/ui2/shell/status', { credentials: 'same-origin' }).then(function (r) {
      return r.ok ? r.text() : Promise.reject(r.status);
    }).then(function (html) {
      data.innerHTML = html;
    }).catch(function () {
      data.textContent = 'status unavailable';
    }).then(function () {
      inFlight = false;
      if (again) { again = false; refresh(); }
    });
  }
  function soon() {
    if (timer) return;
    timer = setTimeout(function () { timer = null; refresh(); }, 1500);
  }
  if (liveES) {
    if (liveES.readyState === 1) setStream(true);
    liveES.addEventListener('open', function () { setStream(true); });
    liveES.addEventListener('error', function () { setStream(liveES.readyState === 1); });
    liveES.addEventListener('message', function (e) {
      setStream(true);
      var kind = '';
      try { kind = JSON.parse(e.data).kind || ''; } catch (_) { return; }
      if (kind === 'ping' || kind === 'hello') return;
      if (last) last.textContent = 'last event: ' + kind + ' at ' + new Date().toLocaleTimeString();
      if (kind === 'history' || kind === 'scope' || kind === 'proxy' || kind === 'dashboard') soon();
    });
  } else {
    setStream(false);
  }
  refresh();
  setInterval(refresh, 30000);
})();

(function () {
  function closeMenus(except) {
    document.querySelectorAll('details.menu[open]').forEach(function (d) {
      if (d !== except) d.open = false;
    });
  }
  document.addEventListener('click', function (e) {
    var menu = e.target && e.target.closest ? e.target.closest('details.menu') : null;
    closeMenus(menu);
    if (menu && e.target.closest('.menu-list a')) menu.open = false;
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeMenus(null);
  });
  // File > Import configuration: a chosen bundle file is read into the paste box, so the
  // review step posts plain form text (the route takes no multipart).
  document.addEventListener('change', function (e) {
    var input = e.target;
    if (!input || !input.matches || !input.matches('input[type="file"][data-fill-into]')) return;
    var box = document.getElementById(input.getAttribute('data-fill-into'));
    var file = input.files && input.files[0];
    if (!box || !file) return;
    var reader = new FileReader();
    reader.onload = function () { box.value = String(reader.result || ''); };
    reader.readAsText(file);
  });
// ---- Command palette (mod+K) ----
// Lists every ui2 page (read from the header nav, so a page added there appears here with no
// second list to maintain) plus the Settings page's sections (its headings, read from the
// served fragment on first open). Fuzzy subsequence filter; Enter opens, Esc closes. Recent
// picks persist per browser in localStorage, which may be unavailable (private mode): every
// access is guarded and the palette works without it. Entries are built with textContent only.
(function () {
  var RECENT_KEY = 'burpsy.ui2.palette.recent';
  var MAX_RECENT = 8;
  var overlay = null, input = null, list = null, opener = null;
  var entries = [], shown = [], active = 0, settings = null;

  function loadRecent() {
    try {
      var v = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
      return Array.isArray(v) ? v.filter(function (x) { return x && typeof x.href === 'string' && typeof x.label === 'string'; }) : [];
    } catch (_) { return []; }
  }
  function saveRecent(entry) {
    var next = [{ label: entry.label, href: entry.href }].concat(loadRecent().filter(function (x) { return x.href !== entry.href; })).slice(0, MAX_RECENT);
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(next)); } catch (_) {}
  }
  function pages() {
    var seen = {}, out = [];
    document.querySelectorAll('header nav a[href^="/ui2/"]').forEach(function (a) {
      var href = a.getAttribute('href');
      if (seen[href]) return;
      seen[href] = true;
      out.push({ label: a.textContent.trim(), href: href, group: 'Page' });
    });
    return out;
  }
  function headingEntries(root) {
    var out = [];
    root.querySelectorAll('h2, h3').forEach(function (h) {
      var text = h.textContent.replace(/\s+/g, ' ').trim();
      if (!text) return;
      out.push({ label: 'Settings › ' + text, href: '/ui2/settings#' + (h.id ? h.id : 'section=' + encodeURIComponent(text)), group: 'Settings' });
    });
    return out;
  }
  // The section list is cached for the browser session: every ui2 navigation is a full page
  // load, and re-rendering the whole Settings page per palette open would be waste.
  var SETTINGS_KEY = 'burpsy.ui2.palette.settings';
  function loadSettings() {
    if (settings) return;
    try {
      var cached = JSON.parse(sessionStorage.getItem(SETTINGS_KEY) || 'null');
      if (Array.isArray(cached)) { settings = cached; return; }
    } catch (_) {}
    settings = [];
    fetch('/ui2/settings', { headers: { 'HX-Request': 'true' }, credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.text() : ''; })
      .then(function (t) {
        if (!t) return;
        settings = headingEntries(new DOMParser().parseFromString(t, 'text/html'));
        try { sessionStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (_) {}
        if (overlay && !overlay.hidden) { collect(); render(); }
      })
      .catch(function () {});
  }
  function collect() {
    entries = pages().concat(settings || []);
  }
  // Subsequence score: -1 when q is not a subsequence of the label; higher is better, rewarding
  // consecutive runs and word starts, penalising long labels slightly.
  function score(label, q) {
    if (!q) return 0;
    var l = label.toLowerCase(), s = 0, li = 0, run = 0;
    for (var qi = 0; qi < q.length; qi++) {
      var c = q.charAt(qi);
      if (c === ' ') continue;
      var at = l.indexOf(c, li);
      if (at < 0) return -1;
      run = at === li ? run + 1 : 1;
      s += run * 2;
      if (at === 0 || /[\s›\/(-]/.test(l.charAt(at - 1))) s += 3;
      li = at + 1;
    }
    return s - l.length / 100;
  }
  function filter() {
    var q = input.value.trim().toLowerCase();
    var recent = loadRecent();
    var rank = {};
    recent.forEach(function (r, i) { rank[r.href] = MAX_RECENT - i; });
    if (!q) {
      var byHref = {};
      entries.forEach(function (e) { byHref[e.href] = e; });
      var first = recent.filter(function (r) { return byHref[r.href]; }).map(function (r) {
        return { label: byHref[r.href].label, href: r.href, group: 'Recent' };
      });
      var rest = entries.filter(function (e) { return !rank[e.href]; });
      shown = first.concat(rest);
    } else {
      shown = entries.map(function (e) {
        var sc = score(e.label, q);
        return { e: e, s: sc < 0 ? sc : sc + (rank[e.href] || 0) / 4 };
      }).filter(function (x) { return x.s >= 0; })
        .sort(function (a, b) { return b.s - a.s; })
        .map(function (x) { return x.e; });
    }
    active = 0;
  }
  function render() {
    filter();
    while (list.firstChild) list.removeChild(list.firstChild);
    if (!shown.length) {
      var none = document.createElement('li');
      none.className = 'palette-none';
      none.textContent = 'No page or section matches.';
      list.appendChild(none);
      input.removeAttribute('aria-activedescendant');
      return;
    }
    shown.forEach(function (e, i) {
      var li = document.createElement('li');
      li.id = 'palette-opt-' + i;
      li.setAttribute('role', 'option');
      li.dataset.index = String(i);
      li.dataset.href = e.href;
      var label = document.createElement('span');
      label.textContent = e.label;
      var group = document.createElement('span');
      group.className = 'palette-group';
      group.textContent = e.group;
      li.appendChild(label);
      li.appendChild(group);
      list.appendChild(li);
    });
    highlight();
  }
  function highlight() {
    list.querySelectorAll('[role=option]').forEach(function (li, i) {
      var on = i === active;
      li.classList.toggle('active', on);
      li.setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) { li.scrollIntoView({ block: 'nearest' }); input.setAttribute('aria-activedescendant', li.id); }
    });
  }
  function go(i) {
    var e = shown[i];
    if (!e) return;
    saveRecent(e);
    close();
    location.href = e.href;
  }
  function build() {
    var style = document.createElement('style');
    style.textContent =
      '#ui2-palette{position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:100;display:flex;justify-content:center;align-items:flex-start;padding-top:12vh}' +
      '#ui2-palette[hidden]{display:none}' +
      '#ui2-palette .palette-box{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;width:min(560px,calc(100vw - 32px));box-shadow:0 8px 30px rgba(0,0,0,.35);overflow:hidden}' +
      '#ui2-palette input{width:100%;border:0;border-bottom:1px solid var(--line);border-radius:0;padding:10px 12px;font-size:15px}' +
      '#ui2-palette ul{list-style:none;margin:0;padding:4px 0;max-height:min(50vh,420px);overflow-y:auto}' +
      '#ui2-palette li{display:flex;justify-content:space-between;gap:12px;padding:6px 12px;cursor:pointer}' +
      '#ui2-palette li.active{background:var(--sel)}' +
      '#ui2-palette .palette-group,#ui2-palette .palette-none{color:var(--muted);font-size:12px}';
    document.head.appendChild(style);
    overlay = document.createElement('div');
    overlay.id = 'ui2-palette';
    overlay.hidden = true;
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Command palette');
    var box = document.createElement('div');
    box.className = 'palette-box';
    input = document.createElement('input');
    input.type = 'text';
    input.id = 'palette-input';
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-expanded', 'true');
    input.setAttribute('aria-controls', 'palette-list');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-label', 'Go to a page or settings section');
    input.placeholder = 'Go to… (type to filter, Enter opens, Esc closes)';
    input.autocomplete = 'off';
    list = document.createElement('ul');
    list.id = 'palette-list';
    list.setAttribute('role', 'listbox');
    box.appendChild(input);
    box.appendChild(list);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    input.addEventListener('input', render);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { active = Math.min(shown.length - 1, active + 1); highlight(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { active = Math.max(0, active - 1); highlight(); e.preventDefault(); }
      else if (e.key === 'Enter') { go(active); e.preventDefault(); }
      else if (e.key === 'Escape') { close(); e.preventDefault(); }
      else if (e.key === 'Tab') { e.preventDefault(); } // focus stays in the dialog
    });
    list.addEventListener('click', function (e) {
      var li = e.target.closest && e.target.closest('[role=option]');
      if (li) go(parseInt(li.dataset.index, 10));
    });
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(); });
  }
  function open() {
    if (!overlay) build();
    if (!overlay.hidden) { input.focus(); return; }
    opener = document.activeElement;
    loadSettings();
    collect();
    input.value = '';
    overlay.hidden = false;
    render();
    input.focus();
  }
  function close() {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    if (opener && opener.focus) { try { opener.focus(); } catch (_) {} }
  }
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      open();
    }
  });
  // A touch-only device has no mod+K: a header button opens the same palette.
  function addButton() {
    var theme = document.getElementById('theme-toggle');
    if (!theme || document.getElementById('palette-open')) return;
    var b = document.createElement('button');
    b.id = 'palette-open';
    b.className = 'btn';
    b.type = 'button';
    b.title = 'Go to… (mod+K)';
    b.setAttribute('aria-label', 'Open the command palette');
    b.textContent = /Mac|iPhone|iPad/.test(navigator.platform || '') ? '⌘K' : 'Ctrl+K';
    b.addEventListener('click', open);
    theme.parentNode.insertBefore(b, theme);
  }
  // A palette pick for a settings heading with no id lands as #section=<text>: scroll to it.
  function revealSection() {
    var h = location.hash;
    if (h.indexOf('#section=') !== 0) return;
    var want;
    try { want = decodeURIComponent(h.slice(9)); } catch (_) { return; }
    var found = Array.prototype.find.call(document.querySelectorAll('main h2, main h3'), function (x) {
      return x.textContent.replace(/\s+/g, ' ').trim() === want;
    });
    if (found) found.scrollIntoView({ block: 'start' });
  }
  function ready() { addButton(); revealSection(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
  window.addEventListener('hashchange', revealSection);
})();
