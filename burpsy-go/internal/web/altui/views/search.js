import { api, esc, fmtTime } from '../api.js';
import { toast } from '../components.js';
import { openExchangeDrawer } from './map.js';

// SEARCH - find bytes in the recorded traffic. This is the suite-wide search
// (GET /api/search): it reads the bytes the store already holds, across every
// tool's captures, and sends nothing anywhere. Results open in the same
// exchange drawer Map uses.

const state = { toolOpts: [], resp: null, searched: false };
let root = null;

export async function renderSearch(el) {
  root = el;
  el.innerHTML = `
    <div class="search-form">
      <div class="tools-row">
        <input type="search" id="sr-q" placeholder="bytes to find in recorded traffic" spellcheck="false" autocomplete="off" style="flex:1;min-width:180px">
        <button class="act primary" id="sr-go">Search</button>
      </div>
      <div class="tools-row">
        <label><input type="checkbox" id="sr-case"> case-sensitive</label>
        <label><input type="checkbox" id="sr-regex"> regex</label>
        <label><input type="checkbox" id="sr-neg"> negative</label>
        <label><input type="checkbox" id="sr-scope"> in scope only</label>
      </div>
      <div class="tools-row">
        <label>look in <select id="sr-loc">
          <option value="both">requests and responses</option>
          <option value="request">requests only</option>
          <option value="response">responses only</option>
        </select></label>
        <label>part <select id="sr-area">
          <option value="both">headers and body</option>
          <option value="headers">headers only</option>
          <option value="body">body only</option>
        </select></label>
      </div>
      <div class="tools-row" id="sr-tools"><span class="mut">loading tool list…</span></div>
      <div class="mut" style="font-size:12px">Searches bytes already recorded. Nothing is sent to any target.</div>
    </div>
    <div class="search-results" id="sr-out"><div class="empty">Enter a term to search every recorded request and response.</div></div>`;
  el.querySelector('#sr-go').onclick = run;
  el.querySelector('#sr-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); run(); } });
  try {
    const d = await api.get('/api/search');
    state.toolOpts = d.tool_options || [];
    drawToolChecks();
  } catch (e) {
    el.querySelector('#sr-tools').innerHTML = `<span class="mut">tool list unavailable: ${esc(e.message)}</span>`;
  }
}

function drawToolChecks() {
  const box = root.querySelector('#sr-tools');
  if (!box) return;
  if (!state.toolOpts.length) { box.innerHTML = ''; return; }
  box.innerHTML = `<span class="mut">tools:</span> ` + state.toolOpts.map((t) => `
    <label><input type="checkbox" class="sr-tool" value="${esc(t.id)}" checked> ${esc(t.label)}</label>`).join('');
}

async function run() {
  const q = root.querySelector('#sr-q').value;
  const out = root.querySelector('#sr-out');
  if (!q.trim()) { out.innerHTML = '<div class="empty">Enter a term to search every recorded request and response.</div>'; return; }
  const p = new URLSearchParams({ q });
  if (root.querySelector('#sr-case').checked) p.set('case', '1');
  if (root.querySelector('#sr-regex').checked) p.set('regex', '1');
  if (root.querySelector('#sr-neg').checked) p.set('negate', '1');
  if (root.querySelector('#sr-scope').checked) p.set('in_scope', '1');
  p.set('location', root.querySelector('#sr-loc').value);
  p.set('area', root.querySelector('#sr-area').value);
  const checked = [...root.querySelectorAll('.sr-tool')].filter((c) => c.checked).map((c) => c.value);
  // All ticked (the opening state) sends no tools parameter, which the backend
  // reads as "every tool"; nothing ticked is refused here with the reason.
  if (state.toolOpts.length && !checked.length) { out.innerHTML = '<div class="empty">Every tool is unticked, so there is nothing to search. Tick at least one.</div>'; return; }
  if (checked.length && checked.length < state.toolOpts.length) p.set('tools', checked.join(','));
  out.innerHTML = '<div class="spin">searching recorded traffic…</div>';
  try {
    state.resp = await api.get('/api/search?' + p.toString());
    state.searched = true;
    drawResults();
  } catch (e) {
    out.innerHTML = `<div class="empty">Search refused: ${esc(e.message)}</div>`;
  }
}

function matchSummary(r) {
  const groups = {};
  for (const m of r.matches || []) {
    const k = `${m.direction} ${m.area}`;
    groups[k] = (groups[k] || 0) + 1;
  }
  let s = Object.entries(groups).map(([k, n]) => `${k} ×${n}`).join(' · ');
  if (r.matches_truncated) s += ' · more not listed';
  return s;
}

function drawResults() {
  const out = root.querySelector('#sr-out');
  const d = state.resp;
  if (!d) return;
  const rows = d.results || [];
  const head = `<div class="search-summary">
    scanned <b>${d.scanned}</b> recorded exchange${d.scanned === 1 ? '' : 's'} ·
    <b>${d.returned}</b> match${d.returned === 1 ? '' : 'es'}${d.truncated ? ' · <b>truncated</b> at the result limit, more matches exist' : ''}
  </div>`;
  if (!rows.length) {
    out.innerHTML = head + `<div class="empty">${d.scanned ? 'No matches in the scanned traffic.' : 'Nothing recorded to search yet.'}</div>`;
    return;
  }
  out.innerHTML = head + `<table class="srows"><thead><tr>
    <th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Matches</th><th>Time</th>
  </tr></thead><tbody>${rows.map((r) => `
    <tr class="data" data-id="${r.id}">
      <td class="mono mut">${r.id}</td>
      <td class="mono m-${esc(r.method)}">${esc(r.method)}</td>
      <td class="mono urlcell" title="${esc(r.host)}:${r.port}${esc(r.path)}">${esc(r.host)}:${r.port}${esc(r.path)}</td>
      <td class="st st-${String(r.status || '')[0] || ''}">${r.status ?? '-'}</td>
      <td class="mono" title="${esc(matchSummary(r))}">${r.match_count}${r.matches_truncated ? '+' : ''}${r.organizer ? ' <span class="chip">organizer</span>' : ''}</td>
      <td class="mono mut">${fmtTime(r.started_ms)}</td>
    </tr>`).join('')}</tbody></table>`;
  out.querySelectorAll('tr.data').forEach((tr) => {
    tr.onclick = () => openExchangeDrawer(Number(tr.dataset.id), document.getElementById('view-search'));
  });
}
