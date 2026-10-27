import { renderMap, refreshMap } from './views/map.js';
import { renderSearch } from './views/search.js';
import { renderProbe, loadExchange } from './views/probe.js';
import { renderProve, refreshProve } from './views/prove.js';
import { renderScope, refreshScope } from './views/scope.js';
import { renderTools } from './views/tools.js';
import { api } from './api.js';
import { shortcutsDialog } from './components.js';

const rendered = new Set();

function switchView(name) {
  document.querySelectorAll('.rail-item').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  const el = document.getElementById(`view-${name}`);
  if (!rendered.has(name)) {
    rendered.add(name);
    if (name === 'map') renderMap(el);
    if (name === 'search') renderSearch(el);
    if (name === 'probe') renderProbe(el);
    if (name === 'prove') renderProve(el);
    if (name === 'tools') renderTools(el);
    if (name === 'scope') renderScope(el);
    if (name === 'attack') el.innerHTML = `<div class="empty" style="margin:auto">
      <b>Attack is not built in this console yet.</b><br><br>
      Active scanning, intruder runs and crawls send real traffic at a target,
      so those controls get their own careful build. Probe (single deliberate
      requests) and Map (observed traffic) are the live lanes.</div>`;
  } else {
    if (name === 'map') refreshMap();
    if (name === 'prove') refreshProve();
    if (name === 'scope') refreshScope();
  }
}

document.querySelectorAll('.rail-item').forEach((b) => {
  b.onclick = () => switchView(b.dataset.view);
});

window.addEventListener('altui:probe-load', (ev) => {
  switchView('probe');
  loadExchange(ev.detail?.exchange);
});

window.addEventListener('altui:refresh-map', () => { if (rendered.has('map')) refreshMap(); if (rendered.has('prove')) refreshProve(); });

// Health + SSE: drive the live badge and refresh views on change events.
async function health() {
  const badge = document.getElementById('live-badge');
  const txt = document.getElementById('live-text');
  try {
    const s = await api.get('/api/stats');
    badge.className = 'live on';
    txt.textContent = `${s.exchanges ?? 0} exch`;
  } catch {
    badge.className = 'live off';
    txt.textContent = 'offline';
  }
}

function events() {
  const es = new EventSource('/api/events');
  es.onmessage = (m) => {
    try {
      const d = JSON.parse(m.data);
      if (d.kind === 'history') { if (rendered.has('map')) refreshMap(); health(); }
      
      if (d.kind === 'issues') { if (rendered.has('prove')) refreshProve(); }
    } catch { /* keep stream */ }
  };
  es.onerror = () => { document.getElementById('live-badge').className = 'live off'; };
}

// Keyboard-first (spec): g then letter switches workflow lane; Enter opens the
// selected history row; j/k move the selection; ctrl/cmd+Enter sends in Probe.
const laneKeys = { m: 'map', s: 'search', p: 'probe', v: 'prove', c: 'scope', t: 'tools' };
let gPending = false;
window.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const send = document.getElementById('p-send');
    if (send && document.getElementById('view-probe').classList.contains('active')) { e.preventDefault(); send.click(); }
    return;
  }
  if (typing) return;
  if (e.key === 'Escape') {
    // Close through the wired close button so focus returns to what opened it.
    const dc = document.querySelector('.drawer [id$=-close]');
    if (dc) { dc.click(); return; }
    const kd = document.querySelector('#keys-dialog [data-x=ok]');
    if (kd) { kd.click(); return; }
    return;
  }
  if (e.key === '?') { shortcutsDialog(); return; }
  if (gPending) {
    gPending = false;
    const lane = laneKeys[e.key];
    if (lane) { switchView(lane); e.preventDefault(); }
    return;
  }
  if (e.key === 'g') { gPending = true; return; }
  const rows = [...document.querySelectorAll('#map-rows tr.data')];
  if (!rows.length) return;
  const cur = rows.findIndex((r) => r.classList.contains('sel'));
  if (e.key === 'j' || e.key === 'k') {
    const next = e.key === 'j' ? Math.min(cur + 1, rows.length - 1) : Math.max(cur - 1, 0);
    rows.forEach((r) => r.classList.remove('sel'));
    rows[next]?.classList.add('sel');
    rows[next]?.scrollIntoView({ block: 'nearest' });
    e.preventDefault();
  } else if (e.key === 'Enter' && cur >= 0) {
    rows[cur].click();
    e.preventDefault();
  }
});

document.getElementById('keys-btn').onclick = shortcutsDialog;

health();
setInterval(health, 10000);
events();
switchView('map');
