import { renderMap, refreshMap } from './views/map.js';
import { renderProbe, loadExchange } from './views/probe.js';
import { renderProve, refreshProve } from './views/prove.js';
import { api } from './api.js';

const rendered = new Set();

function switchView(name) {
  document.querySelectorAll('.rail-item').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  const el = document.getElementById(`view-${name}`);
  if (!rendered.has(name)) {
    rendered.add(name);
    if (name === 'map') renderMap(el);
    if (name === 'probe') renderProbe(el);
    if (name === 'prove') renderProve(el);
    if (name === 'attack') el.innerHTML = `<div class="empty" style="margin:auto">
      <b>Attack is held in this build.</b><br><br>
      Active scanning, intruder runs and crawls send unbounded traffic at a target.
      That lane is held by project policy, so this MVP does not surface those controls.
      Probe (single deliberate requests) and Map (observed traffic) are the live lanes.</div>`;
  } else {
    if (name === 'map') refreshMap();
    if (name === 'prove') refreshProve();
  }
}

document.querySelectorAll('.rail-item').forEach((b) => {
  b.onclick = () => { if (!b.classList.contains('rail-held')) switchView(b.dataset.view); };
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
      if (d.kind === 'history' || d.kind === 'sitemap') { if (rendered.has('map')) refreshMap(); health(); }
      if (d.kind === 'issues') { if (rendered.has('prove')) refreshProve(); }
    } catch { /* keep stream */ }
  };
  es.onerror = () => { document.getElementById('live-badge').className = 'live off'; };
}

health();
setInterval(health, 10000);
events();
switchView('map');
