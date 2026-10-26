import { api, esc } from '../api.js';
import { toast, sevChip } from '../components.js';

// PROVE — the evidence: consolidated findings with severity counts, advisory
// detail and occurrences that deep-link back into Map.

const state = { findings: [], counts: {}, sel: null };

export async function renderProve(el) {
  el.innerHTML = `
    <div class="pane-head">
      <span class="pane-title">Findings</span>
      <span class="countbar" id="pv-counts"></span>
    </div>
    <div class="pane-body" id="pv-list"><div class="spin">loading…</div></div>`;
  await refreshProve();
}

export async function refreshProve() {
  try {
    const d = await api.get('/api/issues');
    state.findings = d.findings || [];
    state.counts = d.counts || {};
    drawCounts(); drawList();
  } catch (e) { toast(`issues: ${e.message}`, true); }
}

function drawCounts() {
  const box = document.getElementById('pv-counts');
  if (!box) return;
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  box.innerHTML = order
    .filter((k) => state.counts[k])
    .map((k) => `${sevChip(k[0].toUpperCase() + k.slice(1))} <span class="mut">${state.counts[k]}</span>`)
    .join(' ');
}

function drawList() {
  const box = document.getElementById('pv-list');
  if (!box) return;
  if (!state.findings.length) { box.innerHTML = '<div class="empty">No findings yet. Passive checks run as traffic flows through the proxy.</div>'; return; }
  box.innerHTML = state.findings.map((f, i) => `
    <div class="issue-row${state.sel === i ? ' sel' : ''}" data-i="${i}">
      ${sevChip(f.severity)}
      <span class="issue-name">${esc(f.check_name || f.issue_name || 'finding')}</span>
      <span class="issue-host">${esc(f.host || '')}</span>
      <span class="chip">${esc(f.confidence || '')}</span>
      ${f.times_seen > 1 ? `<span class="chip">×${f.times_seen}</span>` : ''}
    </div>`).join('');
  box.querySelectorAll('.issue-row').forEach((row) => {
    row.onclick = () => { state.sel = Number(row.dataset.i); drawList(); showDetail(state.findings[state.sel]); };
  });
}

function showDetail(f) {
  document.querySelector('.drawer')?.remove();
  const d = document.createElement('div');
  d.className = 'drawer';
  const occ = (f.occurrences || []).map((o) => `
    <div class="kv" style="padding:3px 0">
      <span class="mono mut">#${o.exchange_id}</span>
      <span class="mono">${esc(o.path || '')}</span>
      <button class="act" data-ex="${o.exchange_id}">open in Map</button>
    </div>`).join('') || '<span class="mut">no occurrences recorded</span>';
  d.innerHTML = `
    <div class="drawer-head">
      ${sevChip(f.severity)}
      <b style="flex:1">${esc(f.check_name || 'finding')}</b>
      <button class="act" id="id-close">✕</button>
    </div>
    <div class="drawer-body">
      <div class="kv"><span class="chip">${esc(f.host || '')}</span><span class="chip">${esc(f.confidence || '')}</span></div>
      ${f.detail ? `<div><div class="section-label">What was seen</div><div style="padding:6px 0">${esc(f.detail)}</div></div>` : ''}
      ${f.remediation ? `<div><div class="section-label">Fix</div><div style="padding:6px 0">${esc(f.remediation)}</div></div>` : ''}
      <div><div class="section-label">Occurrences</div>${occ}</div>
    </div>`;
  document.getElementById('view-prove').appendChild(d);
  d.querySelector('#id-close').onclick = () => d.remove();
  d.querySelectorAll('[data-ex]').forEach((b) => {
    b.onclick = () => {
      d.remove();
      document.querySelector('[data-view=map]').click();
      setTimeout(() => {
        document.querySelector(`tr[data-id="${b.dataset.ex}"]`)?.click();
      }, 300);
    };
  });
}
