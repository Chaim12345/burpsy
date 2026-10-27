import { api, esc } from '../api.js';
import { toast, sevChip, wireDrawer } from '../components.js';

// PROVE - the evidence. Two read-only lanes:
//   Findings: consolidated findings with severity counts, full advisory detail
//     and occurrences that deep-link back into Map.
//   Issue catalogue: the reference definitions (/api/advisories), browsable and
//     searchable whether or not any finding exists yet.

const state = {
  tab: 'findings',
  findings: [], counts: {}, sel: null,
  cat: null, catQ: '', catSev: '', catSel: null,
};
let root = null;

export async function renderProve(el) {
  root = el;
  el.innerHTML = `
    <div class="pane-head">
      <div class="tools-tabs" role="tablist">
        <button class="act tools-tab primary" role="tab" data-tab="findings">Findings</button>
        <button class="act tools-tab" role="tab" data-tab="catalogue">Issue catalogue</button>
      </div>
      <span class="countbar" id="pv-counts"></span>
      <span class="rep-bar">
        <label class="mut" for="pv-repfmt" style="font-size:12px">report</label>
        <select id="pv-repfmt" title="Findings report format">
          <option value="json">JSON</option><option value="sarif">SARIF</option>
          <option value="html">HTML</option><option value="xml">Burp XML</option>
        </select>
        <button class="act" id="pv-repgo" title="Download the current findings as a report file. Read-only: it changes nothing">Download</button>
      </span>
    </div>
    <div id="pv-catbar" class="pane-head filters" hidden>
      <input type="search" id="pv-catq" placeholder="search name and description…" spellcheck="false" autocomplete="off">
      <select id="pv-catsev"><option value="">any severity</option></select>
      <span class="mut" id="pv-catmeta"></span>
      <span class="mut" style="flex-basis:100%;font-size:11px">Reference text from the issue-definition catalogue. A definition existing here does not mean burpsy runs a check for it.</span>
    </div>
    <div class="pane-body" id="pv-list"><div class="spin">loading…</div></div>`;
  el.querySelectorAll('.tools-tab').forEach((b) => {
    b.onclick = () => { state.tab = b.dataset.tab; syncTabs(); };
  });
  el.querySelector('#pv-catq').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); state.catQ = e.target.value.trim(); loadCatalogue(); } });
  el.querySelector('#pv-catq').addEventListener('search', (e) => { state.catQ = e.target.value.trim(); loadCatalogue(); });
  el.querySelector('#pv-catsev').onchange = (e) => { state.catSev = e.target.value; loadCatalogue(); };
  el.querySelector('#pv-repgo').onclick = downloadReport;
  await refreshProve();
}

export async function refreshProve() {
  if (!root) return;
  if (state.tab === 'catalogue') { await loadCatalogue(); return; }
  try {
    const d = await api.get('/api/issues');
    state.findings = d.findings || [];
    state.counts = d.counts || {};
    drawCounts(); drawList();
  } catch (e) { toast(`issues: ${e.message}`, true); }
}

function syncTabs() {
  root.querySelectorAll('.tools-tab').forEach((b) => b.classList.toggle('primary', b.dataset.tab === state.tab));
  root.querySelector('#pv-counts').hidden = state.tab !== 'findings';
  root.querySelector('#pv-catbar').hidden = state.tab !== 'catalogue';
  if (state.tab === 'catalogue' && !state.cat) { loadCatalogue(); }
  else if (state.tab === 'catalogue') { drawCatalogue(); }
  else { drawCounts(); drawList(); }
}

// ---- findings ----

function drawCounts() {
  const box = root.querySelector('#pv-counts');
  if (!box) return;
  const order = ['critical', 'high', 'medium', 'low', 'informational']; // 'info' is a duplicate alias of 'informational' (api_capture.go) - showing both would double-count
  box.innerHTML = order
    .filter((k) => state.counts[k])
    .map((k) => `${sevChip(k[0].toUpperCase() + k.slice(1))} <span class="mut">${state.counts[k]}</span>`)
    .join(' ');
}

function drawList() {
  const box = root.querySelector('#pv-list');
  if (!box) return;
  if (!state.findings.length) { box.innerHTML = '<div class="empty">No findings yet. Passive checks run as traffic flows through the proxy. Imported history can be searched and opened from Map and Search, but it does not create findings on its own.</div>'; return; }
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

// advisoryBlock renders the catalogue definition attached to a finding, or the
// note explaining why there is none. Paragraphs are the plain text the backend
// already flattened for consoles.
function advisoryBlock(f) {
  if (f.advisory) {
    const a = f.advisory;
    return `
      <div><div class="section-label">Definition${a.type_index ? ` · type ${esc(a.type_index)}` : ''}${a.typical_severity ? ` · typically ${esc(a.typical_severity)}` : ''}</div>
        ${(a.description_paragraphs || []).map((p) => `<div class="adv-para">${esc(p)}</div>`).join('')}</div>
      ${(a.remediation_paragraphs || []).length ? `<div><div class="section-label">Remediation</div>
        ${a.remediation_paragraphs.map((p) => `<div class="adv-para">${esc(p)}</div>`).join('')}</div>` : ''}
      ${linksBlock('References', a.references)}
      ${linksBlock('Classifications', a.classifications)}`;
  }
  if (f.advisory_note) return `<div class="mut">${esc(f.advisory_note)}</div>`;
  return '';
}

// safeLink renders a catalogue/reference link only when its scheme is http or
// https. Any other scheme (javascript:, data:) is shown as plain text: HTML
// escaping alone does not make a dangerous scheme inert in an href.
function safeLink(l) {
  const url = String(l.url || '');
  if (/^https?:\/\//i.test(url)) {
    return `<a class="adv-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(l.title || url)}</a>`;
  }
  return `<span class="adv-link mut">${esc(l.title || url)}</span>`;
}

function linksBlock(label, links) {
  if (!links || !links.length) return '';
  return `<div><div class="section-label">${esc(label)}</div><div class="kv" style="flex-direction:column;align-items:flex-start;gap:2px">
    ${links.map(safeLink).join('')}
  </div></div>`;
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
      <div class="kv"><span class="chip" id="fd-host">${esc(f.host || '')}</span><span class="chip">${esc(f.confidence || '')}</span></div>
      ${f.detail ? `<div><div class="section-label">What was seen</div><div style="padding:6px 0">${esc(f.detail)}</div></div>` : ''}
      ${f.remediation ? `<div><div class="section-label">Fix</div><div style="padding:6px 0">${esc(f.remediation)}</div></div>` : ''}
      ${advisoryBlock(f)}
      <div><div class="section-label">Occurrences</div>${occ}</div>
    </div>`;
  root.appendChild(d);
  wireDrawer(d, `Finding: ${f.check_name || 'finding'}`);
  // A merged finding can span hosts; the header carries only the first. Resolve the
  // occurrences' hosts (read-only exchange lookups, capped) and say so honestly when
  // they disagree with it.
  const occIds = [...new Set((f.occurrences || []).map((o) => o.exchange_id))].slice(0, 12);
  if (occIds.length > 1) {
    Promise.all(occIds.map((id) => api.get(`/api/exchange/${id}`).catch(() => null))).then((exs) => {
      const hosts = [...new Set(exs.filter(Boolean).map((e) => e.host))];
      const chip = d.querySelector('#fd-host');
      if (chip && hosts.length > 1) {
        chip.textContent = `${hosts.length} hosts: ${hosts.slice(0, 3).join(', ')}${hosts.length > 3 ? ', ...' : ''}`;
      }
    });
  }
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

// downloadReport saves the current findings as a report file
// (GET /api/report/{json|sarif|html|xml}, riskRead): the backend renders the
// same findings Prove lists into the chosen format. Read-only.
async function downloadReport() {
  const fmt = root.querySelector('#pv-repfmt').value;
  let res;
  try { res = await fetch(`/api/report/${fmt}`); } catch (e) { toast(`report failed: ${e.message}`, true); return; }
  if (!res.ok) { toast(`report refused: ${(await res.text()).trim() || res.statusText}`, true); return; }
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') || '';
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || `burpsy-report.${fmt}`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
  toast(`report downloaded (${name})`);
}

// ---- issue catalogue ----

async function loadCatalogue() {
  const box = root.querySelector('#pv-list');
  const p = new URLSearchParams();
  if (state.catQ) p.set('q', state.catQ);
  if (state.catSev) p.set('severity', state.catSev);
  try {
    state.cat = await api.get('/api/advisories' + (p.toString() ? '?' + p.toString() : ''));
    state.catSel = null;
    drawCatalogue();
  } catch (e) {
    box.innerHTML = `<div class="empty">Catalogue refused: ${esc(e.message)}</div>`;
  }
}

function drawCatalogue() {
  const box = root.querySelector('#pv-list');
  const d = state.cat;
  if (!d) return;
  // Fill the severity select once per load from the whole-catalogue partition.
  const sevSel = root.querySelector('#pv-catsev');
  const counts = d.severity_counts || {};
  sevSel.innerHTML = '<option value="">any severity</option>' + Object.keys(counts)
    .map((s) => `<option${s === state.catSev ? ' selected' : ''}>${esc(s)} (${counts[s]})</option>`).join('');
  root.querySelector('#pv-catmeta').textContent = d.loaded
    ? `${d.matched} of ${d.count} definitions`
    : (d.hint || 'catalogue not loaded');
  const rows = d.advisories || [];
  if (!rows.length) {
    box.innerHTML = `<div class="empty">${d.loaded ? 'No definition matches that filter.' : esc(d.hint || 'No issue-definition catalogue is loaded.')}</div>`;
    return;
  }
  box.innerHTML = rows.map((a, i) => `
    <div class="issue-row${state.catSel === i ? ' sel' : ''}" data-i="${i}">
      ${sevChip(a.typical_severity)}
      <span class="issue-name">${esc(a.name)}</span>
      <span class="chip mono">${esc(a.type_index)}</span>
    </div>`).join('');
  box.querySelectorAll('.issue-row').forEach((row) => {
    row.onclick = () => { state.catSel = Number(row.dataset.i); drawCatalogue(); openAdvisory(rows[state.catSel]); };
  });
}

async function openAdvisory(a) {
  try {
    const d = await api.get(`/api/advisories/${encodeURIComponent(a.type_index)}`);
    document.querySelector('.drawer')?.remove();
    const el = document.createElement('div');
    el.className = 'drawer';
    el.innerHTML = `
      <div class="drawer-head">
        ${sevChip(d.typical_severity)}
        <b style="flex:1">${esc(d.name)}</b>
        <button class="act" id="ad-close">✕</button>
      </div>
      <div class="drawer-body">
        <div class="kv"><span class="chip mono">type ${esc(d.type_index)}</span><span class="chip">typically ${esc(d.typical_severity || 'n/a')}</span></div>
        <div><div class="section-label">Description</div>
          ${(d.description_paragraphs || []).map((p) => `<div class="adv-para">${esc(p)}</div>`).join('') || '<span class="mut">no description</span>'}</div>
        ${(d.remediation_paragraphs || []).length ? `<div><div class="section-label">Remediation</div>
          ${d.remediation_paragraphs.map((p) => `<div class="adv-para">${esc(p)}</div>`).join('')}</div>` : ''}
        ${linksBlock('References', d.references)}
        ${linksBlock('Classifications', d.classifications)}
      </div>`;
    root.appendChild(el);
    wireDrawer(el, `Advisory: ${d.name || d.type_index || ''}`);
  } catch (e) { toast(`advisory: ${e.message}`, true); }
}
