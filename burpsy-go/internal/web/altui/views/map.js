import { api, esc, fmtTime, fmtBytes } from '../api.js';
import { toast, runGated, hlDot, sevChip } from '../components.js';

// MAP - what do we know: live sitemap tree + HTTP history with filters.

const state = {
  tree: [], rows: [], selNode: null, selExchange: null,
  filters: { q: '', method: '', status: '', inScopeOnly: false },
  open: new Set(),
};

export async function renderMap(el) {
  el.innerHTML = `
    <div class="pane" id="map-left">
      <div class="pane-head"><span class="pane-title">Site map</span><span class="mut" id="map-stats"></span></div>
      <div class="pane-body"><div class="tree" id="map-tree"><div class="spin">loading…</div></div></div>
    </div>
    <div class="pane" id="map-right">
      <div class="pane-head filters">
        <span class="pane-title">HTTP history</span>
        <input type="search" id="f-q" placeholder="filter path/host…" value="">
        <select id="f-method"><option value="">any method</option><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select>
        <select id="f-status"><option value="">any status</option><option value="2">2xx</option><option value="3">3xx</option><option value="4">4xx</option><option value="5">5xx</option></select>
        <label class="mut" style="font-size:12px"><input type="checkbox" id="f-scope"> in scope</label>
        <button class="act" id="f-export" title="Download the visible rows as one JSON file: request/response bytes from the store, base64, by message id">Export</button>
      </div>
      <div class="pane-body"><div id="map-rows"><div class="spin">loading…</div></div></div>
    </div>`;
  el.querySelector('#f-q').oninput = (e) => { state.filters.q = e.target.value; drawRows(); };
  el.querySelector('#f-method').onchange = (e) => { state.filters.method = e.target.value; drawRows(); };
  el.querySelector('#f-status').onchange = (e) => { state.filters.status = e.target.value; drawRows(); };
  el.querySelector('#f-scope').onchange = (e) => { state.filters.inScopeOnly = e.target.checked; drawRows(); };
  el.querySelector('#f-export').onclick = exportVisible;
  await refreshMap();
}

export async function refreshMap() {
  try {
    const [sm, hist] = await Promise.all([api.get('/api/sitemap'), api.get('/api/history')]);
    state.tree = sm.tree || [];
    state.rows = hist || [];
    const st = document.getElementById('map-stats');
    if (st) st.textContent = `${sm.exchanges ?? 0} exchanges · ${sm.nodes ?? 0} nodes${sm.in_flight ? ` · ${sm.in_flight} in flight` : ''}`;
    drawTree();
    drawRows();
  } catch (e) {
    toast(`map refresh failed: ${e.message}`, true);
  }
}

function drawTree() {
  const root = document.getElementById('map-tree');
  if (!root) return;
  if (!state.tree.length) { root.innerHTML = '<div class="empty">No traffic recorded yet.<br>Probe sends and any traffic captured by the proxy appear here.</div>'; return; }
  root.innerHTML = state.tree.map((n) => treeNode(n)).join('');
  root.querySelectorAll('.tree-row').forEach((row) => {
    row.onclick = () => {
      const key = row.dataset.key;
      if (row.dataset.haskids === '1') {
        state.open.has(key) ? state.open.delete(key) : state.open.add(key);
      }
      state.selNode = key;
      drawTree(); drawRows();
    };
  });
}

function treeNode(n) {
  const kids = n.children || [];
  const isOpen = state.open.has(n.key);
  const sel = state.selNode === n.key ? ' sel' : '';
  const toggle = kids.length ? (isOpen ? '▾' : '▸') : '';
  const sev = n.worst_severity && n.subtree_issues > 0 ? sevChip(n.worst_severity) : '';
  return `<div class="tree-node">
    <div class="tree-row${sel}" data-key="${esc(n.key)}" data-haskids="${kids.length ? 1 : 0}" title="${esc(n.key)}">
      <span class="tree-toggle">${toggle}</span>
      <span>${esc(n.segment || n.path)}</span>
      <span class="tree-count">${n.subtree_exchanges ?? ''}</span>
      <span class="tree-sev">${sev}</span>
    </div>
    ${kids.length && isOpen ? `<div class="tree-children">${kids.map(treeNode).join('')}</div>` : ''}
  </div>`;
}

function filteredRows() {
  const f = state.filters;
  return state.rows.filter((r) => {
    if (f.q) {
      const hay = `${r.method} ${r.host}:${r.port}${r.path}`.toLowerCase();
      if (!hay.includes(f.q.toLowerCase())) return false;
    }
    if (f.method && r.method !== f.method) return false;
    if (f.status && String(r.status || '')[0] !== f.status) return false;
    if (f.inScopeOnly && state.selNode && !`${r.host}:${r.port}`.includes(state.selNode.replace(/^https?:\/\//, ''))) return false;
    if (state.selNode && !f.inScopeOnly) {
      const prefix = state.selNode.replace(/\0.*$/, '');
      const url = `http${r.tls ? 's' : ''}://${r.host}:${r.port}${r.path}`;
      if (!url.startsWith(prefix.split('\0')[0])) {
        // node keys are prefixes of the request URL; be lenient on mismatch
        if (!state.selNode.includes(`${r.host}`)) return false;
      }
    }
    return true;
  });
}

function drawRows() {
  const box = document.getElementById('map-rows');
  if (!box) return;
  const rows = filteredRows();
  if (!rows.length) { box.innerHTML = '<div class="empty">Nothing matches.</div>'; return; }
  box.innerHTML = `<table class="rows"><thead><tr>
    <th></th><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Len</th><th>MIME</th><th>Time</th>
  </tr></thead><tbody>${rows.map((r) => `
    <tr class="data" data-id="${r.id}">
      <td>${hlDot(r.highlight)}</td>
      <td class="mono mut">${r.id}</td>
      <td class="mono m-${esc(r.method)}">${esc(r.method)}</td>
      <td class="mono urlcell" title="${esc(r.host)}:${r.port}${esc(r.path)}">${esc(r.host)}:${r.port}${esc(r.path)}</td>
      <td class="st st-${String(r.status || '')[0] || ''}">${r.status ?? '-'}</td>
      <td class="mono mut">${fmtBytes(r.response_len)}</td>
      <td class="mut">${esc(r.mime || '')}</td>
      <td class="mono mut">${fmtTime(r.started_ms)}</td>
    </tr>`).join('')}</tbody></table>`;
  box.querySelectorAll('tr.data').forEach((tr) => { tr.onclick = () => openExchange(Number(tr.dataset.id)); });
}

async function openExchange(id) {
  openExchangeDrawer(id, document.getElementById('view-map'));
}

// openExchangeDrawer fetches one recorded exchange and shows it in the shared
// drawer. Exported so Search results open the same drawer Map rows do. Reads
// only; the drawer's annotate and scope actions stay behind their own clicks.
export async function openExchangeDrawer(id, container) {
  try {
    const ex = await api.get(`/api/exchange/${id}`);
    const [req, resp] = await Promise.all([
      api.get(`/api/message/${ex.request}?max_bytes=65536`).catch(() => null),
      ex.response ? api.get(`/api/message/${ex.response}?max_bytes=65536`).catch(() => null) : null,
    ]);
    showDrawer(ex, req, resp, container);
  } catch (e) { toast(`exchange: ${e.message}`, true); }
}

function fmtMsg(m, fallback) {
  if (!m) return fallback;
  if (m.text != null) return m.text; // unwindowed shape
  let out = (m.head || '');
  const body = m.window_text || '';
  if (m.window_utf8 === false) out += '\r\n\r\n[non-UTF-8 body - exact octets available via body_base64]';
  else out += '\r\n\r\n' + body;
  if (m.next_offset != null) out += `\n[truncated at ${m.max_bytes} bytes - message continues]`;
  return out;
}

function showDrawer(ex, req, resp, container) {
  document.querySelector('.drawer')?.remove();
  const d = document.createElement('div');
  d.className = 'drawer';
  d.innerHTML = `
    <div class="drawer-head">
      <b class="mono m-${esc(ex.method)}">${esc(ex.method)}</b>
      <span class="mono" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(ex.host)}:${ex.port}${esc(ex.path)}</span>
      <span class="st st-${String(ex.status || '')[0] || ''}">${ex.status ?? '-'}</span>
      <button class="act" id="dx-probe">Send to Probe</button>
      <button class="act" id="dx-scope" title="Add this host:port to the engagement scope (needs your explicit confirm)">Add to scope</button>
      <button class="act" id="dx-close">✕</button>
    </div>
    <div class="drawer-body">
      <div class="kv mut" style="font-size:12px">
        <span class="chip">${esc(ex.protocol || 'http')}</span>
        <span class="chip">${fmtBytes(ex.response_len)}</span>
        <span class="chip">${esc(ex.mime || 'no mime')}</span>
        <span class="chip">${fmtTime(ex.started_ms)}</span>
        <span class="chip">source: ${esc(ex.source || '')}</span>
      </div>
      <div>
        <div class="section-label">Request</div>
        <div class="msgview" id="dx-req">${esc(fmtMsg(req, '(unavailable)'))}</div>
      </div>
      <div>
        <div class="section-label">Response</div>
        <div class="msgview" id="dx-resp">${esc(fmtMsg(resp, '(no response recorded)'))}</div>
      </div>
      <div>
        <div class="section-label">Annotate</div>
        <div class="kv">
          <select id="dx-hl">
            <option value="">no highlight</option>
            <option value="red">red</option><option value="orange">orange</option>
            <option value="yellow">yellow</option><option value="green">green</option>
            <option value="cyan">cyan</option><option value="blue">blue</option>
            <option value="pink">pink</option><option value="gray">gray</option>
          </select>
          <input id="dx-notes" placeholder="note…" style="flex:1" value="${esc(ex.notes ?? '')}">
          <button class="act" id="dx-save">Save</button>
        </div>
      </div>
    </div>`;
  (container || document.getElementById('view-map')).appendChild(d);
  d.querySelector('#dx-close').onclick = () => d.remove();
  d.querySelector('#dx-hl').value = ex.highlight || '';
  d.querySelector('#dx-probe').onclick = () => {
    window.dispatchEvent(new CustomEvent('altui:probe-load', { detail: { exchange: ex.id } }));
    d.remove();
  };
  d.querySelector('#dx-save').onclick = async () => {
    const body = { highlight: d.querySelector('#dx-hl').value, notes: d.querySelector('#dx-notes').value };
    try {
      await runGated('PATCH', `/api/exchange/${ex.id}`, body);
      toast('annotation saved');
      refreshMap();
    } catch (e) { toast(e.message, true); }
  };
  d.querySelector('#dx-scope').onclick = async () => {
    const body = { action: 'include', pattern: ex.host, port: ex.port };
    try {
      const r = await runGated('POST', '/api/scope', body);
      if (r !== undefined) toast(`${ex.host}:${ex.port} added to scope`);
    } catch (e) { toast(e.message, true); }
  };
}

// exportVisible downloads the rows the history table currently shows as one
// JSON file. The backend (POST /api/repeater/history-export, a read that sends
// nothing) resolves each row's request/response bytes from the store by
// message id, so binary bodies round-trip byte-identical, and rows it cannot
// serve come back listed under "skipped" rather than dropped.
async function exportVisible() {
  const rows = filteredRows().slice().reverse(); // file order: oldest first, as recorded
  if (!rows.length) { toast('nothing to export: no visible rows', true); return; }
  const entries = rows.map((r) => ({
    request_msg_id: r.request ?? null,
    response_msg_id: r.response ?? null,
    exchange_id: r.id,
    kind: 'http',
    sent_at: r.started_ms ? new Date(r.started_ms).toISOString() : undefined,
  }));
  const f = state.filters;
  const desc = [f.q && `path/host contains "${f.q}"`, f.method && `method ${f.method}`, f.status && `status ${f.status}xx`, f.inScopeOnly && 'in scope only']
    .filter(Boolean).join(', ');
  const body = {
    tab: 'http-history',
    target: desc ? `visible rows (${desc})` : 'all visible rows',
    note: 'recorded HTTP history exported from the alternative console',
    entries,
  };
  let res;
  try {
    res = await fetch('/api/repeater/history-export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) { toast(`export failed: ${e.message}`, true); return; }
  if (!res.ok) { toast(`export refused: ${await res.text()}`, true); return; }
  const file = await res.json();
  const cd = res.headers.get('Content-Disposition') || '';
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || 'burpsy-history-export.json';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
  const skipped = (file.skipped || []).length;
  toast(`exported ${file.exported} of ${file.requested} rows` +
    (skipped ? ` · ${skipped} skipped (listed in the file)` : '') +
    (file.missing_responses ? ` · ${file.missing_responses} without a recorded response` : ''));
}
