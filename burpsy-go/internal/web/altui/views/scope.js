import { api, esc } from '../api.js';
import { toast, runGated } from '../components.js';

// SCOPE - what every sender (Probe, and any future lane) is allowed to reach.
// Reading and checking changes nothing. Add/remove/enable/disable change what the
// backend allows, so each one is staged and only an explicit Apply click sends it.

let root = null;

export async function renderScope(el) {
  root = el;
  el.innerHTML = '<div class="tools-wrap" id="sc-wrap"><div class="spin">loading…</div></div>';
  await load();
}
export async function refreshScope() { if (root) await load(); }

async function load() {
  const wrap = root.querySelector('#sc-wrap');
  let s;
  try { s = await api.get('/api/scope'); } catch (e) { wrap.innerHTML = `<div class="empty">Could not read scope: ${esc(e.message)}</div>`; return; }
  const rules = s.rules || [];
  const mode = s.allow_all ? 'Allow all' : (rules.some((r) => r.kind === 'Include' && r.enabled) ? 'Restricted to include rules' : 'Allow all (no include rules)');
  wrap.innerHTML = `
    <div class="sc-state"><b>${esc(mode)}</b>
      <span class="mut">${rules.length} rule${rules.length === 1 ? '' : 's'}${s.drop_out_of_scope ? ' · out-of-scope requests are dropped' : ''}</span></div>
    ${rules.length ? '' : '<div class="mut">No rules: every target is allowed. Add an include rule to restrict what Probe can reach.</div>'}
    <div id="sc-rules">${rules.map((r, i) => `
      <div class="sc-rule ${r.enabled ? '' : 'off'}">
        <span class="chip">${esc(r.kind)}</span>
        <code>${esc(r.protocol ? r.protocol + '://' : '')}${esc(r.host)}${r.port ? ':' + r.port : ''}${esc(r.path || '')}</code>
        <span class="sc-btns">
          <button class="act" data-a="toggle" data-i="${i}">${r.enabled ? 'Disable' : 'Enable'}</button>
          <button class="act" data-a="remove" data-i="${i}">Remove</button>
        </span>
      </div>`).join('')}</div>
    <label class="tools-lab">Check a URL (changes nothing, sends nothing)</label>
    <div class="tools-row"><input id="sc-url" class="tools-key" placeholder="https://host/path" spellcheck="false" autocomplete="off"><button class="act" id="sc-check">Check</button></div>
    <div id="sc-verdict" class="tools-out" hidden></div>
    <label class="tools-lab">Add a rule</label>
    <div class="sc-form">
      <label>Kind<select id="sc-kind"><option value="include">Include</option><option value="exclude">Exclude</option></select></label>
      <label class="sc-grow">Host pattern<input id="sc-pat" placeholder="example.com or *.example.com" spellcheck="false" autocomplete="off"></label>
      <label class="sc-grow">Path prefix (optional)<input id="sc-path" placeholder="/admin" spellcheck="false" autocomplete="off"></label>
      <label>Port (optional)<input id="sc-port" placeholder="443" inputmode="numeric" class="sc-port"></label>
      <label>Scheme<select id="sc-proto"><option value="">http and https</option><option>http</option><option>https</option></select></label>
      <button class="act primary" id="sc-add">Stage rule</button>
    </div>
    <div id="sc-stage" class="sc-stage" hidden></div>`;
  wrap.querySelectorAll('[data-a]').forEach((b) => {
    b.onclick = () => {
      const r = rules[+b.dataset.i];
      const base = { kind: r.kind.toLowerCase(), pattern: r.host, path: r.path || '', port: r.port, protocol: r.protocol || '' };
      const label = `${b.dataset.a === 'remove' ? 'Remove' : (r.enabled ? 'Disable' : 'Enable')} ${r.kind.toLowerCase()} rule for ${r.host}${r.port ? ':' + r.port : ''}${r.path || ''}`;
      stage(wrap, label, b.dataset.a === 'remove' ? { action: 'remove', ...base } : { action: 'toggle', ...base, enabled: !r.enabled });
    };
  });
  wrap.querySelector('#sc-check').onclick = async () => {
    const u = wrap.querySelector('#sc-url').value.trim();
    const v = wrap.querySelector('#sc-verdict');
    if (!u) { toast('enter a URL to check', true); return; }
    try {
      const r = await api.post('/api/scope/check', { urls: [u] });
      const x = (r.results || [])[0] || {};
      v.hidden = false;
      v.textContent = x.error ? `Not a valid http(s) URL: ${x.error}` : `${x.in_scope ? 'IN scope' : 'OUT of scope'} (reason: ${x.reason || 'n/a'}). Proxy forwards: ${x.proxy_forwards ? 'yes' : 'no'}`;
    } catch (e) { toast(e.message, true); }
  };
  wrap.querySelector('#sc-add').onclick = () => {
    const pat = wrap.querySelector('#sc-pat').value.trim();
    if (!pat) { toast('enter a host pattern', true); return; }
    const kind = wrap.querySelector('#sc-kind').value;
    const body = { action: kind, pattern: pat };
    const path = wrap.querySelector('#sc-path').value.trim(); if (path) body.path = path;
    const port = wrap.querySelector('#sc-port').value.trim();
    if (port) { const n = Number(port); if (!Number.isInteger(n) || n < 1 || n > 65535) { toast('port must be 1-65535', true); return; } body.port = n; }
    const proto = wrap.querySelector('#sc-proto').value; if (proto) body.protocol = proto;
    stage(wrap, `Add ${kind} rule: ${proto ? proto + '://' : ''}${pat}${port ? ':' + port : ''}${path}`, body);
  };
}

function stage(wrap, label, body) {
  const st = wrap.querySelector('#sc-stage');
  st.hidden = false;
  st.innerHTML = `<div><b>${esc(label)}</b><div class="mut">This changes what the backend allows. Nothing is sent until you apply it.</div></div>
    <div class="tools-row"><button class="act primary" id="sc-apply">Apply</button><button class="act" id="sc-cancel">Cancel</button></div>`;
  st.querySelector('#sc-cancel').onclick = () => { st.hidden = true; };
  st.querySelector('#sc-apply').onclick = async () => {
    try { const r = await runGated('POST', '/api/scope', body); if (r !== undefined) toast('scope updated'); } catch (e) { toast(e.message, true); }
    await load();
  };
}
