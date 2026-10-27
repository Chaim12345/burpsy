import { api, esc } from '../api.js';
import { toast } from '../components.js';

// TOOLS — offline helpers: decode, encode, hash, compare. Nothing here sends
// traffic; every call is computed by the backend from the text you type.

const ENCODINGS = ['url', 'html', 'base64', 'base64url', 'hex', 'gzip', 'deflate', 'octal', 'binary', 'rot13', 'ascii'];
const HASHES = ['sha256', 'sha1', 'md5', 'sha512', 'sha3-256', 'blake2b-256', 'hmac-sha256'];
const state = { tab: 'decode' };

export function renderTools(el) {
  el.innerHTML = `
    <div class="tools-wrap">
      <div class="tools-tabs" role="tablist">
        ${['decode', 'encode', 'hash', 'compare'].map((t) => `<button class="act tools-tab" role="tab" data-tab="${t}">${t[0].toUpperCase() + t.slice(1)}</button>`).join('')}
      </div>
      <div id="tools-body"></div>
    </div>`;
  el.querySelectorAll('.tools-tab').forEach((b) => { b.onclick = () => { state.tab = b.dataset.tab; draw(el); }; });
  draw(el);
}

function opts(list, sel) { return list.map((x) => `<option${x === sel ? ' selected' : ''}>${esc(x)}</option>`).join(''); }

function draw(el) {
  el.querySelectorAll('.tools-tab').forEach((b) => b.classList.toggle('primary', b.dataset.tab === state.tab));
  const body = el.querySelector('#tools-body');
  if (state.tab === 'decode' || state.tab === 'encode') {
    const dec = state.tab === 'decode';
    body.innerHTML = `
      <div class="tools-row"><label>${dec ? 'Decode with' : 'Encode as'}
        <select id="t-enc">${dec ? '<option value="auto">auto-detect layers</option>' : ''}${opts(ENCODINGS, 'base64')}</select></label>
        <button class="act primary" id="t-go">${dec ? 'Decode' : 'Encode'}</button></div>
      <label class="tools-lab">Input</label><textarea id="t-in" class="tools-box" spellcheck="false"></textarea>
      <label class="tools-lab">Output <span class="mut" id="t-meta"></span></label><pre id="t-out" class="tools-out"></pre>`;
    body.querySelector('#t-go').onclick = async () => {
      const encoding = body.querySelector('#t-enc').value;
      const input = body.querySelector('#t-in').value;
      try {
        const r = await api.post(`/api/tools/${state.tab}`, dec ? { input, encoding: encoding === 'auto' ? '' : encoding } : { input, encoding });
        body.querySelector('#t-out').textContent = r.output?.text ?? '';
        const bits = [];
        if (r.layers && r.layers.length) bits.push('layers: ' + r.layers.join(' > '));
        if (r.output) bits.push(`${r.output.len} bytes${r.output.utf8 === false ? ', not valid UTF-8' : ''}`);
        if (r.partial) bits.push('partial output');
        body.querySelector('#t-meta').textContent = bits.join(' · ');
      } catch (e) { body.querySelector('#t-out').textContent = ''; body.querySelector('#t-meta').textContent = ''; toast(e.message, true); }
    };
  } else if (state.tab === 'hash') {
    body.innerHTML = `
      <div class="tools-row"><label>Algorithm <select id="t-alg">${opts(HASHES, 'sha256')}</select></label>
        <label>Output <select id="t-outfmt">${opts(['hex', 'base64', 'base64url'], 'hex')}</select></label>
        <button class="act primary" id="t-go">Hash</button></div>
      <label class="tools-lab">Input (text)</label><textarea id="t-in" class="tools-box" spellcheck="false"></textarea>
      <label class="tools-lab">HMAC key (hmac-* only)</label><input id="t-key" class="tools-key" spellcheck="false" autocomplete="off">
      <label class="tools-lab">Digest</label><pre id="t-out" class="tools-out"></pre>`;
    body.querySelector('#t-go').onclick = async () => {
      const algorithm = body.querySelector('#t-alg').value;
      const req = { input: body.querySelector('#t-in').value, algorithm, output: body.querySelector('#t-outfmt').value };
      const key = body.querySelector('#t-key').value;
      if (key) req.key = key;
      try { const r = await api.post('/api/tools/hash', req); body.querySelector('#t-out').textContent = r.output?.text ?? ''; }
      catch (e) { body.querySelector('#t-out').textContent = ''; toast(e.message, true); }
    };
  } else {
    body.innerHTML = `
      <div class="tools-row"><label>Compare by <select id="t-gran">${opts(['words', 'bytes'], 'words')}</select></label>
        <button class="act primary" id="t-go">Compare</button></div>
      <div class="tools-two"><div><label class="tools-lab">A</label><textarea id="t-a" class="tools-box" spellcheck="false"></textarea></div>
      <div><label class="tools-lab">B</label><textarea id="t-b" class="tools-box" spellcheck="false"></textarea></div></div>
      <label class="tools-lab">Result</label><div id="t-out" class="tools-out"></div>`;
    body.querySelector('#t-go').onclick = async () => {
      try {
        const r = await api.post('/api/tools/compare', { a: body.querySelector('#t-a').value, b: body.querySelector('#t-b').value, granularity: body.querySelector('#t-gran').value });
        const out = body.querySelector('#t-out');
        const A = new TextEncoder().encode(body.querySelector('#t-a').value), B = new TextEncoder().encode(body.querySelector('#t-b').value);
        const sl = (buf, off, len) => new TextDecoder().decode(buf.slice(off, off + len));
        if (r.identical) { out.textContent = 'Identical.'; return; }
        const ops = (r.ops || []).filter((o) => o.kind !== 'equal');
        out.innerHTML = `<div class="mut">${esc(r.granularity)}: ${r.deleted_tokens} removed, ${r.inserted_tokens} added${r.truncated ? ' (truncated)' : ''}</div>` +
          ops.map((o) => `<div class="cmp-op cmp-${esc(o.kind)}"><b>${esc(o.kind)}</b> ${o.a_len ? `<code class="cmp-a">${esc(sl(A, o.a_offset, o.a_len))}</code>` : ''}${o.a_len && o.b_len ? ' &rarr; ' : ''}${o.b_len ? `<code class="cmp-b">${esc(sl(B, o.b_offset, o.b_len))}</code>` : ''} <span class="mut">A@${o.a_offset} B@${o.b_offset}</span></div>`).join('');
      } catch (e) { toast(e.message, true); }
    };
  }
}
