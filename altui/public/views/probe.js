import { api, esc, fmtBytes, ConfirmRequired, mintConfirm } from '../api.js';
import { toast, confirmDialog } from '../components.js';

// PROBE — poke it and see: a request workbench (repeater) with an explicit
// dry-run that shows the scope verdict before any byte leaves.

const state = {
  target: 'http://127.0.0.1:28099',
  request: 'GET / HTTP/1.1\r\nHost: 127.0.0.1:28099\r\n\r\n',
  response: null, sending: false,
};

export async function renderProbe(el) {
  el.innerHTML = `
    <div id="probe-targetbar">
      <span class="pane-title">Probe</span>
      <input class="target" id="p-target" spellcheck="false" placeholder="http://host:port" value="${esc(state.target)}">
      <button class="act" id="p-dry" title="Apply edits and show the scope verdict without sending">Dry run</button>
      <button class="act primary" id="p-send">Send</button>
    </div>
    <div id="probe-split">
      <div id="probe-req">
        <div class="pane-head"><span class="pane-title">Request</span><span class="mut" id="p-reqmeta"></span></div>
        <textarea class="editor" id="p-editor" spellcheck="false"></textarea>
        <div class="verdict" id="p-verdict" style="display:none"></div>
      </div>
      <div id="probe-resp">
        <div class="pane-head"><span class="pane-title">Response</span><span class="mut" id="p-respmeta"></span></div>
        <div class="resp-meta" id="p-meta" style="display:none"></div>
        <div class="msgview" id="p-resp" style="flex:1;border:0;border-radius:0;max-height:none">Send a request to see the response here.</div>
      </div>
    </div>`;
  const editor = el.querySelector('#p-editor');
  editor.value = state.request.replace(/\r\n/g, '\n');
  editor.oninput = () => { state.request = editor.value; updateReqMeta(); };
  el.querySelector('#p-target').oninput = (e) => { state.target = e.target.value; };
  el.querySelector('#p-send').onclick = () => doSend(false);
  el.querySelector('#p-dry').onclick = () => doSend(true);
  updateReqMeta();

  window.addEventListener('altui:probe-load', async (ev) => {
    const id = ev.detail?.exchange;
    if (id == null) return;
    try {
      const ex = await api.get(`/api/exchange/${id}`);
      const msg = await api.get(`/api/message/${ex.request}`);
      state.target = `http${ex.tls ? 's' : ''}://${ex.host}:${ex.port}`;
      state.request = msg.text;
      document.querySelector('#p-target').value = state.target;
      editor.value = msg.text;
      state.response = null;
      drawResp();
      updateReqMeta();
      document.querySelector('[data-view=probe]').click();
      toast(`exchange #${id} loaded into Probe`);
    } catch (e) { toast(`load exchange: ${e.message}`, true); }
  });
}

function updateReqMeta() {
  const m = document.getElementById('p-reqmeta');
  if (m) m.textContent = `${state.request.length} bytes`;
}

function normalizedRaw() {
  // HTTP on the wire is CRLF; the editor is a textarea (LF). Send CRLF bytes.
  return state.request.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
}

async function doSend(dry) {
  if (state.sending) return;
  const target = state.target.trim();
  if (!target) { toast('set a target first, e.g. http://127.0.0.1:28099', true); return; }
  const body = { request: normalizedRaw(), target, dry_run: dry };
  state.sending = true;
  document.getElementById('p-send').disabled = true;
  try {
    const r = await api.post('/api/repeater/send', body);
    if (dry) {
      const v = document.getElementById('p-verdict');
      v.style.display = '';
      v.className = 'verdict ' + (r.scope?.allowed ? 'ok' : 'no');
      v.textContent = `${r.scope?.allowed ? '✓ in scope' : '✗ OUT OF SCOPE — refused'} · ${r.scope?.explanation || ''}`;
      if (r.request_utf8 === false) toast('note: request is not valid UTF-8', true);
    } else {
      state.response = r;
      drawResp();
      window.dispatchEvent(new CustomEvent('altui:refresh-map'));
    }
  } catch (e) {
    if (e instanceof ConfirmRequired) {
      const ok = await confirmDialog({ challenge: e.challenge, method: 'POST', url: '/api/repeater/send', body });
      if (ok) {
        try {
          const tok = await mintConfirm(e.challenge.route, 'POST', '/api/repeater/send', body);
          const r = await e.retry(tok.token);
          state.response = r; drawResp();
          window.dispatchEvent(new CustomEvent('altui:refresh-map'));
        } catch (e2) { toast(e2.message, true); }
      }
    } else {
      toast(e.message, true);
      const v = document.getElementById('p-verdict');
      v.style.display = ''; v.className = 'verdict no'; v.textContent = `✗ ${e.message}`;
    }
  } finally {
    state.sending = false;
    document.getElementById('p-send').disabled = false;
  }
}

function drawResp() {
  const box = document.getElementById('p-resp');
  const meta = document.getElementById('p-meta');
  const rm = document.getElementById('p-respmeta');
  const r = state.response;
  if (!r) { box.textContent = 'Send a request to see the response here.'; meta.style.display = 'none'; if (rm) rm.textContent = ''; return; }
  meta.style.display = '';
  meta.innerHTML = `
    <span class="st st-${String(r.status || '')[0] || ''}">${r.status ?? '—'}</span>
    <span class="mut">${r.duration_ms ?? 0} ms</span>
    <span class="mut">${fmtBytes(r.response?.length ?? 0)}</span>
    ${r.exchange_id != null ? `<span class="mut">exchange #${r.exchange_id}</span>` : ''}`;
  box.textContent = r.response || '(empty response)';
}
