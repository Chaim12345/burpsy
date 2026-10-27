import { api, esc, fmtBytes } from '../api.js';
import { toast, runGated } from '../components.js';

// PROBE — poke it and see: a request workbench (repeater) with an explicit
// dry-run that shows the scope verdict before any byte leaves.

const state = {
  target: '',
  request: '',
  response: null, sending: false,
  // Exact-replay fidelity: when a stored exchange is loaded and the editor is
  // untouched, sends go by from_exchange (the backend replays the stored octets).
  // The textarea is text: LF and UTF-8 only, so a typed/edited send is the
  // labeled text path, never a silent corruption of the original bytes.
  fromExchange: null, loadedText: null, binaryLoaded: false,
};

export async function renderProbe(el) {
  el.innerHTML = `
    <div id="probe-targetbar">
      <span class="pane-title">Probe</span>
      <input class="target" id="p-target" spellcheck="false" placeholder="enter a target you are authorized to test, e.g. http://host:port" value="${esc(state.target)}">
      <button class="act" id="p-dry" title="Apply edits and show the scope verdict without sending">Dry run</button>
      <button class="act primary" id="p-send">Send</button>
    </div>
    <div id="probe-split">
      <div id="probe-req">
        <div class="pane-head"><span class="pane-title">Request</span><span class="mut" id="p-reqmeta"></span></div>
        <textarea class="editor" id="p-editor" spellcheck="false" placeholder="GET / HTTP/1.1&#10;Host: host:port"></textarea>
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
  editor.oninput = () => { state.request = editor.value; state.binaryLoaded = false; updateReqMeta(); };
  el.querySelector('#p-target').oninput = (e) => { state.target = e.target.value; };
  el.querySelector('#p-send').onclick = () => doSend(false);
  el.querySelector('#p-dry').onclick = () => doSend(true);
  updateReqMeta();

}

// Called by app.js after the Probe view is rendered; loads a stored exchange.
export async function loadExchange(id) {
  const editor = document.getElementById('p-editor');
  if (id == null || !editor) return;
  {
    try {
      const ex = await api.get(`/api/exchange/${id}`);
      const msg = await api.get(`/api/message/${ex.request}?max_bytes=65536`);
      state.target = `http${ex.tls ? 's' : ''}://${ex.host}:${ex.port}`;
      const text = msg.text != null ? msg.text : (msg.head || '') + '\r\n\r\n' + (msg.window_text || '');
      state.fromExchange = id;
      state.binaryLoaded = msg.window_utf8 === false;
      if (state.binaryLoaded) {
        // Non-UTF-8 request bytes cannot survive a textarea. Show a placeholder;
        // Send replays the exact stored octets via from_exchange.
        state.loadedText = `[binary request #${id}: ${msg.len ?? '?'} bytes - Send replays the exact stored bytes; typing here switches to the text path]`;
        state.request = '';
      } else {
        state.loadedText = text.replace(/\r\n/g, '\n');
        state.request = text;
      }
      document.querySelector('#p-target').value = state.target;
      editor.value = state.loadedText;
      state.response = null;
      drawResp();
      updateReqMeta();
      toast(`exchange #${id} loaded into Probe`);
    } catch (e) { toast(`load exchange: ${e.message}`, true); }
  }
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
  if (!target) { toast('set a target first, e.g. http://host:port', true); return; }
  const editor = document.getElementById('p-editor');
  const pristine = state.fromExchange != null && editor.value === state.loadedText;
  const body = pristine
    ? { from_exchange: state.fromExchange, target, dry_run: dry }
    : { request: normalizedRaw(), target, dry_run: dry };
  if (!pristine && !dry) {
    toast('text path: LF normalized to CRLF; non-UTF-8 bytes are not representable here', false);
  }
  state.sending = true;
  document.getElementById('p-send').disabled = true;
  try {
    const r = await runGated('POST', '/api/repeater/send', body);
    if (r === undefined) return; // human declined the confirm dialog
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
    toast(e.message, true);
    const v = document.getElementById('p-verdict');
    v.style.display = ''; v.className = 'verdict no'; v.textContent = `✗ ${e.message}`;
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
