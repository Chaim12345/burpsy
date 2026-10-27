import { api, mintConfirm, ConfirmRequired, esc } from './api.js';

export function toast(msg, isErr = false) {
  const root = document.getElementById('toast-root');
  const el = document.createElement('div');
  el.className = 'toast' + (isErr ? ' err' : '');
  if (isErr) el.setAttribute('role', 'alert');
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

// Drawers are dialogs: give them an accessible name, move focus to the close
// button when one opens, and return focus to whatever opened it when it
// closes. The global Escape handler clicks the close button so every close
// path (button, Escape, code) returns focus the same way.
export function wireDrawer(d, label) {
  d.setAttribute('role', 'dialog');
  d.setAttribute('aria-label', label);
  const prev = document.activeElement;
  const closeBtn = d.querySelector('[id$=-close]');
  if (closeBtn) {
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.onclick = () => { d.remove(); if (prev && prev.isConnected) prev.focus(); };
    closeBtn.focus();
  }
}

// The shortcuts that already exist, listed somewhere discoverable: the "?" key
// and the "?" button next to the connection badge both open this.
export function shortcutsDialog() {
  const root = document.getElementById('modal-root');
  const prev = document.activeElement;
  root.innerHTML = `
    <div class="modal-back">
      <div class="modal" id="keys-dialog" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
        <h3>Keyboard shortcuts</h3>
        <div class="keys-list">
          <div><kbd>g</kbd> then <kbd>m</kbd> <kbd>s</kbd> <kbd>p</kbd> <kbd>v</kbd> <kbd>c</kbd> <kbd>t</kbd><span>switch lane: Map, Search, Probe, Prove, Scope, Tools</span></div>
          <div><kbd>j</kbd> / <kbd>k</kbd><span>move the selected history row</span></div>
          <div><kbd>Enter</kbd><span>open the selected row</span></div>
          <div><kbd>Ctrl</kbd>+<kbd>Enter</kbd><span>send, in Probe</span></div>
          <div><kbd>Esc</kbd><span>close the open drawer or this dialog</span></div>
          <div><kbd>?</kbd><span>show this list</span></div>
        </div>
        <div class="modal-btns"><button class="act primary" data-x="ok">Done</button></div>
      </div>
    </div>`;
  const done = root.querySelector('#keys-dialog [data-x=ok]');
  done.onclick = () => { root.innerHTML = ''; if (prev && prev.isConnected) prev.focus(); };
  done.focus();
}

// Human-confirmation dialog for gated calls. Shows the exact call; the human's
// click is the only path to minting a token.
export function confirmDialog({ challenge, method, url, body, preview }) {
  return new Promise((resolve) => {
    const root = document.getElementById('modal-root');
    const risk = esc(challenge.risk || 'sensitive');
    const prettyBody = body === undefined ? '' : (typeof body === 'string' ? body : JSON.stringify(body, null, 2));
    root.innerHTML = `
      <div class="modal-back">
        <div class="modal" role="dialog" aria-modal="true" aria-label="Confirm action">
          <div class="risk">⚠ ${risk} - needs your explicit go</div>
          <h3>Confirm this exact call</h3>
          <div class="why">The backend refuses to run this from an unattended caller.
          Approving mints a one-time token for <b>this exact request only</b> (valid ~${esc(challenge.expires_in ?? 60)}s).</div>
          <div class="call">${esc(method)} ${esc(url)}${prettyBody ? '\n\n' + esc(prettyBody) : ''}</div>
          ${preview ? `<details class="why"><summary>Exact request the server will run, and its hash</summary>
          <div class="hash">sha256 ${esc(preview.body_sha256 || 'n/a')}</div>
          <div class="call">${esc(preview.method || '')} ${esc(preview.url || '')}${preview.body ? '\n\n' + esc(preview.body) : ''}</div></details>` : ''}
          <div class="modal-btns">
            <button class="act" data-x="cancel">Cancel</button>
            <button class="act primary" data-x="ok">I mean it - run it</button>
          </div>
        </div>
      </div>`;
    root.querySelector('[data-x=cancel]').onclick = () => { root.innerHTML = ''; resolve(false); };
    root.querySelector('[data-x=ok]').onclick = () => { root.innerHTML = ''; resolve(true); };
  });
}

export function sevChip(sev) {
  if (!sev) return '';
  return `<span class="sev sev-${esc(sev)}">${esc(sev)}</span>`;
}

// Highlight colours come back from the store, so treat them as data: only the
// known annotate palette is allowed into the inline style; anything else gets
// the neutral default from .hl.
const HL_COLORS = new Set(['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'gray']);
export function hlDot(color) {
  if (!color) return '';
  const c = String(color).toLowerCase();
  const style = HL_COLORS.has(c) ? ` style="background:${c}"` : '';
  return `<span class="hl"${style} title="${esc(color)}"></span>`;
}

// Run a possibly-gated call: on a 428 challenge show the human the exact call,
// and only their click mints the one-time token and retries. Returns the result;
// returns undefined if the human declines.
export async function runGated(method, url, body) {
  try {
    return await api[method.toLowerCase()](url, body);
  } catch (e) {
    if (!(e instanceof ConfirmRequired)) throw e;
    // Mint first (minting is harmless, spending is not), show the human the
    // SERVER-RESOLVED call the token authorizes, and only their click spends it.
    const mint = await mintConfirm(e.challenge.route, method, url, body);
    const ok = await confirmDialog({ challenge: e.challenge, method, url, body, preview: mint.call });
    if (!ok) return undefined;
    return await e.retry(mint.token);
  }
}
