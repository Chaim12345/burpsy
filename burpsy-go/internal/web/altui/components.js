import { api, mintConfirm, ConfirmRequired, esc } from './api.js';

export function toast(msg, isErr = false) {
  const root = document.getElementById('toast-root');
  const el = document.createElement('div');
  el.className = 'toast' + (isErr ? ' err' : '');
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => el.remove(), 4200);
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

export function hlDot(color) {
  if (!color) return '';
  return `<span class="hl" style="background:${esc(color)}" title="${esc(color)}"></span>`;
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
