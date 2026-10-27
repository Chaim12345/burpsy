import { api, esc } from '../api.js';
import { toast, runGated } from '../components.js';

// ATTACK - active lanes. These send traffic to a target, so every launch:
//  1. is checked against the engagement scope first (shown before you start),
//  2. goes through the backend's own confirm gate (a dialog with the exact call),
//  3. runs as a task you can watch and cancel.
// Intruder and discovery are not in this build yet; see the note at the bottom.

let root = null;
let poll = null;

export function renderAttack(el) {
  root = el;
  el.innerHTML = `
  <div class="tools-wrap">
    <div class="sc-state"><b>Active lanes</b><span class="mut">These send requests to the target you name. Targets must be in scope.</span></div>

    <label class="tools-lab">Scan one captured exchange</label>
    <div class="sc-form">
      <label>Exchange id<input id="at-xid" inputmode="numeric" placeholder="0" class="sc-port"></label>
      <button class="act primary" id="at-scan">Start scan</button>
    </div>
    <div class="mut">Runs the active scanner against one exchange from Map. The id is the # column in HTTP history.</div>

    <label class="tools-lab">Crawl from seed URLs</label>
    <label class="at-seeds">Seed URLs (one per line)<textarea id="at-seeds" class="tools-box" spellcheck="false" placeholder="https://example.com/"></textarea></label>
    <div class="sc-form">
      <button class="act" id="at-check">Check seeds against scope</button>
      <button class="act primary" id="at-crawl">Start crawl</button>
    </div>
    <div id="at-verdict" class="tools-out at-wrap" hidden></div>

    <label class="tools-lab">Run status</label>
    <div id="at-run" class="tools-out at-wrap"><span class="mut">Nothing started in this session.</span></div>
    <div class="tools-row"><button class="act" id="at-cancel" hidden>Cancel run</button></div>

    <div class="mut">Not in this build yet: Intruder (payload sets, positions) and content discovery.</div>
  </div>`;
  const q = (s) => el.querySelector(s);

  q('#at-check').onclick = async () => {
    const urls = seeds(q);
    if (!urls.length) { toast('enter at least one seed URL', true); return; }
    try {
      const r = await api.post('/api/scope/check', { urls });
      const v = q('#at-verdict'); v.hidden = false;
      v.innerHTML = (r.results || []).map((x) => x.error
        ? `<div>${esc(x.url)}: not a valid http(s) URL</div>`
        : `<div><b>${x.in_scope ? 'IN scope' : 'OUT of scope'}</b> ${esc(x.url)} <span class="mut">(${esc(x.reason || '')})</span></div>`).join('')
        + (r.allow_all ? '<div class="mut">No scope rules are set, so every target is allowed. Set rules in Scope first if you want a boundary.</div>' : '');
    } catch (e) { toast(e.message, true); }
  };

  q('#at-crawl').onclick = async () => {
    const urls = seeds(q);
    if (!urls.length) { toast('enter at least one seed URL', true); return; }
    try {
      const r = await runGated('POST', '/api/crawl', { seeds: urls, protocols: 'specified' });
      if (r === undefined) { toast('crawl not started'); return; }
      watch(q, { kind: 'crawl', id: r.task_id });
      if (r.out_of_scope_seeds && r.out_of_scope_seeds.length) toast(`${r.out_of_scope_seeds.length} seed(s) refused as out of scope`);
    } catch (e) { toast(e.message, true); }
  };

  q('#at-scan').onclick = async () => {
    const id = q('#at-xid').value.trim();
    if (!/^\d+$/.test(id)) { toast('enter the exchange id (a whole number)', true); return; }
    try {
      const r = await runGated('POST', `/api/audit/${id}`, { async: true });
      if (r === undefined) { toast('scan not started'); return; }
      watch(q, { kind: 'scan', id: r.task_id ?? r.id });
    } catch (e) { toast(e.message, true); }
  };
}

function seeds(q) { return q('#at-seeds').value.split('\n').map((s) => s.trim()).filter(Boolean); }

function watch(q, run) {
  if (poll) clearInterval(poll);
  const out = q('#at-run');
  const cancel = q('#at-cancel');
  cancel.hidden = false;
  cancel.onclick = async () => {
    try { await api.post(`/api/tasks/${run.id}/cancel`, {}); toast('cancel requested'); } catch (e) { toast(e.message, true); }
  };
  const tick = async () => {
    try {
      const url = run.kind === 'crawl' ? `/api/crawl?task=${run.id}` : `/api/tasks/${run.id}`;
      const d = await api.get(url);
      const state = run.kind === 'crawl' ? d.state : (d.done ? 'done' : 'running');
      const err = d.error || d.Error || '';
      let facts = '';
      if (run.kind === 'crawl' && d.report) facts = `fetched ${d.report.fetched}, refused ${d.report.refused}, failed ${d.report.failed}`;
      if (run.kind === 'scan' && d.task) facts = d.task.note || d.task.progress || '';
      out.innerHTML = `<div><b>${esc(run.kind)} #${esc(run.id)}</b> - ${esc(state)}${err ? ' - ' + esc(err) : ''}</div>${facts ? `<div>${esc(facts)}</div>` : ''}${run.kind === 'scan' && d.task && d.task.result && d.task.result.summary ? `<div class="mut">${esc(d.task.result.summary)}</div>` : ''}
        <details><summary>Details</summary><pre class="at-pre">${esc(JSON.stringify(d, null, 2).slice(0, 6000))}</pre></details>`;
      if (state !== 'running') { clearInterval(poll); poll = null; cancel.hidden = true; window.dispatchEvent(new Event('altui:refresh-map')); }
    } catch (e) { out.textContent = e.message; clearInterval(poll); poll = null; }
  };
  tick(); poll = setInterval(tick, 2000);
}
