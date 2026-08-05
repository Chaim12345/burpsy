// Sequencer tab: analyse token randomness across captured responses. The sequencer captures
// tokens from responses (cookies, CSRF tokens, etc.) and analyses their entropy to determine
// whether they are sufficiently random to be unpredictable.

import { $, esc, getJSON, postJSON, toast, makeSortable, renderEmptyState, copyText } from "./common";

interface TokenSample {
  position: number;
  token: string;
  length: number;
  charset: string;
  entropy: number;
  is_random: boolean;
  confidence: number;
}

interface PositionAnalysis {
  position: number;
  name: string;
  samples: number;
  avg_entropy: number;
  is_random: boolean;
  character_distribution: Record<string, number>;
}

interface SequencerState {
  positions: PositionAnalysis[];
  samples: TokenSample[];
  running: boolean;
  progress: number;
  total: number;
}

export function initSequencer(): void {
  const section = $("#sequencer");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Analyse token randomness to detect predictable values</span>
      <span class="grow"></span>
      <button class="go" id="seq-start" onclick="startSequencer()">Start Capture</button>
      <button class="ghost" id="seq-stop" onclick="stopSequencer()" style="display:none">Stop</button>
      <span id="seq-progress" class="hint" style="margin-left:8px"></span>
    </div>
    
    <div class="card">
      <div class="card-title">Token Positions</div>
      <p class="hint">Positions where tokens were found in responses</p>
      <table>
        <thead>
          <tr>
            <th data-sort="position">Position</th>
            <th data-sort="name">Name</th>
            <th data-sort="samples">Samples</th>
            <th data-sort="avg_entropy">Avg Entropy</th>
            <th data-sort="is_random">Random?</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="seq-positions-body"></tbody>
      </table>
      <div id="seq-positions-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Recent Samples</div>
      <p class="hint">Most recent token samples captured</p>
      <table>
        <thead>
          <tr>
            <th data-sort="position">Position</th>
            <th>Token</th>
            <th data-sort="length">Length</th>
            <th data-sort="entropy">Entropy</th>
            <th data-sort="is_random">Random?</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="seq-samples-body"></tbody>
      </table>
      <div id="seq-samples-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div id="seq-analysis" style="margin-top:10px"></div>
  `;

  // Initialize table sorting
  makeSortable('seq-positions-body', 'position');
  makeSortable('seq-samples-body', 'position');
  
  // Load initial data
  void loadSequencerState();
}

async function loadSequencerState(): Promise<void> {
  try {
    const response = await fetch("/api/sequencer");
    if (!response.ok) throw new Error(`Failed to load sequencer state: ${response.status}`);
    
    const state = await response.json() as SequencerState;
    
    renderPositions(state.positions);
    renderSamples(state.samples);
    updateProgress(state);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

function renderPositions(positions: PositionAnalysis[]): void {
  const tbody = $("#seq-positions-body")!;
  const emptyEl = $("#seq-positions-empty")!;
  
  if (positions.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No token positions found",
      "Start capture to analyse tokens from responses",
      "🎲",
      6
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = positions.map(p => `
    <tr>
      <td>${p.position}</td>
      <td>${esc(p.name)}</td>
      <td>${p.samples.toLocaleString()}</td>
      <td>${p.avg_entropy.toFixed(2)}</td>
      <td><span class="status-pill ${p.is_random ? 'good' : 'bad'}">${p.is_random ? 'Random' : 'Predictable'}</span></td>
      <td>
        <button class="ghost small" onclick="showPositionAnalysis(${p.position})">Analyse</button>
        <button class="ghost small" onclick="copyPosition(${p.position})">Copy</button>
      </td>
    </tr>
  `).join('');
}

function renderSamples(samples: TokenSample[]): void {
  const tbody = $("#seq-samples-body")!;
  const emptyEl = $("#seq-samples-empty")!;
  
  if (samples.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No samples captured yet",
      "Start capture to see token samples here",
      "📊",
      6
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = samples.slice(0, 50).map(s => `
    <tr>
      <td>${s.position}</td>
      <td>${esc(s.token.slice(0, 30))}${s.token.length > 30 ? '...' : ''}</td>
      <td>${s.length}</td>
      <td>${s.entropy.toFixed(2)}</td>
      <td><span class="status-pill ${s.is_random ? 'good' : 'bad'}">${s.is_random ? 'Random' : 'Predictable'}</span></td>
      <td>
        <button class="ghost small" onclick="copyToken('${esc(s.token)}')">Copy</button>
      </td>
    </tr>
  `).join('');
  
  if (samples.length > 50) {
    tbody.innerHTML += `<tr><td colspan="6" class="hint">Showing 50 of ${samples.length.toLocaleString()} samples</td></tr>`;
  }
}

function updateProgress(state: SequencerState): void {
  const startBtn = $("#seq-start")!;
  const stopBtn = $("#seq-stop")!;
  const progressEl = $("#seq-progress")!;
  
  if (state.running) {
    startBtn.style.display = 'none';
    stopBtn.style.display = 'inline-block';
    progressEl.innerHTML = `<span class="spinner spinner-small"></span> ${state.progress.toLocaleString()} / ${state.total.toLocaleString()}`;
  } else {
    startBtn.style.display = 'inline-block';
    stopBtn.style.display = 'none';
    progressEl.textContent = '';
  }
}

// Global functions
window.startSequencer = async function(): Promise<void> {
  try {
    await postJSON("/api/sequencer/start", {});
    toast("Sequencer started", 'success');
    void loadSequencerState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.stopSequencer = async function(): Promise<void> {
  try {
    await postJSON("/api/sequencer/stop", {});
    toast("Sequencer stopped", 'success');
    void loadSequencerState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.showPositionAnalysis = function(position: number): void {
  toast(`Showing analysis for position ${position}`, 'info');
  // In a real implementation, this would show a detailed modal
};

window.copyPosition = function(position: number): void {
  toast(`Copy position ${position} functionality would copy the position data`, 'info');
};

window.copyToken = function(token: string): void {
  copyText(token, 'token');
};
