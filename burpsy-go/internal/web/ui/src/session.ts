// Session tab: configure session handling rules and login macros. Session rules define how
// burpsy maintains session state (cookies, headers) across requests, and login macros automate
// re-authentication when session is lost.

import { $, esc, getJSON, postJSON, putJSON, delJSON, toast, makeSortable, renderEmptyState } from "./common";

interface SessionRule {
  id: number;
  name: string;
  scope: "all" | { hosts: string[] };
  kind: "cookie" | "header" | "parameter";
  action: "add" | "remove" | "update";
  match: string;
  value: string;
  enabled: boolean;
}

interface LoginMacro {
  id: number;
  name: string;
  request: string;
  success_pattern: string;
  enabled: boolean;
}

interface SessionState {
  rules: SessionRule[];
  macros: LoginMacro[];
  session_valid: boolean;
  last_check_ms: number;
}

export function initSession(): void {
  const section = $("#session");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Configure how burpsy maintains session state across requests</span>
      <span class="grow"></span>
      <button class="go" onclick="checkSession()">Check Session</button>
    </div>
    
    <div class="card">
      <div class="card-title">Session Rules</div>
      <p class="hint">Rules for managing cookies, headers, and parameters across requests</p>
      <div class="row">
        <button class="ghost" onclick="addRule()">+ Add Rule</button>
        <span class="grow"></span>
        <span class="hint" id="session-rules-count">0 rules</span>
      </div>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th data-sort="kind">Type</th>
            <th data-sort="action">Action</th>
            <th>Match</th>
            <th>Value</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="session-rules-body"></tbody>
      </table>
      <div id="session-rules-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Login Macros</div>
      <p class="hint">Automatically re-authenticate when session is lost</p>
      <div class="row">
        <button class="ghost" onclick="addMacro()">+ Add Macro</button>
        <span class="grow"></span>
        <span class="hint" id="session-macros-count">0 macros</span>
      </div>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th>Request</th>
            <th>Success Pattern</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="session-macros-body"></tbody>
      </table>
      <div id="session-macros-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Session Status</div>
      <div id="session-status" class="hint">Loading...</div>
    </div>
  `;

  // Initialize table sorting
  makeSortable('session-rules-body', 'name');
  makeSortable('session-macros-body', 'name');
  
  // Load initial data
  void loadSessionState();
}

async function loadSessionState(): Promise<void> {
  try {
    const response = await fetch("/api/session");
    if (!response.ok) throw new Error(`Failed to load session state: ${response.status}`);
    
    const state = await response.json() as SessionState;
    
    renderRules(state.rules);
    renderMacros(state.macros);
    renderStatus(state);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

function renderRules(rules: SessionRule[]): void {
  const tbody = $("#session-rules-body")!;
  const emptyEl = $("#session-rules-empty")!;
  const countEl = $("#session-rules-count")!;
  
  countEl.textContent = `${rules.length} rules`;
  
  if (rules.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No session rules defined",
      "Add rules to manage cookies, headers, and parameters",
      "🍪",
      7
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = rules.map(r => `
    <tr>
      <td>${esc(r.name)}</td>
      <td>${esc(r.kind)}</td>
      <td>${esc(r.action)}</td>
      <td>${esc(r.match)}</td>
      <td>${esc(r.value)}</td>
      <td>${typeof r.scope === 'string' ? 'All' : esc(r.scope.hosts.join(', '))}</td>
      <td><span class="status-pill ${r.enabled ? 'good' : 'off'}">${r.enabled ? 'Enabled' : 'Disabled'}</span></td>
      <td>
        <button class="ghost small" onclick="toggleRule(${r.id})">${r.enabled ? 'Disable' : 'Enable'}</button>
        <button class="ghost small" onclick="editRule(${r.id})">Edit</button>
        <button class="ghost small" onclick="deleteRule(${r.id})">Delete</button>
      </td>
    </tr>
  `).join('');
}

function renderMacros(macros: LoginMacro[]): void {
  const tbody = $("#session-macros-body")!;
  const emptyEl = $("#session-macros-empty")!;
  const countEl = $("#session-macros-count")!;
  
  countEl.textContent = `${macros.length} macros`;
  
  if (macros.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No login macros defined",
      "Add macros to automatically re-authenticate",
      "🔑",
      5
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = macros.map(m => `
    <tr>
      <td>${esc(m.name)}</td>
      <td>${esc(m.request.slice(0, 50))}${m.request.length > 50 ? '...' : ''}</td>
      <td>${esc(m.success_pattern)}</td>
      <td><span class="status-pill ${m.enabled ? 'good' : 'off'}">${m.enabled ? 'Enabled' : 'Disabled'}</span></td>
      <td>
        <button class="ghost small" onclick="toggleMacro(${m.id})">${m.enabled ? 'Disable' : 'Enable'}</button>
        <button class="ghost small" onclick="editMacro(${m.id})">Edit</button>
        <button class="ghost small" onclick="deleteMacro(${m.id})">Delete</button>
      </td>
    </tr>
  `).join('');
}

function renderStatus(state: SessionState): void {
  const el = $("#session-status")!;
  
  if (state.session_valid) {
    const lastCheck = new Date(state.last_check_ms).toLocaleString();
    el.innerHTML = `
      <div class="status-pill good">Session Valid</div>
      <span class="hint" style="margin-left:8px">Last checked: ${lastCheck}</span>
    `;
  } else {
    el.innerHTML = `
      <div class="status-pill bad">Session Invalid</div>
      <span class="hint" style="margin-left:8px">Session may have expired</span>
    `;
  }
}

// Global functions
window.checkSession = async function(): Promise<void> {
  const el = $("#session-status")!;
  const originalHTML = el.innerHTML;
  
  try {
    el.innerHTML = '<span class="spinner spinner-small"></span> Checking session...';
    
    const response = await fetch("/api/session/check", { method: "POST" });
    if (!response.ok) throw new Error(`Session check failed: ${response.status}`);
    
    const result = await response.json() as { valid: boolean; last_check_ms: number };
    
    renderStatus({
      rules: [],
      macros: [],
      session_valid: result.valid,
      last_check_ms: result.last_check_ms,
    });
    
    toast(result.valid ? "Session is valid" : "Session is invalid", result.valid ? 'success' : 'warning');
  } catch (e) {
    toast((e as Error).message, "error");
    el.innerHTML = originalHTML;
  }
};

window.addRule = function(): void {
  toast("Add rule functionality would open a modal here", 'info');
};

window.editRule = function(id: number): void {
  toast(`Edit rule #${id} functionality would open a modal here`, 'info');
};

window.toggleRule = async function(id: number): Promise<void> {
  try {
    await putJSON(`/api/session/rules/${id}/toggle`, {});
    toast("Rule toggled", 'success');
    void loadSessionState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.deleteRule = async function(id: number): Promise<void> {
  if (!confirm("Are you sure you want to delete this rule?")) return;
  
  try {
    await delJSON(`/api/session/rules/${id}`);
    toast("Rule deleted", 'success');
    void loadSessionState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.addMacro = function(): void {
  toast("Add macro functionality would open a modal here", 'info');
};

window.editMacro = function(id: number): void {
  toast(`Edit macro #${id} functionality would open a modal here`, 'info');
};

window.toggleMacro = async function(id: number): Promise<void> {
  try {
    await putJSON(`/api/session/macros/${id}/toggle`, {});
    toast("Macro toggled", 'success');
    void loadSessionState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.deleteMacro = async function(id: number): Promise<void> {
  if (!confirm("Are you sure you want to delete this macro?")) return;
  
  try {
    await delJSON(`/api/session/macros/${id}`);
    toast("Macro deleted", 'success');
    void loadSessionState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};
