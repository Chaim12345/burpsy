// Match & Replace tab: define rules that rewrite requests and responses on the fly. Each rule
// has a match pattern (regex or literal) and a replacement string. Rules are applied in order,
// and the first match wins.

import { $, esc, getJSON, postJSON, putJSON, delJSON, toast, makeSortable, renderEmptyState } from "./common";

interface MatchReplaceRule {
  id: number;
  name: string;
  match: string;
  replacement: string;
  is_regex: boolean;
  case_sensitive: boolean;
  scope: "request" | "response" | "both";
  enabled: boolean;
}

interface MatchReplaceState {
  rules: MatchReplaceRule[];
  enabled: boolean;
}

export function initMatchReplace(): void {
  const section = $("#matchreplace");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <label class="switch"><input type="checkbox" id="mr-enabled" /><span class="slider"></span></label>
      <span>Match & Replace is on</span>
      <span class="grow"></span>
      <button class="ghost" onclick="addRule()">+ Add Rule</button>
    </div>
    <div class="card">
      <div class="card-title">Rules</div>
      <p class="hint">Rules are applied in order. First match wins.</p>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th data-sort="match">Match</th>
            <th data-sort="replacement">Replacement</th>
            <th>Type</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="mr-body"></tbody>
      </table>
      <div id="mr-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Test Rule</div>
      <p class="hint">Test a rule against sample input to verify it works as expected</p>
      <div class="row">
        <select id="mr-test-rule">
          <option value="">Select a rule to test</option>
        </select>
      </div>
      <div class="two" style="margin-top:8px">
        <div>
          <div class="viewer-header"><b class="muted">Input</b></div>
          <textarea id="mr-test-input" placeholder="Sample input..." spellcheck="false" style="min-height:100px"></textarea>
        </div>
        <div>
          <div class="viewer-header"><b class="muted">Output</b></div>
          <textarea id="mr-test-output" readonly spellcheck="false" style="min-height:100px"></textarea>
        </div>
      </div>
      <div class="row" style="margin-top:8px">
        <button class="go" onclick="testRule()">Test</button>
        <button class="ghost" onclick="clearTest()">Clear</button>
      </div>
    </div>
  `;

  // Initialize table sorting
  makeSortable('mr-body', 'name');
  
  // Load initial data
  void loadState();
  
  // Enable/disable handler
  const enabledCb = $<HTMLInputElement>("#mr-enabled")!;
  enabledCb.addEventListener('change', () => {
    void setEnabled(enabledCb.checked);
  });
}

let allRules: MatchReplaceRule[] = [];

async function loadState(): Promise<void> {
  try {
    const response = await fetch("/api/tools/matchreplace");
    if (!response.ok) throw new Error(`Failed to load match & replace state: ${response.status}`);
    
    const state = await response.json() as MatchReplaceState;
    allRules = state.rules;
    
    const enabledCb = $<HTMLInputElement>("#mr-enabled")!;
    enabledCb.checked = state.enabled;
    
    renderRules();
    updateTestRuleSelect();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

function renderRules(rules: MatchReplaceRule[] = allRules): void {
  const tbody = $("#mr-body")!;
  const emptyEl = $("#mr-empty")!;
  
  if (rules.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No rules defined",
      "Add rules to rewrite requests and responses on the fly",
      "🔄",
      7
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = rules.map(r => `
    <tr>
      <td>${esc(r.name)}</td>
      <td>${esc(r.match)}</td>
      <td>${esc(r.replacement)}</td>
      <td>${r.is_regex ? 'Regex' : 'Literal'}</td>
      <td>${esc(r.scope)}</td>
      <td><span class="status-pill ${r.enabled ? 'good' : 'off'}">${r.enabled ? 'Enabled' : 'Disabled'}</span></td>
      <td>
        <button class="ghost small" onclick="toggleRule(${r.id})">${r.enabled ? 'Disable' : 'Enable'}</button>
        <button class="ghost small" onclick="editRule(${r.id})">Edit</button>
        <button class="ghost small" onclick="deleteRule(${r.id})">Delete</button>
      </td>
    </tr>
  `).join('');
}

function updateTestRuleSelect(): void {
  const select = $("#mr-test-rule") as HTMLSelectElement;
  if (!select) return;
  
  select.innerHTML = '<option value="">Select a rule to test</option>' +
    allRules.map(r => `<option value="${r.id}">${esc(r.name)}</option>`).join('');
}

// Global functions
window.addRule = function(): void {
  toast("Add rule functionality would open a modal here", 'info');
};

window.editRule = function(id: number): void {
  toast(`Edit rule #${id} functionality would open a modal here`, 'info');
};

window.toggleRule = async function(id: number): Promise<void> {
  try {
    await putJSON(`/api/tools/matchreplace/rules/${id}/toggle`, {});
    toast("Rule toggled", 'success');
    void loadState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.deleteRule = async function(id: number): Promise<void> {
  if (!confirm("Are you sure you want to delete this rule?")) return;
  
  try {
    await delJSON(`/api/tools/matchreplace/rules/${id}`);
    toast("Rule deleted", 'success');
    void loadState();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

async function setEnabled(enabled: boolean): Promise<void> {
  try {
    await postJSON("/api/tools/matchreplace/enable", { enabled });
    toast(`Match & Replace ${enabled ? 'enabled' : 'disabled'}`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

window.testRule = async function(): Promise<void> {
  const select = $("#mr-test-rule") as HTMLSelectElement;
  const input = $("#mr-test-input") as HTMLTextAreaElement;
  const output = $("#mr-test-output") as HTMLTextAreaElement;
  
  if (!select || !input || !output) return;
  
  const ruleId = parseInt(select.value, 10);
  if (isNaN(ruleId)) {
    toast("Please select a rule to test", "error");
    return;
  }
  
  if (!input.value) {
    toast("Please enter test input", "error");
    return;
  }
  
  try {
    const response = await fetch(`/api/tools/matchreplace/test/${ruleId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: input.value }),
    });
    
    if (!response.ok) throw new Error(`Test failed: ${response.status}`);
    
    const result = await response.json() as { output: string };
    output.value = result.output;
    toast("Rule tested successfully", 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.clearTest = function(): void {
  const input = $("#mr-test-input") as HTMLTextAreaElement;
  const output = $("#mr-test-output") as HTMLTextAreaElement;
  
  if (input) input.value = '';
  if (output) output.value = '';
  toast("Test cleared", 'success');
};
