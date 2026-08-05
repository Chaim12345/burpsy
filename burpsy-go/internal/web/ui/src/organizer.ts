// Organizer tab: save and organize interesting requests. The organizer is a simple key/value
// store: every saved item is an exchange id plus a user-supplied note. That is enough to build
// a "favorites" list, a "to do" list, or a set of regression tests.

import { $, esc, getJSON, postJSON, delJSON, toast, makeSortable, renderEmptyState, copyText } from "./common";

interface OrganizerItem {
  id: number;
  exchange_id: number;
  note: string;
  color: string;
  created_ms: number;
}

interface OrganizerState {
  items: OrganizerItem[];
  colors: string[];
}

export function initOrganizer(): void {
  const section = $("#organizer");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Save interesting requests with notes and colors for later review</span>
      <span class="grow"></span>
      <button class="ghost" onclick="exportOrganizer()">Export</button>
    </div>
    <div class="row">
      <input id="org-search" placeholder="Search notes..." style="width:300px" />
      <select id="org-color-filter">
        <option value="">All colors</option>
      </select>
      <button class="ghost" onclick="clearFilter()">Clear</button>
    </div>
    <table>
      <thead>
        <tr>
          <th data-sort="exchange_id">Exchange ID</th>
          <th data-sort="note">Note</th>
          <th>Color</th>
          <th data-sort="created_ms">Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="org-body"></tbody>
    </table>
    <div id="org-empty" class="hint" style="margin-top:8px"></div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Add to Organizer</div>
      <div class="row">
        <input id="org-exchange-id" type="number" placeholder="Exchange ID" style="width:120px" />
        <input id="org-note" placeholder="Note" style="width:300px" />
        <select id="org-color">
          <option value="">No color</option>
        </select>
        <button class="go" onclick="addToOrganizer()">Add</button>
      </div>
    </div>
  `;

  // Initialize table sorting
  makeSortable('org-body', 'created_ms');
  
  // Load colors and items
  void loadColors();
  void loadItems();
  
  // Search and filter
  const searchInput = $("#org-search") as HTMLInputElement;
  const colorFilter = $("#org-color-filter") as HTMLSelectElement;
  
  searchInput?.addEventListener('input', () => filterItems());
  colorFilter?.addEventListener('change', () => filterItems());
}

let allItems: OrganizerItem[] = [];
let allColors: string[] = [];

async function loadColors(): Promise<void> {
  try {
    const response = await fetch("/api/tools/organizer/colors");
    if (response.ok) {
      allColors = await response.json() as string[];
      const colorSelect = $("#org-color") as HTMLSelectElement;
      const colorFilter = $("#org-color-filter") as HTMLSelectElement;
      
      if (colorSelect) {
        colorSelect.innerHTML = '<option value="">No color</option>' + 
          allColors.map(c => `<option value="${c}">${esc(c)}</option>`).join('');
      }
      if (colorFilter) {
        colorFilter.innerHTML = '<option value="">All colors</option>' + 
          allColors.map(c => `<option value="${c}">${esc(c)}</option>`).join('');
      }
    }
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function loadItems(): Promise<void> {
  try {
    const response = await fetch("/api/tools/organizer");
    if (!response.ok) throw new Error(`Failed to load organizer items: ${response.status}`);
    
    allItems = await response.json() as OrganizerItem[];
    filterItems();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

function filterItems(): void {
  const search = ($("#org-search") as HTMLInputElement)?.value.toLowerCase() || '';
  const color = ($("#org-color-filter") as HTMLSelectElement)?.value || '';
  
  let items = allItems;
  
  if (search) {
    items = items.filter(i => i.note.toLowerCase().includes(search));
  }
  
  if (color) {
    items = items.filter(i => i.color === color);
  }
  
  renderItems(items);
}

function renderItems(items: OrganizerItem[]): void {
  const tbody = $("#org-body")!;
  const emptyEl = $("#org-empty")!;
  
  if (items.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No items in organizer",
      "Add requests to organize them for later review",
      "📚",
      5
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = items.map(i => `
    <tr>
      <td>${i.exchange_id}</td>
      <td>${esc(i.note)}</td>
      <td>${i.color ? `<span class="pill hl-${i.color}">${esc(i.color)}</span>` : ''}</td>
      <td>${new Date(i.created_ms).toLocaleString()}</td>
      <td>
        <button class="ghost small" onclick="viewItem(${i.id})">View</button>
        <button class="ghost small" onclick="copyItem(${i.id})">Copy</button>
        <button class="ghost small" onclick="deleteItem(${i.id})">Delete</button>
      </td>
    </tr>
  `).join('');
}

// Global functions
window.addToOrganizer = async function(): Promise<void> {
  const exchangeIdInput = $("#org-exchange-id") as HTMLInputElement;
  const noteInput = $("#org-note") as HTMLInputElement;
  const colorSelect = $("#org-color") as HTMLSelectElement;
  
  if (!exchangeIdInput || !noteInput) return;
  
  const exchangeId = parseInt(exchangeIdInput.value, 10);
  const note = noteInput.value.trim();
  const color = colorSelect?.value || '';
  
  if (isNaN(exchangeId)) {
    toast("Please enter a valid exchange ID", "error");
    return;
  }
  
  if (!note) {
    toast("Please enter a note", "error");
    return;
  }
  
  try {
    await postJSON("/api/tools/organizer", {
      exchange_id: exchangeId,
      note,
      color,
    });
    
    toast("Added to organizer", 'success');
    exchangeIdInput.value = '';
    noteInput.value = '';
    colorSelect.value = '';
    void loadItems();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.viewItem = function(id: number): void {
  toast(`View item #${id} functionality would show the request details`, 'info');
};

window.copyItem = async function(id: number): Promise<void> {
  try {
    const response = await fetch(`/api/tools/organizer/${id}`);
    if (!response.ok) throw new Error(`Failed to load item: ${response.status}`);
    
    const item = await response.json() as OrganizerItem;
    copyText(`Exchange #${item.exchange_id}: ${item.note}`, 'organizer item');
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.deleteItem = async function(id: number): Promise<void> {
  if (!confirm("Are you sure you want to delete this item?")) return;
  
  try {
    await delJSON(`/api/tools/organizer/${id}`);
    toast("Item deleted", 'success');
    void loadItems();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.clearFilter = function(): void {
  ($("#org-search") as HTMLInputElement).value = '';
  ($("#org-color-filter") as HTMLSelectElement).value = '';
  filterItems();
};

window.exportOrganizer = function(): void {
  toast("Export functionality would download organizer items as JSON", 'info');
};
