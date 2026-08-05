// Site map tab: a tree view of all the URLs burpsy has seen, grouped by host. Each node in
// the tree is a path segment or a query parameter, and the leaves are the actual URLs. Clicking a
// node shows the requests that hit that URL in the bottom pane.

import { $, esc, getJSON, toast, makeSortable, renderEmptyState, copyText } from "./common";
import { EVT_FILTER_HISTORY } from "./types";
import { emit } from "./common";

interface SiteNode {
  kind: "host" | "path" | "param" | "leaf";
  name: string;
  full_path: string;
  children: SiteNode[];
  exchange_ids: number[];
  request_count: number;
  last_seen_ms: number;
}

interface SiteMapState {
  roots: SiteNode[];
  total_urls: number;
  total_exchanges: number;
}

export function initSitemap(): void {
  const section = $("#sitemap");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Tree view of all URLs seen by the proxy, grouped by host</span>
      <span class="grow"></span>
      <button class="ghost" onclick="refreshSitemap()">Refresh</button>
      <button class="ghost" onclick="expandAll()">Expand All</button>
      <button class="ghost" onclick="collapseAll()">Collapse All</button>
    </div>
    <div class="row">
      <input id="sitemap-search" placeholder="Search hosts and paths..." style="width:300px" />
      <button class="ghost" onclick="applySitemapFilter()">Search</button>
    </div>
    <div id="sitemap-tree" class="tree"></div>
    <div id="sitemap-empty" class="hint"></div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Selected URL Requests</div>
      <div id="sitemap-requests"></div>
    </div>
  `;

  // Load initial data
  void loadSitemap();
  
  // Search
  const searchInput = $("#sitemap-search") as HTMLInputElement;
  searchInput?.addEventListener('input', () => applySitemapFilter());
}

let allRoots: SiteNode[] = [];
let filteredRoots: SiteNode[] = [];

async function loadSitemap(): Promise<void> {
  try {
    const response = await fetch("/api/sitemap");
    if (!response.ok) throw new Error(`Failed to load sitemap: ${response.status}`);
    
    const state = await response.json() as SiteMapState;
    allRoots = state.roots;
    filteredRoots = allRoots;
    
    renderTree();
  } catch (e) {
    const treeEl = $("#sitemap-tree")!;
    treeEl.innerHTML = `<div class="err">${esc((e as Error).message)}</div>`;
  }
}

function renderTree(nodes: SiteNode[] = filteredRoots): void {
  const treeEl = $("#sitemap-tree")!;
  const emptyEl = $("#sitemap-empty")!;
  
  if (nodes.length === 0) {
    treeEl.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No URLs captured yet",
      "Browse through the proxy to build the site map",
      "🗺️",
      1
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  treeEl.innerHTML = nodes.map(renderNode).join('');
}

function renderNode(node: SiteNode, depth: number = 0): string {
  const hasChildren = node.children.length > 0;
  const isExpanded = depth < 2; // Auto-expand first few levels
  const count = node.request_count > 0 ? ` (${node.request_count})` : '';
  const name = esc(node.name) + count;
  
  if (hasChildren) {
    return `
      <ul>
        <li>
          <span class="node ${node.exchange_ids.length === 0 ? 'unrequested' : ''}" 
                onclick="toggleNode(this)"
                data-path="${esc(node.full_path)}">
            <span class="seg">${name}</span>
            <span class="count">${node.exchange_ids.length} exchanges</span>
          </span>
          <div style="display: ${isExpanded ? 'block' : 'none'}" class="children">
            ${node.children.map(c => renderNode(c, depth + 1)).join('')}
          </div>
        </li>
      </ul>
    `;
  } else {
    return `
      <ul>
        <li>
          <span class="node leaf ${node.exchange_ids.length === 0 ? 'unrequested' : ''}" 
                onclick="showNodeRequests('${esc(node.full_path)}')"
                data-path="${esc(node.full_path)}">
            <span class="seg">${name}</span>
            <span class="count">${node.exchange_ids.length} exchanges</span>
          </span>
        </li>
      </ul>
    `;
  }
}

function applySitemapFilter(): void {
  const search = ($("#sitemap-search") as HTMLInputElement)?.value.toLowerCase() || '';
  
  if (!search) {
    filteredRoots = allRoots;
  } else {
    filteredRoots = allRoots.map(filterNode);
  }
  
  renderTree();
}

function filterNode(node: SiteNode): SiteNode {
  const search = ($("#sitemap-search") as HTMLInputElement)?.value.toLowerCase() || '';
  
  // Filter children first
  const filteredChildren = node.children.map(filterNode).filter(c => 
    c.children.length > 0 || c.name.toLowerCase().includes(search) || c.full_path.toLowerCase().includes(search)
  );
  
  // If this node or any of its children match, keep it
  const matches = node.name.toLowerCase().includes(search) || 
                  node.full_path.toLowerCase().includes(search) ||
                  filteredChildren.length > 0;
  
  return matches ? { ...node, children: filteredChildren } : { ...node, children: [] };
}

function showNodeRequests(path: string): void {
  const node = findNodeByPath(path, allRoots);
  if (!node) return;
  
  const requestsEl = $("#sitemap-requests")!;
  
  if (node.exchange_ids.length === 0) {
    requestsEl.innerHTML = renderEmptyState(
      "No requests for this URL",
      `This URL has been seen but no requests have been captured for it`,
      "📭",
      1
    );
    return;
  }
  
  requestsEl.innerHTML = `
    <div class="row">
      <span class="hint">${node.exchange_ids.length.toLocaleString()} requests for <code>${esc(path)}</code></span>
      <span class="grow"></span>
      <button class="ghost small" onclick="filterHistoryByPath('${esc(path)}')">Show in History</button>
    </div>
    <table>
      <thead>
        <tr><th>Exchange ID</th><th>Method</th><th>Status</th><th>Time</th><th>Actions</th></tr>
      </thead>
      <tbody>
        ${node.exchange_ids.map(id => `
          <tr>
            <td>${id}</td>
            <td>-</td>
            <td>-</td>
            <td>-</td>
            <td><button class="ghost small" onclick="showExchange(${id})">View</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function findNodeByPath(path: string, nodes: SiteNode[]): SiteNode | null {
  for (const node of nodes) {
    if (node.full_path === path) return node;
    const found = findNodeByPath(path, node.children);
    if (found) return found;
  }
  return null;
}

// Global functions
window.refreshSitemap = function(): void {
  void loadSitemap();
};

window.expandAll = function(): void {
  const nodes = $all(".node");
  nodes.forEach(n => {
    const children = n.nextElementSibling as HTMLElement;
    if (children && children.classList.contains('children')) {
      children.style.display = 'block';
    }
  });
};

window.collapseAll = function(): void {
  const nodes = $all(".node");
  nodes.forEach(n => {
    const children = n.nextElementSibling as HTMLElement;
    if (children && children.classList.contains('children')) {
      children.style.display = 'none';
    }
  });
};

window.toggleNode = function(el: HTMLElement): void {
  const children = el.nextElementSibling as HTMLElement;
  if (children && children.classList.contains('children')) {
    children.style.display = children.style.display === 'none' ? 'block' : 'none';
  }
};

window.showExchange = function(id: number): void {
  emit(EVT_FILTER_HISTORY, { search: String(id) });
  // In a real implementation, this would switch to history tab and show the exchange
  toast(`Showing exchange #${id} in History`, 'info');
};

window.filterHistoryByPath = function(path: string): void {
  emit(EVT_FILTER_HISTORY, { search: path });
  toast(`Filtering History by path: ${path}`, 'info');
};

window.applySitemapFilter = function(): void {
  applySitemapFilter();
};
