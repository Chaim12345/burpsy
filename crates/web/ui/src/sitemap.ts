// Site map tab: the host -> path tree folded from captured traffic (GET /api/sitemap). The API
// answers one node's children at a time, so the tree here is built the same way: the root fetch
// already carries one level of children, and expanding any deeper node lazily re-fetches it.
//
// A filter bar (free-text `q` + in-scope-only) narrows what the backend returns, and selecting a
// node (clicking its row, not its twisty) fetches that node on its own to get its capped recent-
// exchange id list, then shows those exchanges plus any findings recorded against that exact path.

import { $, esc, getJSON, emit, switchTab } from "./common";
import { EVT_SHOW_EXCHANGE } from "./types";

interface NodeView {
  id: number;
  segment: string;
  path: string;
  depth: number;
  exchanges: number;
  requested: boolean;
  subtree_exchanges: number;
  child_count: number;
  methods: string[];
  statuses: number[];
  params: string[];
  last_exchange: number | null;
  recent_exchanges?: number[];
  children?: NodeView[];
}

interface TreeResp {
  exchanges: number;
  nodes: number;
  synced: number;
  in_flight: number;
  matched?: number;
  tree: NodeView[];
}

interface ExchangeView {
  id: number;
  method: string;
  host: string;
  path: string;
  status: number | null;
  response_len: number;
  duration_ms: number;
}

interface Occurrence {
  exchange_id: number;
  path: string;
}

interface Finding {
  id: number;
  check_name: string;
  issue_name: string | null;
  severity: string;
  host: string;
  occurrences: Occurrence[];
}

let selected: { host: string; path: string } | null = null;
let searchDebounce: ReturnType<typeof setTimeout> | undefined;

export function initSitemap(): void {
  const section = $("#sitemap");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <button class="go" id="site-refresh">Refresh</button>
      <input id="site-q" placeholder="filter by segment or path…" style="width:220px" />
      <label><input type="checkbox" id="site-scope-only" /> in scope only</label>
      <span id="site-note" class="hint"></span>
    </div>
    <div id="site-tree" class="tree"></div>
    <div id="site-detail"></div>
  `;
  $("#site-refresh")!.addEventListener("click", () => void load());
  $<HTMLInputElement>("#site-q")!.addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => void load(), 300);
  });
  $<HTMLInputElement>("#site-scope-only")!.addEventListener("change", () => void load());
  $("#site-tree")!.addEventListener("click", (e) => {
    const target = e.target as HTMLElement;
    const twisty = target.closest<HTMLElement>(".twisty");
    const node = target.closest<HTMLElement>(".node");
    if (!node) return;
    if (twisty) {
      void toggle(node);
    } else {
      void select(node);
    }
  });
  void load();
}

function query(): string {
  const q = $<HTMLInputElement>("#site-q")!.value.trim();
  const scopeOnly = $<HTMLInputElement>("#site-scope-only")!.checked;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (scopeOnly) params.set("in_scope_only", "true");
  const s = params.toString();
  return s ? `?${s}` : "";
}

async function load(): Promise<void> {
  const note = $("#site-note")!;
  const container = $("#site-tree")!;
  try {
    const resp = await getJSON<TreeResp>(`/api/sitemap${query()}`);
    const matched = resp.matched != null ? ` · ${resp.matched} of ${resp.nodes} match` : "";
    note.textContent =
      `${resp.exchanges} exchanges · ${resp.nodes} nodes` +
      (resp.in_flight ? ` · ${resp.in_flight} in flight` : "") +
      matched;
    container.innerHTML = resp.tree.length
      ? `<ul>${resp.tree.map((n) => nodeLi(n, n.segment)).join("")}</ul>`
      : `<p class="hint">no traffic yet${resp.matched != null ? " matches the filter" : ""}</p>`;
  } catch (e) {
    container.innerHTML = `<p class="err">${esc((e as Error).message)}</p>`;
  }
}

function nodeLi(n: NodeView, rootHost: string): string {
  const hasChildren = n.child_count > 0;
  const loaded = (n.children?.length ?? 0) > 0;
  const meta = [
    `${n.exchanges}/${n.subtree_exchanges}`,
    n.methods.length ? n.methods.join(",") : "",
    n.statuses.length ? n.statuses.join(",") : "",
    n.params.length ? `params: ${n.params.join(",")}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  const childrenHtml = loaded ? `<ul>${n.children!.map((c) => nodeLi(c, rootHost)).join("")}</ul>` : "";
  const isSelected = selected && selected.host === rootHost && selected.path === n.path;
  return `<li>
    <div class="node${n.requested ? "" : " unrequested"}${isSelected ? " on" : ""}" data-host="${esc(rootHost)}" data-path="${esc(n.path)}"
         data-haschildren="${hasChildren ? 1 : 0}" data-loaded="${loaded ? 1 : 0}">
      <span class="twisty">${hasChildren ? (loaded ? "▾" : "▸") : "·"}</span>
      <span class="seg">${esc(n.segment)}</span>
      <span class="count">${esc(meta)}</span>
    </div>
    <div class="children"${hasChildren ? "" : ' style="display:none"'}>${childrenHtml}</div>
  </li>`;
}

async function toggle(node: HTMLElement): Promise<void> {
  if (node.dataset["haschildren"] !== "1") return;
  const childrenDiv = node.nextElementSibling as HTMLElement | null;
  if (!childrenDiv) return;
  const twisty = node.querySelector<HTMLElement>(".twisty")!;

  if (node.dataset["loaded"] === "1") {
    const open = childrenDiv.style.display !== "none";
    childrenDiv.style.display = open ? "none" : "";
    twisty.textContent = open ? "▸" : "▾";
    return;
  }

  const host = node.dataset["host"] ?? "";
  const path = node.dataset["path"] ?? "/";
  twisty.textContent = "…";
  try {
    const resp = await getJSON<TreeResp>(
      `/api/sitemap?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&depth=1${query() ? "&" + query().slice(1) : ""}`,
    );
    const n = resp.tree[0];
    childrenDiv.innerHTML =
      n && (n.children?.length ?? 0) > 0
        ? `<ul>${n.children!.map((c) => nodeLi(c, host)).join("")}</ul>`
        : `<span class="hint">no children</span>`;
    node.dataset["loaded"] = "1";
    twisty.textContent = "▾";
  } catch (e) {
    childrenDiv.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    twisty.textContent = "▸";
  }
}

async function select(node: HTMLElement): Promise<void> {
  const host = node.dataset["host"] ?? "";
  const path = node.dataset["path"] ?? "/";
  if (selected && selected.host === host && selected.path === path) {
    selected = null;
    $("#site-detail")!.innerHTML = "";
    node.classList.remove("on");
    return;
  }
  selected = { host, path };
  const out = $("#site-detail")!;
  out.innerHTML = `<p class="hint">loading…</p>`;
  try {
    const resp = await getJSON<TreeResp>(
      `/api/sitemap?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&depth=0`,
    );
    const n = resp.tree[0];
    if (!n) {
      out.innerHTML = `<p class="err">node not found</p>`;
      return;
    }
    await renderDetail(n, host);
  } catch (e) {
    out.innerHTML = `<p class="err">${esc((e as Error).message)}</p>`;
  }
}

/// Show at most this many of a node's recent exchanges in detail — recent_exchanges can hold up to
/// 200 ids, and fetching 200 individual `/api/exchange/{id}` responses for one click is excessive.
const DETAIL_EXCHANGE_LIMIT = 25;

async function renderDetail(n: NodeView, rootHost: string): Promise<void> {
  const out = $("#site-detail")!;
  const ids = (n.recent_exchanges ?? []).slice(0, DETAIL_EXCHANGE_LIMIT);
  const [exchanges, findings] = await Promise.all([loadExchanges(ids), loadFindingsFor(n.path)]);

  const exRows = exchanges.length
    ? exchanges
        .map(
          (e) =>
            `<tr class="clickable" data-exchange-id="${e.id}">` +
            `<td>${e.id}</td><td>${esc(e.method)}</td><td>${e.status ?? ""}</td>` +
            `<td>${e.response_len}</td><td>${e.duration_ms} ms</td></tr>`,
        )
        .join("")
    : `<tr><td colspan="5" class="hint">no captured exchanges at this exact node</td></tr>`;

  const total = n.exchanges;
  const shownNote =
    total > ids.length ? `showing newest ${ids.length} of ${total}` : `${total} exchange${total === 1 ? "" : "s"}`;

  const findingRows = findings.length
    ? findings
        .map(
          (f) =>
            `<div class="row">` +
            `<span class="sev-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>` +
            `<b>${esc(f.issue_name ?? f.check_name)}</b>` +
            `<span class="grow"></span>` +
            `<button class="ghost small" data-jump-finding="${f.id}">view in Scanner</button>` +
            `</div>`,
        )
        .join("")
    : `<span class="hint">no findings recorded at this exact path</span>`;

  out.innerHTML = `
    <div class="card">
      <div class="row">
        <b class="card-title">${esc(rootHost)}${esc(n.path)}</b>
        <span class="hint">${shownNote}</span>
      </div>
      <table>
        <thead><tr><th>id</th><th>method</th><th>status</th><th>len</th><th>duration</th></tr></thead>
        <tbody>${exRows}</tbody>
      </table>
      <div class="stack" style="margin-top:8px">
        <b class="muted">Findings</b>
        ${findingRows}
      </div>
    </div>
  `;
  out.querySelectorAll<HTMLElement>("tr[data-exchange-id]").forEach((row) => {
    row.addEventListener("click", () => {
      emit(EVT_SHOW_EXCHANGE, { exchangeId: Number(row.dataset["exchangeId"]) });
      switchTab("history");
    });
  });
  out.querySelectorAll<HTMLElement>("button[data-jump-finding]").forEach((btn) => {
    btn.addEventListener("click", () => switchTab("scanner"));
  });
}

async function loadExchanges(ids: number[]): Promise<ExchangeView[]> {
  const results = await Promise.all(
    ids.map((id) =>
      getJSON<ExchangeView>(`/api/exchange/${id}`).catch(() => null),
    ),
  );
  return results.filter((e): e is ExchangeView => e !== null);
}

async function loadFindingsFor(path: string): Promise<Finding[]> {
  try {
    const resp = await getJSON<{ findings: Finding[] }>("/api/issues");
    return resp.findings.filter((f) => f.occurrences.some((o) => o.path === path));
  } catch {
    return [];
  }
}
