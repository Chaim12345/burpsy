// Site map tab: the host -> path tree folded from captured traffic (GET /api/sitemap). The API
// answers one node's children at a time, so the tree here is built the same way: the root fetch
// already carries one level of children, and expanding any deeper node lazily re-fetches it.
//
// A filter bar (free-text `q` + in-scope-only) narrows what the backend returns, and selecting a
// node (clicking its row, not its twisty) fetches that node on its own to get its capped recent-
// exchange id list, then shows those exchanges plus any findings recorded against that exact path.

import { $, esc, getJSON, emit, switchTab } from "./common";
import { EVT_SHOW_EXCHANGE } from "./types";
import { attachRowContextMenu } from "./contextmenu";
import type { MenuItem } from "./contextmenu";
import { exchangeIdMenuItems } from "./sendto";
import { registerRowTarget } from "./shortcuts";
import { live } from "./live";

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
/** The selected node's most recent exchange, or null when nothing has been captured at that exact
 * node. A site-map node is a path, not a request, so this id is the only thing the send-to actions
 * and the keyboard shortcuts can act on. */
let selectedExchange: number | null = null;
let searchDebounce: ReturnType<typeof setTimeout> | undefined;

export function initSitemap(): void {
  const section = $("#sitemap");
  if (!section) return;
  section.innerHTML = `
    <div class="command-bar">
      <input id="site-q" placeholder="Filter by segment or path…" class="control-wide" />
      <label><input type="checkbox" id="site-scope-only" /> in scope only</label>
      <button class="ghost" id="site-refresh">Refresh tree</button>
      <span id="site-note" class="hint"></span>
      <span id="site-stale" class="hint"></span>
    </div>
    <div class="explorer-layout">
      <div class="panel explorer-tree"><div class="panel-head"><div><div class="eyebrow">Structure</div><div class="panel-title">Discovered surface</div></div></div><div id="site-tree" class="tree"></div></div>
      <div id="site-detail" class="explorer-detail"><div class="empty-state"><b>Select a node</b><span>Its captured methods, statuses, and latest exchange will appear here.</span></div></div>
    </div>
  `;
  $("#site-refresh")!.addEventListener("click", () => void load());
  // The one pane that keeps its Refresh button, and the reason is the tree: it is lazily expanded, and
  // load() redraws it from the root, so pushing a redraw would collapse whatever branch the operator had
  // opened — every 150ms, for as long as a crawl runs. Losing someone's place in the tree is worse than
  // a stale count. What is pushed instead is the fact that the tree is out of date, which is the part
  // they could not otherwise know without clicking.
  live({ kinds: ["history"], section: "sitemap", refresh: markTreeStale, minGapMs: 1000 });
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
  attachRowContextMenu<HTMLElement>({
    container: "#site-tree",
    rowSelector: ".node",
    resolve: (node) => node,
    heading: (node) => `${node.dataset["host"] ?? ""}${node.dataset["path"] ?? ""}`,
    // Right-click selects but never deselects: `select()` toggles on a second click, and a menu that
    // dropped the selection out from under itself would act on nothing.
    select: (node) => {
      if (selected?.host !== node.dataset["host"] || selected?.path !== node.dataset["path"]) void select(node);
    },
    items: (node) => nodeMenuItems(node),
  });
  registerRowTarget("sitemap", () =>
    selected
      ? {
          label: `${selected.host}${selected.path}`,
          ...(selectedExchange !== null ? { exchangeId: selectedExchange } : {}),
          note: `nothing has been captured at ${selected.host}${selected.path} yet — there is no request to send`,
        }
      : null,
  );
  void load();
}

/** Reads the node's most recent exchange id out of its dataset. Exchange id 0 is a real id in this
 * store, so an absent value is distinguished from a zero one by the empty string, not by falsiness. */
function nodeExchangeId(node: HTMLElement): number | null {
  const raw = node.dataset["lastExchange"];
  if (raw === undefined || raw === "") return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function nodeMenuItems(node: HTMLElement): MenuItem[] {
  const items: MenuItem[] = [];
  if (node.dataset["haschildren"] === "1") {
    // A node whose children have never been fetched reads as "not none" too, so `loaded` decides
    // first: only an already-loaded, already-shown node can be collapsed.
    const open =
      node.dataset["loaded"] === "1" && (node.nextElementSibling as HTMLElement | null)?.style.display !== "none";
    items.push({ label: open ? "Collapse" : "Expand", run: () => void toggle(node) }, { separator: true });
  }
  items.push(
    ...exchangeIdMenuItems(nodeExchangeId(node), "no exchange captured at this node yet", { showInHistory: true }),
  );
  return items;
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

/** Exchanges captured since the tree was last drawn, from the stream's own counts. */
let staleSince = 0;

/** Says the tree is out of date, without redrawing it — see the live() registration in initSitemap.
 *
 * `changes` of 0 means the refresh was a poll rather than a pushed change, and a poll cannot tell
 * whether anything arrived — so the marker is left saying whatever it last honestly knew rather than
 * claiming zero. That is also why the site map shows no staleness marker at all while the event stream
 * is down: the pane is back to exactly what it did before, a button and no claim. */
function markTreeStale(changes: number): void {
  if (changes <= 0) return;
  staleSince += changes;
  const marker = $("#site-stale");
  if (marker) marker.textContent = `· ${staleSince} captured since this tree was drawn — Refresh`;
}

async function load(): Promise<void> {
  const note = $("#site-note")!;
  const container = $("#site-tree")!;
  staleSince = 0;
  const marker = $("#site-stale");
  if (marker) marker.textContent = "";
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
         data-haschildren="${hasChildren ? 1 : 0}" data-loaded="${loaded ? 1 : 0}"
         data-last-exchange="${n.last_exchange ?? ""}">
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
    selectedExchange = null;
    $("#site-detail")!.innerHTML = "";
    node.classList.remove("on");
    return;
  }
  selected = { host, path };
  // Read from the row's own dataset rather than waiting for the fetch below: a Ctrl+R landing between
  // the click and the response should still act on the row that was clicked.
  selectedExchange = nodeExchangeId(node);
  $("#site-tree")!.querySelectorAll(".node.on").forEach((n) => n.classList.remove("on"));
  node.classList.add("on");
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
    // The fetched node is authoritative; the dataset value was only the optimistic first guess. Guard
    // against a second click having landed while this was in flight.
    if (selected?.host === host && selected?.path === path) selectedExchange = n.last_exchange;
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
