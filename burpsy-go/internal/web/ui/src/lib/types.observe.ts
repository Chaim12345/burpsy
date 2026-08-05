/**
 * Observe-area wire types that are richer than the shared trimmed views in `types.ts`.
 * Kept in their own module so this page's work doesn't collide with concurrent edits to the
 * shared `types.ts` file. Field names mirror the Go json tags exactly.
 */

/** Full payload view for one WS frame; the Go handler embeds wsRowView's fields at the top level,
 * so `opcode` here is what decides whether `text` or `hex` is the payload to show. */
export interface WsMessageDetail {
  id: number;
  exchange: number;
  direction: string;
  opcode: string;
  len: number;
  dropped: number;
  truncated: boolean;
  at_ms: number;
  text: string;
  hex: string;
  close?: { code: number; reason: string };
}

/** Site-map node, including the fields the trimmed shared `SiteNode` omits (`id`, `segment`) that
 * this page needs for a stable expand/collapse key and a display label independent of the full path. */
export interface SiteNodeDetail {
  id: number;
  segment: string;
  path: string;
  exchanges: number;
  subtree_exchanges: number;
  methods: string[];
  statuses: number[];
  /** Omitted entirely by the server for leaf nodes, so it must be treated as optional. */
  children?: SiteNodeDetail[];
}

export interface SiteMapDetail {
  exchanges: number;
  nodes: number;
  synced: number;
  in_flight: number;
  tree: SiteNodeDetail[];
}
