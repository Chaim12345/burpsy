/** Wire types for the burpsy HTTP API. Field names mirror the Go json tags exactly. */

export interface Stats {
  exchanges: number;
  messages: number;
  stored_bytes: number;
}

export interface ScopeRule {
  host?: string;
  port?: number;
  protocol?: string;
  path_prefix?: string;
  include?: boolean;
}

export interface Scope {
  allow_all: boolean;
  rules: ScopeRule[];
}

export interface Exchange {
  id: number;
  request: number;
  response: number | null;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  response_len: number;
  started_ms: number;
  duration_ms: number;
  /** Whether the exchange was carried over TLS. This — not `protocol` — decides http vs https. */
  tls: boolean;
  /** The HTTP version the exchange used: "Http1" or "Http2". Never "http"/"https". */
  protocol: string;
  mime?: string;
  source?: string;
  notes?: string | null;
  related?: number[];
}

export interface MessageView {
  text: string;
  truncated?: boolean;
  len?: number;
  hex?: string;
}

export interface CoverageBreakdown {
  found: number;
  skipped: number;
  errored: number;
  gated: number;
  unaccounted: number;
  complete: boolean;
}

export interface CoverageSummary {
  label: string;
  unit: string;
  work_unit: string;
  breakdown: CoverageBreakdown;
}

export interface TaskResult {
  summary: string;
}

export interface TaskRow {
  id: number;
  kind: string;
  target: string;
  state: string;
  progress: string;
  elapsed_ms: number;
  result: TaskResult;
}

export interface ActivityRow {
  tool: string;
  method: string;
  path: string;
  status: number | null;
  started_ms: number;
  host?: string;
  port?: number;
}

export interface ToolEvent {
  kind: string;
  severity: string;
  detail: string;
  at_ms: number;
}

export interface Dashboard {
  summaries: CoverageSummary[];
  tasks: TaskRow[];
  tasks_running: number;
  activity: ActivityRow[];
  events: ToolEvent[];
  exchanges: number;
  messages: number;
  stored_bytes: number;
  sources: Record<string, number>;
}

export interface Occurrence {
  exchange_id: number;
  path: string;
}

export interface Finding {
  check_name?: string;
  issue_name?: string | null;
  severity: string;
  confidence: string;
  host: string;
  detail: string;
  remediation: string;
  times_seen: number;
  occurrences: Occurrence[];
}

export interface Issues {
  enabled: boolean;
  hint?: string;
  findings: Finding[];
  counts?: Record<string, number>;
}

export interface HeldMessage {
  id: number;
  direction: string;
  host: string;
  method: string;
  path: string;
  raw: string;
}

export interface InterceptState {
  enabled: boolean;
  wired: boolean;
  hint?: string;
  pending: number;
  held: HeldMessage[];
}

export interface RepeaterResult {
  status: number;
  duration_ms: number;
  response: string;
  exchange_id: number;
}

export interface InsertionPoint {
  index: number;
  kind: string;
  label: string;
  current: string;
}

export interface SequencerReport {
  tokens: number;
  grade: string;
  verdict: string;
  warnings: string[];
  encoding: string;
  bits?: { bit_entropy?: number; [key: string]: unknown };
  chars?: Record<string, unknown>;
}

export interface WsConnection {
  exchange: number;
  host: string;
  port: number;
  path: string;
  messages: number;
  sent: number;
  received: number;
  last_ms: number;
}

export interface WsRow {
  id: number;
  direction: string;
  opcode: string;
  len: number;
  at_ms: number;
  truncated: boolean;
}

export interface WsHistory {
  total: number;
  rows: WsRow[];
}

export interface WsMessage {
  text?: string;
  hex?: string;
  close?: { code: number; reason: string };
}

export interface SiteNode {
  path: string;
  exchanges: number;
  subtree_exchanges: number;
  methods: string[];
  statuses: number[];
  children: SiteNode[];
}

export interface SiteMap {
  exchanges: number;
  nodes: number;
  synced: number;
  in_flight: number;
  tree: SiteNode[];
}

export interface LogEntry {
  tool: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  error?: string;
  started_ms: number;
  duration_ms: number;
}

export interface ToolLog {
  total: number;
  shown: number;
  dropped: number;
  entries: LogEntry[];
}

export interface OrganizerItem {
  id: number;
  exchange: number;
  title: string;
  note: string;
  highlight: string;
}

export interface TrafficRule {
  rule_type: string;
  enabled: boolean;
  string_match: string;
  string_replace: string;
  category: string;
  comment?: string;
}

export interface MatchReplaceConfig {
  rules: TrafficRule[];
  update_content_length: boolean;
}

export interface MatchReplaceResponse {
  affects_requests: boolean;
  affects_responses: boolean;
  config: MatchReplaceConfig;
}

export interface SessionStep {
  method?: string;
  url?: string;
  headers?: string[][];
  body?: string;
}

export interface SessionRule {
  id?: number;
  name?: string;
  enabled: boolean;
  method?: string;
  url?: string;
  headers?: string[][];
  body?: string;
  steps?: SessionStep[];
}

export interface SessionRules {
  wired: boolean;
  rules: SessionRule[];
  hint?: string;
}

export interface ToolOutput {
  text: string;
  [key: string]: unknown;
}
