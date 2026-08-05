// Core types for burpsy React POC

// API Response Types
export interface Exchange {
  id: number;
  request: number;
  response: number | null;
  host: string;
  port: number;
  tls: boolean;
  method: string;
  path: string;
  status: number | null;
  response_len: number;
  started_ms: number;
  duration_ms: number;
  notes: string | null;
  related: RelatedItem[];
  protocol: Protocol;
}

export interface RelatedItem {
  kind: string;
  id: number;
}

export type Protocol = 'Http1' | 'Http2';

export interface MessageView {
  id: number;
  len: number;
  text: string;
}

export interface Stats {
  exchanges: number;
  messages: number;
  stored_bytes: number;
}

export interface ScopeInfo {
  allow_all: boolean;
  rules: ScopeRule[];
  empty: boolean;
}

export interface ScopeRule {
  kind: 'include' | 'exclude';
  field: 'host' | 'path' | 'method' | 'status' | 'mime';
  pattern: string;
  enabled: boolean;
}

// UI State Types
export interface UIState {
  currentTab: string;
  theme: 'light' | 'dark';
  filters: Record<string, string>;
}

export interface HistoryState {
  exchanges: Exchange[];
  loading: boolean;
  error: string | null;
  selectedId: number | null;
  searchQuery: string;
  statusFilters: Set<string>;
  scopeOnly: boolean;
  selectedRows: Set<number>;
}

export interface DashboardState {
  stats: Stats;
  loading: boolean;
  error: string | null;
}

// Component Props
export interface TableProps<T> {
  data: T[];
  columns: Column<T>[];
  keyExtractor: (item: T) => string | number;
  onRowClick?: (item: T) => void;
  onRowSelect?: (selected: Set<string | number>) => void;
  emptyMessage?: string;
  loading?: boolean;
}

export interface Column<T> {
  key: string;
  header: string;
  sortable?: boolean;
  width?: string;
  render?: (item: T) => React.ReactNode;
  className?: string;
}

// API Types
export interface ApiError {
  message: string;
  status: number;
  body?: unknown;
}

// Toast Types
export type ToastType = 'info' | 'success' | 'warning' | 'error';

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  dismissible?: boolean;
  duration?: number;
}
