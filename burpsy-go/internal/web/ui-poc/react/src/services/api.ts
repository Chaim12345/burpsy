// API client for burpsy
import type { Exchange, MessageView, Stats, ScopeInfo } from '../types';

const API_BASE = '/api';

// Custom error class
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public body?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// Helper to handle fetch errors
async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    throw new ApiError(
      typeof body === 'object' && body && 'error' in body 
        ? (body as { error: string }).error 
        : `${response.status} ${response.statusText}`,
      response.status,
      body
    );
  }
  return response.json() as Promise<T>;
}

// API methods
export const api = {
  // Stats
  getStats: (): Promise<Stats> => 
    fetch(`${API_BASE}/stats`).then(res => handleResponse<Stats>(res)),
  
  // Scope
  getScope: (): Promise<ScopeInfo> => 
    fetch(`${API_BASE}/scope`).then(res => handleResponse<ScopeInfo>(res)),
  
  // History
  getHistory: (limit?: number, query?: string): Promise<Exchange[]> => {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (query) params.set('q', query);
    const qs = params.toString();
    return fetch(`${API_BASE}/history${qs ? `?${qs}` : ''}`).then(res => handleResponse<Exchange[]>(res));
  },
  
  // Exchange
  getExchange: (id: number): Promise<Exchange> => 
    fetch(`${API_BASE}/exchange/${id}`).then(res => handleResponse<Exchange>(res)),
  
  // Message
  getMessage: (id: number): Promise<MessageView> => 
    fetch(`${API_BASE}/message/${id}`).then(res => handleResponse<MessageView>(res)),
  
  // Dashboard
  getDashboard: (): Promise<any> => 
    fetch(`${API_BASE}/dashboard`).then(res => handleResponse<any>(res)),
  
  // Issues
  getIssues: (): Promise<any> => 
    fetch(`${API_BASE}/issues`).then(res => handleResponse<any>(res)),
  
  // Repeater
  sendRequest: (target: string, raw: string, protocol: string): Promise<any> => 
    fetch(`${API_BASE}/repeater/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, raw, protocol }),
    }).then(res => handleResponse<any>(res)),
  
  // Scanner
  startAudit: (exchangeId: number): Promise<any> => 
    fetch(`${API_BASE}/scanner/audit/${exchangeId}`, {
      method: 'POST',
    }).then(res => handleResponse<any>(res)),
  
  // Intercept
  getInterceptStatus: (): Promise<any> => 
    fetch(`${API_BASE}/intercept`).then(res => handleResponse<any>(res)),
  
  enableIntercept: (enabled: boolean): Promise<any> => 
    fetch(`${API_BASE}/intercept/enable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    }).then(res => handleResponse<any>(res)),
  
  // CA Certificate
  getCACert: (): Promise<Blob> => 
    fetch('/ca.crt').then(res => {
      if (!res.ok) throw new ApiError('CA certificate not available', res.status);
      return res.blob();
    }),
};

// Hook for using API with React Query
export function useApi<T>(key: string[], fetchFn: () => Promise<T>) {
  // This would integrate with @tanstack/react-query
  // For POC, we'll use a simple implementation
  return {
    data: null as T | null,
    loading: true,
    error: null as ApiError | null,
    refetch: async () => {
      try {
        const data = await fetchFn();
        return { data, error: null };
      } catch (e) {
        return { data: null, error: e as ApiError };
      }
    },
  };
}

export default api;
