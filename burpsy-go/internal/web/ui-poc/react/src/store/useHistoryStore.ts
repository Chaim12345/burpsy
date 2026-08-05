import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import type { Exchange, HistoryState } from '../types';

interface HistoryActions {
  setExchanges: (exchanges: Exchange[]) => void;
  addExchange: (exchange: Exchange) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setSelectedId: (id: number | null) => void;
  setSearchQuery: (query: string) => void;
  toggleStatusFilter: (status: string) => void;
  setScopeOnly: (scopeOnly: boolean) => void;
  toggleRowSelection: (id: number) => void;
  selectAllRows: (select: boolean) => void;
  clearSelection: () => void;
}

type HistoryStore = HistoryState & HistoryActions;

const initialState: HistoryState = {
  exchanges: [],
  loading: false,
  error: null,
  selectedId: null,
  searchQuery: '',
  statusFilters: new Set(['2', '3', '4', '5']),
  scopeOnly: false,
  selectedRows: new Set(),
};

export const useHistoryStore = create<HistoryStore>()(
  devtools(
    (set, get) => ({
      ...initialState,
      
      setExchanges: (exchanges) => set({ exchanges, loading: false, error: null }),
      
      addExchange: (exchange) => set((state) => ({
        exchanges: [exchange, ...state.exchanges],
      })),
      
      setLoading: (loading) => set({ loading }),
      
      setError: (error) => set({ error, loading: false }),
      
      setSelectedId: (id) => set({ selectedId: id }),
      
      setSearchQuery: (query) => set({ searchQuery: query }),
      
      toggleStatusFilter: (status) => set((state) => {
        const newFilters = new Set(state.statusFilters);
        if (newFilters.has(status)) {
          newFilters.delete(status);
        } else {
          newFilters.add(status);
        }
        return { statusFilters: newFilters };
      }),
      
      setScopeOnly: (scopeOnly) => set({ scopeOnly }),
      
      toggleRowSelection: (id) => set((state) => {
        const newSelection = new Set(state.selectedRows);
        if (newSelection.has(id)) {
          newSelection.delete(id);
        } else {
          newSelection.add(id);
        }
        return { selectedRows: newSelection };
      }),
      
      selectAllRows: (select) => set((state) => {
        if (select) {
          return { selectedRows: new Set(state.exchanges.map(e => e.id)) };
        }
        return { selectedRows: new Set() };
      }),
      
      clearSelection: () => set({ selectedRows: new Set() }),
    }),
    { name: 'HistoryStore' }
  )
);

// Selectors
export const selectFilteredExchanges = (state: HistoryStore): Exchange[] => {
  let filtered = state.exchanges;
  
  // Filter by status
  if (state.statusFilters.size > 0) {
    filtered = filtered.filter(ex => {
      if (ex.status === null) return false;
      return state.statusFilters.has(String(ex.status)[0]);
    });
  }
  
  // Filter by search
  if (state.searchQuery) {
    const query = state.searchQuery.toLowerCase();
    filtered = filtered.filter(ex => 
      `${ex.method} ${ex.host} ${ex.path}`.toLowerCase().includes(query)
    );
  }
  
  return filtered;
};

export const selectSelectedExchange = (state: HistoryStore): Exchange | null => {
  if (!state.selectedId) return null;
  return state.exchanges.find(e => e.id === state.selectedId) ?? null;
};

export const selectSelectedCount = (state: HistoryStore) => state.selectedRows.size;

export const selectHasSelection = (state: HistoryStore) => state.selectedRows.size > 0;
