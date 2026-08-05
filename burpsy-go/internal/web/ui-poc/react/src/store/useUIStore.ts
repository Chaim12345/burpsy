import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { UIState } from '../types';

interface UIActions {
  setCurrentTab: (tab: string) => void;
  toggleTheme: () => void;
  setTheme: (theme: 'light' | 'dark') => void;
  setFilter: (key: string, value: string) => void;
  clearFilter: (key: string) => void;
  clearAllFilters: () => void;
}

type UIStore = UIState & UIActions;

const initialState: UIState = {
  currentTab: 'dashboard',
  theme: 'dark',
  filters: {},
};

export const useUIStore = create<UIStore>()(
  persist(
    (set, get) => ({
      ...initialState,
      
      setCurrentTab: (tab) => set({ currentTab: tab }),
      
      toggleTheme: () => {
        const current = get().theme;
        set({ theme: current === 'light' ? 'dark' : 'light' });
      },
      
      setTheme: (theme) => set({ theme }),
      
      setFilter: (key, value) => set((state) => ({
        filters: { ...state.filters, [key]: value },
      })),
      
      clearFilter: (key) => set((state) => {
        const newFilters = { ...state.filters };
        delete newFilters[key];
        return { filters: newFilters };
      }),
      
      clearAllFilters: () => set({ filters: {} }),
    }),
    {
      name: 'burpsy-ui-storage',
      partialize: (state) => ({
        theme: state.theme,
        filters: state.filters,
      }),
    }
  )
);

// Selectors
export const selectCurrentTab = (state: UIStore) => state.currentTab;
export const selectTheme = (state: UIStore) => state.theme;
export const selectFilter = (state: UIStore, key: string) => state.filters[key];
export const selectAllFilters = (state: UIStore) => state.filters;
