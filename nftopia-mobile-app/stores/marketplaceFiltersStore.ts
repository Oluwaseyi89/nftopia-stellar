import { createStore } from '@/src/utils/store.factory';
import {
  DEFAULT_MARKETPLACE_FILTERS,
  MarketplaceFilters,
  MarketplaceSortOption,
  MarketplaceStatusFilter,
} from '@/src/utils/marketplaceViewModels';

export const VERSION = 1;

interface MarketplaceFiltersStore extends MarketplaceFilters {
  setCategory: (category: string | undefined) => void;
  setStatus: (status: MarketplaceStatusFilter) => void;
  setPriceRange: (minPrice: number | undefined, maxPrice: number | undefined) => void;
  setSortBy: (sortBy: MarketplaceSortOption) => void;
  clearAll: () => void;
}

const initialState: MarketplaceFiltersStore = {
  ...DEFAULT_MARKETPLACE_FILTERS,

  setCategory: () => {},
  setStatus: () => {},
  setPriceRange: () => {},
  setSortBy: () => {},
  clearAll: () => {},
};

export const useMarketplaceFiltersStore = createStore<MarketplaceFiltersStore>({
  name: 'marketplace-filters-store',
  initialState,
  actions: (set) => ({
    ...initialState,

    setCategory: (category: string | undefined) => {
      set({ category });
    },

    setStatus: (status: MarketplaceStatusFilter) => {
      set({ status });
    },

    setPriceRange: (minPrice: number | undefined, maxPrice: number | undefined) => {
      set({ minPrice, maxPrice });
    },

    setSortBy: (sortBy: MarketplaceSortOption) => {
      set({ sortBy });
    },

    clearAll: () => {
      set({ ...DEFAULT_MARKETPLACE_FILTERS });
    },
  }),
  persist: {
    enabled: true,
    name: 'marketplace-filters-storage',
    version: VERSION,
    partialize: (state: MarketplaceFiltersStore) => ({
      category: state.category,
      status: state.status,
      minPrice: state.minPrice,
      maxPrice: state.maxPrice,
      sortBy: state.sortBy,
    }),
    storage: 'async',
  },
  devtools: {
    enabled: __DEV__,
    name: 'MarketplaceFiltersStore',
  },
});
