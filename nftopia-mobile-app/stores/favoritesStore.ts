import { createStore } from '@/src/utils/store.factory';

export const VERSION = 1;

interface FavoritesStore {
  favorites: string[];
  favoriteCollections: string[];
  watchlist: string[];
  recentSearches: string[];
  isLoading: boolean;

  addFavorite: (nftId: string) => void;
  removeFavorite: (nftId: string) => void;
  toggleFavorite: (nftId: string) => void;
  isFavorite: (nftId: string) => boolean;
  addFavoriteCollection: (collectionId: string) => void;
  removeFavoriteCollection: (collectionId: string) => void;
  toggleFavoriteCollection: (collectionId: string) => void;
  isFavoriteCollection: (collectionId: string) => boolean;
  favoriteCount: () => number;
  addToWatchlist: (nftId: string) => void;
  removeFromWatchlist: (nftId: string) => void;
  toggleWatchlist: (nftId: string) => void;
  isInWatchlist: (nftId: string) => boolean;
  addRecentSearch: (query: string) => void;
  clearRecentSearches: () => void;
  clearAll: () => void;
  setLoading: (loading: boolean) => void;
}

const initialState: FavoritesStore = {
  favorites: [],
  favoriteCollections: [],
  watchlist: [],
  recentSearches: [],
  isLoading: false,

  addFavorite: () => {},
  removeFavorite: () => {},
  toggleFavorite: () => {},
  isFavorite: () => false,
  addFavoriteCollection: () => {},
  removeFavoriteCollection: () => {},
  toggleFavoriteCollection: () => {},
  isFavoriteCollection: () => false,
  favoriteCount: () => 0,
  addToWatchlist: () => {},
  removeFromWatchlist: () => {},
  toggleWatchlist: () => {},
  isInWatchlist: () => false,
  addRecentSearch: () => {},
  clearRecentSearches: () => {},
  clearAll: () => {},
  setLoading: () => {},
};

export const useFavoritesStore = createStore<FavoritesStore>({
  name: 'favorites-store',
  initialState,
  actions: (set, get) => ({
    ...initialState,

    addFavorite: (nftId: string) => {
      set((state) => {
        if (state.favorites.includes(nftId)) return state;
        return { favorites: [...state.favorites, nftId] };
      });
    },

    removeFavorite: (nftId: string) => {
      set((state) => ({
        favorites: state.favorites.filter((id) => id !== nftId),
      }));
    },

    toggleFavorite: (nftId: string) => {
      const isFav = get().isFavorite(nftId);
      if (isFav) {
        get().removeFavorite(nftId);
      } else {
        get().addFavorite(nftId);
      }
    },

    isFavorite: (nftId: string) => {
      return get().favorites.includes(nftId);
    },

    addFavoriteCollection: (collectionId: string) => {
      set((state) => {
        if (state.favoriteCollections.includes(collectionId)) return state;
        return { favoriteCollections: [...state.favoriteCollections, collectionId] };
      });
    },

    removeFavoriteCollection: (collectionId: string) => {
      set((state) => ({
        favoriteCollections: state.favoriteCollections.filter((id) => id !== collectionId),
      }));
    },

    toggleFavoriteCollection: (collectionId: string) => {
      const isFav = get().isFavoriteCollection(collectionId);
      if (isFav) {
        get().removeFavoriteCollection(collectionId);
      } else {
        get().addFavoriteCollection(collectionId);
      }
    },

    isFavoriteCollection: (collectionId: string) => {
      return get().favoriteCollections.includes(collectionId);
    },

    favoriteCount: () => {
      return get().favorites.length + get().favoriteCollections.length;
    },

    addToWatchlist: (nftId: string) => {
      set((state) => {
        if (state.watchlist.includes(nftId)) return state;
        return { watchlist: [...state.watchlist, nftId] };
      });
    },

    removeFromWatchlist: (nftId: string) => {
      set((state) => ({
        watchlist: state.watchlist.filter((id) => id !== nftId),
      }));
    },

    toggleWatchlist: (nftId: string) => {
      const isWatched = get().isInWatchlist(nftId);
      if (isWatched) {
        get().removeFromWatchlist(nftId);
      } else {
        get().addToWatchlist(nftId);
      }
    },

    isInWatchlist: (nftId: string) => {
      return get().watchlist.includes(nftId);
    },

    addRecentSearch: (query: string) => {
      set((state) => {
        const searches = state.recentSearches.filter((s) => s !== query);
        return {
          recentSearches: [query, ...searches].slice(0, 10),
        };
      });
    },

    clearRecentSearches: () => {
      set({ recentSearches: [] });
    },

    clearAll: () => {
      set({
        favorites: [],
        favoriteCollections: [],
        watchlist: [],
        recentSearches: [],
      });
    },

    setLoading: (isLoading: boolean) => {
      set({ isLoading });
    },
  }),
  persist: {
    enabled: true,
    name: 'favorites-storage',
    version: VERSION,
    partialize: (state: FavoritesStore) => ({
      favorites: state.favorites,
      favoriteCollections: state.favoriteCollections,
      watchlist: state.watchlist,
      recentSearches: state.recentSearches,
    }),
    storage: 'async',
    // Don't persist loading state
    blacklist: ['isLoading'],
  },
  devtools: {
    enabled: __DEV__,
    name: 'FavoritesStore',
  },
});