// ── Mocks ─────────────────────────────────────────────────────────────────────

(global as unknown as { __DEV__: boolean }).__DEV__ = false;

const asyncStorageStore: Record<string, string> = {};

jest.mock('@react-native-async-storage/async-storage', () => ({
  getItem: jest.fn((key: string) => Promise.resolve(asyncStorageStore[key] ?? null)),
  setItem: jest.fn((key: string, value: string) => {
    asyncStorageStore[key] = value;
    return Promise.resolve();
  }),
  removeItem: jest.fn((key: string) => {
    delete asyncStorageStore[key];
    return Promise.resolve();
  }),
  mergeItem: jest.fn(),
  clear: jest.fn(() => {
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
    return Promise.resolve();
  }),
  getAllKeys: jest.fn(() => Promise.resolve(Object.keys(asyncStorageStore))),
  multiGet: jest.fn(),
  multiSet: jest.fn(),
  multiRemove: jest.fn(),
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────

import { useFavoritesStore } from '../favoritesStore';

function getStore() {
  return useFavoritesStore.getState();
}

const flushMicrotasks = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('useFavoritesStore', () => {
  beforeEach(() => {
    useFavoritesStore.setState({
      favorites: [],
      favoriteCollections: [],
      watchlist: [],
      recentSearches: [],
      isLoading: false,
    });
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
  });

  describe('NFT favorites', () => {
    it('starts with empty favorites', () => {
      expect(getStore().favorites).toEqual([]);
    });

    it('addFavorite adds an id', () => {
      getStore().addFavorite('nft-1');
      expect(getStore().favorites).toEqual(['nft-1']);
    });

    it('addFavorite does not add duplicates', () => {
      getStore().addFavorite('nft-1');
      getStore().addFavorite('nft-1');
      expect(getStore().favorites).toEqual(['nft-1']);
    });

    it('removeFavorite removes the id', () => {
      getStore().addFavorite('nft-1');
      getStore().removeFavorite('nft-1');
      expect(getStore().favorites).toEqual([]);
    });

    it('toggleFavorite adds then removes', () => {
      getStore().toggleFavorite('nft-1');
      expect(getStore().isFavorite('nft-1')).toBe(true);
      getStore().toggleFavorite('nft-1');
      expect(getStore().isFavorite('nft-1')).toBe(false);
    });

    it('isFavorite reflects membership', () => {
      expect(getStore().isFavorite('nft-1')).toBe(false);
      getStore().addFavorite('nft-1');
      expect(getStore().isFavorite('nft-1')).toBe(true);
    });
  });

  describe('collection favorites', () => {
    it('starts with empty collection favorites', () => {
      expect(getStore().favoriteCollections).toEqual([]);
    });

    it('addFavoriteCollection adds a collection id', () => {
      getStore().addFavoriteCollection('col-1');
      expect(getStore().favoriteCollections).toEqual(['col-1']);
    });

    it('does not add duplicate collection ids', () => {
      getStore().addFavoriteCollection('col-1');
      getStore().addFavoriteCollection('col-1');
      expect(getStore().favoriteCollections).toEqual(['col-1']);
    });

    it('removeFavoriteCollection removes the id', () => {
      getStore().addFavoriteCollection('col-1');
      getStore().removeFavoriteCollection('col-1');
      expect(getStore().favoriteCollections).toEqual([]);
    });

    it('toggleFavoriteCollection adds then removes', () => {
      getStore().toggleFavoriteCollection('col-1');
      expect(getStore().isFavoriteCollection('col-1')).toBe(true);
      getStore().toggleFavoriteCollection('col-1');
      expect(getStore().isFavoriteCollection('col-1')).toBe(false);
    });

    it('isFavoriteCollection reflects membership', () => {
      expect(getStore().isFavoriteCollection('col-1')).toBe(false);
      getStore().addFavoriteCollection('col-1');
      expect(getStore().isFavoriteCollection('col-1')).toBe(true);
    });
  });

  describe('favoriteCount', () => {
    it('counts NFTs and collections together', () => {
      expect(getStore().favoriteCount()).toBe(0);
      getStore().addFavorite('nft-1');
      getStore().addFavorite('nft-2');
      getStore().addFavoriteCollection('col-1');
      expect(getStore().favoriteCount()).toBe(3);
    });
  });

  describe('clearAll', () => {
    it('clears NFT and collection favorites', () => {
      getStore().addFavorite('nft-1');
      getStore().addFavoriteCollection('col-1');
      getStore().clearAll();
      expect(getStore().favorites).toEqual([]);
      expect(getStore().favoriteCollections).toEqual([]);
      expect(getStore().favoriteCount()).toBe(0);
    });
  });

  describe('persistence', () => {
    it('persists NFT and collection favorites to storage', async () => {
      getStore().addFavorite('nft-1');
      getStore().addFavoriteCollection('col-1');
      await flushMicrotasks();

      const raw = asyncStorageStore['favorites-storage'];
      expect(raw).toBeDefined();
      expect(raw).toContain('nft-1');
      expect(raw).toContain('col-1');
    });

    it('removes unfavorited items from storage', async () => {
      getStore().addFavorite('nft-1');
      await flushMicrotasks();
      getStore().removeFavorite('nft-1');
      await flushMicrotasks();

      const raw = asyncStorageStore['favorites-storage'];
      expect(raw).toBeDefined();
      expect(raw).not.toContain('nft-1');
    });
  });
});
