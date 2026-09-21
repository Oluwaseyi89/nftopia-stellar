// ── Mocks ─────────────────────────────────────────────────────────────────────

// React Native injects this global at build time; this repo's jest config
// runs in a plain node environment, so shim it before the store module
// (which reads it via the shared createStore factory) is imported.
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

import { useMarketplaceFiltersStore } from '../marketplaceFiltersStore';
import { DEFAULT_MARKETPLACE_FILTERS } from '@/src/utils/marketplaceViewModels';

// ── Helpers ───────────────────────────────────────────────────────────────────

function getStore() {
  return useMarketplaceFiltersStore.getState();
}

const flushMicrotasks = () => new Promise((resolve) => setTimeout(resolve, 0));

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('useMarketplaceFiltersStore', () => {
  beforeEach(() => {
    useMarketplaceFiltersStore.setState({ ...DEFAULT_MARKETPLACE_FILTERS });
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
  });

  describe('initial state', () => {
    it('starts with the default filters', () => {
      expect(getStore().category).toBeUndefined();
      expect(getStore().status).toBe('ACTIVE');
      expect(getStore().minPrice).toBeUndefined();
      expect(getStore().maxPrice).toBeUndefined();
      expect(getStore().sortBy).toBe('newest');
    });
  });

  describe('setCategory', () => {
    it('sets the active category', () => {
      getStore().setCategory('art');
      expect(getStore().category).toBe('art');
    });

    it('clears the category when set to undefined', () => {
      getStore().setCategory('art');
      getStore().setCategory(undefined);
      expect(getStore().category).toBeUndefined();
    });
  });

  describe('setStatus', () => {
    it('sets the status filter', () => {
      getStore().setStatus('SOLD');
      expect(getStore().status).toBe('SOLD');
    });
  });

  describe('setPriceRange', () => {
    it('sets min and max price together', () => {
      getStore().setPriceRange(10, 100);
      expect(getStore().minPrice).toBe(10);
      expect(getStore().maxPrice).toBe(100);
    });

    it('allows an open-ended range (only min or only max)', () => {
      getStore().setPriceRange(10, undefined);
      expect(getStore().minPrice).toBe(10);
      expect(getStore().maxPrice).toBeUndefined();
    });
  });

  describe('setSortBy', () => {
    it('sets the sort order', () => {
      getStore().setSortBy('price_asc');
      expect(getStore().sortBy).toBe('price_asc');
    });
  });

  describe('clearAll', () => {
    it('resets every filter and sort back to defaults', () => {
      getStore().setCategory('gaming');
      getStore().setStatus('SOLD');
      getStore().setPriceRange(5, 50);
      getStore().setSortBy('price_desc');

      getStore().clearAll();

      expect(getStore().category).toBeUndefined();
      expect(getStore().status).toBe('ACTIVE');
      expect(getStore().minPrice).toBeUndefined();
      expect(getStore().maxPrice).toBeUndefined();
      expect(getStore().sortBy).toBe('newest');
    });

    it('is a no-op on an already-default state', () => {
      getStore().clearAll();
      expect(getStore()).toMatchObject(DEFAULT_MARKETPLACE_FILTERS);
    });
  });

  describe('persistence', () => {
    it('writes filter changes to storage', async () => {
      getStore().setCategory('music');
      await flushMicrotasks();

      const raw = asyncStorageStore['marketplace-filters-storage'];
      expect(raw).toBeDefined();
      expect(raw).toContain('music');
    });

    it('persists a cleared state back to storage', async () => {
      getStore().setCategory('music');
      await flushMicrotasks();
      getStore().clearAll();
      await flushMicrotasks();

      const raw = asyncStorageStore['marketplace-filters-storage'];
      expect(raw).toBeDefined();
      expect(raw).not.toContain('"category":"music"');
    });
  });
});
