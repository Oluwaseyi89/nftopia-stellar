import { Keypair } from 'stellar-sdk';

// ── Mocks ─────────────────────────────────────────────────────────────────────
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
  getAllKeys: jest.fn(() => Promise.resolve(Object.keys(asyncStorageStore))),
  multiGet: jest.fn(),
  multiSet: jest.fn(),
  multiRemove: jest.fn(),
}));

jest.mock('expo-secure-store', () => ({
  setItemAsync: jest.fn(),
  getItemAsync: jest.fn(),
  deleteItemAsync: jest.fn(),
}));

jest.mock('expo-clipboard', () => ({
  setStringAsync: jest.fn(),
  getStringAsync: jest.fn(),
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────
import {
  useAddressBookStore,
  isValidStellarAddress,
  filterAddressBook,
} from '../addressBookStore';

// Helpers
function randomAddress(): string {
  return Keypair.random().publicKey();
}
const INVALID_ADDRESS = 'GINVALIDADDRESS12345678901234567890123456789012345678901234';

function getStore() {
  return useAddressBookStore.getState();
}

describe('addressBookStore', () => {
  beforeEach(() => {
    useAddressBookStore.setState({ entries: [], recentRecipients: [] });
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
    jest.clearAllMocks();
  });

  describe('isValidStellarAddress', () => {
    it('returns true for a valid Stellar address', () => {
      expect(isValidStellarAddress(randomAddress())).toBe(true);
    });
    it('returns false for invalid address', () => {
      expect(isValidStellarAddress(INVALID_ADDRESS)).toBe(false);
    });
    it('returns false for empty', () => {
      expect(isValidStellarAddress('')).toBe(false);
    });
  });

  describe('filterAddressBook', () => {
    it('filters by label case-insensitive', () => {
      const entries = [
        { id: '1', label: 'Alice', address: randomAddress(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        { id: '2', label: 'Bob', address: randomAddress(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ];
      expect(filterAddressBook(entries, 'alice')).toHaveLength(1);
      expect(filterAddressBook(entries, 'ALICE')).toHaveLength(1);
    });
    it('filters by address substring', () => {
      const addr = randomAddress();
      const entries = [
        { id: '1', label: 'Alice', address: addr, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ];
      expect(filterAddressBook(entries, addr.slice(0, 5))).toHaveLength(1);
      expect(filterAddressBook(entries, 'ZZZZ')).toHaveLength(0);
    });
    it('returns all when query empty', () => {
      const entries = [
        { id: '1', label: ' Alice', address: randomAddress(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ];
      expect(filterAddressBook(entries, '')).toHaveLength(1);
      expect(filterAddressBook(entries, '   ')).toHaveLength(1);
    });
  });

  describe('addEntry', () => {
    it('adds a valid entry', () => {
      const addr = randomAddress();
      const result = getStore().addEntry('Alice', addr);
      expect(result.success).toBe(true);
      expect(result.entry).toBeDefined();
      expect(getStore().entries).toHaveLength(1);
      expect(getStore().entries[0].label).toBe('Alice');
      expect(getStore().entries[0].address).toBe(addr);
    });

    it('rejects duplicate addresses', () => {
      const addr = randomAddress();
      expect(getStore().addEntry('Alice', addr).success).toBe(true);
      const dup = getStore().addEntry('Bob', addr);
      expect(dup.success).toBe(false);
      expect(dup.error).toMatch(/already saved/i);
      expect(getStore().entries).toHaveLength(1);
    });

    it('rejects invalid address with clear message', () => {
      const result = getStore().addEntry('Alice', INVALID_ADDRESS);
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/Invalid Stellar address/i);
    });

    it('rejects empty label', () => {
      const result = getStore().addEntry('', randomAddress());
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/Label is required/i);
    });

    it('trims whitespace', () => {
      const addr = randomAddress();
      const result = getStore().addEntry('  Alice  ', `  ${addr}  `);
      expect(result.success).toBe(true);
      expect(getStore().entries[0].label).toBe('Alice');
      expect(getStore().entries[0].address).toBe(addr);
    });

    it('persists across store state (entries length check)', () => {
      // Simple persistence check via store state – AsyncStorage mock will store under address-book-storage
      const addr = randomAddress();
      getStore().addEntry('Persisted', addr);
      expect(getStore().entries).toHaveLength(1);
    });
  });

  describe('updateEntry', () => {
    it('updates label and address', () => {
      const addr1 = randomAddress();
      const addr2 = randomAddress();
      const { entry } = getStore().addEntry('Alice', addr1);
      const result = getStore().updateEntry(entry!.id, { label: 'Alice Updated', address: addr2 });
      expect(result.success).toBe(true);
      expect(getStore().entries[0].label).toBe('Alice Updated');
      expect(getStore().entries[0].address).toBe(addr2);
    });

    it('rejects duplicate on update', () => {
      const addr1 = randomAddress();
      const addr2 = randomAddress();
      const e1 = getStore().addEntry('Alice', addr1).entry!;
      const e2 = getStore().addEntry('Bob', addr2).entry!;
      const result = getStore().updateEntry(e2.id, { address: addr1 });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/already saved/i);
    });

    it('rejects invalid address on update', () => {
      const addr = randomAddress();
      const { entry } = getStore().addEntry('Alice', addr);
      const result = getStore().updateEntry(entry!.id, { address: INVALID_ADDRESS });
      expect(result.success).toBe(false);
    });

    it('returns error for non-existent id', () => {
      const result = getStore().updateEntry('nonexistent', { label: 'Foo' });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/not found/i);
    });
  });

  describe('removeEntry', () => {
    it('removes an entry', () => {
      const addr = randomAddress();
      const { entry } = getStore().addEntry('Alice', addr);
      expect(getStore().entries).toHaveLength(1);
      const result = getStore().removeEntry(entry!.id);
      expect(result.success).toBe(true);
      expect(getStore().entries).toHaveLength(0);
    });

    it('returns error for non-existent id', () => {
      const result = getStore().removeEntry('nope');
      expect(result.success).toBe(false);
    });
  });

  describe('searchEntries', () => {
    it('correctly filters the address book list', () => {
      const addr1 = randomAddress();
      const addr2 = randomAddress();
      getStore().addEntry('Alice Wonderland', addr1);
      getStore().addEntry('Bob Builder', addr2);
      expect(getStore().searchEntries('alice')).toHaveLength(1);
      expect(getStore().searchEntries('builder')).toHaveLength(1);
      expect(getStore().searchEntries('nonexistent')).toHaveLength(0);
      expect(getStore().searchEntries('')).toHaveLength(2);
    });
  });

  describe('recentRecipients', () => {
    it('adds recent recipients and deduplicates with count increment', () => {
      const addr = randomAddress();
      getStore().addRecentRecipient(addr);
      expect(getStore().recentRecipients).toHaveLength(1);
      expect(getStore().recentRecipients[0].count).toBe(1);
      getStore().addRecentRecipient(addr);
      expect(getStore().recentRecipients).toHaveLength(1);
      expect(getStore().recentRecipients[0].count).toBe(2);
    });

    it('suggests recently sent-to addresses without being permanently saved', () => {
      const addr = randomAddress();
      getStore().addRecentRecipient(addr);
      // Should appear in recents
      expect(getStore().getRecentRecipients(false)).toHaveLength(1);
      // Not in saved entries
      expect(getStore().entries).toHaveLength(0);
      // getRecentRecipients(true) should still return it since not saved
      expect(getStore().getRecentRecipients(true)).toHaveLength(1);
      // After saving the same address, recent suggestion should be filtered out
      getStore().addEntry('Alice', addr);
      expect(getStore().getRecentRecipients(true)).toHaveLength(0);
      // But with excludeSaved false it still appears
      expect(getStore().getRecentRecipients(false)).toHaveLength(1);
    });

    it('ignores invalid addresses for recents', () => {
      getStore().addRecentRecipient(INVALID_ADDRESS);
      expect(getStore().recentRecipients).toHaveLength(0);
    });

    it('clearRecentRecipients empties list', () => {
      getStore().addRecentRecipient(randomAddress());
      getStore().addRecentRecipient(randomAddress());
      expect(getStore().recentRecipients.length).toBeGreaterThan(0);
      getStore().clearRecentRecipients();
      expect(getStore().recentRecipients).toHaveLength(0);
    });

    it('caps recent list at 20', () => {
      for (let i = 0; i < 25; i++) {
        getStore().addRecentRecipient(randomAddress());
      }
      expect(getStore().recentRecipients).toHaveLength(20);
    });

    it('reorders recent on re-add (most recent first)', () => {
      const addr1 = randomAddress();
      const addr2 = randomAddress();
      getStore().addRecentRecipient(addr1);
      getStore().addRecentRecipient(addr2);
      expect(getStore().recentRecipients[0].address).toBe(addr2);
      // Re-add addr1 -> should move to front
      getStore().addRecentRecipient(addr1);
      expect(getStore().recentRecipients[0].address).toBe(addr1);
    });
  });

  describe('export/import', () => {
    it('exportData returns JSON with entries', () => {
      const addr = randomAddress();
      getStore().addEntry('Alice', addr);
      const json = getStore().exportData();
      const parsed = JSON.parse(json);
      expect(parsed.entries).toHaveLength(1);
      expect(parsed.entries[0].address).toBe(addr);
      expect(parsed.version).toBe(1);
    });

    it('importData merges valid entries and skips duplicates', () => {
      const addr1 = randomAddress();
      const addr2 = randomAddress();
      getStore().addEntry('Alice', addr1);
      const payload = JSON.stringify({
        entries: [
          { label: 'Bob', address: addr2 },
          { label: 'Duplicate', address: addr1 },
          { label: 'Bad', address: INVALID_ADDRESS },
        ],
        recentRecipients: [],
        version: 1,
        exportedAt: new Date().toISOString(),
      });
      const result = getStore().importData(payload);
      expect(result.success).toBe(true);
      expect(result.count).toBe(1);
      expect(getStore().entries).toHaveLength(2);
      expect(getStore().entries.find((e: any) => e.address === addr2)).toBeDefined();
    });

    it('importData handles raw array format', () => {
      const addr = randomAddress();
      const json = JSON.stringify([{ label: 'Dave', address: addr }]);
      const result = getStore().importData(json);
      expect(result.success).toBe(true);
      expect(getStore().entries).toHaveLength(1);
    });

    it('importData returns error for invalid JSON', () => {
      const result = getStore().importData('not json');
      expect(result.success).toBe(false);
    });

    it('importData returns error for invalid format', () => {
      const result = getStore().importData(JSON.stringify({ foo: 'bar' }));
      expect(result.success).toBe(false);
    });
  });

  describe('clearAll', () => {
    it('clears both entries and recents', () => {
      getStore().addEntry('Alice', randomAddress());
      getStore().addRecentRecipient(randomAddress());
      getStore().clearAll();
      expect(getStore().entries).toHaveLength(0);
      expect(getStore().recentRecipients).toHaveLength(0);
    });
  });
});
