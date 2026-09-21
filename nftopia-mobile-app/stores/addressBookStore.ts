import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { StrKey } from 'stellar-sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export interface AddressBookEntry {
  id: string;
  label: string;
  address: string;
  memo?: string;
  createdAt: string;
  updatedAt: string;
}

export interface RecentRecipient {
  address: string;
  lastSentAt: string;
  count: number;
}

export interface ExportData {
  entries: AddressBookEntry[];
  recentRecipients: RecentRecipient[];
  exportedAt: string;
  version: number;
}

export interface OperationResult {
  success: boolean;
  error?: string;
  entry?: AddressBookEntry;
}

// ---------------------------------------------------------------------------
// Helpers – exported for unit testing and screen usage
// ---------------------------------------------------------------------------
export function isValidStellarAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return false;
  try {
    return StrKey.isValidEd25519PublicKey(address.trim());
  } catch {
    return false;
  }
}

export function validateLabel(label: string): string | null {
  if (!label || !label.trim()) return 'Label is required';
  if (label.trim().length > 50) return 'Label must be 50 characters or less';
  return null;
}

export function filterAddressBook(entries: AddressBookEntry[], query: string): AddressBookEntry[] {
  if (!query || !query.trim()) return entries;
  const lower = query.trim().toLowerCase();
  return entries.filter(
    (e) =>
      e.label.toLowerCase().includes(lower) ||
      e.address.toLowerCase().includes(lower) ||
      (e.memo && e.memo.toLowerCase().includes(lower))
  );
}

export function filterRecentRecipients(recents: RecentRecipient[], query: string): RecentRecipient[] {
  if (!query || !query.trim()) return recents;
  const lower = query.trim().toLowerCase();
  return recents.filter((r) => r.address.toLowerCase().includes(lower));
}

function generateId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

const MAX_RECENT = 20;

// ---------------------------------------------------------------------------
// Store interface
// ---------------------------------------------------------------------------
export interface AddressBookState {
  entries: AddressBookEntry[];
  recentRecipients: RecentRecipient[];
}

export interface AddressBookActions {
  addEntry: (label: string, address: string, memo?: string) => OperationResult;
  updateEntry: (id: string, updates: { label?: string; address?: string; memo?: string }) => OperationResult;
  removeEntry: (id: string) => OperationResult;
  getEntry: (id: string) => AddressBookEntry | undefined;
  searchEntries: (query: string) => AddressBookEntry[];
  addRecentRecipient: (address: string) => void;
  removeRecentRecipient: (address: string) => void;
  clearRecentRecipients: () => void;
  getRecentRecipients: (excludeSaved?: boolean) => RecentRecipient[];
  exportData: () => string;
  importData: (json: string) => OperationResult & { count?: number };
  clearAll: () => void;
}

export type AddressBookStore = AddressBookState & AddressBookActions;

// ---------------------------------------------------------------------------
// Zustand store with persist
// ---------------------------------------------------------------------------
export const useAddressBookStore = create<AddressBookStore>()(
  persist(
    (set, get) => ({
      entries: [],
      recentRecipients: [],

      addEntry: (label: string, address: string, memo?: string) => {
        const trimmedLabel = label?.trim() ?? '';
        const trimmedAddress = address?.trim() ?? '';

        const labelError = validateLabel(trimmedLabel);
        if (labelError) return { success: false, error: labelError };

        if (!trimmedAddress) return { success: false, error: 'Address is required' };
        if (!isValidStellarAddress(trimmedAddress)) {
          return { success: false, error: 'Invalid Stellar address' };
        }

        const duplicate = get().entries.find((e) => e.address === trimmedAddress);
        if (duplicate) {
          return { success: false, error: 'This address is already saved' };
        }

        const now = new Date().toISOString();
        const entry: AddressBookEntry = {
          id: generateId(),
          label: trimmedLabel,
          address: trimmedAddress,
          memo: memo?.trim() || undefined,
          createdAt: now,
          updatedAt: now,
        };

        set((state) => ({ entries: [...state.entries, entry] }));
        return { success: true, entry };
      },

      updateEntry: (id: string, updates: { label?: string; address?: string; memo?: string }) => {
        const existing = get().entries.find((e) => e.id === id);
        if (!existing) return { success: false, error: 'Contact not found' };

        const newLabel = updates.label !== undefined ? updates.label.trim() : existing.label;
        const newAddress = updates.address !== undefined ? updates.address.trim() : existing.address;
        const newMemo = updates.memo !== undefined ? updates.memo.trim() : existing.memo;

        const labelError = validateLabel(newLabel);
        if (labelError) return { success: false, error: labelError };

        if (!newAddress) return { success: false, error: 'Address is required' };
        if (!isValidStellarAddress(newAddress)) {
          return { success: false, error: 'Invalid Stellar address' };
        }

        // Duplicate guard: same address under different id
        const duplicate = get().entries.find((e) => e.address === newAddress && e.id !== id);
        if (duplicate) {
          return { success: false, error: 'This address is already saved' };
        }

        const now = new Date().toISOString();
        const updated: AddressBookEntry = {
          ...existing,
          label: newLabel,
          address: newAddress,
          memo: newMemo || undefined,
          updatedAt: now,
        };

        set((state) => ({
          entries: state.entries.map((e) => (e.id === id ? updated : e)),
        }));
        return { success: true, entry: updated };
      },

      removeEntry: (id: string) => {
        const exists = get().entries.find((e) => e.id === id);
        if (!exists) return { success: false, error: 'Contact not found' };
        set((state) => ({
          entries: state.entries.filter((e) => e.id !== id),
        }));
        return { success: true };
      },

      getEntry: (id: string) => {
        return get().entries.find((e) => e.id === id);
      },

      searchEntries: (query: string) => {
        return filterAddressBook(get().entries, query);
      },

      addRecentRecipient: (address: string) => {
        const trimmed = address?.trim() ?? '';
        if (!trimmed || !isValidStellarAddress(trimmed)) return;

        // Do not add if already in address book? We keep it but callers can filter.
        // Keep recent list deduplicated and ordered by recency.
        set((state) => {
          const existing = state.recentRecipients.find((r) => r.address === trimmed);
          const now = new Date().toISOString();
          let updated: RecentRecipient[];
          if (existing) {
            updated = [
              { address: trimmed, lastSentAt: now, count: existing.count + 1 },
              ...state.recentRecipients.filter((r) => r.address !== trimmed),
            ];
          } else {
            updated = [{ address: trimmed, lastSentAt: now, count: 1 }, ...state.recentRecipients];
          }
          // Cap size
          if (updated.length > MAX_RECENT) updated = updated.slice(0, MAX_RECENT);
          return { recentRecipients: updated };
        });
      },

      removeRecentRecipient: (address: string) => {
        set((state) => ({
          recentRecipients: state.recentRecipients.filter((r) => r.address !== address),
        }));
      },

      clearRecentRecipients: () => {
        set({ recentRecipients: [] });
      },

      getRecentRecipients: (excludeSaved = true) => {
        const { recentRecipients, entries } = get();
        if (!excludeSaved) return recentRecipients;
        const savedSet = new Set(entries.map((e) => e.address));
        return recentRecipients.filter((r) => !savedSet.has(r.address));
      },

      exportData: () => {
        const { entries, recentRecipients } = get();
        const payload: ExportData = {
          entries,
          recentRecipients,
          exportedAt: new Date().toISOString(),
          version: 1,
        };
        return JSON.stringify(payload, null, 2);
      },

      importData: (json: string) => {
        if (!json || typeof json !== 'string') {
          return { success: false, error: 'Invalid import data' };
        }
        try {
          const parsed = JSON.parse(json);
          // Support both raw array and ExportData shape
          let incomingEntries: any[] = [];
          let incomingRecents: any[] = [];

          if (Array.isArray(parsed)) {
            incomingEntries = parsed;
          } else if (parsed.entries && Array.isArray(parsed.entries)) {
            incomingEntries = parsed.entries;
            if (Array.isArray(parsed.recentRecipients)) incomingRecents = parsed.recentRecipients;
          } else {
            return { success: false, error: 'Invalid import format' };
          }

          // Validate entries
          const validEntries: AddressBookEntry[] = [];
          const errors: string[] = [];
          const existingAddresses = new Set(get().entries.map((e) => e.address));

          for (const item of incomingEntries) {
            if (!item.address || !isValidStellarAddress(item.address)) {
              errors.push(`Invalid address: ${item.address}`);
              continue;
            }
            if (!item.label || typeof item.label !== 'string' || !item.label.trim()) {
              errors.push(`Missing label for address: ${item.address}`);
              continue;
            }
            if (existingAddresses.has(item.address) || validEntries.find((e) => e.address === item.address)) {
              // Skip duplicates silently
              continue;
            }
            const now = new Date().toISOString();
            validEntries.push({
              id: item.id || generateId(),
              label: item.label.trim(),
              address: item.address.trim(),
              memo: item.memo?.trim() || undefined,
              createdAt: item.createdAt || now,
              updatedAt: item.updatedAt || now,
            });
            existingAddresses.add(item.address);
          }

          // Validate recents
          const validRecents: RecentRecipient[] = [];
          for (const r of incomingRecents) {
            if (r.address && isValidStellarAddress(r.address)) {
              validRecents.push({
                address: r.address.trim(),
                lastSentAt: r.lastSentAt || new Date().toISOString(),
                count: typeof r.count === 'number' ? r.count : 1,
              });
            }
          }

          if (validEntries.length === 0 && validRecents.length === 0) {
            return { success: false, error: errors[0] || 'No valid entries to import' };
          }

          set((state) => ({
            entries: [...state.entries, ...validEntries],
            recentRecipients:
              validRecents.length > 0 ? [...validRecents, ...state.recentRecipients].slice(0, MAX_RECENT) : state.recentRecipients,
          }));

          return { success: true, count: validEntries.length };
        } catch (e) {
          return { success: false, error: e instanceof Error ? e.message : 'Failed to parse import data' };
        }
      },

      clearAll: () => {
        set({ entries: [], recentRecipients: [] });
      },
    }),
    {
      name: 'address-book-storage',
      storage: createJSONStorage(() => AsyncStorage),
      partialize: (state) => ({
        entries: state.entries,
        recentRecipients: state.recentRecipients,
      }),
      version: 1,
    }
  )
);
