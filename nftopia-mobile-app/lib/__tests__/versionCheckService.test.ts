// ── Mocks (must be hoisted before imports) ───────────────────────────────────
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
}));

const mockNetInfo = {
  fetch: jest.fn(),
};
jest.mock('@react-native-community/netinfo', () => ({
  fetch: (...args: unknown[]) => mockNetInfo.fetch(...args),
  addEventListener: jest.fn(),
}));

const mockAppStateListeners: Array<(next: string) => void> = [];
jest.mock('react-native', () => ({
  AppState: {
    currentState: 'active',
    addEventListener: jest.fn((_type: string, handler: (next: string) => void) => {
      mockAppStateListeners.push(handler);
      return { remove: jest.fn() };
    }),
  },
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────
import {
  runVersionCheck,
  shouldCheck,
  fetchVersionGate,
  sealCurrentVersion,
} from '../versionCheckService';
import { CACHED_GATE_KEY, LAST_CHECK_KEY } from '../versionCheck';

function jsonOk(body: unknown) {
  return {
    ok: true,
    status: 200,
    json: async () => body,
  } as Response;
}

describe('versionCheckService', () => {
  beforeEach(() => {
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
    mockNetInfo.fetch.mockReset();
    mockAppStateListeners.length = 0;
    jest.clearAllMocks();
    sealCurrentVersion('1.0.0');
  });

  describe('shouldCheck', () => {
    it('returns true when no previous check exists', async () => {
      // No stored timestamp => last treated as 0 => elapsed for any real "now".
      expect(await shouldCheck(Date.now(), 60000)).toBe(true);
    });

    it('returns false within the throttle window', async () => {
      asyncStorageStore[LAST_CHECK_KEY] = '1000';
      expect(await shouldCheck(5000, 60000)).toBe(false);
    });

    it('returns true once the interval has elapsed', async () => {
      asyncStorageStore[LAST_CHECK_KEY] = '1000';
      expect(await shouldCheck(1000 + 60001, 60000)).toBe(true);
    });
  });

  describe('fetchVersionGate', () => {
    it('resolves the gate from the endpoint payload', async () => {
      const fetchImpl = jest.fn().mockResolvedValue(
        jsonOk({ minimum: '1.2.0', latest: '2.0.0' })
      );
      const gate = await fetchVersionGate(fetchImpl as unknown as typeof fetch, 'http://x');
      expect(gate).toEqual({ minimum: '1.2.0', latest: '2.0.0' });
    });

    it('returns null on an HTTP error status', async () => {
      const fetchImpl = jest.fn().mockResolvedValue({ ok: false, status: 500 });
      expect(await fetchVersionGate(fetchImpl as unknown as typeof fetch)).toBeNull();
    });

    it('returns null on a network exception (no-op failure)', async () => {
      const fetchImpl = jest.fn().mockRejectedValue(new Error('offline'));
      expect(await fetchVersionGate(fetchImpl as unknown as typeof fetch)).toBeNull();
    });
  });

  describe('runVersionCheck', () => {
    it('no-ops when throttled (returning null)', async () => {
      asyncStorageStore[LAST_CHECK_KEY] = String(Date.now());
      const result = await runVersionCheck({ checkIntervalMs: 60 * 60 * 1000 });
      expect(result).toBeNull();
      expect(mockNetInfo.fetch).not.toHaveBeenCalled();
    });

    it('no-ops gracefully when offline and no cached gate exists', async () => {
      mockNetInfo.fetch.mockResolvedValue({
        isConnected: false,
        isInternetReachable: false,
      });
      const result = await runVersionCheck({ checkIntervalMs: 0 });
      expect(result).toBeNull();
    });

    it('reuses the cached gate when offline', async () => {
      asyncStorageStore[CACHED_GATE_KEY] = JSON.stringify({
        minimum: '1.5.0',
        latest: '2.0.0',
      });
      mockNetInfo.fetch.mockResolvedValue({
        isConnected: false,
        isInternetReachable: false,
      });
      const result = await runVersionCheck({ checkIntervalMs: 0 });
      expect(result?.state).toBe('update_required');
      expect(result?.latest).toBe('2.0.0');
    });

    it('returns a soft nudge when below latest but above minimum', async () => {
      mockNetInfo.fetch.mockResolvedValue({
        isConnected: true,
        isInternetReachable: true,
      });
      const fetchImpl = jest.fn().mockResolvedValue(
        jsonOk({ minimum: '1.2.0', latest: '2.0.0' })
      );
      const result = await runVersionCheck({
        checkIntervalMs: 0,
        appVersion: '1.5.0',
        fetchImpl: fetchImpl as unknown as typeof fetch,
        endpoint: 'http://x',
      });
      expect(result?.state).toBe('update_available');
    });

    it('returns a hard requirement when below minimum', async () => {
      mockNetInfo.fetch.mockResolvedValue({
        isConnected: true,
        isInternetReachable: true,
      });
      const fetchImpl = jest.fn().mockResolvedValue(
        jsonOk({ minimum: '1.5.0', latest: '2.0.0' })
      );
      const result = await runVersionCheck({
        checkIntervalMs: 0,
        appVersion: '1.0.0',
        fetchImpl: fetchImpl as unknown as typeof fetch,
        endpoint: 'http://x',
      });
      expect(result?.state).toBe('update_required');
    });
  });
});
