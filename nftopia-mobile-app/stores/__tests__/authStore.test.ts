// ── Mocks ─────────────────────────────────────────────────────────────────────

// React Native injects this global at build time; this repo's jest config
// runs in a plain node environment, so shim it before the store module
// (which reads it via the shared createStore factory) is imported.
(global as unknown as { __DEV__: boolean }).__DEV__ = false;

const secureStoreData: Record<string, string> = {};

jest.mock('expo-secure-store', () => ({
  setItemAsync: jest.fn((key: string, value: string) => {
    secureStoreData[key] = value;
    return Promise.resolve();
  }),
  getItemAsync: jest.fn((key: string) => Promise.resolve(secureStoreData[key] ?? null)),
  deleteItemAsync: jest.fn((key: string) => {
    delete secureStoreData[key];
    return Promise.resolve();
  }),
  WHEN_UNLOCKED: 'WHEN_UNLOCKED',
}));

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

jest.mock('@/src/services/auth/walletAuth.service', () => ({
  walletAuthService: {
    walletLogin: jest.fn(),
    refreshAccessToken: jest.fn(),
  },
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────

import { Keypair } from 'stellar-sdk';
import { useAuthStore } from '../authStore';
import { walletAuthService } from '@/src/services/auth/walletAuth.service';
import { AuthResponse } from '@/src/services/auth/types';
import { Wallet } from '@/src/services/stellar/types';

const mockWalletAuthService = walletAuthService as jest.Mocked<typeof walletAuthService>;

// ── Helpers ───────────────────────────────────────────────────────────────────

const makeWallet = (): Wallet => {
  const kp = Keypair.random();
  return { publicKey: kp.publicKey(), secretKey: kp.secret() };
};

const makeAuthResponse = (wallet: Wallet): AuthResponse => ({
  access_token: 'access-token-abc',
  refresh_token: 'refresh-token-xyz',
  user: {
    id: 'user-001',
    walletAddress: wallet.publicKey,
    walletProvider: 'freighter',
  },
});

function getStore() {
  return useAuthStore.getState();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('useAuthStore (top-level)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useAuthStore.setState({
      user: null,
      wallet: null,
      loading: false,
      isAuthenticated: false,
      isCreator: false,
      error: null,
      isCheckingAuth: true,
      lastLogin: null,
    });
    Object.keys(secureStoreData).forEach((k) => delete secureStoreData[k]);
    Object.keys(asyncStorageStore).forEach((k) => delete asyncStorageStore[k]);
  });

  describe('initial state', () => {
    it('has the correct default values', () => {
      const { user, wallet, isAuthenticated, loading, error } = getStore();
      expect(user).toBeNull();
      expect(wallet).toBeNull();
      expect(isAuthenticated).toBe(false);
      expect(loading).toBe(false);
      expect(error).toBeNull();
    });
  });

  describe('setWallet', () => {
    it('updates the wallet field', () => {
      const wallet = makeWallet();
      getStore().setWallet(wallet);
      expect(getStore().wallet).toEqual(wallet);
    });

    it('accepts null', () => {
      getStore().setWallet(makeWallet());
      getStore().setWallet(null);
      expect(getStore().wallet).toBeNull();
    });
  });

  describe('loginWithWallet', () => {
    it('authenticates via WalletAuthService and sets wallet/user/isAuthenticated on success', async () => {
      const wallet = makeWallet();
      const authResponse = makeAuthResponse(wallet);
      mockWalletAuthService.walletLogin.mockResolvedValue(authResponse);

      await getStore().loginWithWallet(wallet);

      expect(mockWalletAuthService.walletLogin).toHaveBeenCalledWith(wallet);
      const { wallet: storedWallet, user, isAuthenticated, loading, error } = getStore();
      expect(storedWallet).toEqual(wallet);
      expect(user).toEqual(
        expect.objectContaining({ id: 'user-001', walletAddress: wallet.publicKey }),
      );
      expect(isAuthenticated).toBe(true);
      expect(loading).toBe(false);
      expect(error).toBeNull();
    });

    it('sets error, leaves isAuthenticated false, and rethrows when WalletAuthService rejects', async () => {
      const wallet = makeWallet();
      mockWalletAuthService.walletLogin.mockRejectedValue(new Error('Invalid wallet signature'));

      await expect(getStore().loginWithWallet(wallet)).rejects.toThrow(
        'Invalid wallet signature',
      );

      const { isAuthenticated, error, loading } = getStore();
      expect(isAuthenticated).toBe(false);
      expect(error).toBe('Invalid wallet signature');
      expect(loading).toBe(false);
    });
  });

  describe('logout', () => {
    it('clears user, wallet and isAuthenticated', async () => {
      const wallet = makeWallet();
      useAuthStore.setState({
        user: { id: '1', email: 'a@b.com' },
        wallet,
        isAuthenticated: true,
      });

      await getStore().logout();

      const { user, wallet: storedWallet, isAuthenticated, loading } = getStore();
      expect(user).toBeNull();
      expect(storedWallet).toBeNull();
      expect(isAuthenticated).toBe(false);
      expect(loading).toBe(false);
    });

    it('clears the real access/refresh tokens from storage', async () => {
      secureStoreData['nftopia_access_token'] = 'some-access-token';
      secureStoreData['nftopia_refresh_token'] = 'some-refresh-token';

      await getStore().logout();

      expect(secureStoreData['nftopia_access_token']).toBeUndefined();
      expect(secureStoreData['nftopia_refresh_token']).toBeUndefined();
    });

    it('still clears state even when clearing tokens throws', async () => {
      const SecureStore = require('expo-secure-store');
      SecureStore.deleteItemAsync.mockRejectedValueOnce(new Error('delete failed'));

      useAuthStore.setState({ isAuthenticated: true, wallet: makeWallet() });
      await getStore().logout();

      expect(getStore().isAuthenticated).toBe(false);
      expect(getStore().wallet).toBeNull();
    });
  });

  describe('initializeAuth', () => {
    it('sets isAuthenticated false when nothing is stored', async () => {
      await getStore().initializeAuth();

      expect(getStore().isAuthenticated).toBe(false);
      expect(getStore().isCheckingAuth).toBe(false);
    });

    it('sets isAuthenticated true when a non-expired access token is stored', async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600;
      const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64');
      const payload = Buffer.from(JSON.stringify({ exp: futureExp })).toString('base64');
      secureStoreData['nftopia_access_token'] = `${header}.${payload}.sig`;

      await getStore().initializeAuth();

      expect(getStore().isAuthenticated).toBe(true);
    });

    it('attempts a refresh when the access token is expired but a refresh token exists', async () => {
      const pastExp = Math.floor(Date.now() / 1000) - 60;
      const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64');
      const payload = Buffer.from(JSON.stringify({ exp: pastExp })).toString('base64');
      secureStoreData['nftopia_access_token'] = `${header}.${payload}.sig`;
      secureStoreData['nftopia_token_expiry'] = pastExp.toString();
      secureStoreData['nftopia_refresh_token'] = 'stored-refresh-token';
      mockWalletAuthService.refreshAccessToken.mockResolvedValue(
        makeAuthResponse(makeWallet()),
      );

      await getStore().initializeAuth();

      expect(mockWalletAuthService.refreshAccessToken).toHaveBeenCalled();
      expect(getStore().isAuthenticated).toBe(true);
    });

    it('logs out when the refresh attempt fails', async () => {
      const pastExp = Math.floor(Date.now() / 1000) - 60;
      secureStoreData['nftopia_token_expiry'] = pastExp.toString();
      secureStoreData['nftopia_refresh_token'] = 'stale-refresh-token';
      mockWalletAuthService.refreshAccessToken.mockRejectedValue(new Error('expired'));

      await getStore().initializeAuth();

      expect(getStore().isAuthenticated).toBe(false);
      expect(getStore().user).toBeNull();
      expect(getStore().wallet).toBeNull();
    });
  });
});
