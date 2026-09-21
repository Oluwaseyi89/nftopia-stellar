import { createStore } from '@/src/utils/store.factory';
import { AuthStore, User } from '@/types/auth';
import { Wallet } from '@/src/services/stellar/types';
import { walletAuthService } from '@/src/services/auth/walletAuth.service';
import { tokenStorage } from '@/src/services/auth/tokenStorage';

export const VERSION = 2;

// Migrations for auth store
const migrations = [
  {
    version: 1,
    up: (state: any) => {
      // Add isCreator field if missing
      return {
        ...state,
        isCreator: state.user?.isCreator || false,
      };
    },
  },
  {
    version: 2,
    up: (state: any) => {
      // Add lastLogin field
      return {
        ...state,
        lastLogin: state.lastLogin || new Date().toISOString(),
      };
    },
  },
];

const initialState: AuthStore = {
  user: null,
  wallet: null,
  loading: false,
  isAuthenticated: false,
  isCreator: false,
  error: null,
  isCheckingAuth: true,
  lastLogin: null,

  setUser: () => {},
  setWallet: () => {},
  setLoading: () => {},
  setError: () => {},
  clearError: () => {},
  setIsCheckingAuth: () => {},
  setIsCreator: () => {},
  initializeAuth: async () => {},
  loginWithWallet: async () => {},
  logout: async () => {},
  navigateToScreen: () => {},
  goBack: () => {},
  resetToScreen: () => {},
};

export const useAuthStore = createStore<AuthStore>({
  name: 'auth-store',
  initialState,
  actions: (set, get) => ({
    ...initialState,

    // State Management Actions
    setUser: (user: User | null) =>
      set({
        user,
        isAuthenticated: !!user,
        isCreator: user?.isCreator || false,
        lastLogin: user ? new Date().toISOString() : get().lastLogin,
      }),

    setWallet: (wallet: Wallet | null) => set({ wallet }),
    setLoading: (loading: boolean) => set({ loading }),
    setError: (error: string | null) => set({ error }),
    clearError: () => set({ error: null }),
    setIsCheckingAuth: (isChecking: boolean) => set({ isCheckingAuth: isChecking }),
    setIsCreator: (isCreator: boolean) => set({ isCreator }),

    // Authentication Actions
    initializeAuth: async () => {
      set({ isCheckingAuth: true, loading: true });
      try {
        const hasValidSession = await tokenStorage.hasValidSession();
        if (hasValidSession) {
          // `user`/`isAuthenticated` were already restored from persisted
          // state by the store's persist middleware — this just confirms
          // the access token backing that session is still valid.
          set({ isAuthenticated: true });
        } else {
          const refreshToken = await tokenStorage.getRefreshToken();
          if (refreshToken) {
            try {
              await walletAuthService.refreshAccessToken();
              set({ isAuthenticated: true });
            } catch {
              set({ isAuthenticated: false, user: null, wallet: null });
            }
          } else {
            set({ isAuthenticated: false });
          }
        }
      } catch (error) {
        set({
          error: error instanceof Error ? error.message : 'Failed to restore session',
          isAuthenticated: false,
        });
      } finally {
        set({ isCheckingAuth: false, loading: false });
      }
    },

    // Full challenge -> sign -> verify wallet login, replacing any prior session.
    loginWithWallet: async (wallet: Wallet) => {
      set({ loading: true, error: null });
      try {
        const authResponse = await walletAuthService.walletLogin(wallet);
        set({
          user: {
            id: authResponse.user.id,
            email: authResponse.user.email,
            username: authResponse.user.username,
            walletAddress: authResponse.user.walletAddress,
          },
          wallet,
          isAuthenticated: true,
          isCreator: false,
          loading: false,
          lastLogin: new Date().toISOString(),
        });
      } catch (error) {
        set({
          error: error instanceof Error ? error.message : 'Failed to sign in with wallet',
          loading: false,
        });
        // Re-throw so the calling screen (which owns its own submit/loading
        // UI) knows not to proceed past the login step.
        throw error;
      }
    },

    logout: async () => {
      try {
        set({ loading: true });
        // Only the auth session is cleared here — the wallet's keys stay on
        // device (via the separate wallet store) so the user can sign back
        // in without re-entering their secret key or recovery phrase.
        await tokenStorage.clearTokens();
      } catch (error) {
        set({
          error: error instanceof Error ? error.message : 'Failed to logout',
        });
      } finally {
        set({
          user: null,
          wallet: null,
          isAuthenticated: false,
          isCreator: false,
          loading: false,
          error: null,
        });
      }
    },

    // Navigation Actions
    navigateToScreen: (_screen: string) => {
      // Will be handled by React Navigation
    },

    goBack: () => {
      // Will be handled by React Navigation
    },

    resetToScreen: (_screen: string) => {
      // Will be handled by React Navigation
    },
  }),
  persist: {
    enabled: true,
    name: 'auth-storage',
    version: VERSION,
    migrate: async (state: any, version: number) => {
      let migratedState = state;
      for (const migration of migrations) {
        if (migration.version > version) {
          migratedState = await migration.up(migratedState);
        }
      }
      return migratedState;
    },
    partialize: (state: AuthStore) => ({
      user: state.user,
      isAuthenticated: state.isAuthenticated,
      isCreator: state.isCreator,
      lastLogin: state.lastLogin,
    }),
    storage: 'secure', // Use secure storage for auth
  },
  devtools: {
    enabled: __DEV__,
    name: 'AuthStore',
  },
});
