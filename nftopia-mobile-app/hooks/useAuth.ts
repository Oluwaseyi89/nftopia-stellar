import { useCallback, useEffect } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { useWalletConnect } from './useWalletConnect';
import { walletAuthService } from '@/src/services/auth/walletAuth.service';
import { tokenStorage } from '@/src/services/auth/tokenStorage';
import { Wallet } from '@/src/services/stellar/types';

const SESSION_CHECK_INTERVAL_MS = 60_000;
/** Refresh once the access token has this little time left, not only once it's fully expired. */
const REFRESH_BUFFER_SECONDS = 120;

/**
 * Public entry point for wallet authentication and session state. Wraps
 * the auth store (session/token bookkeeping, via WalletAuthService) and
 * the wallet store (which wallet is connected), and owns two background
 * behaviors neither store does on its own:
 *  - if the connected wallet changes or disconnects out from under an
 *    authenticated session, that session is no longer provable and is
 *    ended;
 *  - the stored session is checked on an interval and refreshed shortly
 *    before it actually expires, falling back to logout if that fails.
 */
export function useAuth() {
  const user = useAuthStore((s) => s.user);
  const wallet = useAuthStore((s) => s.wallet);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLoading = useAuthStore((s) => s.loading);
  const isCheckingAuth = useAuthStore((s) => s.isCheckingAuth);
  const error = useAuthStore((s) => s.error);
  const clearError = useAuthStore((s) => s.clearError);
  const storeLoginWithWallet = useAuthStore((s) => s.loginWithWallet);
  const storeLogout = useAuthStore((s) => s.logout);

  const { activeWallet, activePublicKey } = useWalletConnect();

  /** Signs in with the given wallet, or the currently connected one if omitted. */
  const login = useCallback(
    async (walletToUse?: Wallet) => {
      const target = walletToUse ?? activeWallet;
      if (!target) {
        throw new Error('No wallet available to sign in with');
      }
      await storeLoginWithWallet(target);
    },
    [activeWallet, storeLoginWithWallet],
  );

  const logout = useCallback(() => storeLogout(), [storeLogout]);

  const authenticatedPublicKey = wallet?.publicKey;
  useEffect(() => {
    if (!isAuthenticated || !authenticatedPublicKey) return;
    if (activePublicKey === authenticatedPublicKey) return;
    // The wallet backing this session was switched or disconnected — the
    // session no longer corresponds to a wallet this device can prove it
    // controls, so end it rather than leave a stale "authenticated" state.
    void logout();
  }, [isAuthenticated, authenticatedPublicKey, activePublicKey, logout]);

  useEffect(() => {
    if (!isAuthenticated) return;

    const checkSession = async () => {
      try {
        const remaining = await tokenStorage.getTimeRemaining();
        if (remaining !== null && remaining <= REFRESH_BUFFER_SECONDS) {
          await walletAuthService.refreshAccessToken();
        }
      } catch {
        // The refresh token is missing, invalid, or the request failed —
        // the session can no longer be kept alive, so end it. This is what
        // drives the "expired session redirects to login" behavior, since
        // logout() flips isAuthenticated and the root navigator switches
        // to the auth stack.
        await storeLogout();
      }
    };

    const interval = setInterval(checkSession, SESSION_CHECK_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [isAuthenticated, storeLogout]);

  return {
    user,
    wallet,
    isAuthenticated,
    isLoading,
    isCheckingAuth,
    error,
    clearError,
    login,
    logout,
  };
}
