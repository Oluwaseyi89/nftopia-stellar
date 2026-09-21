jest.mock('expo-secure-store', () => ({
  setItemAsync: jest.fn(),
  getItemAsync: jest.fn(),
  deleteItemAsync: jest.fn(),
}));
jest.mock('expo-local-authentication', () => ({
  hasHardwareAsync: jest.fn().mockResolvedValue(false),
  isEnrolledAsync: jest.fn().mockResolvedValue(false),
  authenticateAsync: jest.fn().mockResolvedValue({ success: true }),
}));
jest.mock('@/src/services/stellar/wallet.service', () => ({
  StellarWalletService: jest.fn().mockImplementation(() => ({})),
  WalletError: class WalletError extends Error {},
}));
jest.mock('@/src/services/stellar/balance.service', () => ({
  fetchXlmBalance: jest.fn(),
  fetchTokenBalances: jest.fn(),
}));

import { useWalletStore } from '../walletStore';

describe('walletStore state actions', () => {
  beforeEach(() => useWalletStore.getState().clearWallets());

  it('switches network and clears cached balances', () => {
    useWalletStore.setState({ balances: { GTEST: { xlm: '2', tokens: [] } } });
    useWalletStore.getState().switchNetwork('mainnet');
    expect(useWalletStore.getState().network).toBe('mainnet');
    expect(useWalletStore.getState().balances).toEqual({});
  });

  it('removes the active wallet and selects the remaining wallet', () => {
    const first = { publicKey: 'GFIRST', secretKey: 'SFIRST' };
    const second = { publicKey: 'GSECOND', secretKey: 'SSECOND' };
    useWalletStore.setState({ wallets: [first, second], activePublicKey: 'GSECOND' });
    useWalletStore.getState().removeWallet('GSECOND');
    expect(useWalletStore.getState().wallets).toEqual([first]);
    expect(useWalletStore.getState().activePublicKey).toBe('GFIRST');
  });
});
