import {
  HORIZON_MAINNET,
  HORIZON_TESTNET,
  NETWORK_PASSPHRASE_MAINNET,
  NETWORK_PASSPHRASE_TESTNET,
  getHorizonUrl,
  getNetworkPassphrase,
} from '../network';

describe('network configuration', () => {
  it('selects the matching Horizon endpoint and passphrase', () => {
    expect(getHorizonUrl('testnet')).toBe(HORIZON_TESTNET);
    expect(getHorizonUrl('mainnet')).toBe(HORIZON_MAINNET);
    expect(getNetworkPassphrase('testnet')).toBe(NETWORK_PASSPHRASE_TESTNET);
    expect(getNetworkPassphrase('mainnet')).toBe(NETWORK_PASSPHRASE_MAINNET);
  });
});
