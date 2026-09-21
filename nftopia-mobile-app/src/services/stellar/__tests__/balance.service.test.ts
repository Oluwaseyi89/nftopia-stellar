jest.mock('../network', () => ({
  createServer: jest.fn(),
}));

import { createServer } from '../network';
import { fetchTokenBalances, fetchXlmBalance } from '../balance.service';

const mockedCreateServer = createServer as jest.MockedFunction<typeof createServer>;

describe('balance service', () => {
  beforeEach(() => jest.clearAllMocks());

  it('returns the native balance', async () => {
    mockedCreateServer.mockReturnValue({
      loadAccount: jest.fn().mockResolvedValue({
        balances: [{ asset_type: 'native', balance: '12.5' }],
      }),
    } as never);
    await expect(fetchXlmBalance('GTEST', 'testnet')).resolves.toBe('12.5');
  });

  it('returns zero when the account has no native balance', async () => {
    mockedCreateServer.mockReturnValue({
      loadAccount: jest.fn().mockResolvedValue({ balances: [] }),
    } as never);
    await expect(fetchXlmBalance('GTEST', 'mainnet')).resolves.toBe('0');
  });

  it('maps issued assets and propagates Horizon errors', async () => {
    const error = new Error('network unavailable');
    mockedCreateServer.mockReturnValue({
      loadAccount: jest.fn().mockRejectedValue(error),
    } as never);
    await expect(fetchTokenBalances('GTEST', 'testnet')).rejects.toBe(error);

    mockedCreateServer.mockReturnValue({
      loadAccount: jest.fn().mockResolvedValue({
        balances: [
          { asset_type: 'native', balance: '1' },
          { asset_type: 'credit_alphanum4', asset_code: 'USDC', asset_issuer: 'GISSUER', balance: '4' },
        ],
      }),
    } as never);
    await expect(fetchTokenBalances('GTEST', 'testnet')).resolves.toEqual([
      { asset_type: 'credit_alphanum4', asset_code: 'USDC', asset_issuer: 'GISSUER', balance: '4' },
    ]);
  });
});
