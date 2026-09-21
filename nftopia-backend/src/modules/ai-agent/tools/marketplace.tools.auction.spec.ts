import {
  buildMarketplaceTools,
  MARKETPLACE_TOOL_NAMES,
} from './marketplace.tools';
import type { RunnableToolLike } from './tool-set.types';
import { AuctionStatus } from '../../auction/interfaces/auction.interface';

describe('marketplace.tools — auction tools (#489)', () => {
  const auctionService = {
    findAll: jest.fn(),
    findOne: jest.fn(),
    getBids: jest.fn(),
  };

  const otherDeps = {
    nftService: {} as never,
    listingService: {} as never,
    collectionService: {} as never,
    orderService: {} as never,
    userId: 'user-1',
  };

  const getTool = (name: string): RunnableToolLike => {
    const tools = buildMarketplaceTools({
      ...otherDeps,
      auctionService: auctionService as never,
    });
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Tool "${name}" not found`);
    return tool;
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('exposes search_auctions, get_auction, and get_auction_bids in MARKETPLACE_TOOL_NAMES', () => {
    expect(MARKETPLACE_TOOL_NAMES).toContain('search_auctions');
    expect(MARKETPLACE_TOOL_NAMES).toContain('get_auction');
    expect(MARKETPLACE_TOOL_NAMES).toContain('get_auction_bids');
  });

  it('matches exactly what buildMarketplaceTools returns for these three names (no drift)', () => {
    const tools = buildMarketplaceTools({
      ...otherDeps,
      auctionService: auctionService as never,
    });
    const names = tools.map((t) => t.name);
    expect(names).toEqual(
      expect.arrayContaining([
        'search_auctions',
        'get_auction',
        'get_auction_bids',
      ]),
    );
  });

  describe('search_auctions', () => {
    it('forwards filters to AuctionService.findAll', async () => {
      auctionService.findAll.mockResolvedValue([{ id: 'auction-1' }]);

      await getTool('search_auctions').run({
        status: AuctionStatus.ACTIVE,
        nftContractId: 'contract-1',
        nftTokenId: 'token-1',
        page: 2,
        limit: 10,
      });

      expect(auctionService.findAll).toHaveBeenCalledWith({
        status: AuctionStatus.ACTIVE,
        nftContractId: 'contract-1',
        nftTokenId: 'token-1',
        page: 2,
        limit: 10,
      });
    });

    it('makes no other AuctionService call (read-only)', async () => {
      auctionService.findAll.mockResolvedValue([]);

      await getTool('search_auctions').run({});

      expect(auctionService.findOne).not.toHaveBeenCalled();
      expect(auctionService.getBids).not.toHaveBeenCalled();
    });

    it('returns whatever AuctionService.findAll returns, as JSON', async () => {
      const payload = [{ id: 'auction-1', status: AuctionStatus.ACTIVE }];
      auctionService.findAll.mockResolvedValue(payload);

      const result = await getTool('search_auctions').run({});

      expect(JSON.parse(result as string)).toEqual(payload);
    });

    it('propagates a rejection from AuctionService.findAll', async () => {
      auctionService.findAll.mockRejectedValue(new Error('db down'));

      await expect(getTool('search_auctions').run({})).rejects.toThrow(
        'db down',
      );
    });
  });

  describe('get_auction', () => {
    it('calls AuctionService.findOne with the given id', async () => {
      auctionService.findOne.mockResolvedValue({ id: 'auction-1' });

      await getTool('get_auction').run({ id: 'auction-1' });

      expect(auctionService.findOne).toHaveBeenCalledWith('auction-1');
    });

    it('makes no other AuctionService call (read-only) and does not fetch bids implicitly', async () => {
      auctionService.findOne.mockResolvedValue({ id: 'auction-1' });

      await getTool('get_auction').run({ id: 'auction-1' });

      expect(auctionService.findAll).not.toHaveBeenCalled();
      expect(auctionService.getBids).not.toHaveBeenCalled();
    });

    it('returns the auction as JSON', async () => {
      const auction = {
        id: 'auction-1',
        status: AuctionStatus.ACTIVE,
        currentPrice: '100',
      };
      auctionService.findOne.mockResolvedValue(auction);

      const result = await getTool('get_auction').run({ id: 'auction-1' });

      expect(JSON.parse(result as string)).toEqual(auction);
    });

    it('propagates a NotFoundException-style rejection from AuctionService.findOne', async () => {
      auctionService.findOne.mockRejectedValue(new Error('Auction not found'));

      await expect(
        getTool('get_auction').run({ id: 'missing-auction' }),
      ).rejects.toThrow('Auction not found');
    });
  });

  describe('get_auction_bids', () => {
    it('calls AuctionService.getBids with the given auctionId', async () => {
      auctionService.getBids.mockResolvedValue([]);

      await getTool('get_auction_bids').run({ auctionId: 'auction-1' });

      expect(auctionService.getBids).toHaveBeenCalledWith('auction-1');
    });

    it('makes no other AuctionService call (read-only)', async () => {
      auctionService.getBids.mockResolvedValue([]);

      await getTool('get_auction_bids').run({ auctionId: 'auction-1' });

      expect(auctionService.findAll).not.toHaveBeenCalled();
      expect(auctionService.findOne).not.toHaveBeenCalled();
    });

    it('returns the bid list as JSON, most-recent-first as provided by the service', async () => {
      const bids = [
        { id: 'bid-2', amount: '150', createdAt: '2026-01-02T00:00:00Z' },
        { id: 'bid-1', amount: '100', createdAt: '2026-01-01T00:00:00Z' },
      ];
      auctionService.getBids.mockResolvedValue(bids);

      const result = await getTool('get_auction_bids').run({
        auctionId: 'auction-1',
      });

      expect(JSON.parse(result as string)).toEqual(bids);
    });

    it('propagates a rejection from AuctionService.getBids', async () => {
      auctionService.getBids.mockRejectedValue(new Error('db down'));

      await expect(
        getTool('get_auction_bids').run({ auctionId: 'auction-1' }),
      ).rejects.toThrow('db down');
    });
  });
});
