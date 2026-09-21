import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { OrderService } from './order.service';
import { Order } from './entities/order.entity';
import { OrderInterface } from './interfaces/order.interface';
import { MarketplaceSettlementClient } from '../stellar/marketplace-settlement.client';
import { OrderType, OrderStatus } from './dto/create-order.dto';
import { SelectQueryBuilder } from 'typeorm';

describe('OrderService', () => {
  let service: OrderService;
  let orderRepository: jest.Mocked<Repository<Order>>;
  let configService: ConfigService;
  let settlementClient: MarketplaceSettlementClient;

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn().mockReturnValue(false),
    };
    const mockSettlementClient = {
      createTrade: jest.fn(),
      createBundle: jest.fn(),
      executeBundle: jest.fn(),
      cancelBundle: jest.fn(),
    };

    const mockRepository = {
      createQueryBuilder: jest.fn(),
      create: jest.fn().mockReturnValue({}),
      save: jest.fn().mockResolvedValue({}),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrderService,
        {
          provide: getRepositoryToken(Order),
          useValue: mockRepository,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: MarketplaceSettlementClient,
          useValue: mockSettlementClient,
        },
      ],
    }).compile();

    service = module.get<OrderService>(OrderService);
    orderRepository = module.get(getRepositoryToken(Order));
    configService = module.get<ConfigService>(ConfigService);
    settlementClient = module.get<MarketplaceSettlementClient>(
      MarketplaceSettlementClient,
    );
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    beforeEach(() => {
      jest.spyOn(configService, 'get').mockImplementation((key) => {
        if (key === 'ENABLE_ONCHAIN_SETTLEMENT') return true;
        return false;
      });
      jest.spyOn(settlementClient, 'createBundle').mockResolvedValue(123);
    });

    it('should throw BadRequestException if bundle has less than 2 items', async () => {
      const dto = {
        type: OrderType.PURCHASE,
        items: [{ nftContractAddress: 'contract1', tokenId: '1' }],
        totalPrice: '100',
        durationSeconds: 3600,
        sellerId: 'seller-id',
        buyerId: 'buyer-id',
        nftId: 'nft-id',
        price: '100',
      };
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      await expect(service.create(dto as any)).rejects.toThrow(
        'Bundle orders must contain at least 2 items',
      );
    });

    it('should throw BadRequestException if bundle totalPrice is invalid', async () => {
      const dto = {
        type: OrderType.PURCHASE,
        items: [
          { nftContractAddress: 'contract1', tokenId: '1' },
          { nftContractAddress: 'contract2', tokenId: '2' },
        ],
        totalPrice: '0',
        durationSeconds: 3600,
        sellerId: 'seller-id',
        buyerId: 'buyer-id',
        nftId: 'nft-id',
        price: '0',
      };
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      await expect(service.create(dto as any)).rejects.toThrow(
        'Bundle orders require a valid totalPrice > 0',
      );
    });

    it('should throw BadRequestException if bundle duration is invalid', async () => {
      const dto = {
        type: OrderType.PURCHASE,
        items: [
          { nftContractAddress: 'contract1', tokenId: '1' },
          { nftContractAddress: 'contract2', tokenId: '2' },
        ],
        totalPrice: '100',
        durationSeconds: 0,
        sellerId: 'seller-id',
        buyerId: 'buyer-id',
        nftId: 'nft-id',
        price: '100',
      };
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      await expect(service.create(dto as any)).rejects.toThrow(
        'Bundle duration must be between 1 second and 30 days',
      );
    });

    it('should successfully call createBundle on settlement client', async () => {
      const dto = {
        type: OrderType.PURCHASE,
        items: [
          { nftContractAddress: 'contract1', tokenId: '1' },
          { nftContractAddress: 'contract2', tokenId: '2' },
        ],
        totalPrice: '100',
        durationSeconds: 3600,
        currency: 'USDC',
        sellerId: 'seller-id',
        buyerId: 'buyer-id',
        nftId: 'nft-id',
        price: '100',
      };

      const result = await service.create(dto);
      expect(result).toEqual({ success: true, contractId: 123 });
      expect(settlementClient.createBundle).toHaveBeenCalledWith({
        seller: 'seller-id',
        items: [
          { nftContract: 'contract1', tokenId: '1' },
          { nftContract: 'contract2', tokenId: '2' },
        ],
        totalPrice: '100',
        currency: 'USDC',
        durationSeconds: 3600,
      });
    });
  });

  describe('executeBundle', () => {
    it('should successfully execute bundle', async () => {
      jest
        .spyOn(settlementClient, 'executeBundle')
        .mockResolvedValue({ success: true });
      const result = await service.executeBundle('123', 'buyer-id', '100');
      expect(result).toEqual({ success: true });
      expect(settlementClient.executeBundle).toHaveBeenCalledWith(
        123,
        'buyer-id',
        '100',
      );
    });

    it('should map timeout error correctly', async () => {
      jest
        .spyOn(settlementClient, 'executeBundle')
        .mockRejectedValue(new Error('timeout'));
      await expect(service.executeBundle('123', 'buyer-id')).rejects.toThrow(
        'Bundle execution timed out',
      );
    });

    it('should map insufficient funds error correctly', async () => {
      jest
        .spyOn(settlementClient, 'executeBundle')
        .mockRejectedValue(new Error('insufficient funds'));
      await expect(service.executeBundle('123', 'buyer-id')).rejects.toThrow(
        'Insufficient funds to execute bundle',
      );
    });

    it('should map expired error correctly', async () => {
      jest
        .spyOn(settlementClient, 'executeBundle')
        .mockRejectedValue(new Error('expired'));
      await expect(service.executeBundle('123', 'buyer-id')).rejects.toThrow(
        'Bundle has expired',
      );
    });

    it('should map sold error correctly', async () => {
      jest
        .spyOn(settlementClient, 'executeBundle')
        .mockRejectedValue(new Error('sold'));
      await expect(service.executeBundle('123', 'buyer-id')).rejects.toThrow(
        'One or more items in the bundle are already sold',
      );
    });
  });

  describe('cancelBundle', () => {
    it('should successfully cancel bundle', async () => {
      jest
        .spyOn(settlementClient, 'cancelBundle')
        .mockResolvedValue({ success: true });
      const result = await service.cancelBundle('123', 'seller-id');
      expect(result).toEqual({ success: true });
      expect(settlementClient.cancelBundle).toHaveBeenCalledWith(
        123,
        'seller-id',
      );
    });

    it('should map timeout error correctly', async () => {
      jest
        .spyOn(settlementClient, 'cancelBundle')
        .mockRejectedValue(new Error('timeout'));
      await expect(service.cancelBundle('123', 'seller-id')).rejects.toThrow(
        'Bundle cancellation timed out',
      );
    });
  });

  describe('getSalesAnalytics', () => {
    it('should return analytics for completed sales within timeframe', async () => {
      const periodStart = new Date('2024-01-01');
      const periodEnd = new Date('2024-12-31');

      const mockQueryBuilder = {
        select: jest.fn().mockReturnThis(),
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getRawOne: jest.fn().mockResolvedValue({
          volume: '1000.50',
          count: '10',
          averagePrice: '100.05',
        }),
      };

      orderRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder as unknown as SelectQueryBuilder<Order>,
      );

      const result = await service.getSalesAnalytics(periodStart, periodEnd);

      expect(result).toEqual({
        volume: '1000.50',
        count: 10,
        averagePrice: '100.05',
      });

      expect(orderRepository.createQueryBuilder).toHaveBeenCalledWith('order');
      expect(mockQueryBuilder.where).toHaveBeenCalledWith(
        'order.type = :type',
        {
          type: OrderType.SALE,
        },
      );
      expect(mockQueryBuilder.andWhere).toHaveBeenCalledWith(
        'order.status = :status',
        { status: OrderStatus.COMPLETED },
      );
      expect(mockQueryBuilder.andWhere).toHaveBeenCalledWith(
        'order.createdAt BETWEEN :periodStart AND :periodEnd',
        { periodStart, periodEnd },
      );
    });

    it('should return zero values when no orders match criteria', async () => {
      const periodStart = new Date('2024-01-01');
      const periodEnd = new Date('2024-12-31');

      const mockQueryBuilder = {
        select: jest.fn().mockReturnThis(),
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getRawOne: jest.fn().mockResolvedValue(null),
      };

      orderRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder as unknown as SelectQueryBuilder<Order>,
      );

      const result = await service.getSalesAnalytics(periodStart, periodEnd);

      expect(result).toEqual({
        volume: '0',
        count: 0,
        averagePrice: '0',
      });
    });

    it('should handle null values from database', async () => {
      const periodStart = new Date('2024-01-01');
      const periodEnd = new Date('2024-12-31');

      const mockQueryBuilder = {
        select: jest.fn().mockReturnThis(),
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getRawOne: jest.fn().mockResolvedValue({
          volume: null,
          count: null,
          averagePrice: null,
        }),
      };

      orderRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder as unknown as SelectQueryBuilder<Order>,
      );

      const result = await service.getSalesAnalytics(periodStart, periodEnd);

      expect(result).toEqual({
        volume: '0',
        count: 0,
        averagePrice: '0',
      });
    });

    it('should filter only SALE type and COMPLETED status', async () => {
      const periodStart = new Date('2024-01-01');
      const periodEnd = new Date('2024-12-31');

      const mockQueryBuilder = {
        select: jest.fn().mockReturnThis(),
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getRawOne: jest.fn().mockResolvedValue({
          volume: '500.00',
          count: '5',
          averagePrice: '100.00',
        }),
      };

      orderRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder as unknown as SelectQueryBuilder<Order>,
      );

      await service.getSalesAnalytics(periodStart, periodEnd);

      const whereCalls = mockQueryBuilder.where.mock.calls;
      const andWhereCalls = mockQueryBuilder.andWhere.mock.calls;

      expect(whereCalls[0]).toEqual([
        'order.type = :type',
        { type: OrderType.SALE },
      ]);
      expect(andWhereCalls[0]).toEqual([
        'order.status = :status',
        { status: OrderStatus.COMPLETED },
      ]);
    });
  });

  describe('findOneForUser (#488)', () => {
    const makeOrder = (
      overrides: Partial<OrderInterface> = {},
    ): OrderInterface => ({
      id: 'order-1',
      nftId: 'nft-1',
      buyerId: 'buyer-1',
      sellerId: 'seller-1',
      price: '10',
      currency: 'XLM',
      type: OrderType.SALE,
      status: OrderStatus.COMPLETED,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      ...overrides,
    });

    it('returns the order when the caller is its buyer', async () => {
      jest.spyOn(service, 'findOne').mockResolvedValue(makeOrder());

      const result = await service.findOneForUser('buyer-1', 'order-1');

      expect(result.id).toBe('order-1');
    });

    it('returns the order when the caller is its seller', async () => {
      jest.spyOn(service, 'findOne').mockResolvedValue(makeOrder());

      const result = await service.findOneForUser('seller-1', 'order-1');

      expect(result.id).toBe('order-1');
    });

    it('throws ForbiddenException when the caller is neither buyer nor seller', async () => {
      jest.spyOn(service, 'findOne').mockResolvedValue(makeOrder());

      await expect(
        service.findOneForUser('some-other-user', 'order-1'),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('propagates NotFoundException when the order does not exist', async () => {
      jest
        .spyOn(service, 'findOne')
        .mockRejectedValue(new NotFoundException('Order not found'));

      await expect(
        service.findOneForUser('buyer-1', 'missing-order'),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('findAllForUser (#488)', () => {
    const makeOrder = (
      overrides: Partial<OrderInterface> = {},
    ): OrderInterface => ({
      id: 'order-1',
      nftId: 'nft-1',
      buyerId: 'buyer-1',
      sellerId: 'seller-1',
      price: '10',
      currency: 'XLM',
      type: OrderType.SALE,
      status: OrderStatus.COMPLETED,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      ...overrides,
    });

    it('queries as both buyer and seller, scoped to the given userId — never a caller-supplied one', async () => {
      const findAllSpy = jest.spyOn(service, 'findAll').mockResolvedValue([]);

      await service.findAllForUser('user-1', {
        // even if a caller tried to sneak buyerId/sellerId into filters,
        // the Pick<> type excludes them from the parameter entirely
      });

      expect(findAllSpy).toHaveBeenCalledWith(
        expect.objectContaining({ buyerId: 'user-1' }),
      );
      expect(findAllSpy).toHaveBeenCalledWith(
        expect.objectContaining({ sellerId: 'user-1' }),
      );
    });

    it('merges and de-duplicates orders found as both buyer and seller', async () => {
      const shared = makeOrder({ id: 'order-shared' });
      const asBuyerOnly = makeOrder({
        id: 'order-buyer-only',
        createdAt: new Date('2026-01-02T00:00:00Z'),
      });
      jest
        .spyOn(service, 'findAll')
        .mockResolvedValueOnce([shared, asBuyerOnly]) // as buyer
        .mockResolvedValueOnce([shared]); // as seller

      const result = await service.findAllForUser('user-1', {});

      expect(result.items.map((o) => o.id).sort()).toEqual(
        ['order-buyer-only', 'order-shared'].sort(),
      );
      expect(result.totalCount).toBe(2);
    });

    it('sorts merged results by createdAt descending', async () => {
      const older = makeOrder({
        id: 'order-older',
        createdAt: new Date('2026-01-01T00:00:00Z'),
      });
      const newer = makeOrder({
        id: 'order-newer',
        createdAt: new Date('2026-01-05T00:00:00Z'),
      });
      jest
        .spyOn(service, 'findAll')
        .mockResolvedValueOnce([older])
        .mockResolvedValueOnce([newer]);

      const result = await service.findAllForUser('user-1', {});

      expect(result.items.map((o) => o.id)).toEqual([
        'order-newer',
        'order-older',
      ]);
    });

    it('paginates the merged result set', async () => {
      const orders = Array.from({ length: 5 }, (_, i) =>
        makeOrder({
          id: `order-${i}`,
          createdAt: new Date(2026, 0, i + 1),
        }),
      );
      jest
        .spyOn(service, 'findAll')
        .mockResolvedValueOnce(orders)
        .mockResolvedValueOnce([]);

      const result = await service.findAllForUser(
        'user-1',
        {},
        { page: 1, limit: 2 },
      );

      expect(result.items).toHaveLength(2);
      expect(result.totalCount).toBe(5);
      expect(result.hasNextPage).toBe(true);
      // newest first: order-4 (Jan 5) then order-3 (Jan 4)
      expect(result.items.map((o) => o.id)).toEqual(['order-4', 'order-3']);
    });
  });
});
