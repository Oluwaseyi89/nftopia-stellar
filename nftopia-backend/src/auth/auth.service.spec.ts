import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from '../users/user.entity';
import { UserWallet } from './entities/user-wallet.entity';
import { WalletSession } from './entities/wallet-session.entity';
import { StellarSignatureStrategy } from './strategies/stellar.strategy';

describe('AuthService', () => {
  let service: AuthService;

  const userRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const userWalletRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
    count: jest.fn(),
    delete: jest.fn(),
    find: jest.fn(),
  };

  const walletSessionRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
    delete: jest.fn(),
  };

  const jwtService = {
    sign: jest.fn(),
  };

  const stellarStrategy = {
    isValidPublicKey: jest.fn(),
    verifySignedMessage: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: JwtService,
          useValue: jwtService,
        },
        {
          provide: StellarSignatureStrategy,
          useValue: stellarStrategy,
        },
        {
          provide: getRepositoryToken(User),
          useValue: userRepository,
        },
        {
          provide: getRepositoryToken(UserWallet),
          useValue: userWalletRepository,
        },
        {
          provide: getRepositoryToken(WalletSession),
          useValue: walletSessionRepository,
        },
      ],
    }).compile();

    service = moduleRef.get(AuthService);
  });

  it('generates a wallet challenge session', async () => {
    stellarStrategy.isValidPublicKey.mockReturnValue(true);
    const createdSession = {
      walletAddress: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      walletProvider: 'freighter',
      nonce: 'nonce-1',
      challengeMessage: 'NFTopia Wallet Authentication',
      nonceExpiresAt: new Date(Date.now() + 60_000),
      ipAddress: '127.0.0.1',
    };
    walletSessionRepository.create.mockReturnValue(createdSession);
    walletSessionRepository.save.mockResolvedValue({
      id: 'session-1',
      ...createdSession,
    });

    const result = await service.generateWalletChallenge(
      {
        walletAddress:
          'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        walletProvider: 'freighter',
      },
      '127.0.0.1',
    );

    expect(result.sessionId).toEqual('session-1');
    expect(result.walletAddress).toEqual(
      'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    );
    expect(result.nonce).toBeTruthy();
    expect(result.message).toContain('NFTopia Wallet Authentication');
  });

  it('rejects invalid signatures during wallet verification', async () => {
    stellarStrategy.isValidPublicKey.mockReturnValue(true);
    walletSessionRepository.findOne.mockResolvedValue({
      id: 'session-1',
      walletAddress: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      nonce: 'nonce-1',
      challengeMessage: 'test-message',
      nonceExpiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
    });
    stellarStrategy.verifySignedMessage.mockReturnValue(false);

    await expect(
      service.verifyWalletChallenge({
        walletAddress:
          'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        nonce: 'nonce-1',
        signature: Buffer.from('invalid').toString('base64'),
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('verifies wallet challenge and returns token pair', async () => {
    const walletAddress =
      'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

    stellarStrategy.isValidPublicKey.mockReturnValue(true);
    stellarStrategy.verifySignedMessage.mockReturnValue(true);

    walletSessionRepository.findOne.mockResolvedValue({
      id: 'session-1',
      walletAddress,
      nonce: 'nonce-1',
      challengeMessage: 'challenge-message',
      nonceExpiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
    });

    userWalletRepository.findOne
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null);

    userRepository.findOne.mockResolvedValue(null);
    const createdUser = {
      address: walletAddress,
      walletAddress,
      walletProvider: 'freighter',
      walletConnectedAt: new Date(),
    };
    userRepository.create.mockReturnValue(createdUser);
    userRepository.save.mockResolvedValue({
      id: 'user-1',
      ...createdUser,
      walletProvider: 'freighter',
      username: null,
    });

    userWalletRepository.update.mockResolvedValue(undefined);
    const createdWallet = {
      userId: 'user-1',
      walletAddress,
      walletProvider: 'freighter',
      isPrimary: true,
      lastUsedAt: new Date(),
    };
    userWalletRepository.create.mockReturnValue(createdWallet);
    userWalletRepository.save.mockResolvedValue({
      id: 'wallet-1',
      ...createdWallet,
    });

    userRepository.update.mockResolvedValue(undefined);
    walletSessionRepository.save.mockResolvedValue(undefined);

    jwtService.sign
      .mockReturnValueOnce('access-token')
      .mockReturnValueOnce('refresh-token');

    const result = await service.verifyWalletChallenge({
      walletAddress,
      nonce: 'nonce-1',
      signature: Buffer.from('signed').toString('base64'),
    });

    expect(result.access_token).toEqual('access-token');
    expect(result.refresh_token).toEqual('refresh-token');
    expect(result.user.id).toEqual('user-1');
    expect(result.user.walletAddress).toEqual(walletAddress);
  });
});
