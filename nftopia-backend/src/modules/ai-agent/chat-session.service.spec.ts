import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { ChatSessionService } from './chat-session.service';

describe('ChatSessionService', () => {
  let service: ChatSessionService;

  const sessionRepo = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
  };

  const messageRepo = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new ChatSessionService(
      sessionRepo as never,
      messageRepo as never,
    );
  });

  describe('loadOrCreateSession', () => {
    it('creates a new session when no sessionId is given', async () => {
      sessionRepo.create.mockReturnValue({ userId: 'user-1' });
      sessionRepo.save.mockResolvedValue({
        id: 'new-session-1',
        userId: 'user-1',
      });

      const result = await service.loadOrCreateSession('user-1');

      expect(sessionRepo.create).toHaveBeenCalledWith({ userId: 'user-1' });
      expect(sessionRepo.save).toHaveBeenCalled();
      expect(result.session).toEqual({ id: 'new-session-1', userId: 'user-1' });
      expect(result.history).toEqual([]);
      expect(messageRepo.find).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the given sessionId does not exist', async () => {
      sessionRepo.findOne.mockResolvedValue(null);

      await expect(
        service.loadOrCreateSession('user-1', 'missing-session'),
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(messageRepo.find).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when the session belongs to a different user', async () => {
      sessionRepo.findOne.mockResolvedValue({
        id: 'session-1',
        userId: 'user-1',
      });

      await expect(
        service.loadOrCreateSession('user-2', 'session-1'),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(messageRepo.find).not.toHaveBeenCalled();
    });

    it('loads and returns history in chronological order for the owning user', async () => {
      sessionRepo.findOne.mockResolvedValue({
        id: 'session-1',
        userId: 'user-1',
      });
      messageRepo.find.mockResolvedValue([
        {
          role: 'user',
          content: 'Hi',
          createdAt: new Date('2026-01-01T00:00:00Z'),
        },
        {
          role: 'assistant',
          content: 'Hello, how can I help?',
          createdAt: new Date('2026-01-01T00:00:01Z'),
        },
      ]);

      const result = await service.loadOrCreateSession('user-1', 'session-1');

      expect(messageRepo.find).toHaveBeenCalledWith({
        where: { sessionId: 'session-1' },
        order: { createdAt: 'ASC' },
      });
      expect(result.history).toEqual([
        { role: 'user', content: 'Hi' },
        { role: 'assistant', content: 'Hello, how can I help?' },
      ]);
      expect(result.session).toEqual({ id: 'session-1', userId: 'user-1' });
    });
  });

  describe('appendExchange', () => {
    it('persists a user turn and an assistant turn, and bumps updatedAt', async () => {
      messageRepo.create.mockImplementation((input: unknown) => input);

      await service.appendExchange('session-1', 'The question.', 'The reply.');

      expect(messageRepo.save).toHaveBeenCalledWith([
        { sessionId: 'session-1', role: 'user', content: 'The question.' },
        { sessionId: 'session-1', role: 'assistant', content: 'The reply.' },
      ]);
      expect(sessionRepo.update).toHaveBeenCalledTimes(1);
      const [updatedId, updatePayload] = sessionRepo.update.mock.calls[0] as [
        string,
        { updatedAt: Date },
      ];
      expect(updatedId).toBe('session-1');
      expect(updatePayload.updatedAt).toBeInstanceOf(Date);
    });

    it('does not throw when persistence fails (already-generated reply must not be lost)', async () => {
      messageRepo.create.mockImplementation((input: unknown) => input);
      messageRepo.save.mockRejectedValue(new Error('db down'));

      await expect(
        service.appendExchange('session-1', 'q', 'a'),
      ).resolves.toBeUndefined();
    });

    it('does not touch updatedAt when the message save fails', async () => {
      messageRepo.create.mockImplementation((input: unknown) => input);
      messageRepo.save.mockRejectedValue(new Error('db down'));

      await service.appendExchange('session-1', 'q', 'a');

      expect(sessionRepo.update).not.toHaveBeenCalled();
    });
  });
});
