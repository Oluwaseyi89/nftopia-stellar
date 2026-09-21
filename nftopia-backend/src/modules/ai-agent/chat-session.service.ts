import {
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ChatSession } from './entities/chat-session.entity';
import { ChatMessage } from './entities/chat-message.entity';
import { ChatTurnDto } from './dto/chat-request.dto';

export interface LoadedChatSession {
  session: ChatSession;
  history: ChatTurnDto[];
}

/**
 * Owns chat_sessions/chat_messages: resolving which session a chat call
 * continues (or starting a new one), and persisting each exchange. History
 * always comes from here, never from client input — see AiAgentService.
 */
@Injectable()
export class ChatSessionService {
  private readonly logger = new Logger(ChatSessionService.name);

  constructor(
    @InjectRepository(ChatSession)
    private readonly sessionRepo: Repository<ChatSession>,
    @InjectRepository(ChatMessage)
    private readonly messageRepo: Repository<ChatMessage>,
  ) {}

  /**
   * With no sessionId, starts a new (empty) session. With one, loads it —
   * throwing NotFoundException if it doesn't exist, or ForbiddenException
   * if it belongs to a different user — and returns its history in
   * chronological order, ready to feed straight into the model.
   */
  async loadOrCreateSession(
    userId: string,
    sessionId?: string,
  ): Promise<LoadedChatSession> {
    if (!sessionId) {
      const session = await this.sessionRepo.save(
        this.sessionRepo.create({ userId }),
      );
      return { session, history: [] };
    }

    const session = await this.sessionRepo.findOne({
      where: { id: sessionId },
    });
    if (!session) {
      throw new NotFoundException(`Chat session ${sessionId} not found`);
    }
    if (session.userId !== userId) {
      throw new ForbiddenException(
        'You do not have access to this chat session',
      );
    }

    const messages = await this.messageRepo.find({
      where: { sessionId },
      order: { createdAt: 'ASC' },
    });

    return {
      session,
      history: messages.map((m) => ({ role: m.role, content: m.content })),
    };
  }

  /**
   * Persists both turns of a completed exchange and bumps the session's
   * updatedAt. Never throws: the reply was already generated (and billed)
   * by the time this runs, so a storage failure here is logged rather than
   * discarding a good reply from the caller.
   */
  async appendExchange(
    sessionId: string,
    userMessage: string,
    assistantReply: string,
  ): Promise<void> {
    try {
      await this.messageRepo.save([
        this.messageRepo.create({
          sessionId,
          role: 'user',
          content: userMessage,
        }),
        this.messageRepo.create({
          sessionId,
          role: 'assistant',
          content: assistantReply,
        }),
      ]);
      await this.sessionRepo.update(sessionId, { updatedAt: new Date() });
    } catch (error) {
      this.logger.error(
        `Failed to persist chat exchange for session=${sessionId}: ${(error as Error).message}`,
      );
    }
  }
}
