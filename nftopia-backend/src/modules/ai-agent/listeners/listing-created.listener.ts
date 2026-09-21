import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectQueue } from '@nestjs/bull';
import type { Queue } from 'bull';
import {
  AI_MODERATION_QUEUE_NAME,
  MODERATE_LISTING_JOB,
} from './ai-moderation.types';
import type { ListingCreatedEvent } from './ai-moderation.types';

/**
 * Reacts to `listing.created` by enqueuing a moderation job — deliberately
 * doesn't call the AI agent inline, so a slow or unavailable moderation
 * agent never blocks the event handler. A follow-up issue adds the Bull
 * processor that actually consumes this queue.
 */
@Injectable()
export class ListingCreatedListener {
  private readonly logger = new Logger(ListingCreatedListener.name);

  constructor(
    @InjectQueue(AI_MODERATION_QUEUE_NAME)
    private readonly moderationQueue: Queue,
  ) {}

  @OnEvent('listing.created')
  async handleListingCreated(event: ListingCreatedEvent): Promise<void> {
    try {
      await this.moderationQueue.add(MODERATE_LISTING_JOB, event);
    } catch (err) {
      // Swallow: a failed enqueue must never surface back to whoever
      // created the listing — it's already been persisted/settled.
      this.logger.error(
        `Failed to enqueue moderation job for listing=${event.listingId}: ${(err as Error).message}`,
      );
    }
  }
}
