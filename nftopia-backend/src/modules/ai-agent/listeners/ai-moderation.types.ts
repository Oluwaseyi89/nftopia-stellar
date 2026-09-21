export const AI_MODERATION_QUEUE_NAME = 'ai-moderation';
export const MODERATE_LISTING_JOB = 'moderate-listing';

/** Payload of the `listing.created` event, emitted by ListingService.create. */
export interface ListingCreatedEvent {
  listingId: string;
  sellerId: string;
  nftContractId: string;
  nftTokenId: string;
}

/** Job data enqueued on the `ai-moderation` queue for a future Bull processor to consume. */
export type AiModerationJobData = ListingCreatedEvent;
