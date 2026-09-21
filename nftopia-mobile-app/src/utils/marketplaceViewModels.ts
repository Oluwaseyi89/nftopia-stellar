// Pure data-shaping helpers for the Marketplace listing screen. Kept
// side-effect free and decoupled from GraphQL/React so they're cheap to
// unit test independently of rendering.

import { formatXlmAmount } from './discoveryViewModels';

export interface MarketplaceListingRaw {
  id: string;
  price: string;
  currency: string;
  createdAt: string;
  nft?: {
    id: string;
    name: string;
    image?: string | null;
    creator?: {
      id: string;
      username?: string | null;
    } | null;
  } | null;
}

export interface MarketplaceListingCard {
  id: string;
  nftId: string;
  name: string;
  imageUrl: string;
  priceLabel: string;
  creatorName: string;
}

const FALLBACK_IMAGE = '';
const FALLBACK_CREATOR_NAME = 'Unknown';

/** Maps raw `listings` results into card view-models for the Marketplace grid. */
export function mapMarketplaceListings(
  listings: MarketplaceListingRaw[] | null | undefined,
): MarketplaceListingCard[] {
  if (!listings) return [];

  return listings
    .filter((listing): listing is MarketplaceListingRaw & { nft: NonNullable<MarketplaceListingRaw['nft']> } =>
      Boolean(listing.nft),
    )
    .map((listing) => ({
      id: listing.id,
      nftId: listing.nft.id,
      name: listing.nft.name,
      imageUrl: listing.nft.image || FALLBACK_IMAGE,
      priceLabel: `${formatXlmAmount(listing.price)} ${listing.currency}`,
      creatorName: listing.nft.creator?.username || FALLBACK_CREATOR_NAME,
    }));
}

export type MarketplaceSortOption = 'newest' | 'oldest' | 'price_asc' | 'price_desc';

export const MARKETPLACE_SORT_OPTIONS: MarketplaceSortOption[] = [
  'newest',
  'oldest',
  'price_asc',
  'price_desc',
];

export const DEFAULT_MARKETPLACE_SORT: MarketplaceSortOption = 'newest';

// `ListingStatus` values the backend actually supports for buyer-facing
// browsing. There's no fixed-price/auction distinction on `Listing` in the
// schema (that lives on `NFT.auction` instead), so the status dimension is
// scoped to what `ListingFilterInput.status` can filter on. 'ALL' isn't a
// real enum value — it means "omit the status filter entirely".
export type MarketplaceStatusFilter = 'ACTIVE' | 'SOLD' | 'ALL';

export const MARKETPLACE_STATUS_OPTIONS: MarketplaceStatusFilter[] = ['ACTIVE', 'SOLD', 'ALL'];

export const DEFAULT_MARKETPLACE_STATUS: MarketplaceStatusFilter = 'ACTIVE';

export interface MarketplaceFilters {
  category?: string;
  status: MarketplaceStatusFilter;
  minPrice?: number;
  maxPrice?: number;
  sortBy: MarketplaceSortOption;
}

export const DEFAULT_MARKETPLACE_FILTERS: MarketplaceFilters = {
  category: undefined,
  status: DEFAULT_MARKETPLACE_STATUS,
  minPrice: undefined,
  maxPrice: undefined,
  sortBy: DEFAULT_MARKETPLACE_SORT,
};

/** Translates store filter state (+ the separate search query) into `ListingFilterInput` args. */
export function toListingsFilterArgs(
  filters: MarketplaceFilters,
  search?: string,
): {
  status?: 'ACTIVE' | 'SOLD';
  category?: string;
  minPrice?: number;
  maxPrice?: number;
  sortBy?: MarketplaceSortOption;
  search?: string;
} {
  return {
    ...(filters.status !== 'ALL' ? { status: filters.status } : {}),
    ...(filters.category ? { category: filters.category } : {}),
    ...(filters.minPrice !== undefined ? { minPrice: filters.minPrice } : {}),
    ...(filters.maxPrice !== undefined ? { maxPrice: filters.maxPrice } : {}),
    ...(filters.sortBy ? { sortBy: filters.sortBy } : {}),
    ...(search ? { search } : {}),
  };
}

/**
 * Counts filter *dimensions* that differ from the default (category, status,
 * price range as a single dimension) — used for the filter-trigger badge.
 * Sort order isn't counted; it's presented as its own control, not a filter.
 */
export function getActiveMarketplaceFilterCount(
  filters: Pick<MarketplaceFilters, 'category' | 'status' | 'minPrice' | 'maxPrice'>,
): number {
  let count = 0;
  if (filters.category) count += 1;
  if (filters.status !== DEFAULT_MARKETPLACE_STATUS) count += 1;
  if (filters.minPrice !== undefined || filters.maxPrice !== undefined) count += 1;
  return count;
}
