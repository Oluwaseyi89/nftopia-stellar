import {
  mapMarketplaceListings,
  MarketplaceListingRaw,
  MARKETPLACE_SORT_OPTIONS,
  DEFAULT_MARKETPLACE_FILTERS,
  MarketplaceFilters,
  toListingsFilterArgs,
  getActiveMarketplaceFilterCount,
} from './marketplaceViewModels';

describe('mapMarketplaceListings', () => {
  const raw: MarketplaceListingRaw = {
    id: 'listing-1',
    price: '5.0000000',
    currency: 'XLM',
    createdAt: '2026-08-27T00:00:00.000Z',
    nft: {
      id: 'nft-1',
      name: 'Cosmic Cat',
      image: 'https://example.com/nft.png',
      creator: { id: 'creator-1', username: 'astro_artist' },
    },
  };

  it('maps raw listings into card view-models', () => {
    const [card] = mapMarketplaceListings([raw]);

    expect(card).toEqual({
      id: 'listing-1',
      nftId: 'nft-1',
      name: 'Cosmic Cat',
      imageUrl: 'https://example.com/nft.png',
      priceLabel: '5 XLM',
      creatorName: 'astro_artist',
    });
  });

  it('filters out listings with no attached nft', () => {
    const withoutNft: MarketplaceListingRaw = { ...raw, id: 'listing-2', nft: null };
    const cards = mapMarketplaceListings([raw, withoutNft]);
    expect(cards).toHaveLength(1);
    expect(cards[0].id).toBe('listing-1');
  });

  it('returns an empty array for null/undefined input', () => {
    expect(mapMarketplaceListings(null)).toEqual([]);
    expect(mapMarketplaceListings(undefined)).toEqual([]);
  });

  it('returns an empty array for an empty input array', () => {
    expect(mapMarketplaceListings([])).toEqual([]);
  });

  it('falls back to an empty image string when nft.image is missing', () => {
    const [card] = mapMarketplaceListings([
      { ...raw, nft: { ...raw.nft!, image: null } },
    ]);
    expect(card.imageUrl).toBe('');
  });

  it('falls back to "Unknown" when the creator has no username', () => {
    const [card] = mapMarketplaceListings([
      { ...raw, nft: { ...raw.nft!, creator: { id: 'creator-1', username: null } } },
    ]);
    expect(card.creatorName).toBe('Unknown');
  });

  it('falls back to "Unknown" when the nft has no creator at all', () => {
    const [card] = mapMarketplaceListings([
      { ...raw, nft: { ...raw.nft!, creator: null } },
    ]);
    expect(card.creatorName).toBe('Unknown');
  });

  it('preserves ordering from the input array', () => {
    const second: MarketplaceListingRaw = { ...raw, id: 'listing-2', nft: { ...raw.nft!, id: 'nft-2' } };
    const cards = mapMarketplaceListings([raw, second]);
    expect(cards.map((c) => c.id)).toEqual(['listing-1', 'listing-2']);
  });
});

describe('MARKETPLACE_SORT_OPTIONS', () => {
  it('lists every sort option the backend accepts, newest first', () => {
    expect(MARKETPLACE_SORT_OPTIONS).toEqual(['newest', 'oldest', 'price_asc', 'price_desc']);
  });
});

describe('toListingsFilterArgs', () => {
  it('produces just the default status filter when nothing else is set', () => {
    expect(toListingsFilterArgs(DEFAULT_MARKETPLACE_FILTERS)).toEqual({
      status: 'ACTIVE',
      sortBy: 'newest',
    });
  });

  it('omits status entirely when the status filter is ALL', () => {
    const filters: MarketplaceFilters = { ...DEFAULT_MARKETPLACE_FILTERS, status: 'ALL' };
    expect(toListingsFilterArgs(filters)).toEqual({ sortBy: 'newest' });
  });

  it('includes category, price range and search when set', () => {
    const filters: MarketplaceFilters = {
      category: 'art',
      status: 'SOLD',
      minPrice: 5,
      maxPrice: 50,
      sortBy: 'price_asc',
    };
    expect(toListingsFilterArgs(filters, 'cosmic')).toEqual({
      status: 'SOLD',
      category: 'art',
      minPrice: 5,
      maxPrice: 50,
      sortBy: 'price_asc',
      search: 'cosmic',
    });
  });

  it('supports an open-ended price range (min only)', () => {
    const filters: MarketplaceFilters = { ...DEFAULT_MARKETPLACE_FILTERS, minPrice: 10 };
    expect(toListingsFilterArgs(filters)).toEqual({ status: 'ACTIVE', sortBy: 'newest', minPrice: 10 });
  });

  it('omits search when blank', () => {
    expect(toListingsFilterArgs(DEFAULT_MARKETPLACE_FILTERS, '')).not.toHaveProperty('search');
  });
});

describe('getActiveMarketplaceFilterCount', () => {
  it('returns 0 for the default filters', () => {
    expect(getActiveMarketplaceFilterCount(DEFAULT_MARKETPLACE_FILTERS)).toBe(0);
  });

  it('counts a selected category', () => {
    expect(getActiveMarketplaceFilterCount({ ...DEFAULT_MARKETPLACE_FILTERS, category: 'art' })).toBe(1);
  });

  it('counts a non-default status', () => {
    expect(getActiveMarketplaceFilterCount({ ...DEFAULT_MARKETPLACE_FILTERS, status: 'SOLD' })).toBe(1);
  });

  it('counts a price range as a single dimension regardless of whether both bounds are set', () => {
    expect(getActiveMarketplaceFilterCount({ ...DEFAULT_MARKETPLACE_FILTERS, minPrice: 10 })).toBe(1);
    expect(
      getActiveMarketplaceFilterCount({ ...DEFAULT_MARKETPLACE_FILTERS, minPrice: 10, maxPrice: 100 }),
    ).toBe(1);
  });

  it('sums independent dimensions', () => {
    expect(
      getActiveMarketplaceFilterCount({
        category: 'art',
        status: 'SOLD',
        minPrice: 10,
        maxPrice: 100,
      }),
    ).toBe(3);
  });
});
