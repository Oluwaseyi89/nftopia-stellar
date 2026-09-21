import { useQuery } from '@apollo/client';
import { GET_MARKETPLACE_LISTINGS_QUERY } from '@/lib/api/graphql/queries';
import { mapMarketplaceListings, MarketplaceListingRaw, MarketplaceFilters, toListingsFilterArgs } from '@/src/utils/marketplaceViewModels';

const PAGE_SIZE = 12;

export interface MarketplaceListingsData {
  listings: {
    edges: { cursor: string; node: MarketplaceListingRaw }[];
    pageInfo: { hasNextPage: boolean; endCursor: string };
    totalCount: number;
  };
}

export interface MarketplaceListingsVars {
  pagination?: { first?: number; after?: string };
  filter?: {
    status?: string;
    search?: string;
    category?: string;
    minPrice?: number;
    maxPrice?: number;
    sortBy?: string;
  };
}

export interface UseMarketplaceListingsParams {
  filters: MarketplaceFilters;
  search?: string;
}

export const useMarketplaceListings = ({ filters, search }: UseMarketplaceListingsParams) => {
  const filter = toListingsFilterArgs(filters, search);

  const { data, loading, error, fetchMore, refetch } = useQuery<MarketplaceListingsData, MarketplaceListingsVars>(
    GET_MARKETPLACE_LISTINGS_QUERY,
    {
      variables: { pagination: { first: PAGE_SIZE }, filter },
      notifyOnNetworkStatusChange: true,
    },
  );

  const loadMore = () => {
    if (data?.listings.pageInfo.hasNextPage && !loading) {
      fetchMore({
        variables: {
          pagination: { first: PAGE_SIZE, after: data.listings.pageInfo.endCursor },
          filter,
        },
      });
    }
  };

  const rawListings = data?.listings.edges.map((edge) => edge.node) ?? [];

  return {
    listings: mapMarketplaceListings(rawListings),
    loading,
    error,
    loadMore,
    refetch,
    hasNextPage: data?.listings.pageInfo.hasNextPage ?? false,
  };
};
