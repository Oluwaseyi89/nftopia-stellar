# Issue 46: Fix `hasNextPage` Always Returning False in `order.resolver.ts`

## Summary
GraphQL order pagination always reports `hasNextPage: false`, so clients stop fetching after the first page even when more orders exist.

## Problem Statement
Confirmed in backend code:
1. In `order.resolver.ts`, `toConnection()` hardcodes:
   - `hasNextPage: false // TODO: implement real pagination`
2. Resolver computes `totalCount` as `orders.length` (page size), not dataset total.
3. `OrderService.findAll()` uses `skip/take` but only returns current page rows; it does not return total rows.
4. Cursor handling is inconsistent: `after` is treated as numeric page (`Number(pagination.after)`), while emitted cursors are order IDs.

## Required Changes
1. Add a paginated service method returning both rows and total count, e.g.:
   - `findAllWithCount(query): { items, totalCount, page, limit }`
   - Use TypeORM `getManyAndCount()`.
2. Update `myOrders` and `userOrders` resolvers to call this paginated method.
3. Compute `hasNextPage` using total count:
   - `hasNextPage = page * limit < totalCount`.
4. Return real `totalCount` from DB count, not `orders.length`.
5. Align pagination contract:
   - Either keep page-based pagination (`after` as page number) and emit numeric cursors,
   - Or move to true cursor-based pagination and stop parsing cursor as page.
6. Add validation/defaults for pagination inputs (`page >= 1`, sane `limit`).

## Acceptance Criteria
1. For datasets larger than page size, first page returns `hasNextPage: true`.
2. Last page returns `hasNextPage: false`.
3. `totalCount` reflects full filtered dataset, not current page length.
4. Pagination is deterministic and consistent with the cursor/page contract.
5. Tests cover: single-page, multi-page, final-page edge case.

## Dependencies
Depends On: Stable pagination input contract in GraphQL schema
Blocks: Reliable infinite-scroll / load-more behavior in frontend order history views
