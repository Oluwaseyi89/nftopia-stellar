# nftopia-mobile-app — Issue Backlog (source file)

134 minimal issue entries (of an original 150) generated from a direct audit of the current `nftopia-mobile-app/` codebase (2026-09-21). Each entry is a candidate for expansion into a full GitHub issue following the repo's established template (Summary / Discord link / Problem Statement with real file references / Required Changes / Acceptance Criteria / Directory). 8 entries were used to create GitHub issues #543-#550 and removed; a few additional entries in the original "Auth & Session Backend Integration" section cited specific `authStore.ts` line numbers/TODO comments that did not actually exist in the file (verified false on a follow-up read — that file has no TODO comments at all) and were corrected/removed rather than carried into a public issue.

Do **not** duplicate the 10 still-open mobile-app issues: #399 (secure token storage + biometric), #455 (Receive/QR), #456 (QR scanner), #466 (native share), #467 (haptics), #468 (form input library), #469 (bottom sheet), #470 (currency conversion), #471 (fee estimation), #472 (empty/error states) — those remain the active backlog and are excluded from this file. The other 58 mobile-app issues are closed/implemented; entries below build on top of that work rather than repeating it.

When a title from this file is used to create a real GitHub issue, remove its line here.

## AI Assistant Chat UI

- [ ] **Add AI usage summary display consuming `GET /ai/usage`** — no screen shows the user their AI chat usage/quota from `AiUsageService`. _(kind: mobile-app, Typescript)_
- [ ] **Add AI chat entry point to Home and Marketplace screens** — no discoverable affordance (FAB/button) launches the assistant from `HomeScreen.tsx` or `MarketplaceScreen.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add AI chat session persistence across app restarts** — no local store mirrors backend `chat-session.service.ts` sessions so a resumed app loses chat history. _(kind: mobile-app, Typescript)_
- [ ] **Add AI chat message list with markdown/tool-result rendering** — assistant replies from `marketplace.tools.ts` may include structured NFT/listing data with no dedicated rendering component. _(kind: mobile-app, React-Native)_
- [ ] **Add AI chat rate-limit and error UI** — backend's `AiChatRateLimitGuard` can 429; no mobile handling surfaces a friendly retry-after message. _(kind: mobile-app, bug, enhancement)_
- [ ] **Add AI chat health indicator using `GET /ai/health`** — no UI reflects `AiAgentHealthService` down/unconfigured states before a user starts typing. _(kind: mobile-app, Typescript)_
- [ ] **Add accessibility support to the AI chat screen** — plan VoiceOver/TalkBack support (live region for streaming replies) from the start, matching the app's existing a11y work. _(kind: mobile-app, enhancement)_
- [ ] **Add analytics events for AI chat engagement** — wire `useAnalytics.ts` events for chat opened, message sent, and tool-result shown once the chat UI exists. _(kind: mobile-app, telemetry)_

## Navigation Wiring & Dead Screens

- [ ] **Register `TransactionHistoryScreen` in `MainNavigator.tsx`** — `screens/Wallet/TransactionHistoryScreen.tsx` exists with no route or entry point from `WalletManagementScreen.tsx`/`HomeScreen.tsx`. _(kind: mobile-app, bug)_
- [ ] **Register `AddressBookScreen` in `MainNavigator.tsx` and link it from `SendScreen`** — `screens/Wallet/AddressBookScreen.tsx` and `screens/Wallet/components/RecipientPicker.tsx` exist but `Send` route only points to `SendScreen`. _(kind: mobile-app, bug)_
- [ ] **Register `CreatorProfileScreen` in `MainNavigator.tsx`** — `screens/Profile/CreatorProfileScreen.tsx` exists with no route or link from `ProfileScreen.tsx`/NFT detail creator link. _(kind: mobile-app, bug)_
- [ ] **Register `BackupReminderScreen` as a route and confirm `BackupReminderManager.tsx` triggers navigation to it** — verify the manager component actually pushes this screen rather than only rendering inline. _(kind: mobile-app, bug)_
- [ ] **Register `AppLockScreen` as the true navigation root when locked** — confirm `AppLockManager.tsx` renders `screens/Auth/AppLockScreen.tsx` as a blocking overlay/route rather than a component that could be bypassed by direct navigation. _(kind: mobile-app, bug)_
- [ ] **Add an E2E smoke test asserting every screen file has a reachable navigation path** — write a lightweight script/test enumerating `screens/**/*Screen.tsx` and cross-checking against registered route names, to prevent future dead screens. _(kind: mobile-app, test)_

## Auth & Session Backend Integration

- [ ] **Implement registration backend call in `EmailRegisterScreen.tsx`** — `screens/Auth/EmailRegisterScreen.tsx:82` has `// TODO: Implement actual registration logic with backend`. _(kind: mobile-app, bug)_
- [ ] **Add integration tests for the full login → token-refresh → logout lifecycle** — no test exercises `authStore.ts` against a mocked backend end-to-end once the TODOs above are resolved. _(kind: mobile-app, test)_
- [ ] **Audit and unify wallet service layer duplication between `src/services/stellar/` and any newer wallet code paths** — confirm `SendScreen.tsx`, `AddressBookScreen.tsx`, and `TransactionHistoryScreen.tsx` all use the same canonical `wallet.service.ts` rather than diverging copies. _(kind: mobile-app, bug)_

## Marketplace Data & Discovery Hardening

- [ ] **Add integration tests for `useMarketplaceListings.ts` pagination (cursor + `hasNextPage`)** — the Apollo-backed hook has no test verifying `after`/`endCursor` paging behaves correctly against `GET_MARKETPLACE_LISTINGS_QUERY`. _(kind: mobile-app, test, graphql)_
- [ ] **Add error and retry UI to `MarketplaceScreen.tsx` for failed GraphQL fetches** — confirm the screen surfaces Apollo error states distinctly from empty results, using the shared empty/error-state work tracked in open issue #472. _(kind: mobile-app, bug)_
- [ ] **Add cache invalidation strategy for `apolloClient.ts` after a listing purchase/cancel** — confirm the Apollo cache normalizes and updates `listings` after `Listing`/`Order` mutations rather than requiring a manual refetch. _(kind: mobile-app, bug, graphql)_
- [ ] **Add tests for `useNFTDetail.ts` covering not-found and network-error paths** — no test file exists for this hook alongside `NFTDetailScreen.tsx`. _(kind: mobile-app, test)_
- [ ] **Add tests for `useTrendingCollections.ts` and `useNewListings.ts`** — neither discovery hook (used by `TrendingCarousel.tsx`/`NewDropsSection.tsx`) has test coverage. _(kind: mobile-app, test)_
- [ ] **Verify `MarketplaceFiltersStore` filter state survives `MarketplaceScreen` unmount/remount** — confirm filters set via `FilterSheet.tsx` persist correctly when navigating away and back, per `stores/marketplaceFiltersStore.ts`. _(kind: mobile-app, bug)_
- [ ] **Add skeleton-to-content transition tests for `DiscoverySkeletons.tsx`** — no test confirms skeletons correctly swap for real `MarketplaceListingCard.tsx` content once data resolves. _(kind: mobile-app, test)_
- [ ] **Audit `CategorySelector.tsx`/`CategoryChip.tsx` against `constants/categories.ts` for orphaned or missing categories** — confirm the UI list and the canonical category constant stay in sync as categories evolve. _(kind: mobile-app, bug)_
- [ ] **Add pull-to-refresh to `MarketplaceScreen.tsx` via `EnhancedRefreshControl.tsx`** — confirm the shared refresh component (built for Home) is also wired into the marketplace listing screen. _(kind: mobile-app, enhancement)_
- [ ] **Add analytics events for marketplace filter/sort usage** — wire `MarketplaceSortBar.tsx` and `FilterSheet.tsx` interactions into `useAnalytics.ts`. _(kind: mobile-app, telemetry)_

## Auctions

- [ ] **Wire `AuctionsScreen.tsx` to real backend auction listing data** — confirm it calls the backend's `GET /auctions`/`GET /auctions/active` (via GraphQL or REST) rather than placeholder data, once the screen is registered in navigation. _(kind: mobile-app, bug)_
- [ ] **Implement live bid updates on `AuctionDetailScreen.tsx`** — confirm the screen polls or subscribes for new bids rather than showing a static snapshot, given backend `POST /auctions/:id/bids` can be called by any bidder in real time. _(kind: mobile-app, enhancement)_
- [ ] **Add countdown timer accuracy test for auction end times on `AuctionDetailScreen.tsx`** — verify timezone/clock-drift handling against the backend's auction end timestamp. _(kind: mobile-app, test)_
- [ ] **Add bid confirmation flow to `AuctionDetailScreen.tsx`** — confirm a `ConfirmationDialog.tsx`-based review step exists before submitting a bid, showing amount and fee. _(kind: mobile-app, enhancement)_
- [ ] **Add outbid push notification handling** — confirm `usePushNotifications.ts`/`NotificationsScreen.tsx` surface an "you've been outbid" event tied to `stores/auctionStore.ts`. _(kind: mobile-app, enhancement)_
- [ ] **Add auction creation form validation to `CreateAuctionScreen.tsx`** — confirm starting price, reserve price, and duration fields are validated client-side before hitting `POST /auctions`. _(kind: mobile-app, bug)_
- [ ] **Add auction settlement status UI** — confirm a finished auction on `AuctionDetailScreen.tsx` reflects backend `POST /auctions/:id/settle` outcome (won/lost/settled) rather than just ending silently. _(kind: mobile-app, enhancement)_
- [ ] **Add empty state for `AuctionsScreen.tsx` with zero active auctions** — align with the shared empty-state component work tracked in open issue #472. _(kind: mobile-app, enhancement)_
- [ ] **Add auction list filtering (ending soon, newly listed, price range)** — `AuctionsScreen.tsx` has no filter controls comparable to `FilterSheet.tsx` on the marketplace. _(kind: mobile-app, enhancement)_

## Collections

- [ ] **Wire `CollectionsScreen.tsx` to `GET /collections` and `GET /collections/top`** — confirm the listing and "top collections" views call the real backend endpoints rather than static/mock data. _(kind: mobile-app, bug)_
- [ ] **Wire `CollectionDetailScreen.tsx` to `GET /collections/:id`, `/stats`, and `/nfts`** — confirm the detail screen aggregates collection info, stats, and its NFT grid from the three real backend endpoints. _(kind: mobile-app, bug)_
- [ ] **Add collection verification badge to `CollectionDetailScreen.tsx`/`CollectionsScreen.tsx`** — surface the backend's collection verification status (`POST /collections/:id/verify`, admin-approved) visually. _(kind: mobile-app, enhancement)_
- [ ] **Add collection follow/unfollow action to `CollectionDetailScreen.tsx`** — wire to backend social endpoints (`POST/DELETE /social/users/:id/follow`) if collections are followable, or creator-follow as a proxy. _(kind: mobile-app, enhancement)_
- [ ] **Add pagination to the NFT grid on `CollectionDetailScreen.tsx`** — confirm `GET /collections/:id/nfts` results are paginated rather than loaded all at once for large collections. _(kind: mobile-app, bug)_
- [ ] **Add loading skeletons to `CollectionsScreen.tsx`/`CollectionDetailScreen.tsx`** — confirm these newer screens reuse `src/components/skeletons/` rather than a blank flash while fetching. _(kind: mobile-app, enhancement)_
- [ ] **Add unit tests for collection data-mapping utilities** — confirm any view-model mapping used by `CollectionDetailScreen.tsx` (analogous to `marketplaceViewModels.ts`) has test coverage. _(kind: mobile-app, test)_
- [ ] **Add "create collection" entry point audit** — confirm `CreateCollectionScreen.tsx` is reachable from `CreatorDashboardScreen.tsx` and correctly calls `POST /collections`. _(kind: mobile-app, bug)_
- [ ] **Add contract-address lookup fallback to `CollectionDetailScreen.tsx`** — confirm the screen can resolve a collection via `GET /collections/contract/:address` when navigated to from a deep link containing a contract address rather than an internal ID. _(kind: mobile-app, enhancement)_
- [ ] **Add share action to `CollectionDetailScreen.tsx`** — once `ShareButton.tsx` (tracked in open issue #466) exists, ensure collections are a supported share target alongside NFTs. _(kind: mobile-app, enhancement)_

## Creator Tools & Minting

- [ ] **Wire `MintNFTScreen.tsx` file upload to backend storage** — confirm image/metadata upload goes through the real storage service rather than a local-only preview. _(kind: mobile-app, bug)_
- [ ] **Add mint transaction status tracking to `MintNFTScreen.tsx`** — confirm the screen reflects pending/confirmed/failed states from the underlying Soroban mint transaction, not just a fire-and-forget submit. _(kind: mobile-app, enhancement)_
- [ ] **Wire `EarningsScreen.tsx` to real creator earnings data** — confirm it queries actual sales/royalty data rather than static figures. _(kind: mobile-app, bug)_
- [ ] **Add royalty configuration UI to `MintNFTScreen.tsx`/`CreateCollectionScreen.tsx`** — confirm creators can set royalty basis points consumed by the marketplace settlement contract. _(kind: mobile-app, enhancement)_
- [ ] **Wire `MyNFTsScreen.tsx` to `GET /nft/owner/:ownerId`** — confirm the creator's owned/minted NFT list pulls from the real endpoint with pagination. _(kind: mobile-app, bug)_
- [ ] **Add batch minting support to `MintNFTScreen.tsx`** — backend exposes `POST /:address/batch-mint` on `collection-factory`; no mobile UI exposes batch minting. _(kind: mobile-app, enhancement)_
- [ ] **Add draft/save-for-later support to `MintNFTScreen.tsx`** — confirm an in-progress mint form (image + metadata) survives an accidental navigation away or app kill. _(kind: mobile-app, enhancement)_
- [ ] **Add creator dashboard analytics charts to `CreatorDashboardScreen.tsx`/`AnalyticsDashboardScreen.tsx`** — confirm real sales/views/followers trends render, not placeholder numbers. _(kind: mobile-app, bug)_
- [ ] **Add unit tests for `stores/creatorStore.ts`** — no `__tests__/creatorStore.test.ts` exists despite the store backing `CreatorDashboardScreen`, `MyNFTsScreen`, `MintNFTScreen`, and `EarningsScreen`. _(kind: mobile-app, test)_
- [ ] **Add image compression/resizing before upload in `MintNFTScreen.tsx`** — confirm large photos are downscaled client-side before hitting storage, using `OptimizedImage.tsx`/`src/config/image.config.ts` conventions. _(kind: mobile-app, enhancement)_

## Search

- [ ] **Wire `SearchBar.tsx`/`SearchResultsScreen.tsx` to a real search backend query** — confirm results come from `nftopia-backend/src/search` rather than client-side filtering of already-loaded data. _(kind: mobile-app, bug)_
- [ ] **Add debounced search input to `SearchBar.tsx`** — confirm typing doesn't fire a network request per keystroke. _(kind: mobile-app, bug)_
- [ ] **Add recent-searches list to `SearchResultsScreen.tsx`** — no store persists a user's recent search terms for quick re-entry. _(kind: mobile-app, enhancement)_
- [ ] **Add search suggestions/autocomplete** — no typeahead exists as the user types in `SearchBar.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add search result type filters (NFTs vs. collections vs. creators)** — confirm `SearchResultsScreen.tsx` can scope results by entity type. _(kind: mobile-app, enhancement)_
- [ ] **Add unit tests for `stores/searchStore.ts`** — no `__tests__/searchStore.test.ts` exists. _(kind: mobile-app, test)_
- [ ] **Add empty state for zero search results** — align with the shared empty-state work tracked in open issue #472, specifically for the "no results for '{query}'" case. _(kind: mobile-app, enhancement)_
- [ ] **Add search analytics events** — wire query submission and result-tap events into `useAnalytics.ts`. _(kind: mobile-app, telemetry)_
- [ ] **Add voice search entry point (optional, behind a feature flag)** — evaluate `expo-speech`/OS dictation as a low-effort search input alternative. _(kind: mobile-app, enhancement)_
- [ ] **Add search accessibility labels and screen-reader announcements for result counts** — confirm `SearchResultsScreen.tsx` announces "N results found" to assistive tech. _(kind: mobile-app, enhancement)_

## Wallet, Payments & Address Book Hardening

- [ ] **Add multi-wallet selector to `SendScreen.tsx`** — confirm the send flow lets a user pick which wallet/account to send from when `stores/walletStore.ts` holds more than one. _(kind: mobile-app, enhancement)_
- [ ] **Add trustline creation flow for non-XLM assets on `SendScreen.tsx`** — confirm sending an asset the recipient hasn't trusted yet is detected and explained, not just a failed transaction. _(kind: mobile-app, enhancement)_
- [ ] **Add spending confirmation via biometric/PIN before submitting from `SendScreen.tsx`** — confirm high-value transfers require a second auth factor, building on `BiometricConfirmationDialog.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add unit tests for `RecipientPicker.tsx`** — no test covers the address-book-backed recipient selection component. _(kind: mobile-app, test)_
- [ ] **Add duplicate-address validation between `AddressBookScreen.tsx` entries** — confirm the store-level validation (tracked for `addressBookStore.ts`) is enforced in the actual add/edit UI. _(kind: mobile-app, bug)_
- [ ] **Add transaction detail drill-down from `TransactionHistoryScreen.tsx`** — confirm tapping a row opens a detail view with hash, memo, and a block-explorer link, using `src/utils/explorerUrl.ts`-equivalent logic (mirrors `nftopia-admin/src/utils/explorerUrl.ts`). _(kind: mobile-app, enhancement)_
- [ ] **Add pagination/infinite-scroll to `TransactionHistoryScreen.tsx`** — confirm long histories load incrementally rather than all at once. _(kind: mobile-app, bug)_
- [ ] **Add transaction type filter to `TransactionHistoryScreen.tsx`** — confirm payments, mints, sales, and trustline changes can be filtered independently. _(kind: mobile-app, enhancement)_
- [ ] **Add wallet balance auto-refresh after a completed `SendScreen.tsx` transaction** — confirm `BalanceDisplay.tsx` updates immediately post-send rather than requiring a manual pull-to-refresh. _(kind: mobile-app, bug)_
- [ ] **Add offline queuing for a send attempted while disconnected** — confirm `SendScreen.tsx` respects `NetworkStatusManager.tsx`/`ConnectivityBanner.tsx` and either blocks submission or queues it clearly, rather than failing silently. _(kind: mobile-app, enhancement)_

## Notifications

- [ ] **Wire `NotificationsScreen.tsx` to real backend notification data** — confirm it consumes actual push/in-app notification history rather than local-only test data from `PushNotificationTestScreen.tsx`. _(kind: mobile-app, bug)_
- [ ] **Add mark-as-read/unread and swipe-to-dismiss to `NotificationsScreen.tsx`** — confirm per-notification state management exists in `stores/notificationStore.ts`. _(kind: mobile-app, enhancement)_
- [ ] **Add deep-link-on-tap for each notification type** — confirm tapping a bid/sale/follow notification routes to the relevant `AuctionDetailScreen`/`NFTDetailScreen`/`CreatorProfileScreen` via `src/navigation/linking.config.ts`. _(kind: mobile-app, bug)_
- [ ] **Add notification badge count to the tab bar/app icon** — confirm unread count from `stores/notificationStore.ts` surfaces on the OS badge (`expo-notifications` badge API) and in-app tab indicator. _(kind: mobile-app, enhancement)_
- [ ] **Add category grouping to `NotificationsScreen.tsx`** — confirm notifications are grouped (bids, sales, follows, system) matching the categories configurable in `NotificationSettingsScreen.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add quiet-hours enforcement check** — confirm `usePushNotifications.ts` actually respects any quiet-hours window configured in `NotificationSettingsScreen.tsx`/`stores/preferencesStore.ts` rather than only storing the preference. _(kind: mobile-app, bug)_
- [ ] **Add unit tests for `notificationSchedule.ts`** — `src/utils/notificationSchedule.ts` has a `.test.ts` sibling; confirm it covers timezone and DST edge cases for scheduled/local notifications. _(kind: mobile-app, test)_
- [ ] **Add OS notification permission re-request flow** — confirm a denied-permission user gets a clear path back to OS settings from `NotificationSettingsScreen.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add rich push notification content (images) for sale/bid events** — confirm `pushNotification.service.ts` supports an NFT thumbnail in the notification payload where the platform allows it. _(kind: mobile-app, enhancement)_
- [ ] **Add notification empty state to `NotificationsScreen.tsx`** — align with the shared empty-state work tracked in open issue #472. _(kind: mobile-app, enhancement)_

## Social & Profile

- [ ] **Wire `CreatorProfileScreen.tsx` to `GET /social` follow/follower/activity endpoints** — confirm followers, following, and activity feed pull from the real backend social module once the screen is registered in navigation. _(kind: mobile-app, bug)_
- [ ] **Add follow/unfollow button to `CreatorProfileScreen.tsx`** — wire `POST`/`DELETE /social/users/:id/follow`. _(kind: mobile-app, enhancement)_
- [ ] **Add creator suggestions section using `GET /social/suggestions`** — no mobile UI surfaces suggested creators to follow. _(kind: mobile-app, enhancement)_
- [ ] **Add mutual-followers display using `GET /social/mutual/:id`** — no UI shows "followed by X and Y others" on `CreatorProfileScreen.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add activity feed screen using `GET /social/feed`** — confirm a dedicated feed of followed creators' activity exists, distinct from `NotificationsScreen.tsx`. _(kind: mobile-app, enhancement)_
- [ ] **Add profile edit flow to `ProfileScreen.tsx`** — confirm avatar, display name, and bio can be edited, not just viewed. _(kind: mobile-app, enhancement)_
- [ ] **Add "report user" entry point to `CreatorProfileScreen.tsx`** — confirm `ReportModal.tsx`/`report.service.ts` (already built) is actually reachable from a creator's profile, not only from NFT/listing content. _(kind: mobile-app, bug)_
- [ ] **Add follower/following count tap-through to a user list screen** — confirm counts on `CreatorProfileScreen.tsx` are tappable and open a paginated list via `GET /social/users/:id/followers`/`following`. _(kind: mobile-app, enhancement)_
- [ ] **Add block-user capability alongside existing report flow** — evaluate whether `report.service.ts`'s "hide this for me" action should extend to a persistent block list. _(kind: mobile-app, enhancement)_
- [ ] **Add unit tests for social data hooks/store** — no test coverage exists for whatever hook backs `CreatorProfileScreen.tsx`'s follow state. _(kind: mobile-app, test)_

## State Management Test Coverage & Store Hardening

- [ ] **Add unit tests for `stores/offlineStore.ts`** — no `__tests__/offlineStore.test.ts` exists despite this store underpinning offline support. _(kind: mobile-app, test)_
- [ ] **Add unit tests for `stores/preferencesStore.ts`** — no test covers persisted user preferences (theme/currency/notifications). _(kind: mobile-app, test)_
- [ ] **Add unit tests for `stores/toastStore.ts`** — no test covers the toast queue/auto-dismiss logic backing `components/Toast.tsx`/`src/components/Toast.tsx`. _(kind: mobile-app, test)_
- [ ] **Audit `stores/` vs `src/stores/` vs `lib/zustand/` for further duplicated state** — beyond auth/address-book/toast, confirm no other store has a stale duplicate across these three locations. _(kind: mobile-app, bug)_
- [ ] **Document the canonical store location convention** — add a short section to the mobile app README clarifying `stores/` is canonical (or whichever is chosen) so new stores aren't added to the wrong directory. _(kind: mobile-app, documentation)_
- [ ] **Add a lint rule or CI check flagging duplicate-named files across `screens/`/`src/screens/` and `stores/`/`src/stores/`** — prevent the duplication pattern above from recurring. _(kind: mobile-app, test)_
- [ ] **Add rehydration tests for all `persist`-middleware stores** — confirm `marketplaceFiltersStore`, `favoritesStore`, `recentlyViewedStore`, `addressBookStore`, and `notificationStore` all correctly rehydrate from `AsyncStorage`/`SecureStore` on cold start. _(kind: mobile-app, test)_
- [ ] **Add cross-store reset on logout** — confirm every store above is cleared/reset when `authStore.ts` logs a user out, so a subsequent login on the same device can't leak the previous user's cached state. _(kind: mobile-app, bug)_

## Testing (E2E, Integration & Coverage)

- [ ] **Add Detox E2E test for the marketplace browse → NFT detail → purchase flow** — only `e2e/onboarding.e2e.ts` exists; no E2E coverage for the core purchase journey now that `MarketplaceScreen`/`NFTDetailScreen` are built. _(kind: mobile-app, test)_
- [ ] **Add Detox E2E test for the mint flow** — no E2E coverage for `MintNFTScreen.tsx` end-to-end. _(kind: mobile-app, test)_
- [ ] **Add Detox E2E test for the auction bid flow** — no E2E coverage for `AuctionDetailScreen.tsx` bidding, once it's wired into navigation. _(kind: mobile-app, test)_
- [ ] **Add Detox E2E test for the send-funds flow** — no E2E coverage for `SendScreen.tsx` against a testnet fixture account. _(kind: mobile-app, test)_
- [ ] **Add CI job running `e2e/onboarding.e2e.ts` and future Detox specs on PRs** — confirm `eas.json`/CI actually executes the existing E2E test today, or if it's currently dead weight. _(kind: mobile-app, test, docker)_
- [ ] **Add snapshot tests for skeleton components** — `src/components/skeletons/` has multiple shape/shimmer components with no snapshot coverage. _(kind: mobile-app, test)_
- [ ] **Add component tests for `ErrorBoundary.tsx`/`ScreenErrorBoundary`** — confirm the error-boundary wrapper used throughout `MainNavigator.tsx` actually catches and renders `ErrorFallback.tsx` correctly. _(kind: mobile-app, test)_
- [ ] **Add integration test for `DeepLinkHandler.tsx` against `src/navigation/linking.config.ts`** — confirm deep links for NFT/collection/creator routes resolve to the correct screen with correct params. _(kind: mobile-app, test)_
- [ ] **Add a coverage threshold to `jest.config.json` and enforce it in CI** — no minimum coverage gate currently exists. _(kind: mobile-app, test)_
- [ ] **Audit and consolidate the three keyboard/version-check test files** — `lib/__tests__/keyboardAwareScreen.test.ts`, `versionCheck.test.ts`, and `versionCheckService.test.ts` sit alongside near-identically-named non-test files (`lib/versionCheck.ts` vs `lib/versionCheckService.ts`); confirm there isn't a duplicated implementation here too. _(kind: mobile-app, bug)_

## Performance, Offline & Reliability

- [ ] **Add bundle size tracking to CI** — no step measures the Expo/Metro bundle size over time to catch regressions from new dependencies. _(kind: mobile-app, docker)_
- [ ] **Audit `OptimizedImage.tsx` adoption across all NFT-image-rendering components** — confirm `MarketplaceListingCard.tsx`, `NFTDetailScreen.tsx`, and `ImageGallery.tsx` all use it consistently rather than a raw `Image`. _(kind: mobile-app, bug)_
- [ ] **Add cache eviction policy to `imageCacheStore.ts`** — confirm cached images are capped and evicted (LRU) rather than growing unbounded. _(kind: mobile-app, bug)_
- [ ] **Add performance regression tests using `usePerformanceTracking.ts`** — confirm the existing performance service has automated assertions (e.g. time-to-interactive budget) rather than only manual dashboard viewing via `PerformanceDashboardScreen.tsx`. _(kind: mobile-app, test)_
- [ ] **Audit offline queue replay ordering in `stores/offlineStore.ts`** — confirm queued writes (favorites, follows) replay in the order they were made once connectivity returns. _(kind: mobile-app, bug)_
- [ ] **Add conflict resolution for offline edits that also changed server-side** — confirm a favorite toggled offline that changed server-side in the meantime doesn't silently desync. _(kind: mobile-app, bug)_
- [ ] **Add memory-leak audit for screens using `usePullToRefresh.ts`/`EnhancedRefreshControl.tsx`** — confirm refresh-in-flight state is cleaned up on unmount to avoid "update on unmounted component" warnings. _(kind: mobile-app, bug)_
- [ ] **Add startup time budget test** — confirm cold-start-to-interactive time is measured and regressions are caught, given the app now has 150+ screens/components. _(kind: mobile-app, test)_
- [ ] **Audit `NetworkQuality.ts` thresholds against real-world 3G/edge conditions** — confirm `useNetworkQuality.ts` degrades gracefully (e.g. lower-res images) rather than only reporting a binary online/offline state. _(kind: mobile-app, enhancement)_
- [ ] **Add crash-free session rate tracking** — confirm `errorReporting.service.ts`/`errorTracking.service.ts` report a measurable crash-free-sessions metric, not just individual error events. _(kind: mobile-app, telemetry)_

## Internationalization, Design System & Documentation

- [ ] **Audit locale completeness against `I18N-README.md`** — confirm every string introduced by the ~30 newer screens (Auctions, Collections, Search, AI chat once built) has translation keys in `src/i18n/resources/`. _(kind: mobile-app, documentation)_
- [ ] **Add missing-translation-key CI check** — confirm a script fails CI if a `useTranslation.ts` key referenced in code has no entry in one or more locale resource files. _(kind: mobile-app, docker)_
- [ ] **Audit RTL layout support** — confirm screens built after the original i18n work (Auctions, Collections, AI chat) render correctly under a right-to-left locale if one is supported. _(kind: mobile-app, enhancement)_
- [ ] **Document the `constants/theme.tsx` vs `src/theme/` relationship** — two theme-related locations exist (`constants/theme.tsx` colors/spacing/typography, and `src/theme/{colors.ts,ThemeContext.tsx,types.ts}`); clarify and document which is canonical for new components. _(kind: mobile-app, documentation)_
- [ ] **Reconcile `constants/theme.tsx` and `src/theme/colors.ts` color palettes** — confirm both don't define diverging values for the same semantic colors (e.g. `error`, `success`), which would cause inconsistent theming. _(kind: mobile-app, bug)_
- [ ] **Update `ARCHITECTURE-DIAGRAM.md` to reflect the current screen/store/service count** — the diagram likely predates the large recent growth (auctions, collections, search, settings, AI chat once built). _(kind: mobile-app, documentation)_
- [ ] **Update `IMPLEMENTATION_SUMMARY.md` to reflect closed issues since it was last written** — confirm it isn't stale relative to the 58 closed mobile-app issues. _(kind: mobile-app, documentation)_
- [ ] **Add a CONTRIBUTING section on the dev-only screens (`screens/Dev/*`)** — document that `ConfigDebugScreen`, `DeepLinkTestScreen`, `PerformanceDashboardScreen`, `PersistenceDebugScreen`, and `PushNotificationTestScreen` must never ship in a production build, and confirm a build-time guard actually strips them. _(kind: mobile-app, documentation, bug)_
- [ ] **Add Storybook or a lightweight component catalog for `src/components/`** — with 40+ shared components now present, there is no visual catalog for contributors to discover existing ones before building duplicates (see the `Toast.tsx` duplication above). _(kind: mobile-app, documentation, enhancement)_
- [ ] **Add a design-tokens audit comparing mobile spacing/typography against `nftopia-frontend`'s design system** — confirm the two apps share a visually consistent brand identity where it matters (color, type scale), per the "mobile mirrors frontend" project goal. _(kind: mobile-app, documentation)_
