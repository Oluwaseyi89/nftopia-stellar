# Critical Issues Before Mainnet

> 150 issues blocking or required for mainnet deployment and cloud production launch of the NFTopia platform.
> Categorized across Soroban smart contracts, NestJS backend, and Next.js frontend.

---

## Contract Issues (40)

1. **Fix native XLM asset handling panic in `asset_utils.rs`** — `panic!("Native asset handling not implemented in this test version")` will crash the marketplace_settlement contract on any call involving native XLM assets on mainnet.



3. **Define and configure mainnet contract addresses** — No mainnet contract IDs are present anywhere in the codebase; all clients reference testnet addresses which will not work on mainnet.

4. **Create mainnet deployment scripts for all four contracts** — No deployment automation exists for promoting compiled Soroban WASM to the Stellar mainnet network.

5. **Implement a contract upgrade/migration path** — There is no versioning, upgrade interface, or migration strategy to allow contract logic to be safely updated post-deployment without redeployment of the whole contract.

6. **Commission and complete a formal security audit** — None of the four Soroban contracts have undergone a documented third-party security audit before handling real user funds on mainnet.

7. **Calibrate gas/fee limits for mainnet** — All fee estimates in `gas_optimizer.rs` are based on testnet conditions and must be remeasured against real mainnet ledger fee ladder and resource limits.

8. **Harden cross-contract call authorization** — Contracts that call each other (e.g., marketplace_settlement calling nft_contract) do not enforce strict caller authorization checks, risking unauthorized invocations.

### Issue 8 Detailed Breakdown

**Severity:** Critical (mainnet blocker)  
**Area:** `nftopia-stellar/contracts/marketplace_settlement`

**Problem Statement:**
Cross-contract interaction paths are not enforcing strict actor authentication and trusted-target validation before performing sensitive state changes or token/NFT transfers. This creates a risk that a caller can pass spoofed addresses in function parameters and trigger unauthorized execution paths.

**Verified risk signals in current contract code:**
1. Public entry points accept actor addresses (`seller`, `buyer`, `bidder`, `admin`) but do not consistently bind them to signer auth checks.
2. Cross-contract helper methods in `src/utils/asset_utils.rs` still include placeholder behavior (`is_valid_token_contract` always true, `check_nft_ownership` returning success placeholders, transfer helpers returning success stubs).
3. There is no strict allowlist gate for external token/NFT contract addresses before invoking them.

**Required Implementation:**
1. Add `require_auth()` checks on all actor-bearing public entry points in `settlement_core.rs`.
2. Replace placeholder cross-contract helper implementations with real Soroban interface invocations and explicit error propagation.
3. Introduce persistent allowlists for approved NFT contracts and approved payment token contracts.
4. Reject unallowlisted targets before call execution with deterministic error codes.
5. Add admin-only allowlist management methods (add/remove/list) with auth checks.
6. Add actor-consistency checks for transitions (e.g., sale execution, cancellation, disputes, fee withdrawals).
7. Emit authorization failure events for incident tracing and forensic analysis.

**Acceptance Criteria:**
1. A caller cannot execute an action on behalf of another wallet by passing a forged actor parameter.
2. Unauthorized admin operations fail with `SettlementError::Unauthorized`.
3. Calls to unknown token/NFT contracts are rejected before invocation.
4. Placeholder `Ok(())` cross-contract paths are fully removed from production logic.
5. Unit tests include spoofed actor and unallowlisted contract attempts.
6. Integration tests cover end-to-end authorized sale/auction flows.
7. All changes pass `cargo test` with no regressions in settlement flows.

**Dependencies / Impact:**
- Depends on: Issue 2 (asset validation), Issue 3 (mainnet contract address configuration)
- Blocks: Issue 9 (bid refund correctness), Issue 31 (event integrity), backend settlement trust assumptions

9. **Implement bid refund logic in `auction_engine.rs` on cancellation** — When an auction is cancelled or expires without a winner, the losing bidder funds are not provably returned through the contract logic.

10. **Replace placeholder arbitration in `dispute_resolution.rs`** — The dispute module has no integration with an arbitration oracle or trusted third party; resolution logic is a stub that needs a real decision mechanism.

11. **Make fee parameters configurable in `fee_manager.rs` for mainnet** — Platform fee percentages appear hardcoded and must be made admin-configurable to allow operational flexibility without redeployment.

12. **Verify royalty calculation precision in `royalty_distributor.rs`** — Fixed-point arithmetic used for royalty splits must be audited for off-by-one and rounding errors that could cause creator underpayment.

13. **Add emergency halt / circuit breaker to `settlement_core.rs`** — There is no contract-level pause mechanism, meaning a discovered exploit cannot be stopped until a full redeployment.

14. **Validate atomic swap timeout logic against mainnet ledger timing** — `atomic_swap.rs` uses time-based expiry that may behave differently under mainnet ledger close intervals vs. testnet.

15. **Enforce maximum collection count per creator in `collection_factory.rs`** — No cap exists to prevent spam deployments that could bloat ledger state and degrade performance.

16. **Validate NFT token burn authorization in `nft_contract`** — The burn entry point must verify the caller is the token owner (or an approved operator) before allowing destruction.

17. **Document contract event schema for all emitted events** — No schema definition or documentation exists for the events emitted by contracts, blocking reliable off-chain indexing.

18. **Validate `dependency_resolver.rs` logic against mainnet TTLs** — Transaction dependency resolution uses timing assumptions that must be verified against production ledger sequence constraints.

19. **Recalibrate `gas_optimizer.rs` estimates for mainnet resource pricing** — Current estimates are placeholders tuned to testnet; mainnet resource fees for CPU instructions and read/write bytes differ materially.

20. **Test `recovery_system.rs` failure modes under real network conditions** — Recovery paths are unit-tested against mocks but have not been exercised against an actual Soroban RPC with ledger sequence gaps.

21. **Validate mainnet keypair handling in `signature_manager.rs`** — Signature verification logic must be confirmed against real Ed25519 keypairs on mainnet, not just testnet-generated keys.

22. **Add operator escape hatch for stuck states in `state_machine.rs`** — There is no admin-only override to unlock a transaction stuck in a terminal-error state, which would require manual intervention at the ledger level.

23. **Create integration test suite running against mainnet fork or futurenet** — All existing tests use unit mocks; no integration tests exercise the full call stack against a live-like Soroban environment.

24. **Restrict NFT metadata update to owner only in `nft_contract`** — Metadata update logic must validate the caller is the current token owner, preventing unauthorized attribute changes.

25. **Add edge case tests for zero-amount and dust bids** — No tests cover bids with zero or near-zero amounts, which could be exploited to grief auctions or disrupt settlement logic.

26. **Enforce maximum supply cap in `nft_contract`** — There is no hard supply ceiling enforceable at the contract level for a given collection, allowing unlimited minting beyond intended supply.

27. **Add re-entrancy guard to `settlement_core.rs`** — Soroban's execution model reduces re-entrancy risk but an explicit guard should be added given the contract handles value transfers.

28. **Implement contract-level rate limiting on high-frequency entry points** — Entry points such as bid placement have no on-chain throttle, allowing a single account to flood the contract with calls.

29. **Adopt Soroban contract versioning in WASM metadata** — Contracts do not embed a version identifier in their WASM, making it impossible to distinguish deployed versions during incident response.

30. **Configure persistent storage TTL for all storage entries** — Soroban storage entries without TTL will expire and be evicted; persistent entries for all contracts need explicit TTL extension logic.

31. **Ensure all significant state transitions emit contract events** — Several state changes in the transaction_contract (e.g., operation failure rollback) do not emit events, creating indexing blind spots.

32. **Add emergency pause function to `marketplace_settlement` contract** — Unlike ERC standards, no pause/unpause mechanism is present to stop trading activity during a security incident.

33. **Enforce minimum bid increment at contract level in `auction_engine.rs`** — Minimum increment (e.g., 1% above current bid) is not enforced in contract logic, allowing micro-increment bid spam.

34. **Add blocked/blacklisted address support in marketplace contract** — There is no mechanism to block known scammers or sanctioned addresses from interacting with the contract.

35. **Validate factory address ownership for child collections** — The `collection_factory` does not validate that deployed collection contracts report back to the factory's canonical registry.

36. **Make dispute resolution window period configurable** — The time window during which a buyer can raise a dispute is hardcoded and cannot be updated without redeployment.

37. **Constrain approved-operator access in `nft_contract`** — Operator approval grants broad permissions; approval scope (e.g., per-token vs. global) must be clearly enforced and auditable.

38. **Enforce maximum royalty cap in `royalty_distributor.rs`** — No ceiling exists on the royalty percentage a creator can set, which could be set to 100% and make secondary sales economically unwviable.

39. **Implement batch minting support in `nft_contract`** — Single-mint-only design will be a gas cliff for collections; a batch mint entry point is needed for reasonable mainnet economics.

40. **Publish error code reference documentation for all contracts** — Error variants in each contract's `error.rs` are not documented externally, blocking meaningful error handling in client applications.

---

## Backend Issues (55)

41. **Implement event fetching in `contract-event-indexer.job.ts`** — The scheduled job that should fetch Soroban contract events since the last indexed ledger contains only a TODO comment and a dummy `await`, meaning zero events are indexed.

42. **Implement event persistence in `contract-event-indexer.job.ts`** — The second of three TODO stubs: events fetched from the contract are never saved to the database, breaking all event-driven features.

43. **Implement `lastIndexedLedger` update in `contract-event-indexer.job.ts`** — Without updating the cursor after each run, the indexer will re-process all events from ledger 0 on every cron tick once the fetch stub is filled.

44. **Map bundle order to real contract call in `order.service.ts`** — Purchase-type orders return `{ success: true, contractId: -1 }` as a hardcoded placeholder instead of invoking the actual contract.

45. **Replace placeholder analytics in `order.service.ts`** — The `getSalesAnalytics()` method has a comment "TODO: Implement real analytics logic" and returns empty/stub data used by the admin dashboard.

46. **Fix `hasNextPage` always returning false in `order.resolver.ts`** — GraphQL pagination for orders never signals that more pages exist, causing clients to stop fetching after the first page regardless of dataset size.

47. **Implement real admin authorization check in `order.resolver.ts`** — Admin-restricted resolvers contain a TODO comment deferring the real user-role lookup, leaving admin routes effectively unprotected.

48. **Replace generic `Error` throws with domain exceptions in `marketplace-settlement.client.ts`** — All error branches throw `new Error(string)` instead of typed NestJS `HttpException` subclasses, losing HTTP status codes in responses.

49. **Implement `paymentMethod` field in `buy-nft.dto.ts`** — The field is annotated as "placeholder for future payment details" and is never validated or used in order processing.

50. **Add production Dockerfile for the NestJS backend** — No Dockerfile exists in the repository, blocking containerized deployment to any cloud provider.

51. **Add production `docker-compose` configuration** — The existing `docker-compose.yml` is development-only; a production variant with secrets management, health checks, and resource limits is absent.

52. **Create CI/CD pipeline configuration (GitHub Actions/GitLab CI)** — No pipeline definition exists for automated lint, test, build, and deploy on merge to main, creating a manual deployment risk.

53. **Add Kubernetes deployment manifests for backend** — No Helm chart or raw YAML manifests exist for production Kubernetes deployment with replica sets, HPA, and pod disruption budgets.

54. **Configure Kubernetes liveness and readiness probes** — The NestJS app has no `/health/live` and `/health/ready` endpoints wired to Kubernetes probe configuration.

55. **Add global rate limiting on REST and GraphQL endpoints** — No `@nestjs/throttler` or equivalent is applied at the application level, leaving all endpoints vulnerable to abuse and DoS.

56. **Enforce non-default `JWT_SECRET` in production startup validation** — The app will start with a weak or default JWT secret without validation; startup must assert the secret meets minimum entropy requirements.

57. **Configure Redis AUTH password for production** — The Redis connection configuration does not enforce a password, leaving the cache open to anyone on the same network segment.

58. **Set database connection pool size for production load** — TypeORM is initialized without explicit `extra.max` pool size, defaulting to 10 connections and risking pool exhaustion under moderate traffic.

59. **Replace generic `Error` throws in `ipfs.service.ts` with `HttpException`** — All IPFS upload failures throw `new Error(string)`, bypassing NestJS exception handling and returning 500 errors with raw messages to clients.

60. **Replace generic `Error` throws in `arweave.service.ts` with `HttpException`** — Same issue as IPFS service; plain `Error` throws expose internal error messages in API responses.

61. **Add retry mechanism with exponential backoff for Soroban RPC calls** — No retry logic exists for transient RPC failures; a failed contract call raises an exception immediately with no recovery attempt.

62. **Validate and document `SOROBAN_RPC_URL` mainnet endpoint** — The env variable is read but never validated at startup; an unconfigured or wrong RPC URL will silently fail contract calls.

63. **Configure `STELLAR_HORIZON_URL` to mainnet endpoint** — The Horizon URL is pulled from environment config but no startup assertion validates it points to mainnet rather than testnet.

64. **Integrate Prometheus metrics or OpenTelemetry for observability** — No metrics collection exists; without request rates, error rates, and latency histograms, SLO monitoring is impossible in production.

65. **Configure structured JSON logging for production log aggregation** — The app uses NestJS default logger which outputs plain text; a JSON log format is required for centralized log aggregation (Datadog, Loki, etc.).

66. **Add migration locking to prevent concurrent schema changes** — Database migrations can run concurrently on multi-instance startup without a distributed lock, risking schema corruption.

67. **Define production CORS allowlist restricting to known domains** — The `cors.json` configuration in the frontend references origins, but the NestJS backend CORS policy must be locked to production domains only.

68. **Implement API versioning strategy (URL prefix or header)** — No versioning mechanism exists, making breaking changes to existing clients inevitable during iteration; `/api/v1/` prefix should be established.

69. **Add WebSocket message size limits to the notifications gateway** — Unbounded WebSocket message sizes allow resource exhaustion attacks against the notification gateway.

70. **Enforce file upload size limits at the gateway level** — The storage/upload endpoints do not enforce a maximum file size in the NestJS interceptor, risking OOM from large file uploads.

71. **Implement audit logging for sensitive admin operations** — Admin actions (user bans, manual order cancellation, fee changes) are not audit-logged, creating a compliance gap.

72. **Implement queue-based retry for blockchain transaction submissions** — Failed on-chain submissions are not retried via a durable queue; transient network issues cause permanent failures from the user's perspective.

73. **Add dead-letter queue for failed contract event processing** — Events that fail to process are silently dropped with an error log and never retried or flagged for manual review.

74. **Add heartbeat and reconnect logic to the notifications gateway** — The WebSocket gateway does not handle stale connections; clients that lose connectivity are never cleaned up from server-side subscriptions.

75. **Implement transactional email service (SMTP or provider)** — No email service is wired up; registration confirmation, password reset, and bid notification emails are entirely absent.

76. **Implement password reset flow** — There is no endpoint or token-based mechanism for users to reset forgotten passwords, blocking account recovery.

77. **Add two-factor authentication (2FA) support** — Platform manages financial assets but has no 2FA option, making accounts vulnerable to credential compromise.

78. **Implement GDPR data export and account deletion** — No personal data export or right-to-erasure endpoint exists, creating legal liability in GDPR-applicable markets.

79. **Add virus/malware scanning for uploaded NFT media files** — Uploaded files are stored to IPFS/Arweave without content scanning, allowing malicious file uploads that could affect downstream users.

80. **Build image resizing and CDN delivery pipeline for NFT media** — NFT images are served at full resolution with no resizing or CDN caching layer, causing slow load times and high bandwidth costs.

81. **Disable GraphQL introspection in production** — Schema introspection is enabled by default in NestJS Apollo and must be disabled in production to prevent schema harvesting by attackers.

82. **Add throttle guard specifically on authentication endpoints** — Login and Stellar signature verification endpoints have no brute-force protection, allowing credential stuffing attacks.

83. **Handle ledger sequence gap errors in `soroban.service.ts`** — The service does not detect or recover from sequence number mismatches caused by ledger gaps, causing stuck transactions.

84. **Document and automate PostgreSQL backup/restore procedure** — No backup schedule, snapshot policy, or tested restore procedure is defined; a database failure would result in permanent data loss.

85. **Implement secret rotation mechanism for third-party API keys** — Pinata JWT, Arweave key, and other secrets have no rotation process or expiry handling, creating a long-lived credential risk.

86. **Enforce SSL/TLS for PostgreSQL database connections in production** — TypeORM is configured without `ssl: true` or `sslmode=require`, allowing plaintext database traffic in cloud environments.

87. **Implement caching strategy for trending and popular NFT endpoint** — Popular/trending NFT queries hit the database on every request with no caching; this will be a performance bottleneck at scale.

88. **Sign and make pagination cursors opaque in GraphQL resolvers** — Cursors are plain base64-encoded JSON that expose internal field names and can be hand-crafted by clients to cause unintended queries.

89. **Add global NestJS exception filter to catch all unhandled errors** — Unhandled exceptions propagate as 500 responses with raw stack traces; a global filter must sanitize and log these uniformly.

90. **Add graceful shutdown handler for in-flight requests** — The app does not register `SIGTERM` / `SIGINT` handlers to drain active requests before exit, causing request drops during rolling deploys.

91. **Add request correlation IDs for distributed tracing** — No `X-Request-ID` or trace propagation header is injected into the request lifecycle, making cross-service debugging in production impossible.

92. **Validate mainnet contract IDs for `CollectionFactory` client** — The CollectionFactory Soroban client uses a configurable contract ID that is not startup-validated, risking silent calls to the wrong contract.

93. **Validate mainnet contract IDs for `TransactionContract` client** — Same issue as the CollectionFactory client; no startup assertion confirms the contract ID points to a deployed mainnet contract.

94. **Remove `synchronize: true` TypeORM flag before production** — If enabled, TypeORM `synchronize` auto-migrates the schema on startup, which will drop columns and destroy data on schema changes in production.

95. **Implement listing service GraphQL response with real DB backing** — A comment in `listing.service.ts` reads "mock or DB-backed," indicating the GraphQL listing resolver may return incomplete data in some code paths.

---

## Frontend Issues (55)

96. **Replace `mockStats` with real API data on the logged-in dashboard** — `app/[locale]/auth/logged-in/page.tsx` imports and renders hardcoded `mockStats` for NFTs created, total sales, views, and followers instead of fetching live data.

97. **Build NFT detail page under `marketplace/[nftId]/`** — The entire marketplace directory contains only a root `page.tsx`; there is no route for viewing individual NFT details, metadata, or ownership history.

98. **Build bid submission UI for auction NFTs** — No bid form or bid flow exists in the frontend; users have no way to place a bid on an auctioned NFT from the marketplace.

99. **Build direct purchase / checkout flow for fixed-price NFTs** — No purchase confirmation, price breakdown, or payment flow is implemented; users cannot buy NFTs through the platform.

100. **Add filter, sort, and search UI to the marketplace listing page** — The marketplace root page has no filter controls (price range, category, status), no sort order selector, and no search input.

101. **Remove `TestImageUpload/` debug route from production build** — The route at `app/[locale]/TestImageUpload/` is a developer test page with multiple debug `console.log` statements that must not be accessible in production.

102. **Replace hardcoded mock data in `PopularCollection.tsx` with API fetch** — The component statically declares three mock collections with placeholder image paths that do not exist, breaking the homepage hero section.

103. **Implement API persistence for collection "like" in `CollectionCard.tsx`** — Liking a collection only toggles local state and logs to console; the action is never sent to the backend and is lost on page reload.

104. **Remove `console.log(form)` debug statement in `create-your-collection/page.tsx`** — A debug log printing the entire form state fires on every render change and must be removed before production.

105. **Remove `console.log(csrfToken)` debug statement in `create-your-collection/page.tsx`** — The CSRF token is logged to the browser console on every page render, exposing a security-sensitive value in production.

106. **Remove `console.log("useEffect")` debug log in `app/[locale]/page.tsx`** — A debug lifecycle log fires inside a `useEffect` on the homepage, adding noise and indicating unfinished development code.

107. **Fully implement email/password login flow** — The email login path on the login page is incomplete; form submission does not fully wire to the backend authentication endpoint with proper error handling.

108. **Build dedicated auction listing and bidding page** — Despite a `live-auctions.tsx` component existing, there is no route (`/marketplace/auctions`) where users can browse and bid on live-auction NFTs.

109. **Add auction countdown timer component wired to real end times** — No countdown clock component is connected to auction end timestamps from the backend, leaving users without urgency cues.

110. **Build NFT ownership history / provenance section on detail page** — Once the detail page exists, a transfer history section sourced from indexed contract events is required for buyer trust.

111. **Build public creator profile page** — No route exists for viewing a creator's public profile, their listed NFTs, or collection — a fundamental discovery feature.

112. **Replace WalletConnect integration placeholder with real implementation** — The WalletConnect provider in `StellarWalletProvider.tsx` is a placeholder; WalletConnect-compatible wallets cannot connect to the platform.

113. **Implement transaction confirmation feedback UI** — After a user signs and submits a contract transaction, there is no in-app status indicator showing pending / confirmed / failed state.

114. **Add error boundary on marketplace pages to prevent full-page crashes** — No `<ErrorBoundary>` wrapper exists for marketplace routes; an unhandled render error will show a blank page to users.

115. **Add error boundary on creator dashboard pages** — Same absence of error boundaries on all creator dashboard routes, creating a poor experience if any dashboard widget throws.

116. **Add loading skeleton for NFT detail and marketplace pages** — There are no skeleton screens for the NFT detail page (once built), causing jarring layout shifts during data fetching.

117. **Replace placeholder image paths in `PopularCollection.tsx` with real assets** — Paths like `/images/placeholder-main.jpg` do not exist in `public/`, causing 404s and broken image icons on the homepage.

118. **Replace placeholder avatar paths in `CollectionCard.tsx` with fallback** — The card uses `/images/placeholder-avatar.png` which does not exist; a graceful SVG fallback or generated avatar must be used.

119. **Add dynamic SEO meta tags for NFT detail pages** — No `<Head>` metadata or Next.js `generateMetadata` is implemented for NFT detail routes, preventing search engine indexing.

120. **Add dynamic SEO meta tags for collection pages** — Collection pages have no title or description meta tags, making them invisible to search crawlers and unfavorable for social sharing.

121. **Add Open Graph and Twitter Card tags for social sharing** — Neither NFT nor collection pages emit OG tags, so sharing links on social media shows no rich preview.

122. **Generate and serve `sitemap.xml` for marketplace pages** — No sitemap generation is configured; search engines cannot discover NFT and collection URLs systematically.

123. **Create and configure `robots.txt`** — No `robots.txt` file exists in `public/`, leaving crawler behavior undefined and potentially allowing indexing of debug or admin routes.

124. **Remove production `console.log` calls from `web-vitals.tsx`** — Web Vitals metrics are logged to the browser console instead of sent to an analytics endpoint, exposing performance data and cluttering the console.

125. **Remove production `console.log` calls from `InstallPrompt.tsx`** — Accept/dismiss events for the PWA install prompt are logged to the console rather than tracked analytically.

126. **Configure Content Security Policy (CSP) headers** — No CSP headers are set in `next.config.js`, leaving the app vulnerable to XSS attacks from injected scripts or malicious iframes.

127. **Enforce HTTPS redirect in Next.js configuration** — The app does not enforce HTTPS at the application layer; production deployment must redirect all HTTP traffic to HTTPS.

128. **Complete `AuthContext.tsx` implementation** — The auth context file contains the comment "just a placeholder for context API," indicating the authentication state management is not fully implemented.

129. **Implement wallet session persistence across page refreshes** — Connecting a Stellar wallet does not survive a page reload; the session needs to be persisted to `localStorage` with proper re-hydration on mount.

130. **Build mobile-optimized marketplace browsing layout** — The marketplace page is not adapted for small viewports; product cards overflow and interactive elements are too small to tap reliably on mobile.

131. **Build blockchain transaction status notification system** — No toast or sidebar notification exists to inform users when a submitted transaction is confirmed on-chain or fails, leaving users in the dark.

132. **Add ARIA labels and roles to NFT card interactive elements** — Like buttons, bid buttons, and card links in collection/NFT cards lack `aria-label` attributes, failing screen reader accessibility.

133. **Add i18n coverage for all error and validation messages** — Error messages from form validation and API failures are hardcoded in English and not routed through the i18n system.

134. **Add empty state UI for marketplace when no NFTs are listed** — The marketplace page has no "no results" state; a blank page is shown when the query returns nothing.

135. **Implement pagination or infinite scroll for marketplace NFT listing** — The marketplace shows a static number of NFTs with no paging controls or scroll-triggered fetch for additional results.

136. **Add 404 not-found page for invalid NFT and collection routes** — Dynamic routes for NFT detail and collection detail have no `notFound()` handling, causing unhandled Next.js errors on bad URLs.

137. **Wire real data to creator dashboard sales page** — The sales analytics page under creator dashboard renders with no real data from the backend sales analytics endpoint.

138. **Implement save/persist on creator dashboard settings page** — The settings page has no form submission wired to the backend; profile changes are never saved.

139. **Add metadata validation before NFT minting submission** — The mint-nft page does not validate required metadata fields (name, description, file) on the client before calling the contract, allowing partial mints.

140. **Show on-chain listing confirmation on `list-nfts-for-sale` page** — After submitting a listing, the page does not confirm or display the resulting on-chain listing ID or transaction hash to the user.

141. **Add image lazy-loading and blur placeholder for NFT media** — NFT images load eagerly without a blur-up placeholder, causing slow perceived performance and cumulative layout shift on listing pages.

142. **Implement optimistic UI updates after bid and purchase actions** — After placing a bid or buying an NFT, the UI does not immediately reflect the action; it waits for a full page reload or refetch.

143. **Fix wallet disconnect to properly clear auth session and JWT** — Disconnecting a wallet does not invalidate the JWT or clear the auth session cookie, leaving the user authenticated without a connected wallet.

144. **Implement multi-wallet session management (Freighter + WalletConnect)** — There is no session arbitration when multiple wallet adapters are active; simultaneous connections from two wallets create undefined state.

145. **Build offline detection and fallback UI for degraded connectivity** — The app has no offline detection hook wired to a user-visible banner; users on poor connections see spinner loops with no indication of network loss.

146. **Integrate analytics event tracking (conversion and engagement)** — No analytics provider (Google Analytics, Amplitude, Mixpanel) is configured; user behavior data needed for product decisions is not collected.

147. **Add GDPR cookie consent banner** — The platform uses cookies and potentially analytics trackers without an opt-in consent mechanism, violating GDPR for EU users.

148. **Add Terms of Service and Privacy Policy pages** — No ToS or Privacy Policy route exists in the frontend; the footer link targets are absent, creating legal exposure.

149. **Create staging environment configuration for frontend** — No `.env.staging` or separate Next.js build profile exists for pre-production testing against a staging backend.

150. **Configure production-grade environment variables for Next.js frontend** — `NEXT_PUBLIC_*` variables for mainnet RPC, contract IDs, API URL, and analytics keys are not documented or validated in a production environment setup guide.
