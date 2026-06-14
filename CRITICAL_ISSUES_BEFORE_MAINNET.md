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


17. **Document contract event schema for all emitted events** — No schema definition or documentation exists for the events emitted by contracts, blocking reliable off-chain indexing.

20. **Test `recovery_system.rs` failure modes under real network conditions** — Recovery paths are unit-tested against mocks but have not been exercised against an actual Soroban RPC with ledger sequence gaps.

21. **Validate mainnet keypair handling in `signature_manager.rs`** — Signature verification logic must be confirmed against real Ed25519 keypairs on mainnet, not just testnet-generated keys.

22. **Add operator escape hatch for stuck states in `state_machine.rs`** — There is no admin-only override to unlock a transaction stuck in a terminal-error state, which would require manual intervention at the ledger level.

23. **Create integration test suite running against mainnet fork or futurenet** — All existing tests use unit mocks; no integration tests exercise the full call stack against a live-like Soroban environment.



25. **Add edge case tests for zero-amount and dust bids** — No tests cover bids with zero or near-zero amounts, which could be exploited to grief auctions or disrupt settlement logic.

26. **Enforce maximum supply cap in `nft_contract`** — There is no hard supply ceiling enforceable at the contract level for a given collection, allowing unlimited minting beyond intended supply.


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



52. **Create CI/CD pipeline configuration (GitHub Actions/GitLab CI)** — No pipeline definition exists for automated lint, test, build, and deploy on merge to main, creating a manual deployment risk.

53. **Add Kubernetes deployment manifests for backend** — No Helm chart or raw YAML manifests exist for production Kubernetes deployment with replica sets, HPA, and pod disruption budgets.

54. **Configure Kubernetes liveness and readiness probes** — The NestJS app has no `/health/live` and `/health/ready` endpoints wired to Kubernetes probe configuration.

56. **Enforce non-default `JWT_SECRET` in production startup validation** — The app will start with a weak or default JWT secret without validation; startup must assert the secret meets minimum entropy requirements.

57. **Configure Redis AUTH password for production** — The Redis connection configuration does not enforce a password, leaving the cache open to anyone on the same network segment.


61. **Add retry mechanism with exponential backoff for Soroban RPC calls** — No retry logic exists for transient RPC failures; a failed contract call raises an exception immediately with no recovery attempt.

62. **Validate and document `SOROBAN_RPC_URL` mainnet endpoint** — The env variable is read but never validated at startup; an unconfigured or wrong RPC URL will silently fail contract calls.

63. **Configure `STELLAR_HORIZON_URL` to mainnet endpoint** — The Horizon URL is pulled from environment config but no startup assertion validates it points to mainnet rather than testnet.


65. **Configure structured JSON logging for production log aggregation** — The app uses NestJS default logger which outputs plain text; a JSON log format is required for centralized log aggregation (Datadog, Loki, etc.).


75. **Implement transactional email service (SMTP or provider)** — No email service is wired up; registration confirmation, password reset, and bid notification emails are entirely absent.

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



101. **Remove `TestImageUpload/` debug route from production build** — The route at `app/[locale]/TestImageUpload/` is a developer test page with multiple debug `console.log` statements that must not be accessible in production.

104. **Remove `console.log(form)` debug statement in `create-your-collection/page.tsx`** — A debug log printing the entire form state fires on every render change and must be removed before production.

105. **Remove `console.log(csrfToken)` debug statement in `create-your-collection/page.tsx`** — The CSRF token is logged to the browser console on every page render, exposing a security-sensitive value in production.

106. **Remove `console.log("useEffect")` debug log in `app/[locale]/page.tsx`** — A debug lifecycle log fires inside a `useEffect` on the homepage, adding noise and indicating unfinished development code.


112. **Replace WalletConnect integration placeholder with real implementation** — The WalletConnect provider in `StellarWalletProvider.tsx` is a placeholder; WalletConnect-compatible wallets cannot connect to the platform.


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
