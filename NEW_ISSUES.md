# NEW_ISSUES

This backlog is generated from the current workspace state only.

Current reality captured from codebase:
- Web app is still strongly Starknet-coupled.
- Mobile app is mostly scaffold/sample and not production ready.
- Backend has usable Nest.js + Postgres + Redis foundations, but no GraphQL gateway and no MongoDB integration yet.
- Soroban contracts exist but are uneven (for example, `nft_contract` is effectively empty).
- Admin app does not exist yet and is included below as a full Next.js issue stream.

Issue format:
- Each issue is intended to be independently assignable.
- Prefix indicates app/service ownership.
- IDs are globally unique for tracking.

## A. Repo, Architecture, and Program Management (12 issues)

- [ ] ISSUE-001 [Repo] Create monorepo blueprint (`apps`, `backend`, `contracts`, `infrastructure`, `docs`) with migration map and ownership boundaries.
- [ ] ISSUE-002 [Repo] Add Architecture Decision Record (ADR) template and record decisions for Stellar-first stack.
- [ ] ISSUE-003 [Repo] Define domain boundaries for auth, NFT, marketplace, auctions, royalties, analytics, notifications.
- [ ] ISSUE-004 [Repo] Create dependency policy for shared types and anti-circular import rules.
- [ ] ISSUE-005 [Repo] Add CODEOWNERS by app/service and enforce required reviewers.
- [ ] ISSUE-006 [Repo] Define branch strategy and release train (`main`, `release/*`, hotfix procedure).
- [ ] ISSUE-007 [Repo] Add contribution guide with issue triage flow and definition of done.
- [ ] ISSUE-008 [Repo] Create platform-wide error code catalog and naming convention.
- [ ] ISSUE-009 [Repo] Standardize API versioning policy (REST and future GraphQL coexistence).
- [ ] ISSUE-010 [Repo] Build end-to-end architecture diagram in docs from actual modules in this workspace.
- [ ] ISSUE-011 [Repo] Add risk register for migration from Starknet to Stellar with mitigations.
- [ ] ISSUE-012 [Repo] Build milestone board for MVP, Beta, Mainnet-ready phases.

## B. CI/CD, Infrastructure, and SRE (20 issues)

- [ ] ISSUE-013 [CI] Split CI workflows into lint, test, build, security scan jobs with required checks.
- [ ] ISSUE-014 [CI] Add path-based workflow triggers so each app runs only relevant pipelines.
- [ ] ISSUE-015 [CI] Add dependency caching for pnpm/npm and cargo to reduce pipeline times.
- [ ] ISSUE-016 [CI] Add contract build pipeline for all Soroban crates and artifact publishing.
- [ ] ISSUE-017 [CI] Add database migration check job that runs PostgreSQL migrations in CI.
- [ ] ISSUE-018 [CI] Add smoke e2e job for backend health + one NFT read endpoint.
- [ ] ISSUE-019 [CI] Add semantic-release or changesets automation for versioning.
- [ ] ISSUE-020 [Security] Enable secret scanning and fail CI for leaked keys.
- [ ] ISSUE-021 [Security] Add SAST scanning for TS and Rust code.
- [ ] ISSUE-022 [Infra] Expand docker-compose for local parity: api, web, postgres, redis, mongo, worker.
- [ ] ISSUE-023 [Infra] Add production-ready Dockerfiles for backend, web, admin, and workers.
- [ ] ISSUE-024 [Infra] Add reverse proxy config with gzip, caching headers, and websocket support.
- [ ] ISSUE-025 [Infra] Create Terraform modules for VPC, DB, cache, object storage, and secrets.
- [ ] ISSUE-026 [Infra] Provision managed MongoDB and wire network/security groups.
- [ ] ISSUE-027 [Infra] Define backup/restore runbooks for Postgres, MongoDB, and Redis.
- [ ] ISSUE-028 [Observability] Add OpenTelemetry tracing for backend HTTP and blockchain calls.
- [ ] ISSUE-029 [Observability] Add centralized structured logging sink and retention policy.
- [ ] ISSUE-030 [Observability] Build Grafana dashboards for API latency, errors, queue lag, and indexer lag.
- [ ] ISSUE-031 [SRE] Define SLO/SLI for API availability and transaction finality tracking.
- [ ] ISSUE-032 [SRE] Write incident response playbook for failed settlements and chain RPC outages.

## C. Soroban Contracts (30 issues)

- [ ] ISSUE-033 [Contracts/nft_contract] Implement core NFT storage schema: owner, token URI, creator, royalty basis points.
- [ ] ISSUE-034 [Contracts/nft_contract] Implement `mint` with authorization checks and event emission.
- [ ] ISSUE-035 [Contracts/nft_contract] Implement `transfer` with ownership verification and event emission.
- [ ] ISSUE-036 [Contracts/nft_contract] Implement `approve` and operator approvals.
- [ ] ISSUE-037 [Contracts/nft_contract] Implement `burn` with role restrictions.
- [ ] ISSUE-038 [Contracts/nft_contract] Implement metadata update policy (mutable/frozen modes).
- [ ] ISSUE-039 [Contracts/nft_contract] Add collection-level config hooks (name, symbol, base URI).
- [ ] ISSUE-040 [Contracts/nft_contract] Add pagination/query methods for owner tokens and total supply.
- [ ] ISSUE-041 [Contracts/nft_contract] Add contract-level pause/unpause admin controls.
- [ ] ISSUE-042 [Contracts/nft_contract] Add comprehensive unit tests covering happy and revert paths.
- [ ] ISSUE-043 [Contracts/collection_factory] Add deterministic deployment option for new collection contracts.
- [ ] ISSUE-044 [Contracts/collection_factory] Enforce creator limits, fee model, and anti-spam throttling.
- [ ] ISSUE-045 [Contracts/collection_factory] Emit richer events for indexing (creator, collection ID, tx metadata).
- [ ] ISSUE-046 [Contracts/collection_factory] Add tests for unauthorized mint and invalid collection config.
- [ ] ISSUE-047 [Contracts/marketplace_settlement] Implement fixed-price listing create/cancel/purchase lifecycle.
- [ ] ISSUE-048 [Contracts/marketplace_settlement] Implement offer create/accept/cancel lifecycle.
- [ ] ISSUE-049 [Contracts/marketplace_settlement] Implement auction start/bid/cancel/finalize lifecycle.
- [ ] ISSUE-050 [Contracts/marketplace_settlement] Add reserve price and buy-now support for auctions.
- [ ] ISSUE-051 [Contracts/marketplace_settlement] Implement escrow vault accounting and balance invariants.
- [ ] ISSUE-052 [Contracts/marketplace_settlement] Enforce royalties and platform fee distribution policy.
- [ ] ISSUE-053 [Contracts/marketplace_settlement] Add anti-front-running commit/reveal test vectors.
- [ ] ISSUE-054 [Contracts/marketplace_settlement] Add dispute module governance and arbitration guardrails.
- [ ] ISSUE-055 [Contracts/marketplace_settlement] Add reentrancy and replay protection hardening tests.
- [ ] ISSUE-056 [Contracts/transaction_contract] Clarify role and integrate or deprecate duplicate transaction flows.
- [ ] ISSUE-057 [Contracts] Add per-contract interface/spec docs for backend and frontend clients.
- [ ] ISSUE-058 [Contracts] Generate contract clients/ABI bindings for TypeScript consumption.
- [ ] ISSUE-059 [Contracts] Build contract deployment manifest (`dev`, `testnet`, `mainnet`) with version pinning.
- [ ] ISSUE-060 [Contracts] Create upgrade strategy and migration scripts for schema changes.
- [ ] ISSUE-061 [Contracts] Add fuzz/property tests for settlement math and fee distribution.
- [ ] ISSUE-062 [Contracts] Run third-party security audit prep checklist and remediate high risks.

## D. Backend API Gateway and Core Services (36 issues)

- [ ] ISSUE-063 [Backend/API] Introduce API gateway module boundary (auth, rate limit, cache, request IDs).
- [ ] ISSUE-064 [Backend/API] Add `@nestjs/throttler` rate limiting by IP, user, and wallet.
- [ ] ISSUE-065 [Backend/API] Add idempotency key middleware for write endpoints.
- [ ] ISSUE-066 [Backend/API] Implement standardized response envelope and error mapping.
- [ ] ISSUE-067 [Backend/API] Add API key support for internal services and workers.
- [ ] ISSUE-068 [Backend/API] Implement GraphQL gateway sidecar while preserving existing REST endpoints.
- [ ] ISSUE-069 [Backend/API] Add GraphQL schema for user, NFT, collection, listing, auction, bid, order.
- [ ] ISSUE-070 [Backend/API] Add GraphQL resolvers with DataLoader to prevent N+1 queries.
- [ ] ISSUE-071 [Backend/Auth] Replace in-memory nonce store with Redis-backed expiring challenge storage.
- [ ] ISSUE-072 [Backend/Auth] Make network passphrase configurable for testnet/mainnet.
- [ ] ISSUE-073 [Backend/Auth] Implement refresh tokens, session revoke, and device/session listing.
- [ ] ISSUE-074 [Backend/Auth] Add signature replay prevention via nonce reuse audit logs.
- [ ] ISSUE-075 [Backend/Auth] Add role-based access control (user, creator, moderator, admin).
- [ ] ISSUE-076 [Backend/Users] Expand user profile model (display, social links, verification status).
- [ ] ISSUE-077 [Backend/Users] Add user follow/block/report APIs.
- [ ] ISSUE-078 [Backend/NFT] Replace dummy contract list in sync cron with config-driven contract registry.
- [ ] ISSUE-079 [Backend/NFT] Implement resilient Soroban event indexing with checkpoints in DB.
- [ ] ISSUE-080 [Backend/NFT] Add ownership reconciliation worker between chain state and DB state.
- [ ] ISSUE-081 [Backend/NFT] Add metadata validation pipeline against JSON schema.
- [ ] ISSUE-082 [Backend/NFT] Add NFT state machine (`draft`, `minting`, `minted`, `listed`, `sold`).
- [ ] ISSUE-083 [Backend/Collections] Create collection service/module with CRUD, verification workflow.
- [ ] ISSUE-084 [Backend/Marketplace] Create listings service/module with fixed-price marketplace APIs.
- [ ] ISSUE-085 [Backend/Auctions] Create auctions service/module with bid placement and settlement APIs.
- [ ] ISSUE-086 [Backend/Orders] Create orders service/module for completed trade records.
- [ ] ISSUE-087 [Backend/Royalties] Create royalties service/module for payout tracking and reconciliation.
- [ ] ISSUE-088 [Backend/Notifications] Add websocket gateway for bids, outbid, sale, auction events.
- [ ] ISSUE-089 [Backend/Notifications] Add email templates and queue-driven notification delivery.
- [ ] ISSUE-090 [Backend/Analytics] Add analytics service for KPIs and trend aggregation.
- [ ] ISSUE-091 [Backend/Storage] Add S3/R2 adapter alongside IPFS/Arweave with policy-based storage routing.
- [ ] ISSUE-092 [Backend/Storage] Replace in-memory retry queue with Redis/BullMQ durable queue.
- [ ] ISSUE-093 [Backend/Storage] Add malware scanning and content-type verification at upload edge.
- [ ] ISSUE-094 [Backend/Storage] Add thumbnail generation and media derivatives pipeline.
- [ ] ISSUE-095 [Backend] Add contract-aware background workers for indexing and settlement retries.
- [ ] ISSUE-096 [Backend] Harden DTO validation, max payload controls, and file upload limits.
- [ ] ISSUE-097 [Backend] Add per-endpoint cache strategy with key invalidation on writes.
- [ ] ISSUE-098 [Backend] Expand OpenAPI docs and contract examples for all critical flows.

## E. Data Layer: PostgreSQL, MongoDB, Redis (16 issues)

- [ ] ISSUE-099 [PostgreSQL] Create baseline migration for users, collections, nfts, listings, auctions, bids, orders, royalties.
- [ ] ISSUE-100 [PostgreSQL] Add DB constraints for wallet format, uniqueness, and business invariants.
- [ ] ISSUE-101 [PostgreSQL] Add partial indexes for active listings and active auctions.
- [ ] ISSUE-102 [PostgreSQL] Add trigger-based `updated_at` and soft-delete conventions.
- [ ] ISSUE-103 [PostgreSQL] Implement query performance benchmark and slow-query alert thresholds.
- [ ] ISSUE-104 [MongoDB] Introduce Mongo connection and schema models in backend.
- [ ] ISSUE-105 [MongoDB] Implement NFT metadata collection storage and retrieval layer.
- [ ] ISSUE-106 [MongoDB] Implement activity log ingestion pipeline from blockchain events.
- [ ] ISSUE-107 [MongoDB] Implement analytics aggregation collections and daily rollups.
- [ ] ISSUE-108 [MongoDB] Implement notification collection for persistent in-app notifications.
- [ ] ISSUE-109 [MongoDB] Add TTL indexes for temporary cache/documents and cleanup jobs.
- [ ] ISSUE-110 [Redis] Create key strategy conventions for sessions, rate limits, cache, and locks.
- [ ] ISSUE-111 [Redis] Implement distributed lock helper for settlement and sync critical sections.
- [ ] ISSUE-112 [Redis] Add session store with secure cookie/token integration.
- [ ] ISSUE-113 [Redis] Add cache warm-up jobs for homepage and marketplace queries.
- [ ] ISSUE-114 [Data] Add data retention and GDPR delete/anonymization workflows.

## F. Frontend Web (Next.js) Migration to Stellar (24 issues)

- [ ] ISSUE-115 [Web/Wallet] Replace `StarknetProvider` with Stellar wallet provider abstraction.
- [ ] ISSUE-116 [Web/Wallet] Implement Freighter connection flow and account state hydration.
- [ ] ISSUE-117 [Web/Wallet] Add wallet fallback options and unsupported-wallet UX.
- [ ] ISSUE-118 [Web/Auth] Replace Starknet login/register wallet calls with Stellar challenge-sign flow.
- [ ] ISSUE-119 [Web/Auth] Add auth persistence, refresh, and multi-tab logout handling.
- [ ] ISSUE-120 [Web/API] Build typed API client for backend REST/GraphQL with error normalization.
- [ ] ISSUE-121 [Web/Marketplace] Connect marketplace page to real listings API data.
- [ ] ISSUE-122 [Web/Marketplace] Implement NFT detail page with transaction/activity timeline.
- [ ] ISSUE-123 [Web/Marketplace] Implement fixed-price buy flow with transaction modal and confirmations.
- [ ] ISSUE-124 [Web/Auctions] Implement live auction UI (time sync, bid validation, auto-refresh).
- [ ] ISSUE-125 [Web/Auctions] Add bid placement UX with optimistic state and rollback handling.
- [ ] ISSUE-126 [Web/Create] Build mint NFT form with metadata schema validation and preview.
- [ ] ISSUE-127 [Web/Create] Build collection creation flow connected to `collection_factory` contract.
- [ ] ISSUE-128 [Web/Create] Implement media upload flow via backend storage API and progress states.
- [ ] ISSUE-129 [Web/Profile] Implement profile pages (owned, created, listed, sold).
- [ ] ISSUE-130 [Web/Notifications] Add real-time in-app notifications via websocket.
- [ ] ISSUE-131 [Web/Localization] Remove Starknet strings and complete Stellar terminology pass in locales.
- [ ] ISSUE-132 [Web/SEO] Add SEO metadata, OG tags, schema.org for NFT and collection pages.
- [ ] ISSUE-133 [Web/Perf] Add route-level code splitting and image optimization budgets.
- [ ] ISSUE-134 [Web/Perf] Add web-vitals reporting to backend analytics endpoint.
- [ ] ISSUE-135 [Web/Testing] Add integration tests for auth, mint, listing, buy, and bid flows.
- [ ] ISSUE-136 [Web/Testing] Add visual regression baseline for marketplace and dashboard routes.
- [ ] ISSUE-137 [Web/Security] Add CSP, nonce handling, and anti-XSS hardening.
- [ ] ISSUE-138 [Web/PWA] Complete offline behavior and stale-data messaging for marketplace pages.

## G. Mobile App (Expo/React Native) (16 issues)

- [ ] ISSUE-139 [Mobile/Core] Replace sample screens/components with real feature modules.
- [ ] ISSUE-140 [Mobile/Navigation] Define production navigation stacks for auth, home, create, marketplace, profile.
- [ ] ISSUE-141 [Mobile/Wallet] Implement Stellar wallet deep-link integration and session restore.
- [ ] ISSUE-142 [Mobile/Auth] Implement Stellar challenge-sign login with backend JWT session.
- [ ] ISSUE-143 [Mobile/API] Create typed API service layer with retries and offline-safe caching.
- [ ] ISSUE-144 [Mobile/Marketplace] Build marketplace feed with filters and pagination.
- [ ] ISSUE-145 [Mobile/NFT] Build NFT detail screen with activity and ownership status.
- [ ] ISSUE-146 [Mobile/Create] Build mobile mint flow including media picker and upload pipeline.
- [ ] ISSUE-147 [Mobile/Auctions] Build auction list/detail and bid submission UX.
- [ ] ISSUE-148 [Mobile/Profile] Build user profile and portfolio views.
- [ ] ISSUE-149 [Mobile/Notifications] Integrate push notifications for bids, sales, and auction events.
- [ ] ISSUE-150 [Mobile/State] Implement Zustand store slices for auth, wallet, nft, marketplace.
- [ ] ISSUE-151 [Mobile/Design] Build reusable design system tokens and components.
- [ ] ISSUE-152 [Mobile/QA] Add device matrix QA plan and automated smoke tests.
- [ ] ISSUE-153 [Mobile/Security] Secure token storage with keychain/keystore and logout purge.
- [ ] ISSUE-154 [Mobile/Release] Set up EAS build profiles and staged rollout process.

## H. Admin App (New Next.js App - Not Yet Created) (28 issues)

- [ ] ISSUE-155 [Admin/Bootstrap] Create new Next.js admin app workspace (`apps/admin` equivalent in current repo layout).
- [ ] ISSUE-156 [Admin/Bootstrap] Configure TypeScript, ESLint, Prettier, test runner, and CI workflow.
- [ ] ISSUE-157 [Admin/Auth] Implement admin authentication flow with backend JWT and role claims.
- [ ] ISSUE-158 [Admin/Auth] Add route guards and permission-based navigation.
- [ ] ISSUE-159 [Admin/Layout] Build admin shell (sidebar, header, command palette, breadcrumbs).
- [ ] ISSUE-160 [Admin/Dashboard] Implement KPI dashboard (volume, sales, active users, failed txs, indexer lag).
- [ ] ISSUE-161 [Admin/Users] Implement user management table with search, filters, pagination.
- [ ] ISSUE-162 [Admin/Users] Add user detail page (wallets, activity, flags, verification status).
- [ ] ISSUE-163 [Admin/Users] Add actions: verify creator, suspend user, unsuspend user, reset sessions.
- [ ] ISSUE-164 [Admin/Collections] Build collection moderation queue and review actions.
- [ ] ISSUE-165 [Admin/Collections] Add collection verification and badge management workflow.
- [ ] ISSUE-166 [Admin/NFT] Build NFT moderation queue for metadata/image policy violations.
- [ ] ISSUE-167 [Admin/NFT] Add NFT hide/unhide/takedown actions with audit logging.
- [ ] ISSUE-168 [Admin/Marketplace] Build listing moderation and fraud signal review panel.
- [ ] ISSUE-169 [Admin/Auctions] Build auction monitoring panel for anomalous bidding patterns.
- [ ] ISSUE-170 [Admin/Orders] Build transaction explorer with settlement status and payout breakdown.
- [ ] ISSUE-171 [Admin/Royalties] Add royalty reconciliation dashboard and payout mismatch alerts.
- [ ] ISSUE-172 [Admin/Disputes] Build dispute case management UI linked to on-chain/off-chain evidence.
- [ ] ISSUE-173 [Admin/Content] Add blocked assets/hash list manager for unsafe content.
- [ ] ISSUE-174 [Admin/Notifications] Build notification campaign composer (email/in-app/push).
- [ ] ISSUE-175 [Admin/Analytics] Build advanced analytics views by collection, category, creator cohort.
- [ ] ISSUE-176 [Admin/ChainOps] Build contract/ledger monitoring panel (RPC health, contract versions).
- [ ] ISSUE-177 [Admin/ChainOps] Add emergency controls UI (pause marketplace, disable mint windows).
- [ ] ISSUE-178 [Admin/Audit] Implement full audit log viewer with actor/action/resource traceability.
- [ ] ISSUE-179 [Admin/Settings] Add platform settings UI for fees, royalties caps, feature flags.
- [ ] ISSUE-180 [Admin/Testing] Add e2e tests for critical admin flows (suspend user, moderate listing, pause market).
- [ ] ISSUE-181 [Admin/Security] Add mandatory 2FA for admin accounts and sensitive action re-auth.
- [ ] ISSUE-182 [Admin/Release] Add deployment pipeline and environment promotion (staging -> production).

## I. Security, Compliance, and Trust (10 issues)

- [ ] ISSUE-183 [Security] Implement wallet signature abuse detection and anomaly alerts.
- [ ] ISSUE-184 [Security] Add backend request signing for internal service-to-service calls.
- [ ] ISSUE-185 [Security] Add anti-bot challenge on high-risk endpoints (mint/list/bid).
- [ ] ISSUE-186 [Security] Create abuse-prevention policy for wash trading and bid manipulation.
- [ ] ISSUE-187 [Compliance] Add creator KYC/KYB integration hooks for regulated regions.
- [ ] ISSUE-188 [Compliance] Implement sanctions screening for payout addresses.
- [ ] ISSUE-189 [Compliance] Add legal consent/version tracking for terms and marketplace policy.
- [ ] ISSUE-190 [Trust] Implement provenance verification badges and warning states.
- [ ] ISSUE-191 [Trust] Add transparent fee/royalty disclosure panel before transaction confirmation.
- [ ] ISSUE-192 [Trust] Publish incident transparency page fed from admin/status data.

## J. QA, Testing, and Release Readiness (8 issues)

- [ ] ISSUE-193 [QA] Create end-to-end test matrix for mint, collection, listing, buy, auction, settlement.
- [ ] ISSUE-194 [QA] Add contract-in-the-loop integration tests with local Soroban RPC.
- [ ] ISSUE-195 [QA] Add chaos tests for RPC failures, Redis outages, and delayed event indexing.
- [ ] ISSUE-196 [QA] Define synthetic monitoring checks for core public user journeys.
- [ ] ISSUE-197 [Release] Create production readiness checklist and sign-off gates.
- [ ] ISSUE-198 [Release] Add canary release strategy for backend and frontend deployments.
- [ ] ISSUE-199 [Release] Add rollback automation for contract ID and API config mismatches.
- [ ] ISSUE-200 [Release] Run full dress-rehearsal in staging and publish postmortem/action report.

---

## Suggested Labels

- `app:web`
- `app:mobile`
- `app:backend`
- `app:admin`
- `service:contracts`
- `service:data`
- `service:infra`
- `service:security`
- `priority:p0`
- `priority:p1`
- `priority:p2`
- `good-first-issue`
- `needs-design`
- `needs-product`

## Suggested First Execution Slice (P0)

- ISSUE-033, ISSUE-034, ISSUE-035, ISSUE-047, ISSUE-049
- ISSUE-071, ISSUE-078, ISSUE-084, ISSUE-085, ISSUE-092
- ISSUE-115, ISSUE-118, ISSUE-121, ISSUE-126
- ISSUE-139, ISSUE-141, ISSUE-142
- ISSUE-155, ISSUE-157, ISSUE-160
- ISSUE-193, ISSUE-194, ISSUE-197
