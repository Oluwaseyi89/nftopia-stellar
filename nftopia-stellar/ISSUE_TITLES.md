# nftopia-stellar — Issue Title Backlog

Source backlog for expanding into full GitHub issues on
https://github.com/NFTopia-Foundation/nftopia-stellar/issues. Grounded in the
actual Rust source under `contracts/` as of this audit — not copied verbatim
from the stale `NEW_ISSUES.md` "Section C" draft (which predates reading the
code; several of its claims, e.g. that `nft_contract` is a bare scaffold, do
not match what's actually implemented). Entries already covered by open
GitHub issues labeled `Rust`/`Soroban` (dust-bid edge cases, `gas_optimizer.rs`
recalibration, `dependency_resolver.rs` TTL validation, placeholder
arbitration in `dispute_resolution.rs`) are intentionally excluded here.

Each entry: `- [ ] **Title** — description. _(kind: ...)_`

Total entries: 141 (9 entries used to create GitHub issues #551-#558 and #595 have been removed to avoid duplication)

Total entries: 142 (8 entries used to create GitHub issues #551-#558 have been removed to avoid duplication).

## nft_contract — Correctness & Hardening (15)

- [ ] **Audit `mint` for royalty-override abuse by non-admin callers** — `token.rs`'s `mint` accepts a `royalty_override` from the caller; confirm only an authorized minter can set a royalty that diverges from `DefaultRoyalty`, not an arbitrary value benefiting themselves. _(kind: Rust, Soroban, bug)_
- [ ] **Add pagination to owner/collection token queries** — `storage.rs` and `token.rs` expose per-owner token lookups; confirm there's a bounded/paginated query path so an account with many tokens can't produce an unbounded `Vec` read. _(kind: Rust, Soroban, enhancement)_
- [ ] **Document and test the metadata-freeze transition in `metadata.rs`** — verify `MetadataFrozen` can only move false→true, never back, and add a test asserting a post-freeze update is rejected. _(kind: Rust, Soroban, test)_
- [ ] **Add negative tests for `access_control.rs` role checks** — `require_minter`/`require_burner`/`require_metadata_updater` need tests asserting a caller without the role is rejected, not just the happy path. _(kind: Rust, Soroban, test)_
- [ ] **Verify `transfer.rs` clears per-token approvals on transfer** — confirm an approval granted to a previous operator cannot be used after ownership changes. _(kind: Rust, Soroban, bug)_
- [ ] **Add supply-cap boundary tests for `validate_supply_cap`** — cover `max_supply == 0` (unlimited vs. disabled?) and minting exactly at the cap in `storage.rs`. _(kind: Rust, Soroban, test)_
- [ ] **Correct README's "scaffold-level" description of `nft_contract`** — `README.md` says `nft_contract` is scaffolded compared to other packages, but it has 12 modules and 43 tests; update the docs to reflect its actual maturity. _(kind: documentation)_
- [ ] **Add contract-level pause/unpause to `nft_contract`** — confirm whether `IsPaused` (set at `initialize`) is actually checked by `mint`/`transfer`/`burn`; if not enforced everywhere, wire it in consistently. _(kind: Rust, Soroban, bug)_
- [ ] **Add royalty percentage upper-bound test at exactly `MAX_ROYALTY_BPS`** — boundary-test `royalty.rs` at the cap and cap+1 to confirm the off-by-one behavior is intended. _(kind: Rust, Soroban, test)_
- [ ] **Add ownership-transfer event assertions to `events.rs` tests** — confirm every state-changing entrypoint (mint, transfer, burn, royalty update) emits the expected event with correct topics/data. _(kind: Rust, Soroban, test)_
- [ ] **Review `interface.rs` for SEP-41/token-interface alignment** — check whether the public token interface aligns with any relevant Stellar token/NFT interface convention for wallet and indexer compatibility. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add fuzz test for `TokenAttribute` vector size limits in `types.rs`** — confirm an attacker can't mint a token with an unbounded attributes vector to inflate storage cost. _(kind: Rust, Soroban, test)_
- [ ] **Audit `error.rs` for consistent error granularity** — check that distinct failure modes (unauthorized, not-found, already-exists, invalid-input) map to distinct `ContractError` variants rather than being collapsed. _(kind: Rust, Soroban, enhancement)_
- [ ] **Reduce `.unwrap()` usage in `nft_contract` non-test code** — replace panics from `.unwrap()` with explicit `ContractError` returns where the call site can reasonably fail. _(kind: Rust, Soroban, bug)_
- [ ] **Generate and publish `nft_contract` client bindings for backend/frontend TS consumption** — no generated TS client exists yet for this contract's `#[contractimpl]` interface. _(kind: Rust, Soroban, Integration)_

## collection_factory (12)

- [ ] **Add per-creator collection creation rate limit** — confirm `factory.rs` has anti-spam throttling on `create` beyond whatever fee is charged; add one if missing. _(kind: Rust, Soroban, bug)_
- [ ] **Add deterministic (CREATE2-equivalent) deployment option** — evaluate whether Soroban supports predictable collection contract addresses and add support if it does, for off-chain address precomputation. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add richer factory events for indexer consumption** — confirm `events.rs` emits creator, collection ID, and tx metadata sufficient for the backend indexer to avoid extra RPC round-trips. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add test for unauthorized `create` call** — `test.rs` should assert a non-permitted caller cannot deploy a collection if the factory restricts who may call `create`. _(kind: Rust, Soroban, test)_
- [ ] **Add test for invalid collection config rejection** — assert `factory.rs` rejects a zero/invalid `max_supply` or malformed config before deployment. _(kind: Rust, Soroban, test)_
- [ ] **Confirm factory-deployed collections initialize with the correct admin** — verify `collection.rs` wiring passes the actual creator (not the factory contract itself) as the new collection's admin. _(kind: Rust, Soroban, bug)_
- [ ] **Add `get_collection_count` pagination for `list`-style queries** — `verify_contract.sh` calls `get_collection_count`; confirm there's a companion paginated listing function, not just a count. _(kind: Rust, Soroban, enhancement)_
- [ ] **Reduce `.unwrap()` usage in `collection_factory` non-test code** — same audit as `nft_contract`, applied to `factory.rs`/`storage.rs`. _(kind: Rust, Soroban, bug)_
- [ ] **Add factory pause/admin-control tests** — confirm and test that an admin can pause new collection creation platform-wide. _(kind: Rust, Soroban, test)_
- [ ] **Document the factory→collection initialization handshake** — add doc comments explaining exactly what `factory.rs` passes to a newly deployed `nft_contract` instance's `initialize`. _(kind: documentation)_
- [ ] **Add collection-limit-per-creator enforcement test** — if `factory.rs` enforces a max collections per address, add a boundary test; if it doesn't, file as a missing control. _(kind: Rust, Soroban, test)_
- [ ] **Generate and publish `collection_factory` client bindings for TS consumption** — no generated TS client exists for backend/frontend to call factory methods type-safely. _(kind: Rust, Soroban, Integration)_

## marketplace_settlement — Escrow & Atomic Swap (8)

- [ ] **Add test asserting `check_escrow_balance` reflects real holdings** — once fixed, add a regression test depositing funds and confirming the reported balance matches. _(kind: Rust, Soroban, test)_
- [ ] **Audit `release_escrow` for double-release risk** — confirm escrow state is marked released before/atomically-with the actual transfer so it cannot be released twice for the same transaction. _(kind: Rust, Soroban, bug)_
- [ ] **Add atomic-swap timeout/expiry handling** — confirm an initiated swap that's never completed can be cancelled/reclaimed by the initiator after a timeout rather than locking funds indefinitely. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add multi-asset atomic swap test matrix** — cover XLM-for-NFT, NFT-for-NFT, and multi-token bundle swap combinations in `test.rs`. _(kind: Rust, Soroban, test)_
- [ ] **Audit escrow accounting invariants after partial failures** — verify a swap that fails midway leaves escrowed balances exactly matching what's recoverable, with no funds stuck or double-counted. _(kind: Rust, Soroban, bug)_
- [ ] **Add escrow balance reconciliation admin/view function** — expose a read-only method summing all outstanding escrow per asset for operational monitoring. _(kind: Rust, Soroban, enhancement)_
- [ ] **Reduce `.unwrap()` usage in `atomic_swap.rs`** — same non-test `.unwrap()` audit as other contracts. _(kind: Rust, Soroban, bug)_

## marketplace_settlement — Settlement Core & Bundle Trades (8)

- [ ] **Add test proving `execute_trade` actually moves NFT ownership** — once implemented, assert token ownership on `nft_contract` changes as a result of a completed trade, not just the settlement's internal state flag. _(kind: Rust, Soroban, test)_
- [ ] **Add bundle-sale partial-fulfillment handling** — clarify and test what happens if one item in a `create_bundle` sale becomes unavailable (delisted/transferred) before the bundle is purchased. _(kind: Rust, Soroban, bug)_
- [ ] **Add bundle sale test for mixed listing types** — cover a bundle combining fixed-price and previously-auctioned items in `test.rs`. _(kind: Rust, Soroban, test)_
- [ ] **Audit `settlement_core.rs` state machine for stuck states** — enumerate `TransactionState` transitions and confirm every non-terminal state has a defined path to a terminal one (no dead-end state). _(kind: Rust, Soroban, bug)_
- [ ] **Add idempotency guard to trade execution entrypoints** — confirm `execute_trade` cannot be invoked twice for the same `trade_id` after it's already `Executed`. _(kind: Rust, Soroban, test)_
- [ ] **Reduce `.unwrap()` usage in `settlement_core.rs`** — same non-test `.unwrap()` audit. _(kind: Rust, Soroban, bug)_

## marketplace_settlement — Auctions & Bidding (8)

- [ ] **Add configurable minimum bid increment per auction** — confirm `auction_engine.rs` enforces a real, listing-specific minimum increment rather than relying on the placeholder gaming heuristic alone. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add auction extension ("anti-sniping") window test** — verify a bid placed in the final moments extends the auction end time, and add a test asserting the extension amount and cap. _(kind: Rust, Soroban, test)_
- [ ] **Add reserve-price-not-met settlement path test** — confirm an auction ending below reserve returns the NFT to the seller and refunds all bidders, with a test covering it. _(kind: Rust, Soroban, test)_
- [ ] **Audit buy-now vs. active-bid race condition** — confirm a buy-now purchase during an active bidding war is handled deterministically (e.g., rejected once a bid exists, or atomically outbids). _(kind: Rust, Soroban, bug)_
- [ ] **Add auction cancellation refund test with multiple outstanding bids** — verify every bidder, not just the highest, is refunded when a seller cancels an auction. _(kind: Rust, Soroban, test)_
- [ ] **Add bid withdrawal edge case test for the currently-highest bidder** — confirm a highest bidder cannot withdraw while still leading (or the correct next-highest becomes leading if they can). _(kind: Rust, Soroban, test)_
- [ ] **Reduce `.unwrap()` usage in `auction_engine.rs`** — same non-test `.unwrap()` audit. _(kind: Rust, Soroban, bug)_

## marketplace_settlement — Disputes (6)

- [ ] **Add dispute evidence size/format validation** — confirm `initiate_dispute`'s `evidence_uri: Option<Bytes>` has a bounded length check to avoid storage bloat from oversized evidence payloads. _(kind: Rust, Soroban, bug)_
- [ ] **Add dispute timeout/auto-resolution path** — confirm a dispute that receives no votes/resolution within a window has a defined fallback outcome rather than staying open indefinitely. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add multi-party dispute voting quorum test** — once arbitration is implemented (tracked separately), add a test asserting the vote quorum/threshold logic in `dispute_resolution.rs`. _(kind: Rust, Soroban, test)_
- [ ] **Audit dispute initiation for spam/griefing resistance** — confirm there's a cost or rate limit preventing a party from repeatedly opening disputes on the same transaction. _(kind: Rust, Soroban, bug)_
- [ ] **Add dispute-linked escrow freeze test** — confirm funds/NFT related to a disputed transaction are frozen from further settlement until the dispute resolves. _(kind: Rust, Soroban, test)_
- [ ] **Document the dispute lifecycle state diagram** — add a doc comment or README section mapping `initiate → vote → resolve/timeout` states in `dispute_resolution.rs`. _(kind: documentation)_

## marketplace_settlement — Fees & Royalties (8)

- [ ] **Add test for `calculate_complex_royalties` with multiple beneficiaries** — `royalty_distributor.rs` exposes a "complex" royalty calculation path; confirm `test.rs` covers split royalties across more than one recipient. _(kind: Rust, Soroban, test)_
- [ ] **Audit `enforce_royalty_payment` for bypass via direct settlement paths** — confirm every sale/trade path (fixed-price, auction, bundle, atomic swap) routes through royalty enforcement, not just the primary listing flow. _(kind: Rust, Soroban, bug)_
- [ ] **Add VIP fee exemption abuse test** — `fee_manager.rs`'s `add_vip_exemption`/`remove_vip_exemption` need a test confirming only an admin can grant exemptions, not any caller. _(kind: Rust, Soroban, test)_
- [ ] **Add tiered/time-based fee boundary tests** — `calculate_tiered_fee` and `calculate_time_based_fee` need tests at tier boundaries and time-window edges. _(kind: Rust, Soroban, test)_
- [ ] **Audit `withdraw_platform_fees` for double-withdrawal risk** — confirm accumulated fees are zeroed/decremented atomically with the withdrawal so repeated calls can't drain more than what's owed. _(kind: Rust, Soroban, bug)_
- [ ] **Add `get_fee_statistics` accuracy test across mixed asset types** — confirm aggregate fee stats correctly sum across different asset denominations rather than naively adding raw amounts. _(kind: Rust, Soroban, test)_
- [ ] **Add royalty-vs-fee ordering test for underpriced sales** — confirm behavior when a sale price is too low to cover both platform fee and royalty in full (rejected vs. proportionally reduced). _(kind: Rust, Soroban, bug)_
- [ ] **Reduce `.unwrap()` usage in `royalty_distributor.rs` and `fee_manager.rs`** — same non-test `.unwrap()` audit. _(kind: Rust, Soroban, bug)_

## marketplace_settlement — Security Hardening (10)

- [ ] **Optimize commitment cleanup in `frontrun_protection.rs`** — the cleanup routine at line 96 is flagged "simplified... in production you'd want a more efficient approach," iterating all bidders rather than expiring commitments individually. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add reentrancy guard coverage audit across all state-changing entrypoints** — enumerate every public `#[contractimpl]` method in `settlement_core.rs`/`atomic_swap.rs` and confirm each is wrapped by `ReentrancyGuard::execute` where it should be. _(kind: Rust, Soroban, bug)_
- [ ] **Add rate-limiter bypass test via multiple accounts** — confirm `security/rate_limiter.rs` rate-limits by a dimension that can't be trivially sidestepped by spinning up new addresses for a single actor. _(kind: Rust, Soroban, bug)_
- [ ] **Add commit-reveal timing attack test vectors** — extend `frontrun_protection.rs` tests to cover a bidder revealing at the earliest and latest allowed block/ledger boundary. _(kind: Rust, Soroban, test)_
- [ ] **Audit `PauseManager` module granularity vs. actual enforcement** — confirm every `ModuleType` variant checked by `check_module_not_paused` is actually invoked at the start of its corresponding entrypoints, with no gaps. _(kind: Rust, Soroban, bug)_
- [ ] **Add cross-function reentrancy test (not just same-function)** — confirm the reentrancy guard prevents an attacker from re-entering via a *different* guarded function mid-execution, not only the same one. _(kind: Rust, Soroban, test)_
- [ ] **Add fuzz/property tests for `math_utils.rs`** — property-test fee/royalty percentage math for overflow, rounding direction, and sum-to-100%-or-less invariants. _(kind: Rust, Soroban, test)_
- [ ] **Audit `time_utils.rs` for ledger-timestamp manipulation resistance** — confirm time-sensitive logic (auction end, dispute window) uses ledger sequence/timestamp in a way that's resistant to the small drift validators are allowed. _(kind: Rust, Soroban, bug)_
- [ ] **Document the full security module inventory in the README** — the README lists security modules in prose; expand it into a table mapping each module to the specific attack it mitigates and its current maturity (implemented vs. simplified/placeholder). _(kind: documentation)_

## marketplace_settlement — Storage & Pause (7)

- [ ] **Replace O(n) offset pagination in `transaction_store.rs`** — `list`-style queries at line 88 iterate and count every entry to skip to an offset ("Simple offset implementation... in production you'd want a more efficient approach"), which gets expensive as transaction history grows. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add storage TTL/bump policy audit across all `storage/*.rs` modules** — confirm `allowlist_store.rs`, `auction_store.rs`, `blocklist_store.rs`, `dispute_store.rs`, and `transaction_store.rs` all extend entry TTLs appropriately to avoid unexpected archival/eviction. _(kind: Rust, Soroban, bug)_
- [ ] **Add allowlist/blocklist admin-only mutation tests** — confirm only an authorized admin can add/remove entries in `allowlist_store.rs`/`blocklist_store.rs`. _(kind: Rust, Soroban, test)_
- [ ] **Add storage growth/cost estimate documentation** — document approximate per-entry storage cost for auctions, disputes, and transactions to inform fee sizing. _(kind: documentation)_
- [ ] **Audit blocklist enforcement coverage** — confirm a blocklisted address is actually checked and rejected at every relevant entrypoint (listing, bidding, trading), not just one. _(kind: Rust, Soroban, bug)_
- [ ] **Add storage migration/versioning strategy for `storage/*.rs` schema changes** — document how a future field addition to stored structs will be handled for already-persisted entries. _(kind: documentation, enhancement)_
- [ ] **Reduce `.unwrap()` usage across `storage/*.rs`** — same non-test `.unwrap()` audit applied to the storage layer. _(kind: Rust, Soroban, bug)_

## transaction_contract (15)

- [ ] **Audit `signature_manager.rs` for signature replay protection** — confirm signed payloads include a nonce/sequence number preventing the same signature from being reused. _(kind: Rust, Soroban, bug)_
- [ ] **Add `recovery_system.rs` failure-injection tests** — simulate a mid-execution failure and assert the recovery path restores a consistent state. _(kind: Rust, Soroban, test)_
- [ ] **Audit `dependency_resolver.rs` for circular dependency detection** — confirm a malformed operation graph with a cycle is rejected rather than causing infinite resolution. _(kind: Rust, Soroban, bug)_
- [ ] **Add `operation_manager.rs` batch-execution partial-failure test** — confirm behavior when one operation in a batch fails: full rollback vs. partial commit, and that it's the intended one. _(kind: Rust, Soroban, test)_
- [ ] **Audit `execution_engine.rs` for gas/resource exhaustion handling** — confirm a large batch that would exceed Soroban's resource limits fails gracefully with a clear error rather than an opaque abort. _(kind: Rust, Soroban, bug)_
- [ ] **Add `state_machine.rs` invalid-transition test matrix** — enumerate all defined states and assert every disallowed transition is rejected, not just the allowed ones. _(kind: Rust, Soroban, test)_
- [ ] **Reduce `.unwrap()` usage across `transaction_contract`** — same non-test `.unwrap()` audit applied to this package. _(kind: Rust, Soroban, bug)_
- [ ] **Audit `security/permission_checker.rs` against `security/validation_engine.rs` for consistent auth enforcement** — confirm both modules agree on who's authorized for a given operation type, with no gap between the two checks. _(kind: Rust, Soroban, bug)_
- [ ] **Add `security/atomic_execution.rs` all-or-nothing test for multi-step operations** — assert a multi-step operation leaves no partial on-chain effect if any step fails. _(kind: Rust, Soroban, test)_
- [ ] **Add `security/resource_guard.rs` limit-boundary tests** — test exactly-at-limit and one-over-limit resource consumption scenarios. _(kind: Rust, Soroban, test)_
- [ ] **Document `utils/gas_calculator.rs`'s profiling methodology** — the module comment mentions replacing "arbitrary testnet placeholders" with real profiling; document how the current estimates were derived and how to recalibrate them (related to the tracked `gas_optimizer.rs` recalibration issue, but scoped to the calculator, not the optimizer). _(kind: documentation)_
- [ ] **Add `utils/parameter_encoder.rs` malformed-input fuzz test** — confirm encoding/decoding of operation parameters rejects malformed input rather than panicking. _(kind: Rust, Soroban, test)_
- [ ] **Audit `storage/cache_store.rs` for stale-cache correctness** — confirm cached values are invalidated correctly when underlying state changes, so stale reads can't drive an incorrect execution decision. _(kind: Rust, Soroban, bug)_
- [ ] **Generate and publish `transaction_contract` client bindings for TS consumption** — no generated TS client exists for backend/frontend to call this contract's interface type-safely. _(kind: Rust, Soroban, Integration)_

## Cross-Contract Integration & Client Bindings (12)

- [ ] **Define and document the cross-contract call graph** — produce a diagram/doc showing which contracts call which others (e.g., does `marketplace_settlement` invoke `nft_contract` directly for ownership transfer, or expect the backend to sequence both calls?). _(kind: documentation)_
- [ ] **Add integration test spanning `collection_factory` → `nft_contract` → `marketplace_settlement`** — a single test that deploys a collection via the factory, mints via the resulting `nft_contract`, then lists and settles a sale, exercising the full real cross-contract path. _(kind: Rust, Soroban, test)_
- [ ] **Publish a unified TS client package for all four contracts** — consolidate the (currently nonexistent) per-contract generated bindings into one versioned package consumable by `nftopia-backend` and `nftopia-frontend`. _(kind: Integration, Typescript)_
- [ ] **Add per-contract interface/spec docs for backend and frontend integrators** — one doc per contract listing every public method, its parameters, error codes, and events, independent of the Rust doc comments. _(kind: documentation)_
- [ ] **Audit whether `marketplace_settlement` and `nft_contract` addresses are hardcoded or configurable** — confirm the settlement contract references the correct NFT contract instance per collection rather than a single hardcoded address. _(kind: Rust, Soroban, bug)_
- [ ] **Add contract upgrade/migration playbook** — document the process for deploying a new contract version and migrating existing on-chain state/references, beyond what `VERSIONING.md` currently covers (which only covers version *metadata*, not migration). _(kind: documentation)_
- [ ] **Add contract-to-contract auth boundary tests** — confirm one contract cannot be tricked into acting on behalf of another without proper `require_auth()` at the boundary. _(kind: Rust, Soroban, test)_
- [ ] **Wire `nftopia-backend`'s indexer to consume real event streams from all four contracts** — confirm the backend's on-chain event indexing covers `nft_contract` and `transaction_contract` events, not just `marketplace_settlement`/`collection_factory`. _(kind: Integration)_
- [ ] **Add end-to-end WASM size budget check to CI** — track compiled WASM size per contract over time and fail CI if a package exceeds a defined budget (relevant to Soroban's deployment/resource limits). _(kind: Rust, Soroban, docker)_
- [ ] **Document required environment/network configuration per contract for backend integration** — consolidate contract IDs, network passphrases, and RPC endpoints needed by `nftopia-backend` into one reference. _(kind: documentation)_
- [ ] **Add contract ABI/interface diffing check to CI** — fail CI (or warn loudly) when a public contract method's signature changes without a corresponding version bump, to protect downstream TS clients. _(kind: Rust, Soroban, docker)_
- [ ] **Add a local multi-contract devnet bootstrap script** — one script that deploys and wires all four contracts together on a local/testnet sandbox for end-to-end backend/frontend development. _(kind: Rust, Soroban, enhancement)_

## Deployment, Versioning & Release Readiness (15)

- [ ] **Extend `verify_contract.sh` beyond the collection factory** — the script currently only checks `get_collection_count`; add equivalent post-deploy verification calls for `nft_contract`, `marketplace_settlement`, and `transaction_contract`. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add mainnet deployment checklist and dry-run procedure** — document pre-flight checks (audit sign-off, funded deploy account, network passphrase confirmation) before running `deploy_all.sh` against mainnet. _(kind: documentation)_
- [ ] **Add automated rollback/kill-switch procedure for a bad deployment** — document and script how to pause or redirect traffic away from a newly deployed contract found to be broken post-deploy. _(kind: documentation, enhancement)_
- [ ] **Wire `deployments/manifest.json` updates into CI on tagged releases** — confirm `scripts/deployment_manifest.sh` runs automatically as part of a release workflow rather than only manually. _(kind: Rust, Soroban, docker)_
- [ ] **Add WASM hash verification step comparing deployed vs. source-built binary** — confirm `verify_contract.sh` (or a new script) can independently rebuild from source and diff the WASM hash against what's on-chain, for reproducible-build assurance. _(kind: Rust, Soroban, enhancement)_
- [ ] **Document the incident-response checklist referenced at the end of `VERSIONING.md`** — the file's "Incident response checklist" section appears to be cut off/incomplete; finish it. _(kind: documentation)_
- [ ] **Add a `deployments/` entry schema validation test** — confirm `deployment_manifest.sh` writes entries matching the documented JSON schema, catching malformed manifest writes early. _(kind: Rust, test)_
- [ ] **Add environment-specific (testnet/futurenet/mainnet) config separation for deploy scripts** — confirm `NETWORK`/`SOURCE` env handling in `deploy_all.sh` can't accidentally target the wrong network from a stale `.env`. _(kind: Rust, Soroban, bug)_
- [ ] **Add a `cargo audit`/dependency vulnerability scan to CI** — `nftopia-stellar.yml` runs fmt/clippy/test/build but no dependency security audit. _(kind: docker, Rust)_
- [ ] **Add code coverage reporting to contract CI** — `nftopia-stellar.yml` runs `cargo test` but doesn't measure or report coverage; add `cargo tarpaulin` or equivalent. _(kind: docker, Rust, test)_
- [ ] **Add WASM build artifact publishing to CI** — `nftopia-stellar.yml` builds release WASM but doesn't upload it as a workflow artifact for reuse by deploy jobs. _(kind: docker)_
- [ ] **Add a changelog file tracking per-contract version bumps** — `VERSIONING.md` documents *how* to bump a version but no `CHANGELOG.md` records *what* changed at each bump. _(kind: documentation)_

## Testing & Security Audit Readiness (18)

- [ ] **Commission a third-party security audit and track remediation** — no audit has been performed; create the tracking issue and checklist for engaging an external Soroban-specialized auditor before mainnet. _(kind: Rust, Soroban, bug)_
- [ ] **Run and fix all `cargo clippy -- -D warnings` findings workspace-wide** — confirm CI's clippy gate is actually clean, not just configured, across all four packages. _(kind: Rust)_
- [ ] **Add a fuzzing harness (e.g. `cargo-fuzz` or Soroban's fuzz tooling) for settlement math** — property/fuzz-test `math_utils.rs` fee and royalty calculations for panics on extreme inputs. _(kind: Rust, Soroban, test)_
- [ ] **Add negative-path test coverage report per contract** — audit `test.rs` files to confirm each has meaningful revert/error-path coverage, not just happy-path assertions (spot-check found strong coverage in `marketplace_settlement`'s 89 tests, but this should be a documented, repeatable audit for all four). _(kind: Rust, Soroban, test)_
- [ ] **Add integer overflow/underflow regression tests for all fee and royalty math** — despite `overflow-checks = true` in the release profile catching this at runtime (as a panic), add explicit tests asserting the checked-arithmetic paths return errors rather than relying solely on profile-level protection. _(kind: Rust, Soroban, test)_
- [ ] **Add access-control matrix documentation across all four contracts** — one table mapping every privileged operation to exactly which role(s) can call it, auditable against the actual `require_auth`/role-check code. _(kind: documentation)_
- [ ] **Add a formal invariant list for `marketplace_settlement` escrow accounting** — document (and test) the core invariant that total escrowed funds always equal the sum of all open transactions' expected settlement amounts. _(kind: documentation, test)_
- [ ] **Add gas/resource-cost benchmarking suite across all four contracts** — track per-operation resource consumption over time to catch regressions before they hit mainnet fee costs. _(kind: Rust, Soroban, test)_
- [ ] **Add a "known limitations" section to each contract's module doc comment** — explicitly document every found placeholder/simplified-implementation (escrow balance check, bundle trade execution, dispute auction linkage, withdrawal monitoring, increment-gaming heuristic) in one discoverable place until each is resolved. _(kind: documentation)_
- [ ] **Add mutation testing to catch weak assertions in existing test suites** — run a Rust mutation-testing tool (e.g. `cargo-mutants`) to find tests that pass even when the underlying logic is deliberately broken. _(kind: Rust, test)_
- [ ] **Add a `SECURITY.md` for the contracts workspace** — document how to responsibly disclose a vulnerability found in any of the four contracts. _(kind: documentation)_
- [ ] **Add test for concurrent/racing calls to the same auction from multiple simulated bidders** — stress the bidding path with interleaved calls to catch ordering assumptions that only hold in a single-threaded test harness. _(kind: Rust, Soroban, test)_
- [ ] **Add regression test suite specifically for every bug found during the security audit** — placeholder issue to track audit-derived findings once the third-party audit (tracked above) completes. _(kind: Rust, Soroban, test)_
- [ ] **Audit all `Address`-typed storage keys for authorization bypass via address reuse** — confirm no code path lets a caller supply an arbitrary `Address` to read/write another account's data without that account's `require_auth()`. _(kind: Rust, Soroban, bug)_
- [ ] **Add test coverage for admin key rotation across all four contracts** — confirm each contract supports transferring/rotating its admin address, and that the old admin loses privileges immediately after. _(kind: Rust, Soroban, test)_
- [ ] **Document Soroban SDK version upgrade policy** — `soroban-sdk = "23"` is pinned at the workspace level; document the process/testing bar for bumping it. _(kind: documentation)_
- [ ] **Audit whether any contract stores PII or sensitive off-chain-derived data on-chain** — confirm metadata URIs and evidence URIs store only references, never sensitive content directly, given all on-chain data is public. _(kind: Rust, Soroban, bug)_
- [ ] **Publish a public contracts changelog/release notes page** — surface `VERSIONING.md` version bumps and their audit/security implications somewhere discoverable outside the repo for integrators and users. _(kind: documentation)_

## nft_contract — Additional Feature Gaps (8)

- [ ] **Add batch mint operation to `nft_contract` (distinct from `collection_factory`'s `batch-mint`)** — confirm whether `token.rs` itself supports minting multiple tokens in one call, or whether batching only exists at the factory/deploy script layer. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add per-token dynamic attribute update support** — confirm `metadata.rs` supports updating individual `TokenAttribute` entries post-mint (for evolving/dynamic NFTs) if the product requires it, distinct from full metadata freeze/update. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add burn-with-reason/audit-trail support** — confirm `transfer.rs`/`token.rs`'s burn path records why/by-whom a token was burned for provenance purposes. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add royalty payment-splitting to multiple creator addresses natively** — confirm whether `royalty.rs` supports a single recipient only or multiple, and align with `marketplace_settlement`'s `calculate_complex_royalties` multi-beneficiary support. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add explicit `total_supply`/`max_supply` view functions if missing** — confirm both are exposed as public read methods for off-chain display without needing a full storage read. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add test for collection-level default royalty override precedence** — confirm a per-token `royalty_override` correctly takes precedence over `DefaultRoyalty`, and that omitting it correctly falls back. _(kind: Rust, Soroban, test)_
- [ ] **Add explicit contract-level metadata (name/symbol/description) getters** — confirm collection-level display metadata is queryable independent of any single token. _(kind: Rust, Soroban, enhancement)_
- [ ] **Add cross-check test between `nft_contract` royalty data and `marketplace_settlement` royalty enforcement** — confirm the settlement contract actually reads and honors the royalty info stored on the NFT contract rather than requiring it to be re-passed separately (a source of drift if the two diverge). _(kind: Rust, Soroban, bug)_
