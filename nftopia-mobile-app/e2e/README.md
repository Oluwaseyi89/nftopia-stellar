# NFTopia mobile E2E tests

The Detox suite targets an iOS simulator and keeps all wallet data local to
the test run. It does not use funded accounts or submit transactions. This
makes onboarding and wallet-import coverage deterministic and safe for CI.

Generate native projects from Expo, then run:

```bash
npx expo prebuild --no-install
npx detox build --configuration ios.sim
npx detox test --configuration ios.sim --cleanup
```

The purchase/mint journey is intentionally left as a scaffold until the
marketplace transaction screen has a stable test identifier and testnet
fixture contract.
