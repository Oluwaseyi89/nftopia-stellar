# Mobile release pipeline

The mobile workflow runs typecheck, lint, tests, Expo config validation, and the
web build before distribution. A push to `develop` publishes a testnet OTA update
on `preview`; a push to `main` publishes a mainnet update on `production` and
starts the production iOS/Android EAS build.

Configure these GitHub Actions secrets; none belong in the repository:

- `EXPO_TOKEN`: a least-privilege Expo access token.
- `EXPO_PROJECT_ID`: the Expo project UUID.
- Apple and Google credentials are stored in EAS and managed with `eas credentials`.

Every update and build message contains `GITHUB_SHA`, and the app exposes it as
`expo.extra.buildCommit`. The runtime version follows the app version, preventing
native-incompatible updates from reaching an older binary.

## Rollback

For a faulty OTA update, publish the last known-good commit to the same channel
after verification with `npx eas-cli update --channel production --branch
<known-good-branch>`. For native incompatibilities, increment the app version and
ship a new EAS binary; OTA updates cannot change native code.
