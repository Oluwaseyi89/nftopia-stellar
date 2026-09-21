# Accessibility Audit — Auth, Home, Profile, Wallet Management

This documents the audit and fixes made against issue #480. It covers
`screens/Auth/EmailLoginScreen.tsx` (plus its shared `FormInput` and
`ValidationError` components), `screens/Home/HomeScreen.tsx`,
`screens/Profile/ProfileScreen.tsx`, `screens/Profile/WalletManagementScreen.tsx`,
and `components/wallet/WalletList.tsx`.

**Method note:** this pass is a structural/semantic accessibility-tree
walkthrough of each screen's code — tracing what VoiceOver/TalkBack would
announce and in what order, based on each element's role, label, and state,
per the [React Native accessibility API](https://reactnative.dev/docs/accessibility).
No physical device or simulator with VoiceOver/TalkBack was available while
producing this pass, so the "walkthrough" findings below are a code-level
simulation, not a recorded live session. Before shipping, a contributor with
an iOS and an Android device should do one live pass following the checklist
in [`ACCESSIBILITY.md`](./ACCESSIBILITY.md) to confirm these findings
in situ and catch anything platform-specific that static review can miss.

## Summary of fixes

| Area | Before | After |
| --- | --- | --- |
| Interactive elements (all 4 areas) | Most `TouchableOpacity`s had no `accessibilityRole`/`accessibilityLabel`; screen readers fell back to announcing raw child text (or nothing, for icon-only controls) | Explicit `accessibilityRole` + `accessibilityLabel` (+ `accessibilityState` for disabled/selected/checked/busy) on every interactive element |
| `WalletList.tsx` wallet row | Whole card was one `TouchableOpacity` wrapping two more `TouchableOpacity`s (Export/Remove) — a nested-touchable dead end where screen readers can't reach the inner buttons | Select action and Export/Remove actions are now sibling controls, each independently reachable |
| Validation errors | Plain `<Text>`, silent to screen readers unless swiped onto | `accessibilityLiveRegion="polite"` + `AccessibilityInfo.announceForAccessibility()` so errors are spoken immediately |
| Headings | No heading semantics; screen reader users had to read every screen linearly | Screen titles and section titles use `accessibilityRole="header"` |
| Decorative glyphs (`→`, emoji icons) | Read aloud as literal characters/emoji names, duplicating the adjacent label | Hidden via `accessibilityElementsHidden` + `importantForAccessibility="no-hide-descendants"` |
| Touch targets | Several controls (wallet card action buttons, the App Lock switch, lock-timeout chips, back links) were visually smaller than 44x44pt | Padded with `hitSlop`, or given `minHeight: 44`, without changing the visible size |
| Font scaling | `EmailLoginScreen` used a non-scrolling `View` with `justifyContent: 'center'`; at large OS font scales, content could overflow the screen with no way to reach it | Wrapped in a `ScrollView` (`keyboardShouldPersistTaps="handled"`) so scaled content scrolls instead of clipping |
| Color contrast | Several `src/theme/colors.ts` tokens failed WCAG AA (see table below) | Tokens adjusted to pass AA at their existing font sizes/weights |

## Color contrast audit (`src/theme/colors.ts`)

Checked with the WCAG relative-luminance contrast formula. Targets: 4.5:1 for
normal text, 3:1 for large/bold text and non-text UI components.

| Token / pair | Before | Ratio | After | Ratio |
| --- | --- | --- | --- | --- |
| Light `textTertiary` vs `background`/`surface` | `#999999` | 2.85 / 2.70 (fail) | `#707070` | 4.95 / 4.70 (pass) |
| Light `error` / `errorText` vs `errorBackground` | `#FF3B30` | 3.32 (fail) | `#D63228` | 4.52 (pass) |
| Light `info` vs `background` (link/button text) | `#007AFF` | 4.02 (fail) | `#0070EB` | 4.65 (pass) |
| Dark `textTertiary` vs `surface` | `#808080` | 4.22 (fail) | `#8C8C8C` | 4.96 (pass) |
| Dark `infoText` vs `infoBackground` | `#0A84FF` | 4.30 (fail) | `#2B96FF` | 5.16 (pass) |

Tokens already passing AA were left unchanged: `text`, `textSecondary`,
`warningText`, `successText`, `infoText` (light), `error` (dark), and the
dark-theme `text`/`textSecondary` pairs.

**Not changed / out of scope for this pass:** `success` and `warning` (the
base tokens, as opposed to `successText`/`warningText`) are only used as
badge/icon fills, never as text color, in the screens audited here — WCAG's
4.5:1 text requirement doesn't apply to them, and changing them would be a
branding decision outside this issue's scope. If a future screen starts using
`colors.success` or `colors.warning` as a text color, re-check contrast
against that background before doing so.

These are theme-level token changes, so the fix applies automatically
everywhere the tokens are already used (43 files reference these tokens),
not just the four screens named in this issue. `EmailLoginScreen.tsx` and
`FormInput.tsx`/`ValidationError.tsx` hardcode their own colors instead of
importing the theme, so their matching literal color values (`#FF3B30` /
`#007AFF`) were updated directly to the same corrected hex values.

## Screen-by-screen walkthrough

### Auth → Email Login (`EmailLoginScreen.tsx`)

Reading order (top to bottom) was already logical and matches focus order:
title → subtitle → email field → password field → forgot-password link →
sign-in button → sign-up link → back link. No reordering was needed.

- Title now announces as a header ("Welcome Back").
- Email/password fields now announce their label plus, on error, the error
  message as a hint — previously a screen reader had no reliable way to
  associate a validation error with its field.
- Forgot Password / Sign Up / Back all now announce as buttons with a
  descriptive label instead of just their visible text (which for "← Back"
  previously included the arrow glyph).
- Screen now scrolls, so it remains usable at large font scales instead of
  clipping content that no longer fits `flex: 1` centering.

### Home (`HomeScreen.tsx`)

- Greeting and each discovery section title ("Categories", "Trending", "New
  Drops") now announce as headers, so screen reader users can jump directly
  between sections via the rotor/heading navigation instead of reading the
  whole feed linearly.
- The network badge ("Testnet"/"Mainnet") is grouped into one accessible
  element with a clear label ("Network: Testnet") instead of being read as
  bare text with no context.
- The four quick-action cards (Marketplace, Send, Receive, Swap) now announce
  as buttons with their label. Receive and Swap have no `onPress` handler yet
  (pre-existing — not something this pass changed) so they're given an
  `accessibilityHint` of "Coming soon" rather than left silently inert, which
  matches what a sighted user would infer from them not doing anything either.

### Profile (`ProfileScreen.tsx`)

- Screen title and every card title now announce as headers.
- "Manage wallets" and "App settings" rows previously announced only their
  link text plus a stray "→" arrow character; the arrow is now hidden and the
  row has one clean label.
- The App Lock toggle was a custom `View`-based switch with no accessibility
  semantics at all — a screen reader user couldn't tell it was a switch, let
  alone its current state. It now has `accessibilityRole="switch"` and
  `accessibilityState={{ checked }}`.
- Lock-timeout options (Immediately / 30s / 1m / 5m) now announce as buttons
  and report which one is currently selected.
- Sign-out button now has an explicit label matching its visible text.

### Wallet Management (`WalletManagementScreen.tsx`)

- "← Back" now announces as a button labeled "Go back" instead of literal
  arrow-plus-text.
- Screen title announces as a header.
- The empty state ("No Wallets" / "Import or create a wallet to get
  started") is now grouped into a single accessible announcement instead of
  two separate text reads.

### Wallet list (`components/wallet/WalletList.tsx`)

This was the most significant structural fix. Each row was a single
`TouchableOpacity` (the "select this wallet" action) that itself contained
two more `TouchableOpacity`s ("Export", "Remove"). Nesting focusable/
pressable elements like this is a common but serious screen-reader
regression: the OS accessibility tree collapses the nested elements into the
outer one, so VoiceOver/TalkBack users can reach "select wallet" but never
"Export" or "Remove" — a dead end, and one of the acceptance criteria for
this issue was explicitly "without dead ends."

Fixed by making select/export/remove siblings instead of parent/child, each
with its own role, label (including the wallet's identity and active/backup
state, e.g. "Wallet ABC...XYZ, active, backup not confirmed"), and — for the
two action buttons, which were visually smaller than 44pt tall — `hitSlop`.

## Touch target audit

| Element | File | Visible size (approx.) | Fix |
| --- | --- | --- | --- |
| Export / Remove buttons | `WalletList.tsx` | ~34pt tall | `hitSlop` (top/bottom 8, left/right 4) |
| App Lock switch | `ProfileScreen.tsx` | 50x28pt | `hitSlop` 8pt each side (→ ~66x44) |
| Lock-timeout chips | `ProfileScreen.tsx` | ~32pt tall | `hitSlop` (top/bottom 6, left/right 4) |
| Manage Wallets / App Settings rows | `ProfileScreen.tsx` | full-width row, but tight vertical padding | `hitSlop` 8pt each side |
| Back button | `EmailLoginScreen.tsx` | ~40pt tall | `minHeight: 44` |
| Forgot Password / Sign Up links | `EmailLoginScreen.tsx` | ~20pt tall | `hitSlop` (top/bottom 12, left/right 8) |
| Back link | `WalletManagementScreen.tsx` | small text-only tap area | `hitSlop` (top/bottom 12, left/right 8) |

Buttons already at or above 44pt (Sign In, Sign Out, action cards on Home)
were left unchanged.

## Focus order

Verified for each screen that the accessibility tree order matches the
visual top-to-bottom, left-to-right layout order — this is the default in
React Native as long as `flexDirection` isn't reversed and no explicit
`accessibilityViewIsModal`/`importantForAccessibility` reordering is in
play, which held true for all four screens. No focus-order-specific bugs
were found; this section exists to record that the check was made, per the
issue's acceptance criteria.

## Deferred / out of scope for this PR

To keep this change reviewable, the following were **not** touched, but are
good candidates for a follow-up:

- `ConfirmationDialog.tsx`, `WalletExportModal.tsx`,
  `BiometricConfirmationDialog.tsx` — modal dialogs used from Wallet
  Management; worth a dedicated pass on `accessibilityViewIsModal` and focus
  trapping.
- `NetworkSwitcher.tsx`, `ThemeToggle`, `LanguageSwitcher` — shared controls
  rendered inside `ProfileScreen`; not named in the original issue and have
  their own component-level accessibility surface.
- Automated accessibility testing (e.g. `jest-axe`-equivalent for React
  Native, or Detox accessibility assertions) — there's no existing a11y test
  tooling in this repo to extend; adding it is a larger, separate task.
