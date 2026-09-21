# Accessibility Checklist

Use this checklist whenever you build or edit a screen or shared component in
`nftopia-mobile-app`. It reflects the fixes made in the Auth, Home, Profile,
and Wallet Management accessibility pass — see
[`ACCESSIBILITY_AUDIT.md`](./ACCESSIBILITY_AUDIT.md) for the full findings
that produced these rules.

## Before opening a PR

- [ ] **Every interactive element has a role and a label.** Any `Pressable`,
      `TouchableOpacity`, or custom control needs `accessibilityRole`
      (`"button"`, `"switch"`, `"header"`, etc.) and a human-readable
      `accessibilityLabel`. Don't rely on child `<Text>` alone — it's dropped
      whenever you also set an explicit `accessibilityLabel`, and isn't
      exposed at all if the element wraps an icon or image.
- [ ] **State is exposed, not just styled.** If a control is disabled,
      selected, checked, or busy, set the matching `accessibilityState` key
      (`disabled`, `selected`, `checked`, `busy`) in addition to the visual
      style. A greyed-out button that doesn't report `disabled: true` still
      reads as tappable to a screen reader user.
- [ ] **No nested interactive elements.** Never wrap a `TouchableOpacity` (or
      any focusable control) inside another one. On a screen reader, the
      outer element swallows the inner one, and the inner action becomes an
      unreachable dead end. If a row needs one action on tap and other
      actions on inner buttons, put them as siblings, not parent/child (see
      `components/wallet/WalletList.tsx` for the pattern).
- [ ] **Decorative content is hidden.** Emoji icons, arrows (`→`), and dots
      used purely for visual effect should not be read aloud twice. Mark them
      with `accessibilityElementsHidden` and
      `importantForAccessibility="no-hide-descendants"`, and fold what they
      convey into the parent's `accessibilityLabel` instead.
- [ ] **Touch targets are at least 44x44 pt.** If the visual element is
      smaller (a small icon button, a compact switch), pad the hit area with
      `hitSlop` rather than growing the visible element.
- [ ] **Validation errors announce themselves.** Don't just render red text.
      Use `ValidationError` (or the pattern in `FormInput`), which sets
      `accessibilityLiveRegion="polite"` and calls
      `AccessibilityInfo.announceForAccessibility()` so the error is spoken
      as soon as it appears, not only when a user happens to swipe onto it.
- [ ] **Headings use `accessibilityRole="header"`.** Screen titles and
      section titles should be marked as headers so screen reader users can
      jump between sections instead of reading everything linearly.
- [ ] **Layouts survive large font scales.** Test with the OS text size
      turned up (Settings → Accessibility → Larger Text on iOS, Settings →
      Accessibility → Font size on Android, both up to ~200%). Screens with
      a fixed-height, non-scrolling container should be wrapped in a
      `ScrollView` so scaled text can't get clipped or overlap other
      elements.
- [ ] **Color is not the only signal.** If a color communicates status (a
      warning badge, an error border), also add a text label or icon change.
- [ ] **New colors meet WCAG AA contrast.** Body text needs at least 4.5:1
      contrast against its background (3:1 for large/bold text and for
      non-text UI components like icons or borders). Check new colors with a
      contrast calculator before adding them to `src/theme/colors.ts`, and
      prefer the existing tokens (`text`, `textSecondary`, `textTertiary`,
      `error`, `info`, etc.) — they're already verified.

## Quick manual test

1. **iOS**: enable VoiceOver (Settings → Accessibility → VoiceOver, or
   triple-click the side button once configured) and swipe through the
   screen left-to-right. Every interactive element should be reachable, and
   every element's announcement should make sense out of context.
2. **Android**: enable TalkBack (Settings → Accessibility → TalkBack) and do
   the same swipe-through.
3. Confirm there are no "dead ends" — an element that VoiceOver/TalkBack
   announces but that either does nothing or hides other controls behind it.
4. Confirm focus order matches visual/reading order (top-to-bottom,
   left-to-right for LTR layouts).

## Reference

- [React Native accessibility docs](https://reactnative.dev/docs/accessibility)
- [WCAG 2.1 AA quick reference](https://www.w3.org/WAI/WCAG21/quickref/?currentsidebar=%23col_overview&levels=aaa)
