# Notification preferences: local state and backend sync

This documents how `stores/notificationStore.ts`'s `preferences` (per-category
opt-in, push toggle, quiet hours) relates to the backend, for when push
notifications are actually targeted server-side. It also covers the current
quiet-hours enforcement point and its limitations.

## Current state

- **Local store**: `stores/notificationStore.ts` holds `preferences: NotificationPreferences`
  (see `types/index.ts`), persisted to `AsyncStorage` under the
  `notification-storage` key via the shared `createStore` factory, so
  preferences survive app restarts without a network round-trip.
- **Sync calls exist today**: `fetchPreferences()` and `updatePreferences()`
  already call `apiClient.getNotificationPreferences()` /
  `updateNotificationPreferences()` (`lib/api/sample.ts`) on every read/write.
  Today those hit the sample/mock API layer; the shape is already what a real
  backend endpoint would need to receive and return.
- **Optimistic-vs-authoritative**: `updatePreferences` currently applies the
  **server's returned value**, not the caller's optimistic input — if the
  request fails, the local state is left unchanged (see the store's
  `catch` block) rather than silently drifting from the server. This means
  a toggle that fails to save visibly reverts instead of lying to the user.

## What "server-side push targeting" will need once it ships

When push sending actually filters by these preferences (rather than sending
every push to every registered device), the backend's `/notifications/preferences`
endpoint should become the **source of truth** for whether a given push is
sent at all, not just a mirror of local UI state:

1. **Push token ↔ preferences association**: the backend already receives a
   push token via `apiClient.registerPushToken` (`pushNotification.service.ts`).
   The preferences record should be keyed by the same user/device identity so
   the send pipeline can look up "does this token's owner want `outbid`
   pushes" before dispatching.
2. **Category filtering happens server-side**: a client that has `outbid:
   false` should mean the backend never sends that push in the first place —
   not that the client silently drops an unwanted push it already received
   (that still costs a push-service dispatch and battery/data on-device for
   no benefit).
3. **Quiet hours are advisory only, and are enforced client-side today** (see
   below) — the backend does **not** currently receive `quietHours` for
   send-time suppression. This is intentional for now: a client's local clock
   and timezone are the correct authority for "is it currently within this
   *device's* quiet window," and there is no cross-device quiet-hours
   requirement yet (see Operational limitations).
4. **Conflict resolution**: if a user changes preferences on two devices
   before either syncs, last-write-wins per this store's current
   fetch-then-overwrite behavior is the simplest correct default; revisit
   only if multi-device support is prioritized.

## Quiet hours enforcement (current, client-side only)

Quiet hours are enforced in `src/services/pushNotification.service.ts`'s
`Notifications.setNotificationHandler` callback, which controls whether an
**already-delivered** notification is shown while the app is in the
foreground:

- `shouldShowBanner` / `shouldShowList` / `shouldPlaySound` are suppressed
  during the configured window (see `src/utils/notificationSchedule.ts`'s
  `isWithinQuietHours`).
- `shouldSetBadge` is **not** suppressed — the unread badge count still
  updates during quiet hours, so returning to the app afterward correctly
  shows what was missed.

### Operational limitations

- This only affects **foreground presentation**. Background and
  killed-state push delivery/display behavior is controlled by the OS
  notification tray, which this handler does not run for. A backend that
  wants quiet hours honored while the app isn't running would need to either
  (a) receive `quietHours` and defer/suppress the push server-side, or (b)
  schedule it for delivery after the window closes. Neither is implemented;
  this is the natural next step once server-side targeting exists.
- The window is evaluated against the **device's local clock**, so it
  follows the device timezone automatically but has no concept of a
  user-specified timezone independent of the device.
- Only whole-hour boundaries are exposed in the settings UI today
  (`NotificationSettingsScreen.tsx`'s hour picker); `QuietHours.start`/`end`
  are stored as full `"HH:mm"` strings so minute-level precision can be added
  to the UI later without a data migration.
