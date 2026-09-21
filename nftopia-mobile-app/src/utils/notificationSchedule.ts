import { QuietHours } from '@/types';

/**
 * Sensible out-of-the-box quiet hours: off by default (a new install must
 * not silently swallow notifications the user never asked to mute), with a
 * conventional overnight window pre-filled for when they do turn it on.
 */
export const DEFAULT_QUIET_HOURS: QuietHours = {
  enabled: false,
  start: '22:00',
  end: '08:00',
};

/**
 * Parses a "HH:mm" clock time into minutes since midnight. Returns `null`
 * for anything that isn't a well-formed 24-hour time, so a corrupted or
 * hand-edited persisted value fails closed (quiet hours treated as
 * inactive) instead of throwing.
 */
function toMinutes(clock: string): number | null {
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(clock);
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  return hours * 60 + minutes;
}

/**
 * Whether `date` (defaults to now) falls inside the configured quiet-hours
 * window.
 *
 * Handles the overnight case where `start` is later than `end` (e.g.
 * "22:00"–"08:00"): the window is then everything from `start` through
 * midnight plus everything from midnight through `end`. When `start` equals
 * `end`, the window is treated as the full 24 hours (a zero-width window
 * would otherwise be ambiguous between "always on" and "always off"; "always
 * on" is the safer interpretation for a do-not-disturb setting).
 *
 * The window boundaries are inclusive of `start` and exclusive of `end`,
 * matching how a person reads "10 PM to 8 AM": notifications resume exactly
 * at 8:00, not one minute after.
 */
export function isWithinQuietHours(quietHours: QuietHours, date: Date = new Date()): boolean {
  if (!quietHours.enabled) return false;

  const start = toMinutes(quietHours.start);
  const end = toMinutes(quietHours.end);
  if (start === null || end === null) return false;

  const nowMinutes = date.getHours() * 60 + date.getMinutes();

  if (start === end) return true;
  if (start < end) {
    return nowMinutes >= start && nowMinutes < end;
  }
  // Overnight window: wraps past midnight.
  return nowMinutes >= start || nowMinutes < end;
}
