import { isWithinQuietHours, DEFAULT_QUIET_HOURS } from './notificationSchedule';
import { QuietHours } from '@/types';

function at(hours: number, minutes: number): Date {
  const d = new Date(2024, 0, 1, hours, minutes, 0, 0);
  return d;
}

describe('isWithinQuietHours', () => {
  it('is always false when disabled, regardless of the configured window', () => {
    const quietHours: QuietHours = { enabled: false, start: '00:00', end: '00:00' };
    expect(isWithinQuietHours(quietHours, at(3, 0))).toBe(false);
  });

  it('DEFAULT_QUIET_HOURS starts disabled', () => {
    expect(DEFAULT_QUIET_HOURS.enabled).toBe(false);
  });

  describe('same-day window (start < end)', () => {
    const quietHours: QuietHours = { enabled: true, start: '13:00', end: '17:00' };

    it('is false before the window', () => {
      expect(isWithinQuietHours(quietHours, at(12, 59))).toBe(false);
    });

    it('is true at the exact start (inclusive)', () => {
      expect(isWithinQuietHours(quietHours, at(13, 0))).toBe(true);
    });

    it('is true in the middle of the window', () => {
      expect(isWithinQuietHours(quietHours, at(15, 30))).toBe(true);
    });

    it('is false at the exact end (exclusive)', () => {
      expect(isWithinQuietHours(quietHours, at(17, 0))).toBe(false);
    });

    it('is false after the window', () => {
      expect(isWithinQuietHours(quietHours, at(18, 0))).toBe(false);
    });
  });

  describe('overnight window (start > end)', () => {
    const quietHours: QuietHours = { enabled: true, start: '22:00', end: '08:00' };

    it('is true right after the start, before midnight', () => {
      expect(isWithinQuietHours(quietHours, at(23, 30))).toBe(true);
    });

    it('is true at the exact start (inclusive)', () => {
      expect(isWithinQuietHours(quietHours, at(22, 0))).toBe(true);
    });

    it('is true just after midnight', () => {
      expect(isWithinQuietHours(quietHours, at(0, 30))).toBe(true);
    });

    it('is false at the exact end (exclusive)', () => {
      expect(isWithinQuietHours(quietHours, at(8, 0))).toBe(false);
    });

    it('is false in the middle of the day', () => {
      expect(isWithinQuietHours(quietHours, at(14, 0))).toBe(false);
    });

    it('is false one minute before the start', () => {
      expect(isWithinQuietHours(quietHours, at(21, 59))).toBe(false);
    });
  });

  describe('zero-width window (start === end)', () => {
    it('is treated as always-on rather than always-off', () => {
      const quietHours: QuietHours = { enabled: true, start: '09:00', end: '09:00' };
      expect(isWithinQuietHours(quietHours, at(9, 0))).toBe(true);
      expect(isWithinQuietHours(quietHours, at(20, 0))).toBe(true);
    });
  });

  describe('malformed persisted values fail closed', () => {
    it('treats an invalid start time as not-in-quiet-hours', () => {
      const quietHours = { enabled: true, start: 'nonsense', end: '08:00' } as QuietHours;
      expect(isWithinQuietHours(quietHours, at(23, 0))).toBe(false);
    });

    it('treats an out-of-range hour as not-in-quiet-hours', () => {
      const quietHours = { enabled: true, start: '25:00', end: '08:00' } as QuietHours;
      expect(isWithinQuietHours(quietHours, at(23, 0))).toBe(false);
    });
  });
});
