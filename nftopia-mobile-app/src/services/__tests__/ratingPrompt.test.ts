import AsyncStorage from '@react-native-async-storage/async-storage';
import * as StoreReview from 'expo-store-review';
import { canPrompt, dismissRatingPrompt, requestRatingPrompt, resetRatingPrompt, RATING_COOLDOWN_MS } from '../ratingPrompt';

const storage = new Map<string, string>();

jest.mock('@/src/analytics/analytics.service', () => ({
  analyticsService: {
    track: jest.fn(),
    identify: jest.fn(),
    reset: jest.fn(),
    captureException: jest.fn(),
  },
}));

jest.mock('posthog-react-native', () => ({
  PostHog: jest.fn().mockImplementation(() => ({
    capture: jest.fn(),
    debug: jest.fn(),
    flush: jest.fn(async () => undefined),
    identify: jest.fn(),
    register: jest.fn(),
    reset: jest.fn(),
  })),
}));

jest.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: {
    getItem: jest.fn(async (key: string) => storage.get(key) ?? null),
    setItem: jest.fn(async (key: string, value: string) => {
      storage.set(key, value);
    }),
    removeItem: jest.fn(async (key: string) => {
      storage.delete(key);
    }),
  },
}));

jest.mock('expo-store-review', () => ({
  isAvailableAsync: jest.fn(),
  requestReview: jest.fn(),
}));

describe('rating prompt policy', () => {
  beforeEach(async () => {
    await resetRatingPrompt();
    jest.clearAllMocks();
  });

  it('shows only when the store review API is available', async () => {
    jest.mocked(StoreReview.isAvailableAsync).mockResolvedValue(true);
    jest.mocked(StoreReview.requestReview).mockResolvedValue(undefined);
    expect(await requestRatingPrompt(1000)).toBe('shown');
    expect(StoreReview.requestReview).toHaveBeenCalledTimes(1);
    expect(await requestRatingPrompt(1000 + RATING_COOLDOWN_MS - 1)).toBe('cooldown');
  });

  it('remembers a dismissal', async () => {
    await dismissRatingPrompt();
    expect(await canPrompt()).toBe(false);
  });

  it('reports unavailable platforms without throwing', async () => {
    jest.mocked(StoreReview.isAvailableAsync).mockResolvedValue(false);
    expect(await requestRatingPrompt()).toBe('unavailable');
    expect(StoreReview.requestReview).not.toHaveBeenCalled();
  });
});
