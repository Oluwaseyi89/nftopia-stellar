import AsyncStorage from '@react-native-async-storage/async-storage';
import * as StoreReview from 'expo-store-review';
import { analyticsService } from '@/src/analytics/analytics.service';

const LAST_PROMPT_KEY = 'rating_prompt:last_shown';
const DISMISSED_KEY = 'rating_prompt:dismissed';
export const RATING_COOLDOWN_MS = 90 * 24 * 60 * 60 * 1000;

export type RatingPromptResult = 'shown' | 'unavailable' | 'cooldown' | 'dismissed';

export async function canPrompt(now = Date.now()): Promise<boolean> {
  const lastShown = await AsyncStorage.getItem(LAST_PROMPT_KEY);
  const dismissed = await AsyncStorage.getItem(DISMISSED_KEY);
  if (dismissed === 'true') return false;
  return !lastShown || now - Number(lastShown) >= RATING_COOLDOWN_MS;
}

export async function requestRatingPrompt(now = Date.now()): Promise<RatingPromptResult> {
  if (!(await canPrompt(now))) {
    analyticsService.track('rating_prompt_skipped', { reason: 'cooldown_or_dismissed' });
    return 'cooldown';
  }
  if (!(await StoreReview.isAvailableAsync())) {
    analyticsService.track('rating_prompt_unavailable');
    return 'unavailable';
  }

  await AsyncStorage.setItem(LAST_PROMPT_KEY, String(now));
  analyticsService.track('rating_prompt_shown');
  await StoreReview.requestReview();
  return 'shown';
}

export async function dismissRatingPrompt(): Promise<void> {
  await AsyncStorage.setItem(DISMISSED_KEY, 'true');
  analyticsService.track('rating_prompt_dismissed');
}

export async function resetRatingPrompt(): Promise<void> {
  await Promise.all([
    AsyncStorage.removeItem(LAST_PROMPT_KEY),
    AsyncStorage.removeItem(DISMISSED_KEY),
  ]);
}
