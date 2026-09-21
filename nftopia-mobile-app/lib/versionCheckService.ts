import AsyncStorage from '@react-native-async-storage/async-storage';
import NetInfo from '@react-native-community/netinfo';
import { AppState, AppStateStatus } from 'react-native';
import {
  CACHED_GATE_KEY,
  CHECK_INTERVAL_MS,
  LAST_CHECK_KEY,
  VersionCheckResult,
  VersionGate,
  VersionState,
  evaluateVersionState,
} from './versionCheck';

/**
 * Orchestrates the in-app update check:
 *   - fetches the version policy from a lightweight remote endpoint,
 *   - throttles to at most once per app foreground,
 *   - no-ops gracefully when offline / the endpoint fails,
 *   - falls back to a cached gate so re-launches still surface prompts.
 */

export interface VersionCheckServiceConfig {
  fetchImpl?: typeof fetch;
  checkIntervalMs?: number;
  appVersion?: string;
  endpoint?: string;
}

let cachedCurrentVersion: string | null = null;

export function sealCurrentVersion(version: string): void {
  cachedCurrentVersion = version;
}

function getAppVersion(): string {
  return cachedCurrentVersion ?? '1.0.0';
}

function defaultEndpoint(): string {
  return (
    process.env.EXPO_PUBLIC_VERSION_CHECK_URL || 'https://api.nftopia.app/v1/app/version'
  );
}

function defaultInterval(): number {
  const fromEnv = Number(process.env.EXPO_PUBLIC_VERSION_CHECK_INTERVAL_MS);
  return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : CHECK_INTERVAL_MS;
}

function normalizeGate(raw: unknown): VersionGate | null {
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  const minimum = typeof obj.minimum === 'string' ? obj.minimum : undefined;
  const latest = typeof obj.latest === 'string' ? obj.latest : undefined;
  if (!minimum || !latest) return null;
  return {
    minimum,
    latest,
    outdatedBelow: typeof obj.outdatedBelow === 'string' ? obj.outdatedBelow : undefined,
  };
}

async function readLastCheck(): Promise<number> {
  try {
    const stored = await AsyncStorage.getItem(LAST_CHECK_KEY);
    const value = stored ? Number(stored) : 0;
    return Number.isFinite(value) ? value : 0;
  } catch {
    return 0;
  }
}

async function writeLastCheck(now: number): Promise<void> {
  try {
    await AsyncStorage.setItem(LAST_CHECK_KEY, String(now));
  } catch {
    // Best-effort; throttling will simply be less sticky.
  }
}

async function readCachedGate(): Promise<VersionGate | null> {
  try {
    const stored = await AsyncStorage.getItem(CACHED_GATE_KEY);
    if (!stored) return null;
    return normalizeGate(JSON.parse(stored));
  } catch {
    return null;
  }
}

/**
 * Returns true when a fresh network check should be attempted based on the
 * configured throttle window, otherwise false.
 */
export async function shouldCheck(now = Date.now(), intervalMs = CHECK_INTERVAL_MS): Promise<boolean> {
  const last = await readLastCheck();
  return now - last >= intervalMs;
}

/**
 * Fetch the version gate from the remote endpoint. Resolves to `null` on any
 * connectivity / network error so callers can no-op without crashing.
 */
export async function fetchVersionGate(
  fetchImpl: typeof fetch = fetch,
  endpoint = defaultEndpoint()
): Promise<VersionGate | null> {
  try {
    const res = await fetchImpl(endpoint, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return normalizeGate(data);
  } catch {
    return null;
  }
}

/**
 * High-level entry point. Returns null when the app should be left to run
 * untouched (offline, throttled, or below no network), otherwise evaluates
 * the current version against the fetched/cached gate.
 */
export async function runVersionCheck(
  config: VersionCheckServiceConfig = {}
): Promise<VersionCheckResult | null> {
  const now = Date.now();
  const appVersion = config.appVersion ?? getAppVersion();
  const fetchImpl = config.fetchImpl ?? fetch;
  const intervalMs = config.checkIntervalMs ?? defaultInterval();

  // Throttle: at most once per app foreground window.
  if (!(await shouldCheck(now, intervalMs))) {
    return null;
  }

  // Offline no-op: don't attempt network when there is no connectivity.
  let isConnected = true;
  try {
    const state = await NetInfo.fetch();
    isConnected = state.isConnected !== false && state.isInternetReachable !== false;
  } catch {
    isConnected = true; // If NetInfo is unavailable, proceed and let fetch fail softly.
  }

  let gate: VersionGate | null = null;
  if (isConnected) {
    gate = await fetchVersionGate(fetchImpl, config.endpoint ?? defaultEndpoint());
    if (gate) {
      await writeLastCheck(now);
      try {
        await AsyncStorage.setItem(CACHED_GATE_KEY, JSON.stringify(gate));
      } catch {
        // Non-fatal.
      }
    }
  }

  // Fall back to a cached gate so re-launches surface prompts even offline.
  if (!gate) {
    gate = await readCachedGate();
  }

  if (!gate) {
    return null;
  }

  const state: VersionState = evaluateVersionState(appVersion, gate);
  return {
    state,
    currentVersion: appVersion,
    minimum: gate.minimum,
    latest: gate.latest,
  };
}

let didListen = false;

/**
 * Register an AppState listener so the check re-runs on each foreground
 * (cold start and every resume), gated by the throttle window.
 */
export function startVersionCheckListener(
  onResult: (result: VersionCheckResult | null) => void,
  config: VersionCheckServiceConfig = {}
): () => void {
  let running = false;

  const run = async () => {
    if (running) return;
    running = true;
    try {
      const result = await runVersionCheck(config);
      onResult(result);
    } finally {
      running = false;
    }
  };

  const handleAppStateChange = (next: AppStateStatus) => {
    // Only evaluate when the app becomes active (foreground).
    if (next === 'active') {
      run();
    }
  };

  const subscription = AppState.addEventListener('change', handleAppStateChange);

  if (!didListen) {
    // Fire once on the first mount to cover cold start, where the 'active'
    // event may have already been emitted before we subscribed.
    didListen = true;
    run();
  }

  return () => subscription.remove();
}
