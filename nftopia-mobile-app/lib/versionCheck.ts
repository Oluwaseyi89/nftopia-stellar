/**
 * Pure version-comparison + policy utilities for the in-app update checker.
 * Kept free of network/UI/side-effect dependencies so it is trivial to unit
 * test in isolation (no react-native import).
 */

export interface VersionGate {
  /** Minimum version still allowed to run. Users below this get a hard block. */
  minimum: string;
  /** Latest published version. Users above `minimum` but below this get a soft nudge. */
  latest: string;
  /** The app version is considered outdated when it is below this (inclusive floor). */
  outdatedBelow?: string;
}

/** Result of comparing two version strings following semver ordering. */
export type CompareResult = -1 | 0 | 1;

/** Overall update state of the running app relative to the remote gate. */
export type VersionState = 'up_to_date' | 'update_available' | 'update_required';

export interface VersionCheckResult {
  state: VersionState;
  currentVersion: string;
  minimum: string;
  latest: string;
  /** A user-facing title for the latest available version. */
  releaseNotes?: string;
}

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Numeric prerelease id, e.g. 1.0.0-beta.2 -> 2. Lower = older. */
  prerelease?: {
    identifier: string;
    numeric?: number;
  };
}

/**
 * Parse a version string into numeric components for reliable comparison.
 * Handles `1`, `1.2`, `1.2.3`, `v1.2.3`, leading zeros, and an optional
 * `-prerelease` suffix. Non-numeric/invalid input returns `null`.
 */
export function parseVersion(input: string | number | null | undefined): ParsedVersion | null {
  if (input === null || input === undefined) return null;
  const raw = String(input).trim();
  if (raw === '') return null;

  const core = raw.replace(/^[vV]/, '');

  const [numbersPart, prereleasePart] = core.split('-', 2);

  const segments = numbersPart.split('.');
  if (segments.length === 0 || segments.length > 4) return null;

  const nums = segments.map((s) => {
    if (!/^\d+$/.test(s)) return Number.NaN;
    // Strip leading zeros to avoid "01" being parsed as octal in some engines.
    return Number(s.replace(/^0+(?=\d)/, ''));
  });
  if (nums.some(Number.isNaN)) return null;

  const major = nums[0];
  const minor = nums[1] ?? 0;
  const patch = nums[2] ?? 0;
  // A 4th segment (e.g. build number) is ignored for ordering.

  let prerelease: ParsedVersion['prerelease'];
  if (prereleasePart !== undefined && prereleasePart !== '') {
    const match = prereleasePart.match(/^([a-zA-Z][0-9a-zA-Z-]*)\.?([0-9]+)?$/);
    if (!match) return null;
    prerelease = {
      identifier: prereleasePart.replace(/\.\d+$/, ''),
      numeric: match[2] !== undefined ? Number(match[2]) : undefined,
    };
  }

  return {
    major,
    minor,
    patch,
    prerelease,
  };
}

/**
 * Compare two version strings following semver ordering.
 * Returns -1 if `a` < `b`, 0 if equal, 1 if `a` > `b`.
 */
export function compareVersions(a: string, b: string): CompareResult {
  const pa = parseVersion(a);
  const pb = parseVersion(b);

  // A non-numeric side sorts as less than a numeric one (defensive fallback).
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;

  const coreDiff =
    pa.major !== pb.major
      ? Math.sign(pa.major - pb.major)
      : pa.minor !== pb.minor
        ? Math.sign(pa.minor - pb.minor)
        : Math.sign(pa.patch - pb.patch);

  if (coreDiff !== 0) return coreDiff as CompareResult;

  // Same core version: a release sorts > a prerelease.
  if (!pa.prerelease && !pb.prerelease) return 0;
  if (!pa.prerelease) return 1;
  if (!pb.prerelease) return -1;

  if (pa.prerelease.identifier !== pb.prerelease.identifier) {
    const paId = pa.prerelease.identifier;
    const pbId = pb.prerelease.identifier;
    // Numeric identifiers compare by number; otherwise lexically.
    const aNum = Number(paId);
    const bNum = Number(pbId);
    if (Number.isInteger(aNum) && Number.isInteger(bNum)) {
      return (Math.sign(aNum - bNum) || 0) as CompareResult;
    }
    return (paId < pbId ? -1 : paId > pbId ? 1 : 0) as CompareResult;
  }

  const aN = pa.prerelease.numeric ?? 0;
  const bN = pb.prerelease.numeric ?? 0;
  return (Math.sign(aN - bN) || 0) as CompareResult;
}

/** True when version `a` is strictly newer than version `b`. */
export function isNewer(a: string, b: string): boolean {
  return compareVersions(a, b) > 0;
}

/** True when version `a` is equal to or newer than version `b`. */
export function isAtLeast(a: string, b: string): boolean {
  return compareVersions(a, b) >= 0;
}

/** True when version `a` is strictly older than version `b`. */
export function isOlder(a: string, b: string): boolean {
  return compareVersions(a, b) < 0;
}

/**
 * Decide the update state for the running app version given a remote gate.
 *
 *   - update_required: current < minimum (must update to keep using the app)
 *   - update_available: minimum <= current < latest (optional soft nudge)
 *   - up_to_date: current >= latest
 */
export function evaluateVersionState(
  currentVersion: string,
  gate: Pick<VersionGate, 'minimum' | 'latest'>
): VersionState {
  const current = parseVersion(currentVersion);
  if (!current) return 'up_to_date';

  // If the remote config is unparseable, default to no update required so the
  // app never blocks on bad server data.
  const minimum = parseVersion(gate.minimum);
  const latest = parseVersion(gate.latest);

  if (minimum && isOlder(currentVersion, gate.minimum)) {
    return 'update_required';
  }
  if (latest && isOlder(currentVersion, gate.latest)) {
    return 'update_available';
  }
  return 'up_to_date';
}

const BUNDLE_IDENTITY = 'com.nftopia.app';

/** App Store / Play Store listing URL built from the app's bundle/package id. */
export function getStoreDeepLink(platform: 'ios' | 'android' = 'ios'): string {
  const appStoreId = 'id0000000000';
  if (platform === 'android') {
    return `https://play.google.com/store/apps/details?id=${BUNDLE_IDENTITY}`;
  }
  return `https://apps.apple.com/app/${appStoreId}`;
}

/** Throttle window in ms: only check once per app foreground within this time. */
export const CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

/** AsyncStorage key holding the last successful version check timestamp. */
export const LAST_CHECK_KEY = '@nftopia/version_check/last_check';

/** AsyncStorage key holding the last known cached gate (for offline reuse). */
export const CACHED_GATE_KEY = '@nftopia/version_check/cached_gate';
