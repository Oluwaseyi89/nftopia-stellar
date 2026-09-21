import {
  parseVersion,
  compareVersions,
  isAtLeast,
  isOlder,
  isNewer,
  evaluateVersionState,
  getStoreDeepLink,
} from '../versionCheck';

describe('parseVersion', () => {
  it('parses a standard three-part semver', () => {
    expect(parseVersion('1.2.3')).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: undefined,
    });
  });

  it('treats missing minor/patch as zero', () => {
    expect(parseVersion('2')).toEqual({ major: 2, minor: 0, patch: 0, prerelease: undefined });
    expect(parseVersion('2.5')).toEqual({ major: 2, minor: 5, patch: 0, prerelease: undefined });
  });

  it('handles a leading "v" prefix', () => {
    expect(parseVersion('v3.1.4')?.major).toBe(3);
    expect(parseVersion('V3.1.4')?.major).toBe(3);
  });

  it('strips leading zeros from numeric segments', () => {
    expect(parseVersion('01.02.03')).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: undefined,
    });
  });

  it('parses a prerelease suffix', () => {
    expect(parseVersion('1.0.0-beta')).toEqual({
      major: 1,
      minor: 0,
      patch: 0,
      prerelease: { identifier: 'beta', numeric: undefined },
    });
    expect(parseVersion('1.0.0-beta.2')?.prerelease?.numeric).toBe(2);
  });

  it('returns null for invalid input', () => {
    expect(parseVersion('')).toBeNull();
    expect(parseVersion(null)).toBeNull();
    expect(parseVersion(undefined)).toBeNull();
    expect(parseVersion('abc')).toBeNull();
    expect(parseVersion('1.2.x')).toBeNull();
    expect(parseVersion('1.2.3.4.5')).toBeNull();
  });
});

describe('compareVersions', () => {
  it('compares simple versions correctly', () => {
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
    expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
    expect(compareVersions('1.0.1', '1.0.0')).toBe(1);
    expect(compareVersions('1.2.0', '1.1.9')).toBe(1);
    expect(compareVersions('1.2.0', '2.0.0')).toBe(-1);
  });

  it('treats partial versions with implicit zeros', () => {
    expect(compareVersions('1', '1.0.0')).toBe(0);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
  });

  it('orders prereleases below the release', () => {
    expect(compareVersions('1.0.0-beta', '1.0.0')).toBe(-1);
    expect(compareVersions('1.0.0', '1.0.0-beta')).toBe(1);
    expect(compareVersions('1.0.0-alpha', '1.0.0-beta')).toBe(-1);
  });

  it('compares prerelease numeric identifiers', () => {
    expect(compareVersions('1.0.0-beta.1', '1.0.0-beta.2')).toBe(-1);
    expect(compareVersions('1.0.0-beta.10', '1.0.0-beta.2')).toBe(1);
  });
});

describe('helpers', () => {
  it('isNewer and isOlder are opposites', () => {
    expect(isNewer('2.0.0', '1.0.0')).toBe(true);
    expect(isOlder('1.0.0', '2.0.0')).toBe(true);
    expect(isOlder('2.0.0', '1.0.0')).toBe(false);
  });

  it('isAtLeast includes equality', () => {
    expect(isAtLeast('1.2.0', '1.2.0')).toBe(true);
    expect(isAtLeast('1.3.0', '1.2.0')).toBe(true);
    expect(isAtLeast('1.1.0', '1.2.0')).toBe(false);
  });
});

describe('evaluateVersionState', () => {
  it('requires an update when below the minimum', () => {
    expect(
      evaluateVersionState('1.0.0', { minimum: '1.5.0', latest: '2.0.0' })
    ).toBe('update_required');
  });

  it('offers a soft update when at/above minimum but below latest', () => {
    expect(
      evaluateVersionState('1.5.0', { minimum: '1.5.0', latest: '2.0.0' })
    ).toBe('update_available');
    expect(
      evaluateVersionState('1.9.0', { minimum: '1.5.0', latest: '2.0.0' })
    ).toBe('update_available');
  });

  it('is up to date when current is at or above latest', () => {
    expect(
      evaluateVersionState('2.0.0', { minimum: '1.5.0', latest: '2.0.0' })
    ).toBe('up_to_date');
    expect(
      evaluateVersionState('2.1.0', { minimum: '1.5.0', latest: '2.0.0' })
    ).toBe('up_to_date');
  });

  it('prefers the hard requirement over the soft nudge when both apply', () => {
    // Below minimum and below latest => hard requirement wins.
    expect(
      evaluateVersionState('1.2.0', { minimum: '1.5.0', latest: '3.0.0' })
    ).toBe('update_required');
  });

  it('defaults to up to date on an unparseable current version', () => {
    expect(evaluateVersionState('garbage', { minimum: '1.0.0', latest: '2.0.0' })).toBe(
      'up_to_date'
    );
  });

  it('does not block when remote thresholds are unparseable', () => {
    // An unparseable minimum cannot trigger a hard block.
    expect(evaluateVersionState('1.0.0', { minimum: 'bad', latest: '2.0.0' })).not.toBe(
      'update_required'
    );
    // An unparseable latest cannot trigger a soft/hard prompt at all.
    expect(evaluateVersionState('1.0.0', { minimum: '1.0.0', latest: 'bad' })).toBe(
      'up_to_date'
    );
  });
});

describe('getStoreDeepLink', () => {
  it('returns an App Store link for iOS using the bundle id', () => {
    const link = getStoreDeepLink('ios');
    expect(link).toContain('apps.apple.com');
  });

  it('returns a Play Store link for Android using the package id', () => {
    const link = getStoreDeepLink('android');
    expect(link).toContain('play.google.com');
    expect(link).toContain('id=com.nftopia.app');
  });
});
