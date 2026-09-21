const base = require('./app.json');

module.exports = () => {
  const projectId = process.env.EXPO_PROJECT_ID;
  const updates = projectId
    ? { url: `https://u.expo.dev/${projectId}`, enabled: true, checkAutomatically: 'ON_ERROR_RECOVERY' }
    : base.expo.updates;

  return {
    ...base,
    expo: {
      ...base.expo,
      runtimeVersion: { policy: 'appVersion' },
      updates,
      extra: {
        ...base.expo.extra,
        buildCommit: process.env.GITHUB_SHA || process.env.EAS_BUILD_GIT_COMMIT || 'local',
      },
    },
  };
};
