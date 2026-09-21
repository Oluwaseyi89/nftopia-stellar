module.exports = {
  testRunner: 'jest',
  runnerConfig: 'e2e/jest.config.js',
  apps: {
    'ios.debug': {
      type: 'ios.app',
      binaryPath: 'ios/build/Build/Products/Debug-iphonesimulator/NFTopia.app',
      build: 'xcodebuild -workspace ios/NFTopia.xcworkspace -scheme NFTopia -configuration Debug -sdk iphonesimulator -derivedDataPath ios/build',
    },
  },
  devices: {
    simulator: { type: 'ios.simulator', device: { type: 'iPhone 15' } },
  },
  configurations: { 'ios.sim': { device: 'simulator', app: 'ios.debug' } },
};
