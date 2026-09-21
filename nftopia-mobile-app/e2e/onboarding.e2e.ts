import { by, device, element, expect } from 'detox';

describe('onboarding and wallet import', () => {
  beforeAll(async () => {
    await device.launchApp({ newInstance: true });
  });

  it('opens wallet setup from onboarding', async () => {
    await expect(element(by.id('onboarding-get-started'))).toBeVisible();
    await element(by.id('onboarding-get-started')).tap();
    await expect(element(by.text('Create Wallet'))).toBeVisible();
  });

  it('exposes both wallet import paths', async () => {
    await device.reloadReactNative();
    await element(by.id('onboarding-get-started')).tap();
    await element(by.text('Import Wallet')).tap();
    await expect(element(by.id('wallet-import-secret-tab'))).toBeVisible();
    await element(by.id('wallet-import-mnemonic-tab')).tap();
    await expect(element(by.id('mnemonic-input'))).toBeVisible();
  });
});
