import { ThemeColors } from './types';

export const lightColors: ThemeColors = {
  // Primary colors
  primary: '#000000',
  primaryDark: '#333333',
  primaryLight: '#666666',
  
  // Background colors
  background: '#ffffff',
  surface: '#f8f9fa',
  surfaceElevated: '#ffffff',
  surfaceHover: '#f0f0f0',
  
  // Text colors
  text: '#1a1a1a',
  textSecondary: '#666666',
  // #707070 (was #999999): #999999 only reached 2.85:1 against white/surface,
  // failing WCAG AA (4.5:1) for body text. #707070 clears 4.5:1 on both.
  textTertiary: '#707070',
  textInverse: '#ffffff',

  // Border colors
  border: '#e9ecef',
  borderFocused: '#007AFF',
  borderLight: '#f0f0f0',

  // Status colors
  // #D63228 (was #FF3B30): the brighter red only reached 3.32:1 against
  // errorBackground, failing WCAG AA (4.5:1) for error text/labels.
  error: '#D63228',
  errorBackground: '#FFF5F5',
  errorText: '#D63228',

  warning: '#FF9500',
  warningBackground: '#fff3cd',
  warningText: '#856404',

  success: '#34C759',
  successBackground: '#E8F5E9',
  successText: '#2E7D32',

  // #0070EB (was #007AFF): the brighter blue only reached 4.02:1 against
  // white, failing WCAG AA (4.5:1) for link text.
  info: '#0070EB',
  infoBackground: '#e7f3ff',
  infoText: '#084298',
  
  // Network colors
  testnet: '#FF9500',
  mainnet: '#34C759',
  
  // Shadow colors
  shadowColor: '#000000',
  
  // Additional
  overlay: 'rgba(0,0,0,0.5)',
  backdrop: 'rgba(0,0,0,0.3)',
};

export const darkColors: ThemeColors = {
  // Primary colors
  primary: '#ffffff',
  primaryDark: '#e0e0e0',
  primaryLight: '#999999',
  
  // Background colors
  background: '#121212',
  surface: '#1e1e1e',
  surfaceElevated: '#2d2d2d',
  surfaceHover: '#3d3d3d',
  
  // Text colors
  text: '#ffffff',
  textSecondary: '#b0b0b0',
  // #8C8C8C (was #808080): #808080 only reached 4.22:1 against the surface
  // color, failing WCAG AA (4.5:1) for body text.
  textTertiary: '#8C8C8C',
  textInverse: '#000000',
  
  // Border colors
  border: '#333333',
  borderFocused: '#007AFF',
  borderLight: '#404040',
  
  // Status colors
  error: '#FF453A',
  errorBackground: '#2C1A1A',
  errorText: '#FF453A',
  
  warning: '#FF9F0A',
  warningBackground: '#2C241A',
  warningText: '#FF9F0A',
  
  success: '#30D158',
  successBackground: '#1A2C1A',
  successText: '#30D158',
  
  info: '#0A84FF',
  infoBackground: '#1A2430',
  // #2B96FF (was #0A84FF): the darker blue only reached 4.30:1 against
  // infoBackground, failing WCAG AA (4.5:1) for info text.
  infoText: '#2B96FF',
  
  // Network colors
  testnet: '#FF9F0A',
  mainnet: '#30D158',
  
  // Shadow colors
  shadowColor: '#000000',
  
  // Additional
  overlay: 'rgba(0,0,0,0.7)',
  backdrop: 'rgba(0,0,0,0.5)',
};