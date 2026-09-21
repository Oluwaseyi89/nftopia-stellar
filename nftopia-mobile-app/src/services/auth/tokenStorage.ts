import * as SecureStore from "expo-secure-store";
import AsyncStorage from "@react-native-async-storage/async-storage";

// token keys
const ACCESS_TOKEN_KEY = "nftopia_access_token";
const REFRESH_TOKEN_KEY = "nftopia_refresh_token";
const TOKEN_EXPIRY_KEY = "nftopia_token_expiry";

interface TokenPayload {
  exp?: number;
  iat?: number;
  [key: string]: any;
}

// TokenStorage class for managing tokens in secure storage
export class TokenStorage {
  // Writes through expo-secure-store; if the platform has no secure store
  // (e.g. web) that throws, so fall back to AsyncStorage rather than losing
  // the token entirely. Best-effort persistence without OS-level encryption
  // beats forcing the user to re-authenticate on every load.
  private async setItem(key: string, value: string): Promise<void> {
    try {
      await SecureStore.setItemAsync(key, value);
    } catch {
      await AsyncStorage.setItem(key, value);
    }
  }

  private async getItem(key: string): Promise<string | null> {
    try {
      return await SecureStore.getItemAsync(key);
    } catch {
      return AsyncStorage.getItem(key);
    }
  }

  // A key may have been written via either backend depending on what was
  // available at save time, so clear both to guarantee nothing lingers.
  private async removeItem(key: string): Promise<void> {
    await Promise.all([
      SecureStore.deleteItemAsync(key).catch(() => {}),
      AsyncStorage.removeItem(key).catch(() => {}),
    ]);
  }

  // save tokens
  async saveTokens(accessToken: string, refreshToken: string): Promise<void> {
    await this.setItem(ACCESS_TOKEN_KEY, accessToken);
    await this.setItem(REFRESH_TOKEN_KEY, refreshToken);

    // Extract and store expiry time from JWT
    const expiry = this.getTokenExpiry(accessToken);
    if (expiry) {
      await this.setItem(TOKEN_EXPIRY_KEY, expiry.toString());
    }
  }

  // get access token
  async getAccessToken(): Promise<string | null> {
    return this.getItem(ACCESS_TOKEN_KEY);
  }

  // get refresh token
  async getRefreshToken(): Promise<string | null> {
    return this.getItem(REFRESH_TOKEN_KEY);
  }

  // get token expiry time
  async getTokenExpiryTime(): Promise<number | null> {
    const expiry = await this.getItem(TOKEN_EXPIRY_KEY);
    return expiry ? parseInt(expiry, 10) : null;
  }

  // get time remaining until token expiry (in seconds)
  async getTimeRemaining(): Promise<number | null> {
    const expiry = await this.getTokenExpiryTime();
    if (!expiry) return null;

    const now = Math.floor(Date.now() / 1000);
    const remaining = expiry - now;
    return remaining > 0 ? remaining : 0;
  }

  // check if token is expired
  async isTokenExpired(): Promise<boolean> {
    const remaining = await this.getTimeRemaining();
    return remaining === null ? false : remaining <= 0;
  }

  // Whether there's a stored access token that either has no known expiry
  // (opaque token) or has not yet expired.
  async hasValidSession(): Promise<boolean> {
    const token = await this.getAccessToken();
    if (!token) return false;
    return !(await this.isTokenExpired());
  }

  // decode JWT payload (without verification)
  private decodeToken(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = parts[1];
      const decoded = atob(payload);
      return JSON.parse(decoded) as TokenPayload;
    } catch {
      return null;
    }
  }

  // extract expiry from JWT
  private getTokenExpiry(token: string): number | null {
    const payload = this.decodeToken(token);
    return payload?.exp || null;
  }

  // clear all tokens
  async clearTokens(): Promise<void> {
    await this.removeItem(ACCESS_TOKEN_KEY);
    await this.removeItem(REFRESH_TOKEN_KEY);
    await this.removeItem(TOKEN_EXPIRY_KEY);
  }
}

export const tokenStorage = new TokenStorage();
