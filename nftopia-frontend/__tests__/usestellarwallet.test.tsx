import React from "react";
import { renderHook, act } from "@testing-library/react";
import { useStellarWallet } from "@/components/wallet/hooks/useStellarWallet";
import { useWalletStore } from "@/stores/walletStore";
import * as freighterWallet from "@/lib/stellar/wallet/freighter";
import * as albedoWallet from "@/lib/stellar/wallet/albedo";
import * as walletConnectModule from "@/lib/stellar/wallet/walletconnect";

jest.mock("@/lib/stellar/wallet/freighter");
jest.mock("@/lib/stellar/wallet/albedo");
jest.mock("@/lib/stellar/wallet/walletconnect");

describe("useStellarWallet hook", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
    useWalletStore.getState().setDisconnected();
  });

  it("connects with Freighter successfully", async () => {
    (freighterWallet.connectFreighter as jest.Mock).mockResolvedValue("GFREIGHTER12345");

    const { result } = renderHook(() => useStellarWallet());

    await act(async () => {
      await result.current.connect("freighter");
    });

    expect(result.current.connected).toBe(true);
    expect(result.current.address).toBe("GFREIGHTER12345");
    expect(result.current.provider).toBe("freighter");
  });

  it("connects with WalletConnect successfully", async () => {
    (walletConnectModule.connectWalletConnect as jest.Mock).mockResolvedValue("GWALLETCONNECT12345");

    const { result } = renderHook(() => useStellarWallet());
    const mockDisplayUri = jest.fn();

    await act(async () => {
      await result.current.connect("walletconnect", mockDisplayUri);
    });

    expect(walletConnectModule.connectWalletConnect).toHaveBeenCalledWith("testnet", mockDisplayUri);
    expect(result.current.connected).toBe(true);
    expect(result.current.address).toBe("GWALLETCONNECT12345");
    expect(result.current.provider).toBe("walletconnect");
  });

  it("disconnects and clears WalletConnect session", async () => {
    (walletConnectModule.connectWalletConnect as jest.Mock).mockResolvedValue("GWALLETCONNECT12345");
    (walletConnectModule.disconnectWalletConnect as jest.Mock).mockResolvedValue(undefined);

    const { result } = renderHook(() => useStellarWallet());

    await act(async () => {
      await result.current.connect("walletconnect");
    });

    expect(result.current.connected).toBe(true);

    act(() => {
      result.current.disconnect();
    });

    expect(walletConnectModule.disconnectWalletConnect).toHaveBeenCalled();
    expect(result.current.connected).toBe(false);
    expect(result.current.address).toBeNull();
  });

  it("restores WalletConnect session on mount if still connected", async () => {
    sessionStorage.setItem(
      "stellar_wallet_connection",
      JSON.stringify({
        address: "GWALLETCONNECT12345",
        provider: "walletconnect",
        network: "testnet",
      })
    );

    (walletConnectModule.isWalletConnectConnected as jest.Mock).mockResolvedValue(true);
    (walletConnectModule.getWalletConnectAddress as jest.Mock).mockResolvedValue("GWALLETCONNECT12345");

    const { result } = renderHook(() => useStellarWallet());

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(result.current.connected).toBe(true);
    expect(result.current.address).toBe("GWALLETCONNECT12345");
  });
});