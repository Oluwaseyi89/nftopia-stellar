import { renderHook, act } from "@testing-library/react";
import { useStellarTransaction } from "@/components/wallet/hooks/useStellarTransaction";
import * as walletConnectModule from "@/lib/stellar/wallet/walletconnect";
import * as freighterWallet from "@/lib/stellar/wallet/freighter";

jest.mock("@/lib/stellar/wallet/walletconnect");
jest.mock("@/lib/stellar/wallet/freighter");

describe("useStellarTransaction hook", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("signs transaction with WalletConnect provider", async () => {
    (walletConnectModule.signWithWalletConnect as jest.Mock).mockResolvedValue("AAAA_SIGNED_WC_XDR");

    const { result } = renderHook(() => useStellarTransaction("walletconnect", "testnet"));

    let signedXdr: string | undefined;
    await act(async () => {
      signedXdr = await result.current.signTransaction("AAAA_UNSIGNED_XDR");
    });

    expect(walletConnectModule.signWithWalletConnect).toHaveBeenCalledWith(
      "AAAA_UNSIGNED_XDR",
      "testnet"
    );
    expect(signedXdr).toBe("AAAA_SIGNED_WC_XDR");
    expect(result.current.signing).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("handles WalletConnect signing error and updates state", async () => {
    (walletConnectModule.signWithWalletConnect as jest.Mock).mockRejectedValue(
      new Error("User rejected transaction signature")
    );

    const { result } = renderHook(() => useStellarTransaction("walletconnect", "testnet"));

    await act(async () => {
      await expect(result.current.signTransaction("AAAA_UNSIGNED_XDR")).rejects.toThrow(
        "User rejected transaction signature"
      );
    });

    expect(result.current.signing).toBe(false);
    expect(result.current.error).toBe("User rejected transaction signature");
  });
});