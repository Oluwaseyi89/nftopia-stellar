import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { WalletModal } from "@/components/wallet/WalletModal";
import { WalletConnectModal } from "@/components/wallet/WalletConnectModal";

const mockConnect = jest.fn();
const mockClearError = jest.fn();

jest.mock("@/components/wallet/hooks/useStellarWallet", () => ({
  useStellarWallet: () => ({
    connect: mockConnect,
    connecting: false,
    error: null,
    connected: false,
    address: null,
    clearError: mockClearError,
  }),
}));

jest.mock("@/lib/stellar/wallet/detection", () => ({
  detectInstalledWallets: jest.fn().mockResolvedValue([
    {
      id: "freighter",
      name: "Freighter",
      logo: "/wallets/freighter.svg",
      description: "Official Stellar browser extension wallet",
      installUrl: "https://www.freighter.app/",
      available: true,
    },
    {
      id: "walletconnect",
      name: "WalletConnect",
      logo: "/wallets/walletconnect.svg",
      description: "Connect mobile wallets via QR code",
      installUrl: "https://walletconnect.com/",
      available: true,
    },
  ]),
}));

jest.mock("@/hooks/useTranslation", () => ({
  useTranslation: () => ({
    t: (k: string) => k,
  }),
}));

jest.mock("@/lib/stores", () => ({
  useToast: () => ({
    showError: jest.fn(),
    showSuccess: jest.fn(),
  }),
}));

jest.mock("qrcode", () => ({
  toDataURL: jest.fn().mockResolvedValue("data:image/png;base64,mockqrdata"),
}));

describe("WalletModal and WalletConnectModal", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders wallet list and opens QR modal when WalletConnect is clicked", async () => {
    const handleClose = jest.fn();

    render(<WalletModal open={true} onClose={handleClose} />);

    expect(await screen.findByText("WalletConnect")).toBeInTheDocument();

    const wcButton = screen.getByRole("button", { name: /WalletConnect/i });
    fireEvent.click(wcButton);

    expect(mockConnect).toHaveBeenCalledWith("walletconnect", expect.any(Function));
    expect(screen.getByRole("dialog", { name: /Scan with Mobile Wallet/i })).toBeInTheDocument();
  });

  it("renders WalletConnectModal with QR code, copy URI button, and instructions", async () => {
    const handleClose = jest.fn();
    const handleRefresh = jest.fn();

    render(
      <WalletConnectModal
        open={true}
        uri="wc:mock-pairing-uri@2"
        loading={false}
        error={null}
        onClose={handleClose}
        onRefresh={handleRefresh}
      />
    );

    expect(screen.getByText(/Scan with Mobile Wallet/i)).toBeInTheDocument();
    expect(screen.getByText(/LOBSTR/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByAltText("WalletConnect QR Code")).toBeInTheDocument();
    });

    const copyBtn = screen.getByRole("button", { name: /Copy Pairing Code/i });
    expect(copyBtn).toBeInTheDocument();
  });

  it("renders error state and retry action in WalletConnectModal", () => {
    const handleClose = jest.fn();
    const handleRefresh = jest.fn();

    render(
      <WalletConnectModal
        open={true}
        uri={null}
        loading={false}
        error="Connection timed out"
        onClose={handleClose}
        onRefresh={handleRefresh}
      />
    );

    expect(screen.getByText("Connection timed out")).toBeInTheDocument();
    const retryBtn = screen.getByRole("button", { name: /Try Again/i });
    fireEvent.click(retryBtn);
    expect(handleRefresh).toHaveBeenCalled();
  });
});