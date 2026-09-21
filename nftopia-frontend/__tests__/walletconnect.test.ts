import {
  connectWalletConnect,
  signWithWalletConnect,
  disconnectWalletConnect,
  isWalletConnectConnected,
  getWalletConnectAddress,
  getWalletConnectNetwork,
  parseStellarAddress,
  getChainForNetwork,
} from "@/lib/stellar/wallet/walletconnect";

const mockApproval = jest.fn();
const mockConnect = jest.fn();
const mockRequest = jest.fn();
const mockDisconnect = jest.fn();
const mockSessionGet = jest.fn();
const mockOn = jest.fn();

const mockClient = {
  connect: mockConnect,
  request: mockRequest,
  disconnect: mockDisconnect,
  on: mockOn,
  session: {
    get: mockSessionGet,
    values: [] as any[],
  },
};

jest.mock("@walletconnect/sign-client", () => ({
  SignClient: {
    init: jest.fn().mockResolvedValue(mockClient),
  },
}));

describe("lib/stellar/wallet/walletconnect", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
  });

  describe("helper utilities", () => {
    it("parses stellar address correctly from CAIP-10 account string", () => {
      const caip = "stellar:pubnet:GBTESTADDRESS123456789";
      expect(parseStellarAddress(caip)).toBe("GBTESTADDRESS123456789");
    });

    it("returns correct chain for network", () => {
      expect(getChainForNetwork("mainnet")).toBe("stellar:pubnet");
      expect(getChainForNetwork("testnet")).toBe("stellar:testnet");
    });
  });

  describe("connectWalletConnect", () => {
    it("successfully creates pairing URI, waits for approval, and returns address", async () => {
      const mockUri = "wc:sample-pairing-uri@2?relay-protocol=irn";
      const mockSession = {
        topic: "session-topic-123",
        namespaces: {
          stellar: {
            accounts: ["stellar:testnet:GCONNECTACCOUNT123"],
            chains: ["stellar:testnet"],
          },
        },
      };

      mockConnect.mockResolvedValue({
        uri: mockUri,
        approval: mockApproval.mockResolvedValue(mockSession),
      });

      const displayUriCallback = jest.fn();

      const address = await connectWalletConnect("testnet", displayUriCallback);

      expect(displayUriCallback).toHaveBeenCalledWith(mockUri);
      expect(address).toBe("GCONNECTACCOUNT123");
      expect(sessionStorage.getItem("stellar_wc_session")).toContain("GCONNECTACCOUNT123");
      expect(sessionStorage.getItem("stellar_wc_session")).toContain("session-topic-123");
    });

    it("throws error when session has no stellar accounts", async () => {
      mockConnect.mockResolvedValue({
        uri: "wc:uri",
        approval: jest.fn().mockResolvedValue({
          topic: "session-topic-empty",
          namespaces: {
            stellar: {
              accounts: [],
            },
          },
        }),
      });

      await expect(connectWalletConnect("testnet")).rejects.toThrow(
        "No Stellar accounts found in approved WalletConnect session."
      );
    });

    it("handles user rejection gracefully with custom error message", async () => {
      mockConnect.mockResolvedValue({
        uri: "wc:uri",
        approval: jest.fn().mockRejectedValue(new Error("User rejected proposal")),
      });

      await expect(connectWalletConnect("testnet")).rejects.toThrow(
        "Connection request was rejected in your mobile wallet."
      );
    });
  });

  describe("signWithWalletConnect", () => {
    it("signs transaction XDR and returns signed XDR string", async () => {
      const sessionData = {
        topic: "session-topic-123",
        address: "GCONNECTACCOUNT123",
        network: "testnet" as const,
      };
      sessionStorage.setItem("stellar_wc_session", JSON.stringify(sessionData));

      mockSessionGet.mockReturnValue({
        topic: "session-topic-123",
        namespaces: {
          stellar: {
            accounts: ["stellar:testnet:GCONNECTACCOUNT123"],
            chains: ["stellar:testnet"],
          },
        },
      });

      mockRequest.mockResolvedValue({ signedTxXdr: "AAAA_SIGNED_TRANSACTION_XDR" });

      const signedXdr = await signWithWalletConnect("AAAA_UNSIGNED_XDR", "testnet");
      expect(signedXdr).toBe("AAAA_SIGNED_TRANSACTION_XDR");
      expect(mockRequest).toHaveBeenCalledWith({
        topic: "session-topic-123",
        chainId: "stellar:testnet",
        request: {
          method: "stellar_signXdr",
          params: {
            xdr: "AAAA_UNSIGNED_XDR",
            account: "GCONNECTACCOUNT123",
            networkPassphrase: "Test SDF Network ; September 2015",
          },
        },
      });
    });

    it("throws when no active session is present", async () => {
      sessionStorage.clear();
      mockSessionGet.mockImplementation(() => {
        throw new Error("No matching key");
      });
      (mockClient.session as any).values = [];

      await expect(signWithWalletConnect("AAAA_XDR", "testnet")).rejects.toThrow(
        "No active WalletConnect session found."
      );
    });
  });

  describe("disconnectWalletConnect and session queries", () => {
    it("disconnects active session and clears storage", async () => {
      const sessionData = {
        topic: "session-topic-123",
        address: "GCONNECTACCOUNT123",
        network: "testnet" as const,
      };
      sessionStorage.setItem("stellar_wc_session", JSON.stringify(sessionData));
      mockSessionGet.mockReturnValue({ topic: "session-topic-123" });

      await disconnectWalletConnect();

      expect(mockDisconnect).toHaveBeenCalledWith({
        topic: "session-topic-123",
        reason: {
          code: 6000,
          message: "User disconnected session",
        },
      });
      expect(sessionStorage.getItem("stellar_wc_session")).toBeNull();
    });

    it("retrieves address and network from persisted session", async () => {
      const sessionData = {
        topic: "session-topic-456",
        address: "GPERSISTEDADDRESS",
        network: "mainnet" as const,
      };
      sessionStorage.setItem("stellar_wc_session", JSON.stringify(sessionData));
      mockSessionGet.mockReturnValue({ topic: "session-topic-456" });

      const isConnected = await isWalletConnectConnected();
      expect(isConnected).toBe(true);

      const address = await getWalletConnectAddress();
      expect(address).toBe("GPERSISTEDADDRESS");

      const network = await getWalletConnectNetwork();
      expect(network).toBe("mainnet");
    });
  });
});
