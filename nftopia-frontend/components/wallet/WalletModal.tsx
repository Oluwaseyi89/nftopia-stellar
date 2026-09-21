"use client";

import React, { useEffect, useState, useRef, useCallback } from "react";
import QRCode from "qrcode";
import {
  X,
  AlertCircle,
  Loader2,
  ExternalLink,
  ArrowLeft,
  Copy,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";
import { WalletInfo, WalletProvider } from "@/types/stellar";
import { useStellarWallet } from "./hooks/useStellarWallet";
import { detectInstalledWallets } from "@/lib/stellar/wallet/detection";
import { useTranslation } from "@/hooks/useTranslation";
import { OptimizedImage } from "@/components/image";
import { useToast } from "@/lib/stores";
import { Button } from "@/components/ui/button";
import { telemetry } from "@/lib/telemetry";
import { EVENT_NAMES } from "@/lib/telemetry/events";
import { v4 as uuidv4 } from "uuid";

interface WalletModalProps {
  open: boolean;
  onClose: () => void;
  onConnected?: (address: string) => void;
}

export function WalletModal({ open, onClose, onConnected }: WalletModalProps) {
  const { t } = useTranslation();
  const { showError } = useToast();
  const { connect, connecting, error, connected, address, clearError } = useStellarWallet();
  const [wallets, setWallets] = useState<WalletInfo[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<WalletProvider | null>(null);
  const [view, setView] = useState<"list" | "qr">("list");
  const [isVisible, setIsVisible] = useState(false);
  const [wcUri, setWcUri] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const modalRef = useRef<HTMLDivElement>(null);
  const firstFocusableRef = useRef<HTMLButtonElement>(null);
  const lastFocusedElementRef = useRef<HTMLElement | null>(null);
  const lastShownErrorRef = useRef<string | null>(null);
  const [attemptId, setAttemptId] = useState<string | null>(null);
  const [triggerSource, setTriggerSource] = useState<"header_button" | "cta" | "forced_prompt" | "other">("other");

  useEffect(() => {
    if (open) {
      lastFocusedElementRef.current = document.activeElement as HTMLElement;
      detectInstalledWallets().then(setWallets);
      setIsVisible(true);
      setView("list");
      setWcUri(null);
      setQrDataUrl(null);
      document.body.style.overflow = "hidden";
    } else {
      setIsVisible(false);
      setView("list");
      setWcUri(null);
      setQrDataUrl(null);
      document.body.style.overflow = "";
      lastFocusedElementRef.current?.focus();
    }

    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  useEffect(() => {
    if (connected && address && open) {
      setView("list");
      setWcUri(null);
      onConnected?.(address);
      onClose();
    }
  }, [connected, address, open, onConnected, onClose]);

  // Convert WC URI to QR data URL
  useEffect(() => {
    if (wcUri) {
      QRCode.toDataURL(wcUri, {
        width: 220,
        margin: 1,
        color: {
          dark: "#000000",
          light: "#ffffff",
        },
      })
        .then(setQrDataUrl)
        .catch(() => setQrDataUrl(null));
    } else {
      setQrDataUrl(null);
    }
  }, [wcUri]);

  // Telemetry: modal opened
  useEffect(() => {
    if (open) {
      telemetry.track(EVENT_NAMES.walletConnectModalOpened, {
        surface: "modal",
        trigger_source: triggerSource,
      });
    }
  }, [open, triggerSource]);

  const handleClose = useCallback(
    (reason: "backdrop_click" | "escape_key" | "close_button" | "connect_success" | "route_change" = "close_button") => {
      setView("list");
      setWcUri(null);
      telemetry.track(EVENT_NAMES.walletConnectModalClosed, {
        close_reason: reason,
      });
      onClose();
    },
    [onClose]
  );

  // Handle ESC key press
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) {
        if (view === "qr") {
          setView("list");
          setWcUri(null);
          clearError();
        } else {
          handleClose("escape_key");
        }
      }
    },
    [open, view, clearError, handleClose]
  );

  useEffect(() => {
    if (open) {
      document.addEventListener("keydown", handleKeyDown);
      firstFocusableRef.current?.focus();
    }

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open, handleKeyDown]);

  // Show toast errors for list view
  useEffect(() => {
    if (open && error && view === "list" && error !== lastShownErrorRef.current) {
      lastShownErrorRef.current = error;
      showError(error);
    }
    if (!open || !error) {
      lastShownErrorRef.current = null;
    }
  }, [open, error, view, showError]);

  const handleTabKey = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab" || !modalRef.current) return;

    const focusableElements = modalRef.current.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const firstElement = focusableElements[0] as HTMLElement;
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;

    if (e.shiftKey) {
      if (document.activeElement === firstElement) {
        e.preventDefault();
        lastElement.focus();
      }
    } else {
      if (document.activeElement === lastElement) {
        e.preventDefault();
        firstElement.focus();
      }
    }
  }, []);

  const handleProviderSelect = (provider: WalletProvider, available: boolean) => {
    setSelectedProvider(provider);
    clearError();
    telemetry.track(EVENT_NAMES.walletConnectProviderSelected, {
      provider: provider ?? "unknown",
      provider_available: !!available,
    });
  };

  const handleConnect = async (provider: WalletProvider) => {
    setSelectedProvider(provider);
    clearError();
    const newAttemptId = uuidv4();
    setAttemptId(newAttemptId);
    telemetry.track(EVENT_NAMES.walletConnectSubmitted, {
      provider: provider ?? "unknown",
      surface: "modal",
      attempt_id: newAttemptId,
    });

    if (provider === "walletconnect" || provider === "lobstr") {
      setView("qr");
      setWcUri(null);
      try {
        await connect(provider, (uri) => {
          setWcUri(uri);
        });
      } catch {
        // Error captured in state
      }
    } else {
      await connect(provider);
    }
  };

  const handleCopyUri = async () => {
    if (!wcUri) return;
    try {
      await navigator.clipboard.writeText(wcUri);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Ignore clipboard error
    }
  };

  if (!open) return null;

  const title =
    view === "qr"
      ? t("walletModal.scanTitle") === "walletModal.scanTitle"
        ? "Scan with Mobile Wallet"
        : t("walletModal.scanTitle")
      : t("walletModal.title") === "walletModal.title"
      ? "Connect Wallet"
      : t("walletModal.title");

  const subtitle =
    t("walletModal.subtitle") === "walletModal.subtitle"
      ? "Choose a Stellar wallet to connect. Freighter is recommended for browser use."
      : t("walletModal.subtitle");

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto flex min-h-full items-center justify-center p-3 sm:p-4 text-center animate-in fade-in duration-200"
      onKeyDown={handleTabKey}
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
        onClick={() => handleClose("backdrop_click")}
        aria-hidden="true"
      />

      {/* Modal Card */}
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wallet-modal-title"
        className={`
          relative my-auto w-full max-w-[420px] max-h-[calc(100vh-2rem)] flex flex-col rounded-2xl border border-purple-500/20 bg-gray-950/95 backdrop-blur-md shadow-2xl text-left
          transform transition-all duration-300 ease-out overflow-hidden
          ${isVisible ? "scale-100 opacity-100" : "scale-95 opacity-0"}
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 sm:py-3.5 border-b border-purple-500/10 flex-shrink-0">
          <div className="flex items-center gap-1.5">
            {view === "qr" && (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => {
                  setView("list");
                  setWcUri(null);
                  clearError();
                }}
                aria-label="Back to wallet options"
                className="text-gray-400 hover:text-white min-h-0 h-7 w-7 rounded-lg hover:bg-white/5 mr-0.5"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h2 id="wallet-modal-title" className="text-base sm:text-lg font-semibold text-white">
              {title}
            </h2>
          </div>
          <Button
            ref={firstFocusableRef}
            variant="ghost"
            size="icon"
            onClick={() => handleClose("close_button")}
            aria-label="Close wallet modal"
            className="text-gray-400 hover:text-white min-h-0 h-7 w-7 rounded-lg hover:bg-white/5"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>

        {/* Body */}
        <div className="px-5 py-3 sm:py-4 overflow-y-auto flex-1">
          {view === "list" ? (
            <>
              {error && (
                <div
                  className="mb-3 flex items-start gap-2.5 p-2.5 rounded-lg bg-red-900/30 border border-red-500/30 text-red-300 text-xs sm:text-sm"
                  role="alert"
                >
                  <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
                  <span>{error}</span>
                </div>
              )}

              <p className="text-xs sm:text-sm text-gray-400 mb-3">{subtitle}</p>

              <div className="space-y-2">
                {wallets.map((wallet) => (
                  <WalletOption
                    key={wallet.id}
                    wallet={wallet}
                    isConnecting={connecting && selectedProvider === wallet.id}
                    onConnect={() => {
                      handleProviderSelect(wallet.id, wallet.available);
                      handleConnect(wallet.id);
                    }}
                  />
                ))}
              </div>
            </>
          ) : (
            /* QR View */
            <div className="flex flex-col items-center py-0.5">
              {/* QR Container */}
              <div className="relative w-44 h-44 sm:w-48 sm:h-48 bg-white p-2.5 rounded-xl shadow-inner flex items-center justify-center overflow-hidden">
                {qrDataUrl ? (
                  <img
                    src={qrDataUrl}
                    alt="WalletConnect QR Code"
                    className="w-full h-full object-contain rounded-lg"
                  />
                ) : error ? (
                  <div className="flex flex-col items-center gap-1.5 p-2.5 text-center">
                    <AlertCircle className="h-7 w-7 text-red-500" aria-hidden="true" />
                    <span className="text-xs font-semibold text-gray-800">
                      Connection Failed
                    </span>
                    <p className="text-[10px] sm:text-[11px] text-gray-500 line-clamp-3">{error}</p>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleConnect(selectedProvider || "walletconnect")}
                      className="mt-1 text-xs text-gray-800 border-gray-300 hover:bg-gray-100 min-h-0 h-6 px-2.5 rounded-lg"
                    >
                      <RefreshCw className="h-3 w-3 mr-1" /> Try Again
                    </Button>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-1.5 text-gray-500">
                    <Loader2 className="h-7 w-7 animate-spin text-purple-600" />
                    <span className="text-xs font-medium">Generating QR code…</span>
                  </div>
                )}

                {connecting && qrDataUrl && (
                  <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px] rounded-xl flex flex-col items-center justify-center text-white">
                    <Loader2 className="h-6 w-6 animate-spin text-purple-400 mb-1.5" />
                    <p className="text-xs font-medium">Waiting for wallet approval…</p>
                  </div>
                )}
              </div>

              <p className="text-[11px] sm:text-xs text-gray-400 mt-2.5 text-center max-w-xs">
                Open <strong className="text-gray-200">LOBSTR</strong> (or any WalletConnect <b>Stellar</b> <br /> wallet), scan the code, and approve.
              </p>

              {/* Actions */}
              <div className="w-full mt-3 flex gap-2">
                <Button
                  onClick={handleCopyUri}
                  disabled={!wcUri}
                  className="flex-1 rounded-xl bg-purple-600/25 hover:bg-purple-600/40 border border-purple-500/40 hover:border-purple-400/60 text-white font-medium text-xs min-h-0 h-9 transition-all shadow-sm disabled:opacity-50"
                >
                  {copied ? (
                    <>
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-400 mr-1.5 flex-shrink-0" />
                      <span className="text-green-300 font-medium">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5 mr-1.5 text-purple-300 flex-shrink-0" />
                      <span className="text-white font-medium">Copy Pairing Code</span>
                    </>
                  )}
                </Button>

                <Button
                  variant="ghost"
                  onClick={() => handleConnect(selectedProvider || "walletconnect")}
                  className="rounded-xl text-xs text-gray-300 hover:text-white hover:bg-white/10 border border-purple-500/20 min-h-0 h-9 px-3"
                  title="Refresh QR Code"
                  aria-label="Refresh QR Code"
                >
                  <RefreshCw className="h-3.5 w-3.5 text-purple-300" />
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-2.5 sm:py-3 border-t border-purple-500/10 flex-shrink-0">
          <p className="text-[11px] sm:text-xs text-gray-500 text-center">
            Secured by Stellar blockchain{" "}
            <a
              href="https://stellar.org"
              target="_blank"
              rel="noopener noreferrer"
              className="text-purple-400 hover:text-purple-300 inline-flex items-center gap-1 ml-1"
            >
              stellar.org <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

function WalletOption({
  wallet,
  isConnecting,
  onConnect,
}: {
  key?: string | number;
  wallet: WalletInfo;
  isConnecting: boolean;
  onConnect: (id: WalletProvider) => void;
}) {
  return (
    <Button
      variant="outline"
      onClick={() => onConnect(wallet.id)}
      disabled={isConnecting}
      className="w-full justify-start gap-3 p-2.5 sm:p-3 rounded-xl border-purple-500/15 hover:border-purple-500/40 hover:bg-purple-500/5 min-h-0 h-auto group"
    >
      <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0 overflow-hidden">
        <OptimizedImage
          src={wallet.logo}
          alt={wallet.name}
          width={28}
          height={28}
          className="object-contain"
          fallbackSrc="/images/fallbacks/avatar-fallback.svg"
        />
      </div>

      <div className="flex-1 text-left">
        <div className="flex items-center gap-2">
          <span className="font-medium text-white text-xs sm:text-sm">{wallet.name}</span>
          {wallet.available && (
            <span className="text-[9px] sm:text-[10px] font-medium text-green-400 bg-green-400/10 px-1.5 py-0.5 rounded-full">
              Detected
            </span>
          )}
        </div>
        <p className="text-[11px] sm:text-xs text-gray-500 mt-0.5 leading-tight">{wallet.description}</p>
      </div>

      {isConnecting ? (
        <Loader2 className="h-4 w-4 text-purple-400 animate-spin" aria-label="Connecting..." />
      ) : (
        <span className="text-purple-400 opacity-0 group-hover:opacity-100 transition-opacity" aria-hidden="true">
          →
        </span>
      )}
    </Button>
  );
}
