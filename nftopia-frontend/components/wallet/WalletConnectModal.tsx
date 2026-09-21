"use client";

import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import { X, AlertCircle, Loader2, Copy, CheckCircle2, RefreshCw, Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/hooks/useTranslation";

interface WalletConnectModalProps {
  open: boolean;
  uri: string | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
  onRefresh?: () => void;
}

export function WalletConnectModal({
  open,
  uri,
  loading,
  error,
  onClose,
  onRefresh,
}: WalletConnectModalProps) {
  const { t } = useTranslation();
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (uri) {
      QRCode.toDataURL(uri, {
        width: 260,
        margin: 2,
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
  }, [uri]);

  if (!open) return null;

  const handleCopyUri = async () => {
    if (!uri) return;
    try {
      await navigator.clipboard.writeText(uri);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Ignore clipboard write failure
    }
  };

  const scanTitle =
    t("walletModal.scanTitle") === "walletModal.scanTitle"
      ? "Scan with Mobile Wallet"
      : t("walletModal.scanTitle");

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby="wc-modal-title"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Card */}
      <div className="relative w-full max-w-[460px] max-h-[90vh] flex flex-col rounded-2xl border border-purple-500/20 bg-gray-950/95 backdrop-blur-md shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-purple-500/10 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Smartphone className="h-5 w-5 text-purple-400" aria-hidden="true" />
            <h3 id="wc-modal-title" className="text-lg font-semibold text-white">
              {scanTitle}
            </h3>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
            aria-label="Close QR Modal"
            className="text-gray-400 hover:text-white min-h-0 h-8 w-8 rounded-lg hover:bg-white/5"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>

        {/* Content */}
        <div className="py-4 flex flex-col items-center overflow-y-auto flex-1">
          {error && qrDataUrl && (
            <div
              className="w-full mb-4 flex items-start gap-2.5 p-3 rounded-lg bg-red-900/30 border border-red-500/30 text-red-300 text-sm"
              role="alert"
            >
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
              <div className="flex-1">
                <p>{error}</p>
                {onRefresh && (
                  <button
                    onClick={onRefresh}
                    className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-purple-300 hover:text-purple-200 underline"
                  >
                    <RefreshCw className="h-3 w-3" /> Try Again
                  </button>
                )}
              </div>
            </div>
          )}

          {/* QR Container */}
          <div className="relative w-56 h-56 bg-white p-3 rounded-2xl shadow-inner flex items-center justify-center overflow-hidden">
            {qrDataUrl ? (
              <img
                src={qrDataUrl}
                alt="WalletConnect QR Code"
                className="w-full h-full object-contain rounded-lg"
              />
            ) : error ? (
              <div className="flex flex-col items-center gap-2 p-3 text-center">
                <AlertCircle className="h-8 w-8 text-red-500" aria-hidden="true" />
                <span className="text-xs font-semibold text-gray-800">
                  Connection Failed
                </span>
                <p className="text-[11px] text-gray-500 line-clamp-3">
                  {error}
                </p>
                {onRefresh && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={onRefresh}
                    className="mt-1 text-xs text-gray-800 border-gray-300 hover:bg-gray-100 min-h-0 h-7 px-3 rounded-lg"
                  >
                    <RefreshCw className="h-3 w-3 mr-1" /> Try Again
                  </Button>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2 text-gray-500">
                <Loader2 className="h-8 w-8 animate-spin text-purple-600" />
                <span className="text-xs font-medium">Generating QR code…</span>
              </div>
            )}

            {loading && qrDataUrl && (
              <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px] rounded-2xl flex flex-col items-center justify-center text-white">
                <Loader2 className="h-7 w-7 animate-spin text-purple-400 mb-2" />
                <p className="text-xs font-medium">Waiting for wallet approval…</p>
              </div>
            )}
          </div>

          <p className="text-xs text-gray-400 mt-3 text-center max-w-xs">
            Open <strong className="text-gray-200">LOBSTR</strong> or any WalletConnect-compatible Stellar wallet, scan the QR code, and approve the connection.
          </p>

          {/* Actions */}
          <div className="w-full mt-4 flex gap-2">
            <Button
              onClick={handleCopyUri}
              disabled={!uri}
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

            {onRefresh && (
              <Button
                variant="ghost"
                onClick={onRefresh}
                className="rounded-xl text-xs text-gray-300 hover:text-white hover:bg-white/10 border border-purple-500/20 min-h-0 h-9 px-3"
                title="Refresh QR Code"
                aria-label="Refresh QR Code"
              >
                <RefreshCw className="h-3.5 w-3.5 text-purple-300" />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
