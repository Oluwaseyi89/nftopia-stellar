import React, { useEffect, useState } from 'react';
import { appConfig } from '@/src/config';
import { UpdatePromptModal } from '@/components/ui/UpdatePromptModal';
import type { VersionCheckResult } from '@/lib/versionCheck';
import { startVersionCheckListener, sealCurrentVersion } from '@/lib/versionCheckService';

/**
 * Mounted at the app root. Runs the update check once per app foreground and
 * renders the appropriate soft-nudge / hard-block prompt.
 */
export function VersionCheckManager() {
  const [result, setResult] = useState<VersionCheckResult | null>(null);

  useEffect(() => {
    // Provide the running version so the service can compare against the gate.
    sealCurrentVersion(appConfig.version);

    const unsubscribe = startVersionCheckListener((res) => {
      setResult(res);
    });

    return unsubscribe;
  }, []);

  return <UpdatePromptModal visible={!!result} result={result} />;
}
