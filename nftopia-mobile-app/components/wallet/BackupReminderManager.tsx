import React, { useEffect, useState } from 'react';
import { useNavigation } from '@react-navigation/native';
import { useWalletConnect } from '@/hooks/useWalletConnect';
import { Alert } from 'react-native';

export function useBackupReminderManager() {
  const navigation = useNavigation();
  const { wallets, lastBackupReminderShown, updateLastReminderShown } = useWalletConnect();
  const [hasChecked, setHasChecked] = useState(false);

  useEffect(() => {
    // Only check once when component mounts
    if (hasChecked || wallets.length === 0) return;

    const checkBackupReminders = async () => {
      const now = new Date();
      const unconfirmedWallets = wallets.filter(wallet => !wallet.backupConfirmed);
      
      if (unconfirmedWallets.length === 0) {
        setHasChecked(true);
        return;
      }

      // Check each unconfirmed wallet
      for (const wallet of unconfirmedWallets) {
        const lastShown = lastBackupReminderShown[wallet.publicKey];
        
        if (!lastShown) {
          // First time reminder - show immediately
          showReminder(wallet.publicKey);
          return;
        }

        const lastShownDate = new Date(lastShown);
        const daysSinceLastReminder = Math.floor(
          (now.getTime() - lastShownDate.getTime()) / (1000 * 60 * 60 * 24)
        );

        // Show reminder after 7 days, or if never shown
        if (daysSinceLastReminder >= 7) {
          showReminder(wallet.publicKey);
          return;
        }
      }
      
      setHasChecked(true);
    };

    checkBackupReminders();
  }, [wallets, lastBackupReminderShown, hasChecked]);

  const showReminder = (publicKey: string) => {
    // Update last shown time immediately to prevent multiple prompts
    updateLastReminderShown(publicKey);
    
    Alert.alert(
      'Backup Verification Reminder',
      'It\'s been a while since you created your wallet. Please verify your recovery phrase backup to keep your wallet secure.',
      [
        {
          text: 'Remind Me Later',
          style: 'cancel',
          onPress: () => {
            // Already updated timestamp, so next reminder will be after snooze period
          },
        },
        {
          text: 'Verify Now',
          onPress: () => {
            navigation.navigate('BackupReminder' as any);
          },
        },
      ]
    );
  };

  return {
    hasUnconfirmedBackups: wallets.some(wallet => !wallet.backupConfirmed),
  };
}

// Component that can be placed in the app to trigger reminders
export default function BackupReminderManager() {
  useBackupReminderManager();
  return null; // This component doesn't render anything
}