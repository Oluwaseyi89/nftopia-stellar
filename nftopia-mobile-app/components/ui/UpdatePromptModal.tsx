import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Modal,
  Platform,
  AccessibilityInfo,
} from 'react-native';
import * as Linking from 'expo-linking';
import { colors, spacing, borderRadius, shadows } from '@/constants/theme';
import type { VersionCheckResult } from '@/lib/versionCheck';
import { getStoreDeepLink } from '@/lib/versionCheck';

export interface UpdatePromptModalProps {
  visible: boolean;
  result: VersionCheckResult | null;
  onClose?: () => void;
  forceDismissible?: boolean;
}

/**
 * In-app update prompt.
 *
 * - Soft nudge (update available): dismissible, offers an update button.
 * - Hard block (update required): non-dismissible, back button is swallowed, the
 *   only action is to open the store; cannot be closed without updating.
 */
export function UpdatePromptModal({
  visible,
  result,
  onClose,
  forceDismissible,
}: UpdatePromptModalProps) {
  if (!result || !visible) return null;

  const isHard = result.state === 'update_required';
  const dismissible = isHard ? false : forceDismissible ?? true;

  React.useEffect(() => {
    if (visible) {
      const message = isHard
        ? 'A new version of NFTopia is required. Please update to continue.'
        : `A new version of NFTopia is available (${result.latest}). Would you like to update?`;
      AccessibilityInfo.announceForAccessibility(message);
    }
  }, [visible, isHard, result.latest]);

  const handleUpdate = async () => {
    const url = getStoreDeepLink(Platform.OS === 'android' ? 'android' : 'ios');
    const supported = await Linking.canOpenURL(url);
    if (supported) {
      await Linking.openURL(url);
    }
  };

  const handleClose = () => {
    if (dismissible && onClose) {
      onClose();
    }
  };

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      // Swallow the hardware back button on Android for the hard block so it
      // cannot be dismissed without updating.
      onRequestClose={handleClose}
      accessibilityViewIsModal
    >
      <View style={styles.overlay}>
        <View
          style={[styles.dialog, isHard && styles.hardDialog]}
          accessible
          accessibilityLiveRegion="assertive"
          accessibilityLabel={
            isHard
              ? 'Update required'
              : `Update available, version ${result.latest}`
          }
        >
          <View style={[styles.iconContainer, isHard && styles.hardIconContainer]}>
            <Text style={styles.icon}>{isHard ? '🚨' : '🔄'}</Text>
          </View>

          <Text style={styles.title}>
            {isHard ? 'Update Required' : 'Update Available'}
          </Text>

          <Text style={styles.message}>
            {isHard
              ? `Your version (${result.currentVersion}) is no longer supported. Update to ${result.latest} to continue using NFTopia.`
              : `A new version (${result.latest}) is available. You're running ${result.currentVersion}.`}
          </Text>

          <View style={styles.buttons}>
            {dismissible && (
              <TouchableOpacity
                style={[styles.button, styles.laterButton]}
                onPress={handleClose}
                accessibilityRole="button"
                accessibilityLabel="Maybe later"
              >
                <Text style={styles.laterText}>Maybe Later</Text>
              </TouchableOpacity>
            )}

            <TouchableOpacity
              style={[styles.button, styles.updateButton, isHard && styles.hardUpdateButton]}
              onPress={handleUpdate}
              accessibilityRole="button"
              accessibilityLabel="Update now"
            >
              <Text style={styles.updateText}>Update Now</Text>
            </TouchableOpacity>
          </View>

          {isHard && (
            <Text style={styles.footerText}>
              This version is no longer supported and may be unstable.
            </Text>
          )}
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.5)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: spacing.xl,
  },
  dialog: {
    backgroundColor: colors.background,
    borderRadius: borderRadius.lg,
    padding: spacing.lg,
    width: '100%',
    maxWidth: 360,
    ...shadows.md,
  },
  hardDialog: {
    borderWidth: 2,
    borderColor: colors.warning,
  },
  iconContainer: {
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  hardIconContainer: {
    marginBottom: spacing.md,
  },
  icon: {
    fontSize: 48,
  },
  title: {
    fontSize: 20,
    fontWeight: '700',
    color: colors.text,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  message: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: spacing.lg,
  },
  buttons: {
    flexDirection: 'row',
    gap: spacing.sm,
  },
  button: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: borderRadius.md,
    alignItems: 'center',
    justifyContent: 'center',
  },
  laterButton: {
    borderWidth: 1,
    borderColor: colors.border,
  },
  laterText: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.textSecondary,
  },
  updateButton: {
    backgroundColor: colors.primary,
  },
  hardUpdateButton: {
    backgroundColor: colors.warning,
  },
  updateText: {
    fontSize: 15,
    fontWeight: '600',
    color: Platform.OS === 'ios' ? '#FFFFFF' : '#1a1a1a',
  },
  footerText: {
    fontSize: 12,
    color: colors.textTertiary,
    textAlign: 'center',
    marginTop: spacing.md,
  },
});
