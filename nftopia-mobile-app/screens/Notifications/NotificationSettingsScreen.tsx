import React, { useCallback, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Switch,
  TouchableOpacity,
  Linking,
} from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import * as Notifications from 'expo-notifications';
import { useNotificationStore } from '@/stores/notificationStore';
import apiClient from '@/lib/api/sample';
import { pushNotificationService } from '@/src/services/pushNotification.service';
import { NOTIFICATION_CATEGORIES, NOTIFICATION_CATEGORY_META, NotificationCategory } from '@/types';

interface SettingRowProps {
  label: string;
  description: string;
  value: boolean;
  onValueChange: (value: boolean) => void;
  disabled?: boolean;
}

function SettingRow({ label, description, value, onValueChange, disabled }: SettingRowProps) {
  return (
    <View style={styles.settingRow}>
      <View style={styles.settingInfo}>
        <Text style={styles.settingLabel}>{label}</Text>
        <Text style={styles.settingDescription}>{description}</Text>
      </View>
      <Switch
        value={value}
        onValueChange={onValueChange}
        disabled={disabled}
        trackColor={{ false: '#E0E0E0', true: '#6C5CE7' }}
        thumbColor="#FFFFFF"
      />
    </View>
  );
}

/** Section titles rendered in this fixed order; categories are grouped under them by `NOTIFICATION_CATEGORY_META[...].section`. */
const SECTION_ORDER = ['Marketplace', 'Social', 'Creation'] as const;

const HOURS = Array.from({ length: 24 }, (_, h) => h);
const formatHour = (h: number) => `${String(h).padStart(2, '0')}:00`;

function HourPicker({
  label,
  selectedHour,
  onSelect,
}: {
  label: string;
  selectedHour: number;
  onSelect: (hour: number) => void;
}) {
  return (
    <View style={styles.hourPicker}>
      <Text style={styles.hourPickerLabel}>{label}</Text>
      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.hourScroll}>
        {HOURS.map((h) => {
          const selected = h === selectedHour;
          return (
            <TouchableOpacity
              key={h}
              accessibilityRole="radio"
              accessibilityState={{ checked: selected }}
              onPress={() => onSelect(h)}
              style={[styles.hourChip, selected && styles.hourChipSelected]}
            >
              <Text style={[styles.hourChipText, selected && styles.hourChipTextSelected]}>
                {formatHour(h)}
              </Text>
            </TouchableOpacity>
          );
        })}
      </ScrollView>
    </View>
  );
}

export default function NotificationSettingsScreen({ navigation }: any) {
  const { preferences, updatePreferences, fetchPreferences } = useNotificationStore();
  const [osPermissionDenied, setOsPermissionDenied] = useState(false);

  useFocusEffect(
    useCallback(() => {
      fetchPreferences();
      apiClient.trackEvent('notification_settings_view', { timestamp: new Date().toISOString() });

      pushNotificationService.getPermissionStatus().then((status) => {
        setOsPermissionDenied(status === Notifications.PermissionStatus.DENIED);
      });
      // Re-checked every time this screen regains focus, so returning from
      // the OS Settings app (where the user may have just granted/denied
      // permission) reflects the current state without needing a manual
      // refresh.
    }, [])
  );

  const handleToggle = (key: keyof typeof preferences, value: boolean) => {
    updatePreferences({ [key]: value } as any);
    apiClient.trackEvent('notification_setting_toggle', { setting: key, value });
  };

  const handleQuietHoursToggle = (enabled: boolean) => {
    updatePreferences({ quietHours: { ...preferences.quietHours, enabled } });
    apiClient.trackEvent('quiet_hours_toggle', { enabled });
  };

  const handleQuietHoursStart = (hour: number) => {
    updatePreferences({
      quietHours: { ...preferences.quietHours, start: formatHour(hour) },
    });
  };

  const handleQuietHoursEnd = (hour: number) => {
    updatePreferences({
      quietHours: { ...preferences.quietHours, end: formatHour(hour) },
    });
  };

  const categoriesBySection = (section: (typeof SECTION_ORDER)[number]) =>
    NOTIFICATION_CATEGORIES.filter((cat) => NOTIFICATION_CATEGORY_META[cat].section === section);

  const startHour = Number(preferences.quietHours.start.split(':')[0]) || 0;
  const endHour = Number(preferences.quietHours.end.split(':')[0]) || 0;

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.backButton}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Notification Settings</Text>
        <View style={{ width: 60 }} />
      </View>

      {osPermissionDenied && preferences.pushEnabled && (
        <View style={styles.banner}>
          <Text style={styles.bannerText}>
            Notifications are turned off in your device settings, so you won't receive any even
            though they're enabled here.
          </Text>
          <TouchableOpacity
            style={styles.bannerButton}
            onPress={() => Linking.openSettings()}
            accessibilityRole="button"
          >
            <Text style={styles.bannerButtonText}>Open Settings</Text>
          </TouchableOpacity>
        </View>
      )}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Push Notifications</Text>
        <SettingRow
          label="Push Notifications"
          description="Receive push notifications for all events"
          value={preferences.pushEnabled}
          onValueChange={(v) => handleToggle('pushEnabled', v)}
        />
      </View>

      {SECTION_ORDER.map((section) => (
        <View key={section} style={styles.section}>
          <Text style={styles.sectionTitle}>{section}</Text>
          {categoriesBySection(section).map((category: NotificationCategory) => (
            <SettingRow
              key={category}
              label={NOTIFICATION_CATEGORY_META[category].label}
              description={NOTIFICATION_CATEGORY_META[category].description}
              value={preferences[category]}
              onValueChange={(v) => handleToggle(category, v)}
            />
          ))}
        </View>
      ))}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Quiet Hours</Text>
        <SettingRow
          label="Quiet Hours"
          description="Silence notification banners and sounds during this window. Notifications still arrive and count as unread — they're just not shown while it's active."
          value={preferences.quietHours.enabled}
          onValueChange={handleQuietHoursToggle}
        />
        {preferences.quietHours.enabled && (
          <>
            <HourPicker label="Starts at" selectedHour={startHour} onSelect={handleQuietHoursStart} />
            <HourPicker label="Ends at" selectedHour={endHour} onSelect={handleQuietHoursEnd} />
          </>
        )}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F8F9FA' },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    paddingTop: 60,
    backgroundColor: '#FFFFFF',
    borderBottomWidth: 1,
    borderBottomColor: '#E8E8E8',
  },
  backButton: { fontSize: 16, color: '#6C5CE7', fontWeight: '500' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#1A1A1A' },
  banner: {
    backgroundColor: '#FFF3E0',
    marginTop: 12,
    marginHorizontal: 12,
    padding: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#FFCC80',
  },
  bannerText: { color: '#8A5A00', fontSize: 13, lineHeight: 18, marginBottom: 10 },
  bannerButton: {
    alignSelf: 'flex-start',
    backgroundColor: '#8A5A00',
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 8,
  },
  bannerButtonText: { color: '#FFFFFF', fontSize: 13, fontWeight: '600' },
  section: {
    backgroundColor: '#FFFFFF',
    marginTop: 12,
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderRadius: 12,
    marginHorizontal: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#1A1A1A',
    marginBottom: 16,
  },
  settingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#F0F0F0',
  },
  settingInfo: { flex: 1, marginRight: 16 },
  settingLabel: { fontSize: 15, color: '#1A1A1A', fontWeight: '500' },
  settingDescription: { fontSize: 12, color: '#999', marginTop: 2 },
  hourPicker: { marginTop: 12 },
  hourPickerLabel: { fontSize: 13, fontWeight: '600', color: '#1A1A1A', marginBottom: 8 },
  hourScroll: { flexDirection: 'row' },
  hourChip: {
    borderWidth: 1,
    borderColor: '#E0E0E0',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 6,
    marginRight: 8,
  },
  hourChipSelected: { backgroundColor: '#6C5CE7', borderColor: '#6C5CE7' },
  hourChipText: { color: '#666', fontSize: 13 },
  hourChipTextSelected: { color: '#FFFFFF', fontWeight: '700' },
});
