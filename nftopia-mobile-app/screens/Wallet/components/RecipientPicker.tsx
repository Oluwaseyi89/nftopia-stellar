import React, { useMemo, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, FlatList, StyleSheet, Modal } from 'react-native';
import { colors, spacing, borderRadius } from '@/constants/theme';
import { useAddressBookStore } from '@/stores/addressBookStore';

interface RecipientPickerProps {
  visible: boolean;
  onClose: () => void;
  onSelect: (address: string) => void;
}

export function RecipientPicker({ visible, onClose, onSelect }: RecipientPickerProps) {
  const { entries, recentRecipients, getRecentRecipients } = useAddressBookStore();
  const [query, setQuery] = useState('');

  const filteredEntries = useMemo(() => {
    if (!query.trim()) return entries;
    const lower = query.trim().toLowerCase();
    return entries.filter((e) => e.label.toLowerCase().includes(lower) || e.address.toLowerCase().includes(lower));
  }, [entries, query]);

  const recentFiltered = useMemo(() => {
    const recents = getRecentRecipients(true);
    if (!query.trim()) return recents;
    const lower = query.trim().toLowerCase();
    return recents.filter((r) => r.address.toLowerCase().includes(lower));
  }, [query, entries, recentRecipients, getRecentRecipients]);

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.overlay}>
        <View style={styles.content}>
          <View style={styles.header}>
            <Text style={styles.title}>Select Recipient</Text>
            <TouchableOpacity onPress={onClose}>
              <Text style={styles.close}>✕</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.searchContainer}>
            <TextInput
              style={styles.search}
              placeholder="Search address book"
              placeholderTextColor={colors.textTertiary}
              value={query}
              onChangeText={setQuery}
              accessibilityLabel="Search address book"
            />
          </View>

          <Text style={styles.sectionTitle}>Saved Contacts</Text>
          <FlatList
            data={filteredEntries}
            keyExtractor={(item) => item.id}
            renderItem={({ item }) => (
              <TouchableOpacity style={styles.item} onPress={() => onSelect(item.address)}>
                <Text style={styles.label}>{item.label}</Text>
                <Text style={styles.address} numberOfLines={1}>{item.address}</Text>
              </TouchableOpacity>
            )}
            ListEmptyComponent={<Text style={styles.emptyText}>{entries.length === 0 ? 'No saved contacts' : 'No matches'}</Text>}
            style={styles.list}
          />

          {recentFiltered.length > 0 && (
            <>
              <Text style={styles.sectionTitle}>Recently Sent To</Text>
              <FlatList
                data={recentFiltered}
                keyExtractor={(item) => item.address}
                renderItem={({ item }) => (
                  <TouchableOpacity style={styles.item} onPress={() => onSelect(item.address)}>
                    <Text style={styles.label}>Recent · {item.count}x</Text>
                    <Text style={styles.address} numberOfLines={1}>{item.address}</Text>
                  </TouchableOpacity>
                )}
                style={styles.listShort}
              />
            </>
          )}

          <TouchableOpacity style={styles.closeBtn} onPress={onClose}>
            <Text style={styles.closeBtnText}>Close</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

export default RecipientPicker;

const styles = StyleSheet.create({
  overlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'flex-end' },
  content: {
    backgroundColor: colors.background,
    borderTopLeftRadius: borderRadius.lg,
    borderTopRightRadius: borderRadius.lg,
    maxHeight: '90%',
    paddingBottom: spacing.lg,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: spacing.lg,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  title: { fontSize: 18, fontWeight: '700', color: colors.text },
  close: { fontSize: 20, color: colors.textSecondary, padding: spacing.sm },
  searchContainer: { padding: spacing.md },
  search: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    fontSize: 14,
    color: colors.text,
  },
  sectionTitle: {
    fontSize: 12,
    fontWeight: '600',
    color: colors.textSecondary,
    paddingHorizontal: spacing.md,
    marginTop: spacing.sm,
    marginBottom: spacing.xs,
  },
  list: { maxHeight: 250 },
  listShort: { maxHeight: 150 },
  item: {
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.borderLight,
  },
  label: { fontSize: 14, fontWeight: '600', color: colors.text },
  address: { fontSize: 12, fontFamily: 'monospace', color: colors.textSecondary, marginTop: 2 },
  emptyText: { textAlign: 'center', color: colors.textSecondary, padding: spacing.lg, fontSize: 13 },
  closeBtn: {
    marginHorizontal: spacing.md,
    marginTop: spacing.md,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    alignItems: 'center',
  },
  closeBtnText: { fontWeight: '600', color: colors.text },
});
