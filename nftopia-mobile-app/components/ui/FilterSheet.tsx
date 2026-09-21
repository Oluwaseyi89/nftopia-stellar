import React, { useEffect, useState } from 'react';
import {
  KeyboardAvoidingView,
  Modal,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { useTranslation } from 'react-i18next';
import { colors, spacing, borderRadius, shadows } from '@/constants/theme';
import { CATEGORIES } from '@/constants/categories';
import CategoryChip from './CategoryChip';
import {
  MARKETPLACE_STATUS_OPTIONS,
  MarketplaceFilters,
  MarketplaceStatusFilter,
} from '@/src/utils/marketplaceViewModels';

const STATUS_LABEL_KEYS: Record<MarketplaceStatusFilter, string> = {
  ALL: 'marketplace.filters.statusAll',
  ACTIVE: 'marketplace.filters.statusActive',
  SOLD: 'marketplace.filters.statusSold',
};

export interface FilterSheetProps {
  visible: boolean;
  filters: MarketplaceFilters;
  onApply: (draft: Pick<MarketplaceFilters, 'category' | 'status' | 'minPrice' | 'maxPrice'>) => void;
  onClearAll: () => void;
  onClose: () => void;
  testID?: string;
}

/**
 * Bottom sheet holding the "committed on Apply" filters (category, status,
 * price range). Sort lives outside this sheet as its own always-visible
 * control, so it isn't part of the draft here.
 */
const FilterSheet: React.FC<FilterSheetProps> = ({
  visible,
  filters,
  onApply,
  onClearAll,
  onClose,
  testID,
}) => {
  const { t } = useTranslation();

  const [category, setCategory] = useState(filters.category);
  const [status, setStatus] = useState(filters.status);
  const [minPriceText, setMinPriceText] = useState(filters.minPrice?.toString() ?? '');
  const [maxPriceText, setMaxPriceText] = useState(filters.maxPrice?.toString() ?? '');

  // Reset the draft to the committed filters each time the sheet opens, so
  // a dismiss-without-applying never leaks an edited-but-uncommitted value.
  useEffect(() => {
    if (visible) {
      setCategory(filters.category);
      setStatus(filters.status);
      setMinPriceText(filters.minPrice?.toString() ?? '');
      setMaxPriceText(filters.maxPrice?.toString() ?? '');
    }
  }, [visible, filters.category, filters.status, filters.minPrice, filters.maxPrice]);

  const parsePrice = (text: string): number | undefined => {
    if (!text.trim()) return undefined;
    const value = Number(text);
    return Number.isNaN(value) ? undefined : value;
  };

  const minPrice = parsePrice(minPriceText);
  const maxPrice = parsePrice(maxPriceText);
  const priceRangeInvalid = minPrice !== undefined && maxPrice !== undefined && minPrice > maxPrice;

  const handleApply = () => {
    if (priceRangeInvalid) return;
    onApply({ category, status, minPrice, maxPrice });
  };

  const handleClearAll = () => {
    setCategory(undefined);
    setStatus('ACTIVE');
    setMinPriceText('');
    setMaxPriceText('');
    onClearAll();
  };

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.overlay}>
        <TouchableOpacity
          style={StyleSheet.absoluteFill}
          activeOpacity={1}
          onPress={onClose}
          accessibilityLabel="Close filters"
          accessibilityRole="button"
        />
        <KeyboardAvoidingView
          behavior={Platform.OS === 'ios' ? 'padding' : undefined}
          style={styles.sheetWrapper}
        >
          <View style={styles.sheet} testID={testID} accessibilityViewIsModal>
            <View style={styles.handle} />
            <View style={styles.header}>
              <Text style={styles.title} accessibilityRole="header">
                {t('marketplace.filters.title')}
              </Text>
              <TouchableOpacity
                onPress={onClose}
                accessibilityRole="button"
                accessibilityLabel={t('common.close')}
                testID={testID ? `${testID}-close` : undefined}
              >
                <Text style={styles.closeText}>✕</Text>
              </TouchableOpacity>
            </View>

            <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
              <Text style={styles.sectionLabel}>{t('marketplace.filters.category')}</Text>
              <View style={styles.chipRow}>
                {CATEGORIES.map((cat) => (
                  <CategoryChip
                    key={cat.id}
                    category={cat}
                    label={t(cat.labelKey)}
                    selected={cat.id === category}
                    onPress={(selected) => setCategory(selected.id === category ? undefined : selected.id)}
                    testID={testID ? `${testID}-category-${cat.id}` : undefined}
                  />
                ))}
              </View>

              <Text style={styles.sectionLabel}>{t('marketplace.filters.status')}</Text>
              <View style={styles.chipRow}>
                {MARKETPLACE_STATUS_OPTIONS.map((option) => {
                  const isSelected = option === status;
                  return (
                    <TouchableOpacity
                      key={option}
                      style={[styles.statusChip, isSelected && styles.statusChipSelected]}
                      onPress={() => setStatus(option)}
                      accessibilityRole="button"
                      accessibilityState={{ selected: isSelected }}
                      accessibilityLabel={t(STATUS_LABEL_KEYS[option])}
                      testID={testID ? `${testID}-status-${option}` : undefined}
                    >
                      <Text style={[styles.statusLabel, isSelected && styles.statusLabelSelected]}>
                        {t(STATUS_LABEL_KEYS[option])}
                      </Text>
                    </TouchableOpacity>
                  );
                })}
              </View>

              <Text style={styles.sectionLabel}>{t('marketplace.filters.priceRange')}</Text>
              <View style={styles.priceRow}>
                <TextInput
                  style={styles.priceInput}
                  value={minPriceText}
                  onChangeText={setMinPriceText}
                  placeholder={t('marketplace.filters.minPrice')}
                  placeholderTextColor={colors.textTertiary}
                  keyboardType="decimal-pad"
                  accessibilityLabel={t('marketplace.filters.minPrice')}
                  testID={testID ? `${testID}-min-price` : undefined}
                />
                <Text style={styles.priceSeparator}>—</Text>
                <TextInput
                  style={styles.priceInput}
                  value={maxPriceText}
                  onChangeText={setMaxPriceText}
                  placeholder={t('marketplace.filters.maxPrice')}
                  placeholderTextColor={colors.textTertiary}
                  keyboardType="decimal-pad"
                  accessibilityLabel={t('marketplace.filters.maxPrice')}
                  testID={testID ? `${testID}-max-price` : undefined}
                />
              </View>
              {priceRangeInvalid && (
                <Text style={styles.errorText} accessibilityRole="alert">
                  {t('marketplace.filters.priceRangeInvalid')}
                </Text>
              )}
            </ScrollView>

            <View style={styles.footer}>
              <TouchableOpacity
                style={styles.clearButton}
                onPress={handleClearAll}
                accessibilityRole="button"
                accessibilityLabel={t('marketplace.filters.clearAll')}
                testID={testID ? `${testID}-clear-all` : undefined}
              >
                <Text style={styles.clearButtonText}>{t('marketplace.filters.clearAll')}</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.applyButton, priceRangeInvalid && styles.applyButtonDisabled]}
                onPress={handleApply}
                disabled={priceRangeInvalid}
                accessibilityRole="button"
                accessibilityLabel={t('marketplace.filters.apply')}
                accessibilityState={{ disabled: priceRangeInvalid }}
                testID={testID ? `${testID}-apply` : undefined}
              >
                <Text style={styles.applyButtonText}>{t('marketplace.filters.apply')}</Text>
              </TouchableOpacity>
            </View>
          </View>
        </KeyboardAvoidingView>
      </View>
    </Modal>
  );
};

export default FilterSheet;

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.5)',
    justifyContent: 'flex-end',
  },
  sheetWrapper: {
    maxHeight: '85%',
  },
  sheet: {
    backgroundColor: colors.background,
    borderTopLeftRadius: borderRadius.xl,
    borderTopRightRadius: borderRadius.xl,
    paddingBottom: spacing.xl,
    ...shadows.md,
  },
  handle: {
    alignSelf: 'center',
    width: 40,
    height: 4,
    borderRadius: 2,
    backgroundColor: colors.border,
    marginTop: spacing.sm,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: spacing.lg,
    paddingTop: spacing.md,
    paddingBottom: spacing.sm,
  },
  title: {
    fontSize: 18,
    fontWeight: '700',
    color: colors.text,
  },
  closeText: {
    fontSize: 18,
    color: colors.textSecondary,
    padding: spacing.xs,
  },
  content: {
    paddingHorizontal: spacing.lg,
    paddingBottom: spacing.lg,
    gap: spacing.sm,
  },
  sectionLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: colors.text,
    marginTop: spacing.md,
    marginBottom: spacing.xs,
  },
  chipRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
  },
  statusChip: {
    backgroundColor: colors.surfaceElevated,
    borderRadius: borderRadius.xl,
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
  },
  statusChipSelected: {
    backgroundColor: colors.primary,
    borderColor: colors.primary,
  },
  statusLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: colors.text,
  },
  statusLabelSelected: {
    color: '#FFFFFF',
  },
  priceRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  priceInput: {
    flex: 1,
    height: 44,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    fontSize: 16,
    color: colors.text,
    backgroundColor: colors.surfaceElevated,
  },
  priceSeparator: {
    fontSize: 16,
    color: colors.textSecondary,
  },
  errorText: {
    fontSize: 13,
    color: colors.error,
    marginTop: spacing.xs,
  },
  footer: {
    flexDirection: 'row',
    gap: spacing.sm,
    paddingHorizontal: spacing.lg,
    paddingTop: spacing.md,
  },
  clearButton: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    alignItems: 'center',
  },
  clearButtonText: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.textSecondary,
  },
  applyButton: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: borderRadius.md,
    backgroundColor: colors.primary,
    alignItems: 'center',
  },
  applyButtonDisabled: {
    opacity: 0.5,
  },
  applyButtonText: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.textInverse,
  },
});
