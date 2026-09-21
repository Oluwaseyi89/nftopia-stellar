import React from 'react';
import { ScrollView, StyleSheet, Text, TouchableOpacity } from 'react-native';
import { useTranslation } from 'react-i18next';
import { colors, spacing, borderRadius } from '@/constants/theme';
import type { MarketplaceSortOption } from '@/src/utils/marketplaceViewModels';
import { MARKETPLACE_SORT_OPTIONS } from '@/src/utils/marketplaceViewModels';

const LABEL_KEYS: Record<MarketplaceSortOption, string> = {
  newest: 'marketplace.newest',
  oldest: 'marketplace.oldest',
  price_asc: 'marketplace.priceLow',
  price_desc: 'marketplace.priceHigh',
};

export interface MarketplaceSortBarProps {
  selected: MarketplaceSortOption;
  onSelect: (option: MarketplaceSortOption) => void;
  testID?: string;
}

const MarketplaceSortBar: React.FC<MarketplaceSortBarProps> = ({ selected, onSelect, testID }) => {
  const { t } = useTranslation();

  return (
    <ScrollView
      horizontal
      showsHorizontalScrollIndicator={false}
      contentContainerStyle={styles.content}
      testID={testID}
    >
      {MARKETPLACE_SORT_OPTIONS.map((option) => {
        const isSelected = option === selected;
        return (
          <TouchableOpacity
            key={option}
            style={[styles.chip, isSelected && styles.chipSelected]}
            onPress={() => onSelect(option)}
            activeOpacity={0.7}
            accessibilityRole="button"
            accessibilityState={{ selected: isSelected }}
            testID={testID ? `${testID}-${option}` : undefined}
          >
            <Text style={[styles.label, isSelected && styles.labelSelected]}>
              {t(LABEL_KEYS[option])}
            </Text>
          </TouchableOpacity>
        );
      })}
    </ScrollView>
  );
};

export default MarketplaceSortBar;

const styles = StyleSheet.create({
  content: {
    gap: spacing.sm,
    paddingRight: spacing.lg,
  },
  chip: {
    backgroundColor: colors.surfaceElevated,
    borderRadius: borderRadius.xl,
    paddingVertical: spacing.xs,
    paddingHorizontal: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
  },
  chipSelected: {
    backgroundColor: colors.primary,
    borderColor: colors.primary,
  },
  label: {
    fontSize: 13,
    fontWeight: '600',
    color: colors.text,
  },
  labelSelected: {
    color: '#FFFFFF',
  },
});
