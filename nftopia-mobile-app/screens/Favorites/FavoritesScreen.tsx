import React, { useCallback, useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  ActivityIndicator,
  Alert,
  Image,
  RefreshControl,
} from 'react-native';
import { useTranslation } from 'react-i18next';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { MainStackParamList } from '@/navigation/MainNavigator';
import { useFavoritesStore } from '@/stores/favoritesStore';
import { FavoriteButton } from '@/components/ui/FavoriteButton';
import { colors, spacing, borderRadius, shadows } from '@/constants/theme';
import apiClient from '@/lib/api/sample';
import type { NFT, Collection } from '@/types';

type FavoritesTab = 'nfts' | 'collections';

export default function FavoritesScreen() {
  const { t } = useTranslation();
  const navigation = useNavigation<NativeStackNavigationProp<MainStackParamList>>();
  const favoriteIds = useFavoritesStore((s) => s.favorites);
  const favoriteCollectionIds = useFavoritesStore((s) => s.favoriteCollections);
  const [tab, setTab] = useState<FavoritesTab>('nfts');

  const [nfts, setNfts] = useState<NFT[]>([]);
  const [collections, setCollections] = useState<Collection[]>([]);
  const [loadingNfts, setLoadingNfts] = useState(false);
  const [loadingCollections, setLoadingCollections] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const loadNfts = useCallback(async () => {
    if (favoriteIds.length === 0) {
      setNfts([]);
      setLoadingNfts(false);
      return;
    }
    setLoadingNfts(true);
    try {
      const results = await Promise.all(
        favoriteIds.map((id) =>
          apiClient.getNFTById(id).catch(() => {
            console.warn(`[Favorites] Failed to load NFT ${id}`);
            return null;
          })
        )
      );
      setNfts(results.filter((nft): nft is NFT => nft !== null));
    } catch {
      setNfts([]);
    } finally {
      setLoadingNfts(false);
    }
  }, [favoriteIds]);

  const loadCollections = useCallback(async () => {
    if (favoriteCollectionIds.length === 0) {
      setCollections([]);
      setLoadingCollections(false);
      return;
    }
    setLoadingCollections(true);
    try {
      const results = await Promise.all(
        favoriteCollectionIds.map((id) =>
          apiClient.getCollectionById(id).catch(() => {
            console.warn(`[Favorites] Failed to load collection ${id}`);
            return null;
          })
        )
      );
      setCollections(results.filter((c): c is Collection => c !== null));
    } catch {
      setCollections([]);
    } finally {
      setLoadingCollections(false);
    }
  }, [favoriteCollectionIds]);

  useEffect(() => {
    loadNfts();
  }, [loadNfts]);

  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await Promise.all([loadNfts(), loadCollections()]);
    setRefreshing(false);
  }, [loadNfts, loadCollections]);

  const removeFavorite = useCallback((id: string, isCollection: boolean) => {
    Alert.alert(
      isCollection
        ? t('favorites.removeCollectionTitle')
        : t('favorites.removeTitle'),
      isCollection
        ? t('favorites.removeCollectionMessage')
        : t('favorites.removeMessage'),
      [
        { text: t('common.cancel'), style: 'cancel' },
        {
          text: t('favorites.removeConfirm'),
          style: 'destructive',
          onPress: () => {
            if (isCollection) {
              useFavoritesStore.getState().removeFavoriteCollection(id);
            } else {
              useFavoritesStore.getState().removeFavorite(id);
            }
            loadNfts();
            loadCollections();
          },
        },
      ]
    );
  }, [loadNfts, loadCollections, t]);

  const totalCount = favoriteIds.length + favoriteCollectionIds.length;

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={() => navigation.goBack()}>
          <Text style={styles.backText}>←</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>{t('favorites.title')}</Text>
        {totalCount > 0 && (
          <View style={styles.headerBadge}>
            <Text style={styles.headerBadgeText}>{totalCount}</Text>
          </View>
        )}
      </View>

      <View style={styles.tabs}>
        <TouchableOpacity
          style={[styles.tab, tab === 'nfts' && styles.tabActive]}
          onPress={() => setTab('nfts')}
          accessibilityRole="tab"
          accessibilityState={{ selected: tab === 'nfts' }}
        >
          <Text style={[styles.tabText, tab === 'nfts' && styles.tabTextActive]}>
            {t('favorites.nfts')}
          </Text>
          {favoriteIds.length > 0 && (
            <View style={styles.tabBadge}>
              <Text style={styles.tabBadgeText}>{favoriteIds.length}</Text>
            </View>
          )}
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, tab === 'collections' && styles.tabActive]}
          onPress={() => setTab('collections')}
          accessibilityRole="tab"
          accessibilityState={{ selected: tab === 'collections' }}
        >
          <Text style={[styles.tabText, tab === 'collections' && styles.tabTextActive]}>
            {t('favorites.collections')}
          </Text>
          {favoriteCollectionIds.length > 0 && (
            <View style={styles.tabBadge}>
              <Text style={styles.tabBadgeText}>{favoriteCollectionIds.length}</Text>
            </View>
          )}
        </TouchableOpacity>
      </View>

      {tab === 'nfts' ? (
        <FlatList
          data={nfts}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <TouchableOpacity
              style={styles.itemCard}
              onPress={() => navigation.navigate('NFTDetail', { nftId: item.id })}
              activeOpacity={0.7}
            >
              <Image source={{ uri: item.imageUrl }} style={styles.itemImage} />
              <View style={styles.itemInfo}>
                <Text style={styles.itemName} numberOfLines={1}>{item.name}</Text>
                <Text style={styles.itemSub} numberOfLines={1}>
                  {item.creator?.username || t('common.noResults')}
                </Text>
                {item.price ? (
                  <Text style={styles.itemPrice}>{item.price} {item.currency}</Text>
                ) : null}
              </View>
              <FavoriteButton id={item.id} kind="nft" size="sm" />
            </TouchableOpacity>
          )}
          contentContainerStyle={styles.listContent}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={colors.primary}
            />
          }
          ListEmptyComponent={
            loadingNfts ? (
              <View style={styles.centerLoading}>
                <ActivityIndicator color={colors.primary} />
              </View>
            ) : (
              <EmptyState
                icon="💜"
                title={t('favorites.emptyNftsTitle')}
                message={t('favorites.emptyNftsMessage')}
                ctaLabel={t('favorites.browseNfts')}
                onCta={() => navigation.navigate('Marketplace')}
              />
            )
          }
        />
      ) : (
        <FlatList
          data={collections}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <TouchableOpacity
              style={styles.itemCard}
              onPress={() => navigation.navigate('CollectionDetail', { collectionId: item.id })}
              activeOpacity={0.7}
            >
              <Image source={{ uri: item.imageUrl }} style={styles.itemImage} />
              <View style={styles.itemInfo}>
                <Text style={styles.itemName} numberOfLines={1}>{item.name}</Text>
                <Text style={styles.itemSub} numberOfLines={1}>
                  {item.creator?.username || t('common.noResults')}
                </Text>
                <Text style={styles.itemPrice}>{item.nftCount} {t('favorites.nftCountLabel')}</Text>
              </View>
              <FavoriteButton id={item.id} kind="collection" size="sm" />
            </TouchableOpacity>
          )}
          contentContainerStyle={styles.listContent}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={colors.primary}
            />
          }
          ListEmptyComponent={
            loadingCollections ? (
              <View style={styles.centerLoading}>
                <ActivityIndicator color={colors.primary} />
              </View>
            ) : (
              <EmptyState
                icon="📁"
                title={t('favorites.emptyCollectionsTitle')}
                message={t('favorites.emptyCollectionsMessage')}
                ctaLabel={t('favorites.browseCollections')}
                onCta={() => navigation.navigate('Marketplace')}
              />
            )
          }
        />
      )}
    </View>
  );
}

function EmptyState({
  icon,
  title,
  message,
  ctaLabel,
  onCta,
}: {
  icon: string;
  title: string;
  message: string;
  ctaLabel: string;
  onCta: () => void;
}) {
  return (
    <View style={styles.emptyContainer}>
      <Text style={styles.emptyIcon}>{icon}</Text>
      <Text style={styles.emptyTitle}>{title}</Text>
      <Text style={styles.emptyMessage}>{message}</Text>
      <TouchableOpacity style={styles.emptyCta} onPress={onCta}>
        <Text style={styles.emptyCtaText}>{ctaLabel}</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.md,
    paddingTop: 60,
    backgroundColor: colors.surface,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  backButton: {
    padding: spacing.xs,
    marginRight: spacing.sm,
  },
  backText: {
    fontSize: 24,
    color: colors.text,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: colors.text,
    flex: 1,
  },
  headerBadge: {
    backgroundColor: colors.primary,
    minWidth: 22,
    height: 22,
    borderRadius: 11,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 6,
  },
  headerBadgeText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontWeight: '700',
  },
  tabs: {
    flexDirection: 'row',
    padding: spacing.sm,
    gap: spacing.sm,
    backgroundColor: colors.surface,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  tab: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: borderRadius.lg,
    backgroundColor: colors.surfaceElevated,
  },
  tabActive: {
    backgroundColor: colors.primary,
  },
  tabText: {
    fontSize: 14,
    fontWeight: '600',
    color: colors.textSecondary,
  },
  tabTextActive: {
    color: '#FFFFFF',
  },
  tabBadge: {
    backgroundColor: 'rgba(255,255,255,0.3)',
    minWidth: 18,
    height: 18,
    borderRadius: 9,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 4,
  },
  tabBadgeText: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '700',
  },
  listContent: {
    padding: spacing.md,
    flexGrow: 1,
  },
  itemCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surfaceElevated,
    borderRadius: borderRadius.md,
    padding: spacing.sm,
    marginBottom: spacing.sm,
    ...shadows.sm,
  },
  itemImage: {
    width: 64,
    height: 64,
    borderRadius: borderRadius.sm,
    marginRight: spacing.sm,
    backgroundColor: colors.border,
  },
  itemInfo: {
    flex: 1,
    marginRight: spacing.xs,
  },
  itemName: {
    fontSize: 15,
    fontWeight: '600',
    color: colors.text,
  },
  itemSub: {
    fontSize: 13,
    color: colors.textSecondary,
    marginTop: 2,
  },
  itemPrice: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.primary,
    marginTop: 2,
  },
  centerLoading: {
    padding: spacing.xl,
    alignItems: 'center',
  },
  emptyContainer: {
    alignItems: 'center',
    paddingVertical: spacing.xxl,
    paddingHorizontal: spacing.lg,
  },
  emptyIcon: {
    fontSize: 56,
    marginBottom: spacing.md,
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: colors.text,
    marginBottom: spacing.xs,
    textAlign: 'center',
  },
  emptyMessage: {
    fontSize: 14,
    color: colors.textSecondary,
    textAlign: 'center',
    marginBottom: spacing.lg,
    lineHeight: 20,
  },
  emptyCta: {
    backgroundColor: colors.primary,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
  },
  emptyCtaText: {
    color: '#FFFFFF',
    fontWeight: '700',
    fontSize: 15,
  },
});
