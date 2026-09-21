import React, { useRef } from 'react';
import {
  Platform,
  PlatformOSType,
  ScrollView,
  KeyboardAvoidingView,
  Keyboard,
  StyleSheet,
  StyleProp,
  ViewStyle,
  TouchableWithoutFeedback,
  View,
  ScrollViewProps,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

/**
 * Returns the KeyboardAvoidingView behavior appropriate for a platform.
 *
 *  - iOS: `'padding'` pads the container so content lifts above the keyboard.
 *  - Android: `undefined` — the OS uses `adjustResize` to shrink the window, so
 *    an explicit behavior would fight it. Focused inputs stay visible because the
 *    whole form lives inside a scrollable ScrollView.
 */
export function getKeyboardBehavior(
  platform: PlatformOSType = Platform.OS
): 'padding' | undefined {
  return platform === 'ios' ? 'padding' : undefined;
}

export interface KeyboardAwareScreenProps {
  /** Scrollable form body. */
  children: React.ReactNode;
  /** Pinned to the bottom of the screen, stays visible above the keyboard. */
  footer?: React.ReactNode;
  style?: StyleProp<ViewStyle>;
  contentContainerStyle?: StyleProp<ViewStyle>;
  /** Vertical offset (in px) accounting for headers/tabs above the screen. */
  keyboardVerticalOffset?: number;
  /** How the keyboard behaves when the ScrollView is dragged. */
  keyboardDismissMode?: ScrollViewProps['keyboardDismissMode'];
  /** Forwarded to the inner ScrollView (e.g. refreshControl). */
  scrollProps?: Omit<Partial<ScrollViewProps>, 'contentContainerStyle' | 'style'>;
  /** Ref to the inner ScrollView. */
  scrollRef?: React.Ref<ScrollView>;
  testID?: string;
  /** Content test id passed to the ScrollView for querying. */
  scrollTestID?: string;
}

/**
 * Shared keyboard-aware screen wrapper.
 *
 * Provides:
 *   - KeyboardAvoidingView tuned per platform (iOS padding / Android resize),
 *   - a ScrollView so long forms can scroll and inputs avoid the keyboard,
 *   - automatic scroll-to-focused-input on iOS via `automaticallyAdjustKeyboardInsets`,
 *   - tap-outside-to-dismiss the keyboard,
 *   - a safe-area-aware footer pinned above the keyboard,
 *   - configurable keyboardDismissMode while keeping interactive taps working.
 */
export function KeyboardAwareScreen({
  children,
  footer,
  style,
  contentContainerStyle,
  keyboardVerticalOffset = 0,
  keyboardDismissMode = 'interactive',
  scrollProps,
  scrollRef,
  testID,
  scrollTestID,
}: KeyboardAwareScreenProps) {
  const insets = useSafeAreaInsets();
  const internalScrollRef = useRef<ScrollView>(null);
  const resolvedScrollRef = scrollRef ?? internalScrollRef;

  return (
    <KeyboardAvoidingView
      style={[styles.container, style]}
      behavior={getKeyboardBehavior()}
      keyboardVerticalOffset={keyboardVerticalOffset}
      testID={testID}
    >
      <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
        <ScrollView
          ref={resolvedScrollRef}
          style={styles.scroll}
          contentContainerStyle={[styles.content, contentContainerStyle]}
          keyboardShouldPersistTaps="handled"
          keyboardDismissMode={keyboardDismissMode}
          automaticallyAdjustKeyboardInsets={Platform.OS === 'ios'}
          showsVerticalScrollIndicator={false}
          testID={scrollTestID}
          {...scrollProps}
        >
          {children}
        </ScrollView>
      </TouchableWithoutFeedback>

      {footer ? (
        <View style={[styles.footer, { paddingBottom: Math.max(insets.bottom, 16) }]}>
          {footer}
        </View>
      ) : null}
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
  scroll: {
    flex: 1,
  },
  content: {
    padding: 24,
  },
  footer: {
    paddingHorizontal: 24,
    paddingTop: 16,
  },
});
