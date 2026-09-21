import React, { useEffect } from 'react';
import { View, Text, StyleSheet, AccessibilityInfo } from 'react-native';

interface ValidationErrorProps {
  message: string | null;
  testID?: string;
}

export default function ValidationError({ message, testID }: ValidationErrorProps) {
  useEffect(() => {
    if (message) {
      // Android live regions don't reliably fire on iOS, so announce explicitly
      // to make sure VoiceOver/TalkBack both pick up the new error text.
      AccessibilityInfo.announceForAccessibility(message);
    }
  }, [message]);

  if (!message) return null;

  return (
    <View
      style={styles.container}
      testID={testID}
      accessible
      accessibilityRole="alert"
      accessibilityLiveRegion="polite"
      importantForAccessibility="yes"
    >
      <Text style={styles.errorText}>{message}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    marginTop: 4,
  },
  errorText: {
    fontSize: 12,
    color: '#D63228',
    fontWeight: '500',
  },
});
