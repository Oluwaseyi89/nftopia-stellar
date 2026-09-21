import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  TextInputProps,
  AccessibilityInfo,
} from 'react-native';

export interface FormInputProps {
  label: string;
  placeholder: string;
  value: string;
  onChangeText: (text: string) => void;
  keyboardType?: 'default' | 'email-address' | 'numeric' | 'phone-pad';
  secureTextEntry?: boolean;
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
  autoCorrect?: boolean;
  editable?: boolean;
  error?: string | null;
  testID?: string;
  multiline?: boolean;
  numberOfLines?: number;
  /** Label for the return key (e.g. "next", "done"). */
  returnKeyType?: TextInputProps['returnKeyType'];
  /** Called when the user presses the return key. Use for focus chaining. */
  onSubmitEditing?: () => void;
  /** Dismiss the keyboard after submit (defaults true for single-line). */
  blurOnSubmit?: boolean;
  /** Imperative handle to programmatically focus the input. */
  inputRef?: React.Ref<TextInput>;
}

export default function FormInput({
  label,
  placeholder,
  value,
  onChangeText,
  keyboardType = 'default',
  secureTextEntry = false,
  autoCapitalize = 'none',
  autoCorrect = false,
  editable = true,
  error,
  testID,
  multiline = false,
  numberOfLines = 1,
  returnKeyType,
  onSubmitEditing,
  blurOnSubmit,
  inputRef,
}: FormInputProps) {
  const [isFocused, setIsFocused] = useState(false);

  useEffect(() => {
    if (error) {
      AccessibilityInfo.announceForAccessibility(error);
    }
  }, [error]);

  return (
    <View style={styles.container}>
      <Text style={styles.label} nativeID={`${testID}-label`}>
        {label}
      </Text>
      <TextInput
        ref={inputRef}
        style={[
          styles.input,
          isFocused ? styles.inputFocused : undefined,
          error ? styles.inputError : undefined,
          !editable ? styles.inputDisabled : undefined,
          multiline ? styles.inputMultiline : undefined,
        ]}
        placeholder={placeholder}
        placeholderTextColor="#999"
        value={value}
        onChangeText={onChangeText}
        keyboardType={keyboardType}
        secureTextEntry={secureTextEntry}
        autoCapitalize={autoCapitalize}
        autoCorrect={autoCorrect}
        editable={editable}
        returnKeyType={returnKeyType}
        onSubmitEditing={onSubmitEditing}
        blurOnSubmit={blurOnSubmit}
        onFocus={() => setIsFocused(true)}
        onBlur={() => setIsFocused(false)}
        testID={testID}
        multiline={multiline}
        numberOfLines={numberOfLines}
        accessible
        accessibilityLabel={label}
        accessibilityHint={error ?? undefined}
        accessibilityState={{ disabled: !editable }}
      />
      {error ? (
        <Text
          style={styles.errorText}
          accessible
          accessibilityRole="text"
          accessibilityLiveRegion="polite"
          testID={testID ? `${testID}-error` : undefined}
        >
          {error}
        </Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    gap: 8,
    marginBottom: 4,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#333',
  },
  input: {
    backgroundColor: '#f8f9fa',
    borderRadius: 12,
    paddingVertical: 16,
    paddingHorizontal: 16,
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#e9ecef',
    minHeight: 52,
  },
  inputFocused: {
    borderColor: '#007AFF',
    backgroundColor: '#fff',
  },
  inputError: {
    borderColor: '#D63228',
    backgroundColor: '#FFF5F5',
  },
  inputDisabled: {
    opacity: 0.6,
    backgroundColor: '#f1f3f5',
  },
  inputMultiline: {
    textAlignVertical: 'top',
    paddingTop: 12,
  },
  errorText: {
    fontSize: 12,
    color: '#D63228',
    marginTop: 4,
  },
});
