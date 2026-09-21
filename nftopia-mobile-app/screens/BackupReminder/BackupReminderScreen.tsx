import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  TextInput,
  Alert,
  Modal,
} from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { MainStackParamList } from '@/navigation/MainNavigator';
import { colors, spacing, borderRadius } from '@/constants/theme';
import { useWalletConnect } from '@/hooks/useWalletConnect';
import { useNavigation } from '@react-navigation/native';

type Props = NativeStackScreenProps<MainStackParamList, 'BackupReminder'>;

type QuizStep = 'intro' | 'quiz' | 'success';

export default function BackupReminderScreen({ navigation }: Props) {
  const { wallets, activeWallet, markBackupConfirmed, updateLastReminderShown } = useWalletConnect();
  const nav = useNavigation();
  
  const [step, setStep] = useState<QuizStep>('intro');
  const [mnemonicWords, setMnemonicWords] = useState<string[]>([]);
  const [userInput, setUserInput] = useState<string[]>(Array(12).fill(''));
  const [selectedWordIndices, setSelectedWordIndices] = useState<number[]>([]);
  const [shuffledWords, setShuffledWords] = useState<string[]>([]);
  const [showSnoozeOptions, setShowSnoozeOptions] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Initialize mnemonic quiz when component mounts
  useEffect(() => {
    if (activeWallet?.mnemonic) {
      const words = activeWallet.mnemonic.split(' ');
      setMnemonicWords(words);
      
      // Create shuffled words for the quiz (include 3 correct words and 9 random words)
      const correctIndices = [3, 6, 9]; // Test words at positions 4, 7, 10
      const correctWords = correctIndices.map(i => words[i]);
      
      // Generate random words (in real app, these would be from a word list)
      const randomWords = [
        'apple', 'brave', 'chair', 'dream', 'eagle', 'flame',
        'giant', 'horse', 'image', 'joker', 'kite', 'lemon'
      ].filter(word => !words.includes(word));
      
      // Shuffle all words
      const allWords = [...correctWords, ...randomWords.slice(0, 9)];
      setShuffledWords(allWords.sort(() => Math.random() - 0.5));
      
      // Set which indices we're testing
      setSelectedWordIndices(correctIndices);
    }
  }, [activeWallet]);

  const handleWordSelect = (word: string, position: number) => {
    const newInput = [...userInput];
    newInput[position] = word;
    setUserInput(newInput);
  };

  const handleClearPosition = (position: number) => {
    const newInput = [...userInput];
    newInput[position] = '';
    setUserInput(newInput);
  };

  const handleVerify = () => {
    if (!activeWallet?.mnemonic) return;
    
    const words = activeWallet.mnemonic.split(' ');
    let allCorrect = true;
    
    selectedWordIndices.forEach((index, i) => {
      if (userInput[i] !== words[index]) {
        allCorrect = false;
      }
    });
    
    if (allCorrect) {
      setStep('success');
      // Mark backup as confirmed
      if (activeWallet.publicKey) {
        markBackupConfirmed(activeWallet.publicKey, true);
      }
    } else {
      Alert.alert(
        'Incorrect Words',
        'Some of the words you selected are incorrect. Please try again.',
        [{ text: 'Try Again', onPress: () => {
          // Clear inputs for the tested positions
          const newInput = [...userInput];
          selectedWordIndices.forEach((_, i) => {
            newInput[i] = '';
          });
          setUserInput(newInput);
        }}]
      );
    }
  };

  const handleSnooze = (days: number) => {
    if (activeWallet?.publicKey) {
      updateLastReminderShown(activeWallet.publicKey);
      setShowSnoozeOptions(false);
      navigation.goBack();
    }
  };

  const handleBackupNow = () => {
    // Navigate to wallet management with auto-export flag
    navigation.goBack();
    nav.navigate('WalletManagement' as any, { autoExport: true });
  };

  const handleSkip = () => {
    Alert.alert(
      'Skip Verification',
      'Are you sure? Your wallet is at risk if you lose your recovery phrase.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Skip',
          style: 'destructive',
          onPress: () => {
            setShowSnoozeOptions(true);
          },
        },
      ]
    );
  };

  const renderIntro = () => (
    <View style={styles.content}>
      <Text style={styles.title}>Backup Verification Reminder</Text>
      <Text style={styles.subtitle}>
        It's been a while since you created your wallet. Let's verify you still remember your recovery phrase.
      </Text>
      
      <View style={[styles.warningBox, { backgroundColor: colors.warningBackground }]}>
        <Text style={styles.warningIcon}>⚠️</Text>
        <Text style={[styles.warningText, { color: colors.warningText }]}>
          If you lose your recovery phrase, you will lose access to your wallet and funds permanently.
        </Text>
      </View>

      <View style={styles.buttonContainer}>
        <TouchableOpacity
          style={styles.primaryButton}
          onPress={() => setStep('quiz')}
        >
          <Text style={styles.primaryButtonText}>Start Verification</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={handleBackupNow}
        >
          <Text style={styles.secondaryButtonText}>Backup Now</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.tertiaryButton}
          onPress={handleSkip}
        >
          <Text style={styles.tertiaryButtonText}>Remind Me Later</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  const renderQuiz = () => (
    <ScrollView style={styles.content} contentContainerStyle={styles.quizContent}>
      <Text style={styles.title}>Verify Your Recovery Phrase</Text>
      <Text style={styles.subtitle}>
        Select the correct words for positions {selectedWordIndices.map(i => i + 1).join(', ')} of your recovery phrase.
      </Text>

      <View style={styles.quizGrid}>
        {selectedWordIndices.map((index, i) => (
          <View key={i} style={styles.quizSlot}>
            <Text style={styles.slotLabel}>Word {index + 1}</Text>
            {userInput[i] ? (
              <View style={styles.selectedWordChip}>
                <Text style={styles.selectedWordText}>{userInput[i]}</Text>
                <TouchableOpacity onPress={() => handleClearPosition(i)}>
                  <Text style={styles.clearText}>✕</Text>
                </TouchableOpacity>
              </View>
            ) : (
              <View style={styles.emptySlot}>
                <Text style={styles.emptySlotText}>Select word below</Text>
              </View>
            )}
          </View>
        ))}
      </View>

      <View style={styles.wordBank}>
        <Text style={styles.wordBankTitle}>Word Bank</Text>
        <View style={styles.wordBankGrid}>
          {shuffledWords.map((word, i) => (
            <TouchableOpacity
              key={i}
              style={styles.wordChip}
              onPress={() => {
                // Find first empty slot
                const emptyIndex = userInput.findIndex(input => !input);
                if (emptyIndex !== -1) {
                  handleWordSelect(word, emptyIndex);
                }
              }}
              disabled={userInput.every(input => input)}
            >
              <Text style={styles.wordChipText}>{word}</Text>
            </TouchableOpacity>
          ))}
        </View>
      </View>

      <View style={styles.buttonContainer}>
        <TouchableOpacity
          style={[styles.primaryButton, !userInput.every(input => input) && styles.buttonDisabled]}
          onPress={handleVerify}
          disabled={!userInput.every(input => input)}
        >
          <Text style={styles.primaryButtonText}>Verify</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={() => setStep('intro')}
        >
          <Text style={styles.secondaryButtonText}>Back</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );

  const renderSuccess = () => (
    <View style={styles.content}>
      <Text style={styles.title}>✅ Backup Verified</Text>
      <Text style={styles.subtitle}>
        Great! You've successfully verified your recovery phrase. Your wallet backup is now confirmed.
      </Text>
      
      <View style={[styles.successBox, { backgroundColor: colors.successBackground }]}>
        <Text style={styles.successIcon}>🎉</Text>
        <Text style={[styles.successText, { color: colors.successText }]}>
          Your wallet is now marked as backed up. You won't see reminder notifications for this wallet.
        </Text>
      </View>

      <TouchableOpacity
        style={styles.primaryButton}
        onPress={() => navigation.goBack()}
      >
        <Text style={styles.primaryButtonText}>Continue to App</Text>
      </TouchableOpacity>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.backText}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.title}>Backup Verification</Text>
        <View style={styles.headerSpacer} />
      </View>

      {step === 'intro' && renderIntro()}
      {step === 'quiz' && renderQuiz()}
      {step === 'success' && renderSuccess()}

      {/* Snooze Options Modal */}
      <Modal
        visible={showSnoozeOptions}
        transparent
        animationType="slide"
        onRequestClose={() => setShowSnoozeOptions(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Remind Me Later</Text>
            <Text style={styles.modalSubtitle}>
              How long would you like to snooze this reminder?
            </Text>
            
            <TouchableOpacity
              style={styles.snoozeOption}
              onPress={() => handleSnooze(1)}
            >
              <Text style={styles.snoozeText}>Tomorrow</Text>
            </TouchableOpacity>
            
            <TouchableOpacity
              style={styles.snoozeOption}
              onPress={() => handleSnooze(7)}
            >
              <Text style={styles.snoozeText}>In 1 week</Text>
            </TouchableOpacity>
            
            <TouchableOpacity
              style={styles.snoozeOption}
              onPress={() => handleSnooze(30)}
            >
              <Text style={styles.snoozeText}>In 1 month</Text>
            </TouchableOpacity>
            
            <TouchableOpacity
              style={styles.cancelOption}
              onPress={() => setShowSnoozeOptions(false)}
            >
              <Text style={styles.cancelText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
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
    justifyContent: 'space-between',
    padding: spacing.lg,
    paddingTop: 60,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  backText: {
    fontSize: 16,
    color: colors.info,
    fontWeight: '500',
  },
  headerSpacer: {
    width: 60,
  },
  content: {
    flex: 1,
    padding: spacing.lg,
  },
  quizContent: {
    paddingBottom: spacing.xl,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: colors.text,
    marginBottom: spacing.sm,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: colors.textSecondary,
    marginBottom: spacing.xl,
    textAlign: 'center',
    lineHeight: 24,
  },
  warningBox: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.sm,
    padding: spacing.md,
    borderRadius: borderRadius.sm,
    marginBottom: spacing.xl,
  },
  warningIcon: {
    fontSize: 20,
  },
  warningText: {
    flex: 1,
    fontSize: 14,
    lineHeight: 20,
  },
  successBox: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.sm,
    padding: spacing.md,
    borderRadius: borderRadius.sm,
    marginBottom: spacing.xl,
  },
  successIcon: {
    fontSize: 24,
  },
  successText: {
    flex: 1,
    fontSize: 14,
    lineHeight: 20,
  },
  quizGrid: {
    gap: spacing.md,
    marginBottom: spacing.xl,
  },
  quizSlot: {
    gap: spacing.xs,
  },
  slotLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: colors.text,
  },
  emptySlot: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
    borderStyle: 'dashed',
    alignItems: 'center',
  },
  emptySlotText: {
    color: colors.textTertiary,
    fontSize: 14,
  },
  selectedWordChip: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.primary,
  },
  selectedWordText: {
    fontSize: 16,
    fontWeight: '600',
    color: colors.primary,
  },
  clearText: {
    fontSize: 16,
    color: colors.error,
    fontWeight: 'bold',
  },
  wordBank: {
    marginBottom: spacing.xl,
  },
  wordBankTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: colors.text,
    marginBottom: spacing.sm,
  },
  wordBankGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
  },
  wordChip: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
  },
  wordChipText: {
    fontSize: 14,
    color: colors.text,
    fontWeight: '500',
  },
  buttonContainer: {
    gap: spacing.sm,
    marginTop: spacing.lg,
  },
  primaryButton: {
    backgroundColor: colors.primary,
    borderRadius: borderRadius.md,
    paddingVertical: 16,
    alignItems: 'center',
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  primaryButtonText: {
    color: colors.textInverse,
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryButton: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    paddingVertical: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
  },
  secondaryButtonText: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '600',
  },
  tertiaryButton: {
    paddingVertical: 16,
    alignItems: 'center',
  },
  tertiaryButtonText: {
    color: colors.textSecondary,
    fontSize: 16,
    fontWeight: '600',
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.5)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: spacing.lg,
  },
  modalContent: {
    backgroundColor: colors.background,
    borderRadius: borderRadius.lg,
    padding: spacing.xl,
    width: '100%',
    maxWidth: 400,
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    color: colors.text,
    marginBottom: spacing.sm,
    textAlign: 'center',
  },
  modalSubtitle: {
    fontSize: 15,
    color: colors.textSecondary,
    marginBottom: spacing.xl,
    textAlign: 'center',
    lineHeight: 22,
  },
  snoozeOption: {
    backgroundColor: colors.surface,
    borderRadius: borderRadius.md,
    paddingVertical: 16,
    alignItems: 'center',
    marginBottom: spacing.sm,
    borderWidth: 1,
    borderColor: colors.border,
  },
  snoozeText: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '600',
  },
  cancelOption: {
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: spacing.sm,
  },
  cancelText: {
    color: colors.textSecondary,
    fontSize: 16,
    fontWeight: '600',
  },
});
