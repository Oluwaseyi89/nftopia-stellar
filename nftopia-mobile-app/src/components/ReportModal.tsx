import React, { useState } from 'react';
import { Modal, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { REPORT_REASONS, ReportReason, ReportTargetType, submitReport } from '@/src/services/moderation/report.service';
import { useToast } from '@/src/hooks/useToast';

interface Props {
  visible: boolean;
  targetType: ReportTargetType;
  targetId: string;
  onClose: () => void;
}

export default function ReportModal({ visible, targetType, targetId, onClose }: Props) {
  const [reason, setReason] = useState<ReportReason>('spam');
  const [details, setDetails] = useState('');
  const [hideForMe, setHideForMe] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const { showSuccess, showError } = useToast();

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      await submitReport({ targetType, targetId, reason, details: details.trim() || undefined, hideForMe });
      showSuccess('Report submitted. Thank you for helping keep NFTopia safe.');
      setDetails('');
      onClose();
    } catch (error) {
      showError(error instanceof Error ? error.message : 'Unable to submit report.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.backdrop}>
        <View style={styles.sheet}>
          <Text style={styles.title}>Report content</Text>
          {REPORT_REASONS.map((item) => (
            <Pressable key={item.value} style={styles.reason} onPress={() => setReason(item.value)}>
              <Text style={styles.radio}>{reason === item.value ? '●' : '○'}</Text>
              <Text style={styles.label}>{item.label}</Text>
            </Pressable>
          ))}
          <TextInput
            style={styles.details}
            placeholder="Additional details (optional)"
            value={details}
            onChangeText={setDetails}
            multiline
            maxLength={500}
          />
          <Pressable style={styles.reason} onPress={() => setHideForMe((value) => !value)}>
            <Text style={styles.radio}>{hideForMe ? '☑' : '☐'}</Text>
            <Text style={styles.label}>Hide this content for me</Text>
          </Pressable>
          <View style={styles.actions}>
            <Pressable onPress={onClose} style={styles.cancel}><Text>Cancel</Text></Pressable>
            <Pressable onPress={handleSubmit} disabled={submitting} style={styles.submit}>
              <Text style={styles.submitText}>{submitting ? 'Sending...' : 'Send report'}</Text>
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: 'flex-end', backgroundColor: 'rgba(0,0,0,0.45)' },
  sheet: { backgroundColor: '#fff', padding: 20, borderTopLeftRadius: 18, borderTopRightRadius: 18, gap: 10 },
  title: { fontSize: 20, fontWeight: '700', marginBottom: 4 },
  reason: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 7 },
  radio: { fontSize: 20, color: '#5b45d6' },
  label: { flex: 1, fontSize: 15 },
  details: { minHeight: 80, borderWidth: 1, borderColor: '#ddd', borderRadius: 8, padding: 10, textAlignVertical: 'top' },
  actions: { flexDirection: 'row', justifyContent: 'flex-end', gap: 12, marginTop: 6 },
  cancel: { padding: 12 },
  submit: { backgroundColor: '#5b45d6', borderRadius: 8, padding: 12 },
  submitText: { color: '#fff', fontWeight: '700' },
});
