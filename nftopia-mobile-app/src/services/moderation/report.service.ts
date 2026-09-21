import AsyncStorage from '@react-native-async-storage/async-storage';
import apiClient from '@/lib/api/sample';

export type ReportTargetType = 'nft' | 'collection' | 'profile';
export type ReportReason = 'spam' | 'copyright' | 'offensive' | 'scam' | 'other';

export const REPORT_REASONS: Array<{ value: ReportReason; label: string }> = [
  { value: 'spam', label: 'Spam or misleading content' },
  { value: 'copyright', label: 'Copyright or intellectual property' },
  { value: 'offensive', label: 'Offensive content' },
  { value: 'scam', label: 'Scam or fraud' },
  { value: 'other', label: 'Other' },
];

const REPORTS_KEY = 'moderation:reports';
const RATE_LIMIT_MS = 60 * 1000;

interface StoredReport {
  targetType: ReportTargetType;
  targetId: string;
  submittedAt: number;
}

export interface ReportInput {
  targetType: ReportTargetType;
  targetId: string;
  reason: ReportReason;
  details?: string;
  hideForMe?: boolean;
}

export async function submitReport(input: ReportInput): Promise<void> {
  const reports = await readReports();
  const duplicate = reports.some(
    (report) => report.targetType === input.targetType && report.targetId === input.targetId
  );
  if (duplicate) throw new Error('You have already reported this content.');

  const latest = reports[reports.length - 1];
  if (latest && Date.now() - latest.submittedAt < RATE_LIMIT_MS) {
    throw new Error('Please wait before submitting another report.');
  }

  await apiClient.submitModerationReport(input);

  await AsyncStorage.setItem(
    REPORTS_KEY,
    JSON.stringify([...reports, { ...input, submittedAt: Date.now() }])
  );
  if (input.hideForMe) await hideContent(input.targetType, input.targetId);
}

export async function isContentHidden(targetType: ReportTargetType, targetId: string): Promise<boolean> {
  const hidden = await AsyncStorage.getItem(`moderation:hidden:${targetType}:${targetId}`);
  return hidden === 'true';
}

async function hideContent(targetType: ReportTargetType, targetId: string): Promise<void> {
  await AsyncStorage.setItem(`moderation:hidden:${targetType}:${targetId}`, 'true');
}

async function readReports(): Promise<StoredReport[]> {
  try {
    const raw = await AsyncStorage.getItem(REPORTS_KEY);
    return raw ? (JSON.parse(raw) as StoredReport[]) : [];
  } catch {
    return [];
  }
}
