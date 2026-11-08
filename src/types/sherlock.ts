export type CheckStageId =
  | 'domain_identity'
  | 'impersonation'
  | 'domain_age'
  | 'reputation'
  | 'redirects_page'
  | 'certificate'
  | 'security_posture'
  | 'witness';

export type CheckStatus = 'pending' | 'running' | 'done' | 'failed' | 'timed_out';

export type ClueCategory =
  | 'impersonation'
  | 'page_behavior'
  | 'domain_age'
  | 'url_structure'
  | 'redirects'
  | 'community_reports'
  | 'certificate'
  | 'security_headers'
  | 'reputation_override';

export type ClueSeverity = 'low' | 'caution' | 'high' | 'critical' | 'info';

export type SuspicionLevel =
  | 'low'
  | 'caution'
  | 'high_risk'
  | 'highly_suspicious'
  | 'inconclusive';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface Clue {
  id: string;
  code: string;
  name: string;
  finding: string;
  severity: ClueSeverity;
  explanation: string;
  howChecked: string;
  points: number;
  category: ClueCategory;
  isOverride?: boolean;
}

export interface CategoryBreakdown {
  category: Exclude<ClueCategory, 'reputation_override'>;
  label: string;
  points: number;
  rawPoints?: number;
  maxPoints: number;
  examples: string;
  clueCount?: number;
}

export interface ScoreTallySummary {
  categoryPointsSum: number;
  rawCategoryPointsSum: number;
  maxPossibleCategorySum: number;
  overrideActive: boolean;
  overrideAdjustment: number;
  clampingAdjustment: number;
  finalIndex: number | null;
}

export interface SherlockDeduction {
  summary: string;
  keyReasons: string[];
  recommendedActions: string[];
  uncertaintyNote: string;
  text: string;
  source: 'ai' | 'template';
}

export type WitnessCategory =
  | 'phishing'
  | 'financial_fraud'
  | 'fake_recruitment'
  | 'shopping_scam'
  | 'brand_impersonation'
  | 'other';

export interface WitnessReportEntry {
  id: string;
  host: string;
  category: WitnessCategory;
  note?: string;
  createdAt: string;
}

export interface WitnessSummary {
  host: string;
  totalReports: number;
  byCategory: Record<WitnessCategory, number>;
  firstReported: string | null;
  lastReported: string | null;
  corroborated: boolean;
  recentReports?: WitnessReportEntry[];
}

export type SpecialStateType =
  | 'none'
  | 'inconclusive'
  | 'unreachable'
  | 'domain_not_found'
  | 'blocked_url'
  | 'rate_limited'
  | 'partial_results';

export interface InternetAssetFootprint {
  resolvedIps: string[];
  registrar: string | null;
  registeredAt: string | null;
  expiresAt: string | null;
  domainAgeDays: number | null;
  tlsIssuer: string | null;
  tlsSubject: string | null;
  tlsValidFrom: string | null;
  tlsValidTo: string | null;
  tlsProtocol?: string | null;
  httpStatus: number | null;
  serverHeader: string | null;
  redirectChain: string[];
  pageTitle: string | null;
  metaDescription: string | null;
  formsDetected: number;
  hasPasswordInput: boolean;
  presentSecurityHeaders: string[];
  missingSecurityHeaders: string[];
  godaddyCheckUrl: string;
  godaddyWhoisUrl: string;
}

export interface PublicWebExperience {
  sentiment: 'positive' | 'mixed' | 'negative' | 'unverified';
  summary: string;
  highlights: string[];
  sources: Array<{ title: string; url: string }>;
}

export interface CaseReportData {
  id: string;
  host: string;
  sanitizedUrl: string;
  createdAt: string;
  index: number | null;
  level: SuspicionLevel;
  confidence: ConfidenceLevel;
  clues: Clue[];
  categoryBreakdown: CategoryBreakdown[];
  scoreTally?: ScoreTallySummary;
  deduction: SherlockDeduction;
  witness: WitnessSummary;
  internetAssets?: InternetAssetFootprint;
  webExperience?: PublicWebExperience;
  checkStatuses: Record<CheckStageId, CheckStatus>;
  specialState: SpecialStateType;
  specialMessage?: string;
  hasValidHttps: boolean;
  overrideTriggered?: boolean;
  isDemo?: boolean;
}

export interface CheckProgressEvent {
  type: 'stage' | 'complete' | 'error';
  stage?: CheckStageId;
  status?: CheckStatus;
  detail?: string;
  report?: CaseReportData;
  errorCode?: SpecialStateType;
  message?: string;
  targetHost?: string;
  godaddyCheckUrl?: string;
  godaddyWhoisUrl?: string;
}

