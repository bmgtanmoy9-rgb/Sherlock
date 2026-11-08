import React, { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Copy,
  ExternalLink,
  Flag,
  Globe,
  HelpCircle,
  Info,
  Lock,
  RotateCcw,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { CaseReportData, Clue, ClueSeverity, WitnessCategory } from '../types/sherlock';
import { CATEGORY_WEIGHTS, LEVEL_METADATA, WITNESS_CATEGORY_LABELS } from '../engine/weightsConfig';

interface CaseReportViewProps {
  report: CaseReportData;
  isSampleSection?: boolean;
  onReportSite?: (host: string) => void;
  onInvestigateAnother?: () => void;
}

function getSeverityMeta(severity: ClueSeverity) {
  switch (severity) {
    case 'critical':
      return {
        label: 'Critical Clue',
        iconSymbol: '🔴',
        bg: 'bg-[#B3342F] text-[#F2E6C9] border-[#F2E6C9]/30',
        Icon: AlertOctagon,
      };
    case 'high':
      return {
        label: 'High Severity',
        iconSymbol: '🟠',
        bg: 'bg-[#D9702E] text-[#170E0B] border-[#170E0B]/30',
        Icon: ShieldAlert,
      };
    case 'caution':
      return {
        label: 'Caution Clue',
        iconSymbol: '🟡',
        bg: 'bg-[#D9A93A] text-[#170E0B] border-[#170E0B]/30',
        Icon: AlertTriangle,
      };
    case 'low':
      return {
        label: 'Low Weight Clue',
        iconSymbol: '🟢',
        bg: 'bg-[#5E8B5A] text-[#F2E6C9] border-[#F2E6C9]/30',
        Icon: Info,
      };
    default:
      return {
        label: 'Informational',
        iconSymbol: '⚪',
        bg: 'bg-[#3B4238] text-[#F2E6C9] border-[#D9C79F]/30',
        Icon: HelpCircle,
      };
  }
}

export const CaseReportView: React.FC<CaseReportViewProps> = ({
  report,
  isSampleSection = false,
  onReportSite,
  onInvestigateAnother,
}) => {
  const [expandedClues, setExpandedClues] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    if (report.clues[0]) {
      initial[report.clues[0].id] = true;
    }
    return initial;
  });
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({});
  const [alreadyEnteredOpen, setAlreadyEnteredOpen] = useState(false);
  const [shareFeedback, setShareFeedback] = useState<string | null>(null);

  const levelMeta = LEVEL_METADATA[report.level];

  const toggleClue = (id: string) => {
    setExpandedClues((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => ({ ...prev, [category]: !prev[category] }));
  };

  const handleShareReport = async () => {
    const shareUrl = `${window.location.origin}/?case=${encodeURIComponent(
      report.id
    )}&host=${encodeURIComponent(report.host)}#home`;
    const shareTitle = `SHERLOCK Case Report · ${report.host}`;
    const shareText = `SHERLOCK Digital Detective Case ${report.id} for ${report.host}: ${
      report.index !== null ? `${report.index}/100` : 'Inconclusive'
    } (${levelMeta.badgeText}, Confidence: ${report.confidence}).`;

    if (navigator.share) {
      try {
        await navigator.share({
          title: shareTitle,
          text: shareText,
          url: shareUrl,
        });
        setShareFeedback('Shared via native share sheet.');
        setTimeout(() => setShareFeedback(null), 3500);
        return;
      } catch {
        // User cancelled or share failed; fall back to clipboard copy
      }
    }

    try {
      await navigator.clipboard.writeText(`${shareText} ${shareUrl}`);
      setShareFeedback('Sanitized report link copied to clipboard (query strings removed).');
    } catch {
      setShareFeedback(`Share link: ${shareUrl}`);
    }
    setTimeout(() => setShareFeedback(null), 4000);
  };

  // Dial SVG arc calculation
  const dialRadius = 52;
  const dialCircumference = 2 * Math.PI * dialRadius;
  const numericScore = report.index ?? 0;
  const strokeDashoffset =
    dialCircumference - (Math.min(100, Math.max(0, numericScore)) / 100) * dialCircumference;

  return (
    <div className="rounded-lg border-2 border-[#C9A04A] bg-[#2A1A14] text-[#F2E6C9] shadow-2xl overflow-hidden">
      {/* Partial Results or Special State Alert Banner */}
      {report.specialState === 'partial_results' && (
        <div className="px-4 py-3 bg-[#D9A93A]/20 border-b border-[#D9A93A] flex items-center gap-3 text-sm text-[#F5CE7A]">
          <AlertTriangle className="w-5 h-5 text-[#D9A93A] shrink-0" />
          <span>
            <strong>Partial Results Notice:</strong>{' '}
            {report.specialMessage ||
              'One or more network checks timed out. Showing verified clues with adjusted confidence.'}
          </span>
        </div>
      )}

      {/* 1. CASE HEADER */}
      <div className="px-4 sm:px-6 py-4 bg-[#170E0B] border-b border-[#4A3024] flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs text-[#D9C79F]">
            <span className="font-typewriter px-2 py-0.5 rounded bg-[#5A1F26] border border-[#C9A04A]/70 text-[#F5CE7A]">
              {report.id}
            </span>
            <span aria-hidden="true">·</span>
            <span className="inline-flex items-center gap-1 font-mono-code">
              <Clock className="w-3.5 h-3.5 text-[#C9A04A]" />
              {new Date(report.createdAt).toLocaleString([], {
                dateStyle: 'medium',
                timeStyle: 'short',
              })}
            </span>
            {isSampleSection && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-[#E9A872] font-semibold">Worked Sample Dossier</span>
              </>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs uppercase tracking-wider text-[#D9C79F]">Target Host:</span>
            <span className="font-mono-code text-base sm:text-lg font-semibold text-[#F5CE7A] break-all">
              {report.host}
            </span>
            <span className="text-xs text-[#D9C79F]">(query string &amp; fragment stripped)</span>
          </div>
        </div>

        {/* HTTPS Padlock Explainer Pill */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-[#2A1A14] border border-[#4A3024] text-xs text-[#D9C79F] self-start md:self-auto">
          <Lock className="w-3.5 h-3.5 text-[#C9A04A] shrink-0" />
          <span>
            {report.hasValidHttps
              ? 'HTTPS Padlock Present (Encrypted ≠ Trustworthy)'
              : 'No Valid HTTPS Padlock'}
          </span>
        </div>
      </div>

      {/* 2. VERDICT BANNER */}
      <div
        className="p-4 sm:p-6 border-b border-[#4A3024] relative overflow-hidden"
        style={{
          background:
            'linear-gradient(135deg, rgba(90, 31, 38, 0.92) 0%, rgba(42, 26, 20, 0.98) 100%)',
        }}
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 sm:gap-6 items-center">
          {/* Dial & Score */}
          <div className="lg:col-span-4 flex flex-col sm:flex-row items-center sm:items-center gap-4 sm:gap-5 text-center sm:text-left">
            <div className="relative w-28 h-28 sm:w-32 sm:h-32 shrink-0 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
                <circle
                  cx="60"
                  cy="60"
                  r={dialRadius}
                  fill="#170E0B"
                  stroke="#4A3024"
                  strokeWidth="10"
                />
                {report.index !== null && (
                  <circle
                    cx="60"
                    cy="60"
                    r={dialRadius}
                    fill="transparent"
                    stroke={levelMeta.colorHex}
                    strokeWidth="10"
                    strokeDasharray={dialCircumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                  />
                )}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-[10px] uppercase tracking-widest text-[#D9C79F]">
                  Suspicion
                </span>
                <span className="font-mono-code text-2xl sm:text-3xl font-bold text-[#F2E6C9] tabular-nums">
                  {report.index !== null ? report.index : '—'}
                </span>
                <span className="font-mono-code text-[11px] text-[#D9C79F]">
                  {report.index !== null ? '/ 100' : 'N/A'}
                </span>
              </div>
            </div>

            <div className="space-y-2 flex flex-col items-center sm:items-start">
              <div className="text-xs uppercase tracking-widest text-[#D9C79F]">Verdict Level</div>
              <div
                className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded border-2 font-bold text-sm sm:text-base shadow-md"
                style={{
                  backgroundColor: '#170E0B',
                  borderColor: levelMeta.colorHex,
                  color: '#F2E6C9',
                }}
              >
                <span aria-hidden="true">{levelMeta.iconSymbol}</span>
                <span>{levelMeta.badgeText}</span>
              </div>

              <div className="flex items-center gap-2 text-xs text-[#F2E6C9] pt-1">
                <span className="text-[#D9C79F]">Confidence:</span>
                <span className="font-mono-code uppercase font-semibold px-2 py-0.5 rounded bg-[#170E0B] border border-[#C9A04A]/60 text-[#F5CE7A]">
                  {report.confidence}
                </span>
              </div>
            </div>
          </div>

          {/* Verdict Explanation & Override Notice */}
          <div className="lg:col-span-8 space-y-2.5 border-t lg:border-t-0 lg:border-l border-[#C9A04A]/30 pt-4 lg:pt-0 lg:pl-6">
            {report.overrideTriggered && (
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-[#B3342F] text-[#F2E6C9] text-xs font-semibold">
                <AlertOctagon className="w-4 h-4 shrink-0" />
                <span>Reputation Feed Override Active (Minimum Index 90/100)</span>
              </div>
            )}
            <h3 className="font-serif-display text-xl sm:text-3xl font-bold text-[#F5CE7A]">
              {report.level === 'low'
                ? '🟢 Low suspicion — No strong warning signs found'
                : `${levelMeta.iconSymbol} ${levelMeta.badgeText} — ${levelMeta.description}`}
            </h3>
            <p className="text-sm sm:text-base text-[#F2E6C9]/95 leading-relaxed">
              {report.level === 'low'
                ? 'No strong warning signs found. This is not a guarantee of safety. Deterministic rules found no high-risk impersonation or phishing form indicators on this address.'
                : `Every point in this ${
                    report.index ?? 'Inconclusive'
                  }/100 Suspicion Index traces directly to the forensic clues pinned below. Rules compute the score; AI only explains the evidence.`}
            </p>
          </div>
        </div>
      </div>

      {/* Main Dossier Content */}
      <div className="p-4 sm:p-6 space-y-8">
        {/* 3. SHERLOCK'S DEDUCTION (Handwritten Note Card) */}
        <section aria-label="Sherlock's Deduction" className="handwritten-note rounded-md p-4 sm:p-6 relative">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b border-[#8C6645]/40">
            <div className="flex items-center gap-2">
              <span className="brass-pin shrink-0" aria-hidden="true" />
              <h4 className="font-serif-display text-xl sm:text-2xl font-bold text-[#5A1F26]">
                Sherlock’s Deduction
              </h4>
            </div>
            <span className="font-mono-code text-[11px] sm:text-xs px-2.5 py-0.5 rounded bg-[#2A1A14] text-[#F5CE7A]">
              {report.deduction.source === 'ai'
                ? 'AI Explanation of Rule Clues · Hedged Language'
                : 'Deterministic Case Template · Hedged Language'}
            </span>
          </div>

          <p className="text-base sm:text-lg leading-relaxed text-[#1B1410] font-medium">
            “{report.deduction.text}”
          </p>

          {report.deduction.keyReasons.length > 0 && (
            <div className="mt-4 pt-3 border-t border-[#8C6645]/30 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-[#2A1A14]">
              <div>
                <p className="font-bold uppercase tracking-wider text-xs text-[#5A1F26] mb-1.5">
                  Key Clues Referenced
                </p>
                <ul className="list-disc list-inside space-y-1">
                  {report.deduction.keyReasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="font-bold uppercase tracking-wider text-xs text-[#5A1F26] mb-1.5">
                  Uncertainty &amp; Padlock Note
                </p>
                <p className="italic">{report.deduction.uncertaintyNote}</p>
              </div>
            </div>
          )}
        </section>

        {/* 4. WHAT SHOULD I DO NOW (Matched to Level + 1-Tap Recovery Panel) */}
        <section
          aria-label="Recommended Actions"
          className="rounded-md bg-[#170E0B] border border-[#C9A04A]/70 p-4 sm:p-5 space-y-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <div>
              <span className="font-mono-code text-xs uppercase tracking-wider text-[#C9A04A]">
                Matched to {levelMeta.iconSymbol} {levelMeta.badgeText}
              </span>
              <h4 className="font-serif-display text-xl sm:text-2xl font-bold text-[#F5CE7A]">
                What Should I Do Now?
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setAlreadyEnteredOpen((prev) => !prev)}
              aria-expanded={alreadyEnteredOpen}
              className="min-h-[44px] px-3.5 py-2 rounded bg-[#5A1F26] hover:bg-[#7C2F37] border border-[#E9A872] text-[#F2E6C9] text-xs sm:text-sm font-semibold flex items-center justify-between sm:justify-center gap-2 transition-colors cursor-pointer"
            >
              <AlertTriangle className="w-4 h-4 text-[#F5CE7A] shrink-0" />
              <span>I already entered my details</span>
              {alreadyEnteredOpen ? (
                <ChevronUp className="w-4 h-4 shrink-0" />
              ) : (
                <ChevronDown className="w-4 h-4 shrink-0" />
              )}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {report.deduction.recommendedActions.map((act, index) => (
              <div
                key={index}
                className="p-3.5 rounded bg-[#2A1A14] border border-[#4A3024] flex items-start gap-2.5 text-sm text-[#F2E6C9]"
              >
                <CheckCircle2 className="w-4 h-4 text-[#C9A04A] shrink-0 mt-0.5" />
                <span>{act}</span>
              </div>
            ))}
          </div>

          {/* Expandable "I already entered my details" emergency panel */}
          {alreadyEnteredOpen && (
            <div className="mt-3 p-4 rounded bg-[#5A1F26]/50 border-2 border-[#E9A872] space-y-3 text-[#F2E6C9]">
              <h5 className="font-serif-display text-lg font-bold text-[#F5CE7A]">
                Emergency 5-Step Recovery Checklist (If You Already Entered Details)
              </h5>
              <ol className="list-decimal list-inside space-y-2 text-sm">
                <li>
                  <strong>Change your password immediately</strong> for that account and any other website where you reused the same password.
                </li>
                <li>
                  <strong>Contact your bank or card provider right away</strong> if you shared card numbers, banking credentials, or a one-time passcode (OTP)—use the number on the back of your physical card.
                </li>
                <li>
                  <strong>Turn on two-factor authentication (2FA)</strong> and check your account settings for unfamiliar logged-in devices or forwarding rules.
                </li>
                <li>
                  <strong>Expect follow-up scam calls or texts</strong> pretending to be the company’s “fraud department” offering to help recover your account.
                </li>
                <li>
                  <strong>Report the incident</strong> through your national cybercrime reporting channel (such as Action Fraud, IC3, ScamShield, or Cert-In).
                </li>
              </ol>
            </div>
          )}
        </section>

        {/* 5. EVIDENCE CARDS (Pinned-Note Style with Desktop Red String Connection) */}
        <section aria-label="Forensic Evidence Cards" className="space-y-4 relative">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <div>
              <span className="font-mono-code text-xs uppercase tracking-wider text-[#C9A04A]">
                Evidence Before Verdict
              </span>
              <h4 className="font-serif-display text-xl sm:text-2xl font-bold text-[#F5CE7A]">
                Pinned Evidence &amp; Forensic Clues ({report.clues.length})
              </h4>
            </div>
            <span className="text-xs text-[#D9C79F]">
              Tap any clue note to inspect “Why this matters” and “How we checked”
            </span>
          </div>

          {/* Decorative thin red string connecting Verdict to Clue Cards on Desktop only */}
          <div
            aria-hidden="true"
            className="hidden lg:block absolute left-1/2 -top-4 bottom-4 w-px bg-[#B3342F]/60 pointer-events-none"
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 relative z-10">
            {report.clues.map((clue: Clue, idx: number) => {
              const sev = getSeverityMeta(clue.severity);
              const isExpanded = Boolean(expandedClues[clue.id]);
              const tiltClass = idx % 2 === 0 ? 'evidence-tilt-even' : 'evidence-tilt-odd';

              return (
                <article
                  key={clue.id}
                  className={`parchment-card rounded-md p-4 transition-transform ${tiltClass} flex flex-col justify-between`}
                >
                  <div>
                    {/* Top Row: Brass Pin + Clue Code + Severity Badge + Points */}
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="brass-pin shrink-0" aria-hidden="true" />
                        <span className="font-mono-code text-xs font-semibold text-[#5A1F26]">
                          {clue.code}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold border ${sev.bg}`}
                        >
                          <span aria-hidden="true">{sev.iconSymbol}</span>
                          <span>{sev.label}</span>
                        </span>
                        <span className="font-mono-code text-xs font-bold px-2 py-0.5 rounded bg-[#170E0B] text-[#F5CE7A]">
                          {clue.isOverride ? 'OVERRIDE ≥90' : `+${clue.points} pts`}
                        </span>
                      </div>
                    </div>

                    <h5 className="font-serif-display text-lg font-bold text-[#1B1410] mb-1">
                      {clue.name}
                    </h5>
                    <p className="text-sm text-[#2A1A14] leading-relaxed">{clue.finding}</p>
                  </div>

                  {/* Expandable "Why this matters" & "How we checked" */}
                  <div className="mt-3 pt-2.5 border-t border-[#8C6645]/40">
                    <button
                      type="button"
                      onClick={() => toggleClue(clue.id)}
                      aria-expanded={isExpanded}
                      className="w-full min-h-[44px] flex items-center justify-between text-xs font-bold uppercase tracking-wider text-[#5A1F26] hover:text-[#1B1410] cursor-pointer"
                    >
                      <span>Why this matters &amp; How we checked</span>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 shrink-0" />
                      )}
                    </button>

                    {isExpanded && (
                      <div className="mt-2.5 space-y-2 text-xs sm:text-sm text-[#1B1410] bg-[#FAF3E3]/80 p-3 rounded border border-[#B59257]/60">
                        <div>
                          <span className="font-bold text-[#5A1F26]">Why this matters: </span>
                          <span>{clue.explanation}</span>
                        </div>
                        <div>
                          <span className="font-bold text-[#5A1F26]">How we checked: </span>
                          <span className="font-mono-code text-xs">{clue.howChecked}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        {/* 6. SCORE BREAKDOWN (Horizontal Bars per Category + Override + Total Calculation Tally) */}
        <section
          aria-label="Suspicion Index Score Breakdown"
          className="rounded-md bg-[#170E0B] border border-[#4A3024] p-4 sm:p-5 space-y-5"
        >
          {(() => {
            const overrideClue = report.clues.find(
              (c) => c.isOverride || c.category === 'reputation_override'
            );
            const isOverrideActive = Boolean(report.overrideTriggered || overrideClue);
            const hasCorroboratingSignal =
              isOverrideActive ||
              report.clues.some(
                (c) =>
                  c.points > 0 &&
                  c.category !== 'community_reports' &&
                  c.category !== 'security_headers'
              );

            // Reconcile category breakdown rows deterministically from CATEGORY_WEIGHTS and report clues
            const reconciledRows = CATEGORY_WEIGHTS.map((def) => {
              const existing = report.categoryBreakdown?.find((r) => r.category === def.category);
              const matchingClues = report.clues.filter((c) => c.category === def.category);
              const positiveClues = matchingClues.filter((c) => c.points > 0);
              const computedRaw = matchingClues.reduce((s, c) => s + Math.max(0, c.points), 0);
              const computedEffective =
                def.category === 'community_reports' && !hasCorroboratingSignal
                  ? Math.min(computedRaw, 3)
                  : computedRaw;
              const computedClamped = Math.min(def.maxPoints, computedEffective);

              return {
                category: def.category,
                label: def.label,
                points: existing !== undefined ? existing.points : computedClamped,
                rawPoints: existing?.rawPoints !== undefined ? existing.rawPoints : computedRaw,
                maxPoints: def.maxPoints,
                examples: def.examples,
                matchingClues,
                positiveClueCount: positiveClues.length,
              };
            });

            const categoryPointsSum =
              report.scoreTally?.categoryPointsSum ??
              reconciledRows.reduce((sum, r) => sum + r.points, 0);
            const maxPossibleSum =
              report.scoreTally?.maxPossibleCategorySum ??
              reconciledRows.reduce((sum, r) => sum + r.maxPoints, 0);
            const finalIndex =
              report.scoreTally?.finalIndex !== undefined
                ? report.scoreTally.finalIndex
                : report.index;

            return (
              <>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 border-b border-[#4A3024] pb-3">
                  <div>
                    <h4 className="font-serif-display text-xl sm:text-2xl font-bold text-[#F5CE7A]">
                      Deterministic Score Breakdown by Category
                    </h4>
                    <p className="text-xs text-[#D9C79F]">
                      Tap any category with active clues to inspect the exact rules that added points
                    </p>
                  </div>
                  <span className="font-mono-code text-xs px-2.5 py-1 rounded bg-[#2A1A14] border border-[#C9A04A]/50 text-[#F5CE7A] self-start sm:self-auto">
                    Total clamped to 100 · Rules decide the number
                  </span>
                </div>

                {/* 8 Category Bars */}
                <div className="space-y-2.5">
                  {reconciledRows.map((row) => {
                    const pct = Math.min(100, Math.round((row.points / row.maxPoints) * 100));
                    const barWidth = row.points === 0 ? 0 : Math.max(6, pct);
                    const hasClues = row.matchingClues.length > 0;
                    const isCatExpanded = Boolean(expandedCategories[row.category]);
                    const wasCapped = row.rawPoints > row.points;

                    return (
                      <div
                        key={row.category}
                        className={`rounded-md p-3 border transition-colors ${
                          row.points > 0
                            ? 'bg-[#231510] border-[#C9A04A]/60'
                            : 'bg-[#1D120E]/70 border-[#4A3024]/70'
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => {
                            if (hasClues) toggleCategory(row.category);
                          }}
                          disabled={!hasClues}
                          aria-expanded={hasClues ? isCatExpanded : undefined}
                          className={`w-full text-left space-y-2 ${
                            hasClues ? 'cursor-pointer' : 'cursor-default'
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2 text-xs sm:text-sm">
                            <div className="flex flex-wrap items-center gap-2">
                              <span
                                className={`font-semibold ${
                                  row.points > 0 ? 'text-[#F5CE7A]' : 'text-[#F2E6C9]/85'
                                }`}
                              >
                                {row.label}
                              </span>
                              <span
                                className={`font-mono-code text-[11px] px-2 py-0.5 rounded border ${
                                  row.positiveClueCount > 0
                                    ? 'bg-[#5A1F26] border-[#C9A04A]/60 text-[#F5CE7A]'
                                    : hasClues
                                    ? 'bg-[#2A1A14] border-[#4A3024] text-[#D9C79F]'
                                    : 'bg-[#170E0B] border-[#4A3024]/60 text-[#8A7F72]'
                                }`}
                              >
                                {row.positiveClueCount > 0
                                  ? `${row.positiveClueCount} warning clue${
                                      row.positiveClueCount === 1 ? '' : 's'
                                    }`
                                  : hasClues
                                  ? '1 info note (0 pts)'
                                  : '0 clues'}
                              </span>
                              {wasCapped && (
                                <span className="font-mono-code text-[11px] text-[#E9A872]">
                                  (raw +{row.rawPoints} capped at {row.maxPoints})
                                </span>
                              )}
                            </div>

                            <div className="flex items-center gap-2 ml-auto">
                              <span
                                className={`font-mono-code font-bold tabular-nums ${
                                  row.points > 0 ? 'text-[#F5CE7A]' : 'text-[#8A7F72]'
                                }`}
                              >
                                +{row.points} / {row.maxPoints} pts
                              </span>
                              {hasClues && (
                                <span className="text-[#C9A04A]">
                                  {isCatExpanded ? (
                                    <ChevronUp className="w-4 h-4" />
                                  ) : (
                                    <ChevronDown className="w-4 h-4" />
                                  )}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="w-full h-2.5 rounded-full bg-[#170E0B] overflow-hidden border border-[#4A3024]">
                            <div
                              className="h-full rounded-full transition-all duration-300"
                              style={{
                                width: `${barWidth}%`,
                                backgroundColor:
                                  row.points === 0
                                    ? 'transparent'
                                    : pct >= 70
                                    ? '#B3342F'
                                    : pct >= 40
                                    ? '#D9702E'
                                    : '#C9A04A',
                              }}
                            />
                          </div>
                        </button>

                        {hasClues && isCatExpanded && (
                          <div className="mt-3 pt-2.5 border-t border-[#4A3024] space-y-1.5">
                            {row.matchingClues.map((c) => (
                              <div
                                key={c.id}
                                className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs bg-[#170E0B] px-3 py-2 rounded border border-[#4A3024]"
                              >
                                <div className="flex items-start sm:items-center gap-2">
                                  <span className="font-mono-code text-[11px] text-[#C9A04A] shrink-0">
                                    {c.code}
                                  </span>
                                  <span className="text-[#F2E6C9] font-medium">{c.name}</span>
                                </div>
                                <span className="font-mono-code text-xs font-bold text-[#F5CE7A] shrink-0 tabular-nums">
                                  +{c.points} pts
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {/* Explicit Reputation Blocklist Override Row when active */}
                  {isOverrideActive && (
                    <div className="rounded-md p-3 bg-[#5A1F26]/50 border-2 border-[#B3342F] space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs sm:text-sm">
                        <div className="flex items-center gap-2">
                          <AlertOctagon className="w-4 h-4 text-[#F5CE7A] shrink-0" />
                          <span className="font-bold text-[#F5CE7A]">
                            Threat Intelligence Feed Override Rule
                          </span>
                          <span className="font-mono-code text-[11px] px-2 py-0.5 rounded bg-[#B3342F] text-[#F2E6C9] font-bold">
                            OVERRIDE ACTIVE
                          </span>
                        </div>
                        <span className="font-mono-code font-bold text-[#F5CE7A] tabular-nums">
                          Forces Index ≥ 90 / 100 pts
                        </span>
                      </div>
                      <div className="w-full h-2.5 rounded-full bg-[#170E0B] overflow-hidden border border-[#B3342F]">
                        <div
                          className="h-full rounded-full bg-[#B3342F]"
                          style={{ width: `${Math.max(90, finalIndex ?? 90)}%` }}
                        />
                      </div>
                      {overrideClue && (
                        <p className="text-xs text-[#F2E6C9]">
                          <strong>Triggered by {overrideClue.code}:</strong> {overrideClue.name} —{' '}
                          {overrideClue.finding}
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {/* TOTAL SCORE CALCULATION TALLY ROW (Reconciles Category Sum -> Final Score) */}
                <div className="mt-4 pt-4 border-t-2 border-[#C9A04A]/60">
                  <div className="rounded-md bg-[#2A1A14] border-2 border-[#C9A04A] p-4 space-y-3 shadow-inner">
                    <div className="flex items-center justify-between text-xs font-mono-code uppercase tracking-wider text-[#C9A04A] border-b border-[#4A3024] pb-2">
                      <span>Forensic Score Calculation Tally</span>
                      <span>Arithmetic Proof</span>
                    </div>

                    <div className="space-y-1.5 text-xs sm:text-sm">
                      <div className="flex items-center justify-between text-[#D9C79F]">
                        <span>Sum of 8 Category Scores:</span>
                        <span className="font-mono-code font-semibold text-[#F2E6C9] tabular-nums">
                          +{categoryPointsSum} pts{' '}
                          <span className="text-xs text-[#D9C79F]">
                            (of {maxPossibleSum} max weight)
                          </span>
                        </span>
                      </div>

                      {isOverrideActive && categoryPointsSum < 90 ? (
                        <div className="flex items-center justify-between text-[#F5CE7A]">
                          <span>Reputation Blocklist Override Rule (Min 90):</span>
                          <span className="font-mono-code font-bold tabular-nums">
                            +{90 - categoryPointsSum} pts adjustment (→ ≥90)
                          </span>
                        </div>
                      ) : categoryPointsSum > 100 ? (
                        <div className="flex items-center justify-between text-[#E9A872]">
                          <span>100-Point Index Ceiling Clamp:</span>
                          <span className="font-mono-code font-bold tabular-nums">
                            −{categoryPointsSum - 100} pts (clamped to 100)
                          </span>
                        </div>
                      ) : finalIndex === null ? (
                        <div className="flex items-center justify-between text-[#D9A93A]">
                          <span>Inconclusive Guard (&lt; 4 checks completed):</span>
                          <span className="font-mono-code font-bold">Score withheld</span>
                        </div>
                      ) : (
                        <div className="flex items-center justify-between text-[#D9C79F]">
                          <span>Override / Ceiling Clamping Adjustment:</span>
                          <span className="font-mono-code text-[#5E8B5A] tabular-nums">
                            +0 pts (Exact 1:1 category sum)
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="pt-2.5 border-t border-[#4A3024] space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-serif-display text-lg sm:text-xl font-bold text-[#F5CE7A]">
                            Final Suspicion Index
                          </span>
                          <span
                            className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded border text-xs font-bold"
                            style={{
                              backgroundColor: '#170E0B',
                              borderColor: levelMeta.colorHex,
                              color: '#F2E6C9',
                            }}
                          >
                            <span aria-hidden="true">{levelMeta.iconSymbol}</span>
                            <span>{levelMeta.badgeText}</span>
                          </span>
                        </div>

                        <span className="font-mono-code text-xl sm:text-2xl font-bold text-[#F5CE7A] tabular-nums">
                          {finalIndex !== null ? `${finalIndex} / 100 pts` : 'Inconclusive'}
                        </span>
                      </div>

                      <div className="w-full h-3 rounded-full bg-[#170E0B] overflow-hidden border border-[#C9A04A]/60">
                        <div
                          className="h-full rounded-full transition-all duration-300"
                          style={{
                            width: `${
                              finalIndex !== null
                                ? Math.min(100, Math.max(0, finalIndex))
                                : 0
                            }%`,
                            backgroundColor: levelMeta.colorHex,
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </>
            );
          })()}
        </section>

        {/* 6B. LIVE INTERNET ASSET & TECHNICAL FOOTPRINT */}
        {report.internetAssets && (
          <section
            aria-label="Live Internet Asset & Technical Footprint"
            className="rounded-md bg-[#170E0B] border border-[#4A3024] p-4 sm:p-5 space-y-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#4A3024] pb-3">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-[#C9A04A]" />
                <div>
                  <h4 className="font-serif-display text-xl font-bold text-[#F5CE7A]">
                    Live Internet Asset &amp; Technical Footprint
                  </h4>
                  <p className="text-xs text-[#D9C79F]">
                    Real-time DNS, RDAP WHOIS registrar, TLS X.509 certificate, and HTTP/HTML metadata
                  </p>
                </div>
              </div>
              <a
                href={`https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(
                  report.host
                )}`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono-code text-xs px-3 py-1.5 rounded bg-[#2A1A14] hover:bg-[#3A241C] border border-[#C9A04A]/60 text-[#F5CE7A] inline-flex items-center gap-1.5 transition-colors"
              >
                <Globe className="w-3.5 h-3.5 text-[#C9A04A]" />
                <span>Verify on GoDaddy WHOIS</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs sm:text-sm">
              {/* DNS & Registrar Card */}
              <div className="rounded bg-[#231510] border border-[#4A3024] p-3.5 space-y-2">
                <div className="font-mono-code text-xs uppercase tracking-wider text-[#C9A04A]">
                  DNS &amp; RDAP Registry Profile
                </div>
                <div className="space-y-1 text-[#F2E6C9]">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Resolved IP(s):</span>
                    <span className="font-mono-code text-right text-[#F5CE7A] tabular-nums">
                      {report.internetAssets.resolvedIps.length > 0
                        ? report.internetAssets.resolvedIps.slice(0, 3).join(', ')
                        : 'Unresolved'}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Registrar:</span>
                    <span className="font-mono-code text-right">
                      {report.internetAssets.registrar || 'Not published in public RDAP'}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Registered Date:</span>
                    <span className="font-mono-code text-right tabular-nums">
                      {report.internetAssets.registeredAt
                        ? `${report.internetAssets.registeredAt.slice(0, 10)}${
                            report.internetAssets.domainAgeDays !== null
                              ? ` (${report.internetAssets.domainAgeDays.toLocaleString()}d old)`
                              : ''
                          }`
                        : 'Unavailable'}
                    </span>
                  </div>
                  {report.internetAssets.expiresAt && (
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-[#D9C79F]">Registry Expiry:</span>
                      <span className="font-mono-code text-right tabular-nums">
                        {report.internetAssets.expiresAt.slice(0, 10)}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* TLS Certificate & HTTPS Card */}
              <div className="rounded bg-[#231510] border border-[#4A3024] p-3.5 space-y-2">
                <div className="font-mono-code text-xs uppercase tracking-wider text-[#C9A04A]">
                  TLS / X.509 Certificate Profile
                </div>
                <div className="space-y-1 text-[#F2E6C9]">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Certificate Issuer:</span>
                    <span className="font-mono-code text-right text-[#F5CE7A]">
                      {report.internetAssets.tlsIssuer || 'No valid TLS certificate'}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Subject CN:</span>
                    <span className="font-mono-code text-right break-all">
                      {report.internetAssets.tlsSubject || report.host}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Issued On:</span>
                    <span className="font-mono-code text-right tabular-nums">
                      {report.internetAssets.tlsValidFrom
                        ? report.internetAssets.tlsValidFrom.slice(0, 10)
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[#D9C79F]">Valid Until:</span>
                    <span className="font-mono-code text-right tabular-nums">
                      {report.internetAssets.tlsValidTo
                        ? report.internetAssets.tlsValidTo.slice(0, 10)
                        : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Live HTTP & HTML Metadata Card */}
              <div className="md:col-span-2 rounded bg-[#231510] border border-[#4A3024] p-3.5 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono-code text-xs uppercase tracking-wider text-[#C9A04A]">
                    Live HTTP Response &amp; HTML DOM Inspection
                  </span>
                  <span className="font-mono-code text-xs text-[#D9C79F] tabular-nums">
                    HTTP Status: {report.internetAssets.httpStatus ?? 'Timed out'} · Forms:{' '}
                    {report.internetAssets.formsDetected} · Password Input:{' '}
                    {report.internetAssets.hasPasswordInput ? 'Yes' : 'No'}
                  </span>
                </div>

                {report.internetAssets.pageTitle && (
                  <p className="text-xs sm:text-sm text-[#F2E6C9]">
                    <span className="text-[#D9C79F]">Page Title: </span>
                    <strong className="font-semibold text-[#F5CE7A]">
                      {report.internetAssets.pageTitle}
                    </strong>
                  </p>
                )}

                {report.internetAssets.metaDescription && (
                  <p className="text-xs text-[#D9C79F] leading-relaxed">
                    <span className="text-[#F2E6C9]/80">Meta Description: </span>
                    {report.internetAssets.metaDescription}
                  </p>
                )}

                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#D9C79F] pt-1">
                  <span>
                    Active Headers:{' '}
                    <strong className="font-mono-code text-[#5E8B5A]">
                      {report.internetAssets.presentSecurityHeaders.length > 0
                        ? report.internetAssets.presentSecurityHeaders.join(', ')
                        : 'None'}
                    </strong>
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    Missing Headers:{' '}
                    <strong className="font-mono-code text-[#E9A872]">
                      {report.internetAssets.missingSecurityHeaders.length > 0
                        ? report.internetAssets.missingSecurityHeaders.join(', ')
                        : 'None'}
                    </strong>
                  </span>
                  {report.internetAssets.serverHeader && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span>
                        Server:{' '}
                        <strong className="font-mono-code text-[#F2E6C9]">
                          {report.internetAssets.serverHeader}
                        </strong>
                      </span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* 7. PUBLIC INTERNET EXPERIENCE & WITNESS INTELLIGENCE */}
        <section
          aria-label="Witness Intelligence and Public Internet Experience"
          className="rounded-md bg-[#170E0B] border border-[#4A3024] p-4 sm:p-5 space-y-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#4A3024] pb-3">
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-[#C9A04A]" />
              <div>
                <h4 className="font-serif-display text-xl font-bold text-[#F5CE7A]">
                  Public Internet Experience &amp; Witness Intelligence for {report.host}
                </h4>
                <p className="text-xs text-[#D9C79F]">
                  Real user experiences found on the internet combined with community witness reports
                </p>
              </div>
            </div>
            <span className="font-mono-code text-xs px-2.5 py-1 rounded bg-[#2A1A14] border border-[#4A3024] text-[#D9C79F]">
              Capped at 10 pts · Corroborated with technical assets
            </span>
          </div>

          {/* Public Internet Experience Grounding Card */}
          {report.webExperience && (
            <div className="rounded bg-[#231510] border border-[#C9A04A]/50 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono-code text-xs uppercase tracking-wider text-[#F5CE7A]">
                  Internet-Wide User Experience &amp; Web Reputation
                </span>
                <span
                  className={`font-mono-code text-xs font-bold px-2.5 py-0.5 rounded border ${
                    report.webExperience.sentiment === 'positive'
                      ? 'bg-[#5E8B5A]/25 border-[#5E8B5A] text-[#F2E6C9]'
                      : report.webExperience.sentiment === 'negative'
                      ? 'bg-[#B3342F]/25 border-[#B3342F] text-[#F5CE7A]'
                      : 'bg-[#2A1A14] border-[#C9A04A]/60 text-[#D9C79F]'
                  }`}
                >
                  {report.webExperience.sentiment === 'positive'
                    ? 'Established Public Reputation'
                    : report.webExperience.sentiment === 'negative'
                    ? 'Public Scam / Phishing Warnings Reported'
                    : report.webExperience.sentiment === 'mixed'
                    ? 'Mixed Public Reviews'
                    : 'Unverified / Limited Public Reviews'}
                </span>
              </div>

              <p className="text-sm text-[#F2E6C9] leading-relaxed">
                {report.webExperience.summary}
              </p>

              {report.webExperience.highlights.length > 0 && (
                <ul className="space-y-1 text-xs sm:text-sm text-[#D9C79F] list-disc list-inside">
                  {report.webExperience.highlights.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              )}

              {report.webExperience.sources.length > 0 && (
                <div className="pt-2 border-t border-[#4A3024] flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-[#D9C79F] font-mono-code">Reference Sources:</span>
                  {report.webExperience.sources.map((src, idx) => (
                    <a
                      key={idx}
                      href={src.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#170E0B] hover:bg-[#2A1A14] border border-[#4A3024] text-[#F5CE7A] transition-colors"
                    >
                      <span className="truncate max-w-[220px]">{src.title}</span>
                      <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Local SHERLOCK Witness Reports */}
          {report.witness.totalReports === 0 ? (
            <p className="text-sm text-[#D9C79F]">
              No local SHERLOCK witness reports are currently on file for{' '}
              <span className="font-mono-code text-[#F2E6C9]">{report.host}</span>.
            </p>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-4 text-sm text-[#F2E6C9]">
                <span>
                  Community Witness Reports:{' '}
                  <strong className="font-mono-code text-[#F5CE7A] tabular-nums">
                    {report.witness.totalReports}
                  </strong>
                </span>
                {report.witness.firstReported && (
                  <span>
                    First Reported:{' '}
                    <span className="font-mono-code text-[#D9C79F] tabular-nums">
                      {new Date(report.witness.firstReported).toLocaleDateString()}
                    </span>
                  </span>
                )}
                {report.witness.lastReported && (
                  <span>
                    Last Reported:{' '}
                    <span className="font-mono-code text-[#D9C79F] tabular-nums">
                      {new Date(report.witness.lastReported).toLocaleDateString()}
                    </span>
                  </span>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                {(Object.entries(report.witness.byCategory) as [WitnessCategory, number][])
                  .filter(([, count]) => count > 0)
                  .map(([cat, count]) => (
                    <span
                      key={cat}
                      className="text-xs px-2.5 py-1 rounded bg-[#2A1A14] border border-[#C9A04A]/50 text-[#F2E6C9]"
                    >
                      {WITNESS_CATEGORY_LABELS[cat]}:{' '}
                      <strong className="font-mono-code text-[#F5CE7A] tabular-nums">{count}</strong>
                    </span>
                  ))}
              </div>
            </div>
          )}
        </section>

        {/* 8. CASE REPORT ACTIONS */}
        <div className="pt-2 flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row gap-2.5">
            {onReportSite && (
              <button
                type="button"
                onClick={() => {
                  onReportSite(report.host);
                  setShareFeedback(`Witness report recorded for ${report.host} (query strings stripped).`);
                  setTimeout(() => setShareFeedback(null), 4000);
                }}
                className="min-h-[48px] px-4 py-2.5 rounded bg-[#5A1F26] hover:bg-[#7C2F37] border border-[#C9A04A] text-[#F2E6C9] font-semibold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer"
              >
                <Flag className="w-4 h-4 text-[#F5CE7A]" />
                <span>Report this site</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleShareReport}
              className="min-h-[48px] px-4 py-2.5 rounded bg-[#170E0B] hover:bg-[#231510] border border-[#C9A04A] text-[#F5CE7A] font-semibold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              <Share2 className="w-4 h-4 text-[#C9A04A]" />
              <Copy className="w-3.5 h-3.5 text-[#D9C79F] sm:hidden" />
              <span>Share this report</span>
            </button>
          </div>

          {onInvestigateAnother && (
            <button
              type="button"
              onClick={onInvestigateAnother}
              className="min-h-[48px] px-5 py-2.5 rounded brass-button font-bold text-sm flex items-center justify-center gap-2 cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Investigate another link</span>
            </button>
          )}
        </div>

        {shareFeedback && (
          <div
            role="status"
            aria-live="polite"
            className="p-3 rounded bg-[#5E8B5A]/25 border border-[#5E8B5A] text-xs sm:text-sm text-[#F2E6C9] flex items-center gap-2"
          >
            <ShieldCheck className="w-4 h-4 text-[#5E8B5A] shrink-0" />
            <span>{shareFeedback}</span>
          </div>
        )}
      </div>
    </div>
  );
};
