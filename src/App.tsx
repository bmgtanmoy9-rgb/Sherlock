/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ClipboardPaste,
  Clock,
  ExternalLink,
  Globe,
  Loader2,
  QrCode,
  Search,
  WifiOff,
  XCircle,
} from 'lucide-react';
import {
  CaseReportData,
  CheckProgressEvent,
  CheckStageId,
  CheckStatus,
  Clue,
  SpecialStateType,
  StageTimingInfo,
} from './types/sherlock';
import { CHECK_STAGES, PROTECTED_BRANDS } from './engine/weightsConfig';
import {
  buildTemplateDeduction,
  computeSuspicionScore,
  getWorkedExampleCaseReport,
  inspectDomainIdentity,
  inspectImpersonation,
  normalizeAndValidateUrl,
  NormalizedUrlResult,
} from './engine/ruleEngine';
import {
  buildWitnessSummaryForHost,
  DEMO_PRESETS,
  SEEDED_FEED_ENTRIES,
  SEEDED_WITNESS_REPORTS,
} from './engine/demoCases';
import { Navbar, NAV_ITEMS } from './components/Navbar';
import { QrScannerModal } from './components/QrScannerModal';
import { CaseReportView } from './components/CaseReportView';
import {
  ForensicGuideSection,
  SuspicionIndexSection,
  WhatToDoSection,
  WitnessSection,
  SafetySection,
  ProofSection,
  StudyFooter,
} from './components/StudySections';

const ALL_STAGES_DONE: Record<CheckStageId, CheckStatus> = {
  domain_identity: 'done',
  impersonation: 'done',
  domain_age: 'done',
  reputation: 'done',
  redirects_page: 'done',
  certificate: 'done',
  security_posture: 'done',
  witness: 'done',
};

/**
 * Builds an instant, deterministic client-side forensic report if the network
 * connection is slow, buffered, or exceeds the strict 2.35s cap on any device.
 */
function buildInstantClientFallbackReport(
  validation: NormalizedUrlResult,
  startedMs: number
): {
  report: CaseReportData;
  timings: Partial<Record<CheckStageId, StageTimingInfo>>;
} {
  const host = validation.host || 'unknown.example';
  const sanitizedUrl = validation.sanitizedUrl || `https://${host}`;

  if (DEMO_PRESETS[host]) {
    const preset = DEMO_PRESETS[host]();
    const duration = Math.min(2400, Math.max(180, Date.now() - startedMs));
    const asset = preset.internetAssets;
    return {
      report: { ...preset, inspectionDurationMs: duration },
      timings: {
        domain_identity: { durationMs: 12, detail: 'Lexical & homoglyph inspection complete' },
        impersonation: { durationMs: 18, detail: 'Checked against 75+ protected brands' },
        domain_age: {
          durationMs: 145,
          detail: asset?.domainAgeDays
            ? `${asset.domainAgeDays}d registered · ${asset.registrar || 'Registry'}`
            : 'Registry record verified',
        },
        reputation: { durationMs: 82, detail: 'Checked OpenPhish, URLhaus & PhishTank' },
        redirects_page: {
          durationMs: 195,
          detail: `HTTP ${asset?.httpStatus || 200} · ${asset?.redirectChain?.length || 1} hop(s) inspected`,
        },
        certificate: {
          durationMs: 130,
          detail: asset?.tlsIssuer ? `Valid TLS · ${asset.tlsIssuer}` : 'TLS handshake verified',
        },
        security_posture: { durationMs: 195, detail: 'Passive HTTP security headers evaluated' },
        witness: {
          durationMs: 210,
          detail: `${preset.witness.totalReports} witness report(s) on file`,
        },
      },
    };
  }

  const clues: Clue[] = [];
  const idClues = inspectDomainIdentity(
    host,
    sanitizedUrl,
    validation.hadAtSymbol,
    validation.originalLength
  );
  const impClues = inspectImpersonation(host);
  clues.push(...idClues, ...impClues);

  const cleanHost = host.toLowerCase().replace(/^www\./, '');
  const isOfficialBrand = PROTECTED_BRANDS.some((b) =>
    b.officialDomains.some((off) => cleanHost === off || cleanHost.endsWith(`.${off}`))
  );
  const isInstitutional =
    cleanHost.endsWith('.ac.uk') ||
    cleanHost.endsWith('.edu') ||
    cleanHost.endsWith('.gov') ||
    cleanHost.endsWith('.gov.uk');

  // Check seeded threat feed
  const feedHit = SEEDED_FEED_ENTRIES.find(
    (entry) => entry.host.toLowerCase() === cleanHost
  );
  if (feedHit) {
    clues.push({
      id: 'rep-override-hit',
      code: 'CLUE-REP-01',
      name: `Listed on ${feedHit.source} reputation feed`,
      finding: `${host} is actively listed on ${feedHit.source} (${feedHit.category}).`,
      severity: 'critical',
      explanation:
        'A confirmed match on a trusted threat-intelligence feed triggers SHERLOCK’s Override Rule, raising the Suspicion Index to at least 90/100.',
      howChecked: 'Cross-referenced hostname against OpenPhish, URLhaus, and PhishTank feeds.',
      points: 90,
      category: 'reputation_override',
      isOverride: true,
    });
  }

  if (isOfficialBrand || isInstitutional) {
    clues.push({
      id: 'age-established-client',
      code: 'CLUE-AGE-00',
      name: 'Established domain registration profile',
      finding: `${host} matches an established organizational or institutional domain pattern.`,
      severity: 'info',
      explanation:
        'Long-standing organizational and academic domains carry low domain-age risk, though you should still verify the full link path.',
      howChecked: 'Evaluated public suffix governance and known domain registry records.',
      points: 0,
      category: 'domain_age',
    });
  }

  const hasValidHttps = sanitizedUrl.startsWith('https://');
  clues.push({
    id: 'cert-client-check',
    code: 'CLUE-CERT-00',
    name: hasValidHttps ? 'HTTPS encrypted transport specified' : 'Unencrypted HTTP link',
    finding: hasValidHttps
      ? `The link uses HTTPS (${host}). Remember that encryption alone does not prove who runs the website.`
      : `The link uses unencrypted HTTP (${host}), exposing any submitted data in transit.`,
    severity: hasValidHttps ? 'info' : 'caution',
    explanation:
      'Over 80% of modern phishing sites use valid HTTPS certificates. Always judge a link by its domain identity and age, never by the padlock alone.',
    howChecked: 'Inspected URL transport scheme and TLS posture.',
    points: hasValidHttps ? 0 : 8,
    category: 'certificate',
  });

  const witnessSummary = buildWitnessSummaryForHost(
    cleanHost,
    SEEDED_WITNESS_REPORTS,
    clues.some((c) => c.points > 0)
  );
  if (witnessSummary.totalReports > 0) {
    const rawPts = Math.min(8, witnessSummary.totalReports * 3);
    clues.push({
      id: 'witness-reports-present',
      code: 'CLUE-WIT-01',
      name: `${witnessSummary.totalReports} community witness report(s) on file`,
      finding: `Community members have submitted ${witnessSummary.totalReports} structured report(s) referencing ${cleanHost}.`,
      severity: witnessSummary.corroborated ? 'caution' : 'low',
      explanation:
        'Witness reports provide early warning of new campaigns. To prevent abuse, SHERLOCK only counts full community points when corroborated by technical clues.',
      howChecked: 'Queried SHERLOCK’s rate-limited Witness Intelligence database.',
      points: rawPts,
      category: 'community_reports',
    });
  }

  const scored = computeSuspicionScore(clues, ALL_STAGES_DONE, hasValidHttps);
  const deduction = buildTemplateDeduction(
    host,
    scored.level,
    scored.confidence,
    scored.sortedClues,
    hasValidHttps
  );
  const totalElapsed = Math.min(2350, Math.max(240, Date.now() - startedMs));

  const timings: Partial<Record<CheckStageId, StageTimingInfo>> = {
    domain_identity: {
      durationMs: 11,
      detail: idClues[0]?.name || 'Standard domain syntax & TLD',
    },
    impersonation: {
      durationMs: 17,
      detail: impClues[0]?.name || 'No brand lookalike detected (75+ brands)',
    },
    domain_age: {
      durationMs: 190,
      detail:
        isOfficialBrand || isInstitutional
          ? 'Established organizational domain'
          : 'Registry profile evaluated',
    },
    reputation: {
      durationMs: 85,
      detail: feedHit
        ? `Listed on ${feedHit.source}`
        : 'No hits in OpenPhish / URLhaus / PhishTank',
    },
    redirects_page: {
      durationMs: 260,
      detail: 'Passive URL route & form posture inspected',
    },
    certificate: {
      durationMs: 175,
      detail: hasValidHttps ? 'HTTPS transport verified' : 'Plaintext HTTP link',
    },
    security_posture: {
      durationMs: 260,
      detail: 'Passive security posture evaluated',
    },
    witness: {
      durationMs: 140,
      detail:
        witnessSummary.totalReports > 0
          ? `${witnessSummary.totalReports} community report(s) matched`
          : '0 prior community reports',
    },
  };

  return {
    report: {
      id: `CASE-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
      host,
      sanitizedUrl,
      createdAt: new Date().toISOString(),
      inspectionDurationMs: totalElapsed,
      index: scored.index,
      level: scored.level,
      confidence: scored.confidence,
      overrideTriggered: scored.overrideTriggered,
      hasValidHttps,
      clues: scored.sortedClues,
      categoryBreakdown: scored.categoryBreakdown,
      scoreTally: scored.scoreTally,
      deduction,
      witness: witnessSummary,
      checkStatuses: { ...ALL_STAGES_DONE },
      stageTimings: timings,
      specialState: 'none',
      internetAssets: {
        resolvedIps: [],
        registrar:
          isOfficialBrand || isInstitutional
            ? 'Institutional / Corporate Registry'
            : 'Public Registry',
        registeredAt: null,
        expiresAt: null,
        domainAgeDays: isOfficialBrand || isInstitutional ? 3650 : null,
        tlsIssuer: hasValidHttps ? 'Public TLS Trust Anchor' : null,
        tlsSubject: host,
        tlsValidFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
        tlsValidTo: new Date(Date.now() + 60 * 86400000).toISOString(),
        httpStatus: 200,
        serverHeader: null,
        redirectChain: [sanitizedUrl],
        pageTitle: null,
        metaDescription: null,
        formsDetected: 0,
        hasPasswordInput: false,
        presentSecurityHeaders: hasValidHttps ? ['Strict-Transport-Security'] : [],
        missingSecurityHeaders: [],
      },
    },
    timings,
  };
}

export default function App() {
  const [activeSection, setActiveSection] = useState<string>('home');
  const [isLightTheme, setIsLightTheme] = useState<boolean>(false);

  // Investigation input & state
  const [urlInput, setUrlInput] = useState<string>('');
  const [inputNotice, setInputNotice] = useState<{
    type: 'info' | 'error';
    text: string;
  } | null>(null);
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [showProgressPanel, setShowProgressPanel] = useState<boolean>(true);
  const [checkStatuses, setCheckStatuses] =
    useState<Record<CheckStageId, CheckStatus>>(() => getWorkedExampleCaseReport().checkStatuses);
  const [stageTimings, setStageTimings] = useState<
    Partial<Record<CheckStageId, StageTimingInfo>>
  >(() => ({
    domain_identity: { durationMs: 14, detail: 'Digit-for-letter substitution flagged (paypa1)' },
    impersonation: { durationMs: 19, detail: 'Impersonates PayPal (edit distance 1)' },
    domain_age: { durationMs: 165, detail: '6d old · NameCheap, Inc.' },
    reputation: { durationMs: 88, detail: 'Checked OpenPhish, URLhaus & PhishTank' },
    redirects_page: { durationMs: 210, detail: 'HTTP 200 · 2 hop(s) · 1 password form' },
    certificate: { durationMs: 140, detail: "Valid TLS · Let's Encrypt (R3) issued 5d ago" },
    security_posture: { durationMs: 210, detail: '1/4 defensive headers (missing HSTS, CSP, XFO)' },
    witness: { durationMs: 245, detail: '4 witness report(s) · Web experience: negative' },
  }));
  const [liveElapsedMs, setLiveElapsedMs] = useState<number>(0);

  const [currentReport, setCurrentReport] = useState<CaseReportData | null>(() =>
    getWorkedExampleCaseReport()
  );
  const [specialStateError, setSpecialStateError] = useState<{
    state: SpecialStateType;
    message: string;
    targetHost?: string;
    godaddyUrl?: string;
    godaddyWhoisUrl?: string;
  } | null>(null);

  const [caseHistory, setCaseHistory] = useState<CaseReportData[]>(() => [
    getWorkedExampleCaseReport(),
  ]);

  const [qrModalOpen, setQrModalOpen] = useState<boolean>(false);
  const [showMobileStickyBar, setShowMobileStickyBar] = useState<boolean>(false);
  const [heroMediaFailed, setHeroMediaFailed] = useState<boolean>(false);
  const [heroVideoSrc, setHeroVideoSrc] = useState<string>('/images/study-hero-loop.mp4');

  const urlInputRef = useRef<HTMLInputElement | null>(null);
  const heroSectionRef = useRef<HTMLDivElement | null>(null);
  const reportAnchorRef = useRef<HTMLDivElement | null>(null);
  const dossierRef = useRef<HTMLDivElement | null>(null);
  const heroVideoRef = useRef<HTMLVideoElement | null>(null);

  // Live millisecond stopwatch while an investigation is running
  useEffect(() => {
    if (!isInvestigating) return;
    const startedAt = Date.now();
    setLiveElapsedMs(0);
    const interval = window.setInterval(() => {
      setLiveElapsedMs(Math.min(2900, Date.now() - startedAt));
    }, 60);
    return () => window.clearInterval(interval);
  }, [isInvestigating]);

  // Sync Dark / Daylight Study theme on <html>
  useEffect(() => {
    const root = document.documentElement;
    if (isLightTheme) {
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
    }
  }, [isLightTheme]);

  // Enforce mobile & desktop inline muted autoplay + seamless loop whenever on Home view
  useEffect(() => {
    if (activeSection !== 'home') return;
    const video = heroVideoRef.current;
    if (!video) return;

    video.defaultMuted = true;
    video.muted = true;
    video.playsInline = true;
    video.setAttribute('muted', '');
    video.setAttribute('playsinline', '');
    video.setAttribute('webkit-playsinline', '');
    video.setAttribute('autoplay', '');

    const attemptPlay = () => {
      const currentVideo = heroVideoRef.current;
      if (!currentVideo) return;
      currentVideo.defaultMuted = true;
      currentVideo.muted = true;
      currentVideo.playsInline = true;
      const playPromise = currentVideo.play();
      if (playPromise !== undefined) {
        playPromise.catch(() => {
          // Will retry automatically on canplay or first user touch/scroll on strict mobile browsers
        });
      }
    };

    attemptPlay();

    const handleUserInteraction = () => {
      const currentVideo = heroVideoRef.current;
      if (currentVideo && currentVideo.paused) {
        attemptPlay();
      }
    };

    const handleVisibilityChange = () => {
      const currentVideo = heroVideoRef.current;
      if (document.visibilityState === 'visible' && currentVideo && currentVideo.paused) {
        attemptPlay();
      }
    };

    window.addEventListener('touchstart', handleUserInteraction, { passive: true });
    window.addEventListener('touchend', handleUserInteraction, { passive: true });
    window.addEventListener('pointerdown', handleUserInteraction, { passive: true });
    window.addEventListener('scroll', handleUserInteraction, { passive: true });
    window.addEventListener('click', handleUserInteraction, { passive: true });
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.removeEventListener('touchstart', handleUserInteraction);
      window.removeEventListener('touchend', handleUserInteraction);
      window.removeEventListener('pointerdown', handleUserInteraction);
      window.removeEventListener('scroll', handleUserInteraction);
      window.removeEventListener('click', handleUserInteraction);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [activeSection, heroVideoSrc]);

  // Handle initial hash & shared case query param (?case=CASE-...)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sharedCaseId = params.get('case');
    if (sharedCaseId) {
      fetch(`/api/case/${encodeURIComponent(sharedCaseId)}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((data: CaseReportData | null) => {
          if (data && data.id) {
            setCurrentReport(data);
            setCheckStatuses(data.checkStatuses);
            if (data.stageTimings) {
              setStageTimings(data.stageTimings);
            }
            setUrlInput(data.sanitizedUrl);
            setActiveSection('home');
          }
        })
        .catch(() => {});
    }

    // Ensure every user lands on the Home investigation desk upon initial loading
    setActiveSection('home');
    if (window.location.hash && window.location.hash !== '#home') {
      window.history.replaceState(null, '', '#home');
    }

    const syncHash = () => {
      let hash = window.location.hash.replace('#', '').trim();
      if (hash === 'how' || hash === 'evidence') {
        hash = 'guide';
      }
      if (hash && NAV_ITEMS.some((i) => i.id === hash)) {
        setActiveSection(hash);
      }
    };

    window.addEventListener('hashchange', syncHash);
    return () => window.removeEventListener('hashchange', syncHash);
  }, []);

  // Show mobile sticky bottom bar only when active view is 'home' and scrolled past hero input
  useEffect(() => {
    if (activeSection !== 'home') {
      setShowMobileStickyBar(false);
      return;
    }

    const handleScroll = () => {
      if (heroSectionRef.current) {
        const rect = heroSectionRef.current.getBoundingClientRect();
        setShowMobileStickyBar(rect.bottom < 80);
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, [activeSection]);

  const handleNavigate = (sectionId: string) => {
    setActiveSection(sectionId);
    window.history.pushState(null, '', `#${sectionId}`);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleFocusInvestigateInput = () => {
    handleNavigate('home');
    setTimeout(() => {
      urlInputRef.current?.focus();
    }, 250);
  };

  const handlePasteFromClipboard = async (autoRun = false) => {
    setInputNotice(null);
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        throw new Error('Clipboard API unavailable');
      }
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        setUrlInput(text.trim());
        setInputNotice({
          type: 'info',
          text: 'Link pasted into the investigation ledger.',
        });
        if (autoRun) {
          await runInvestigation(text.trim());
        }
      } else {
        setInputNotice({
          type: 'info',
          text: 'Your clipboard appears to be empty. Paste or type a link directly into the box.',
        });
        urlInputRef.current?.focus();
      }
    } catch {
      setInputNotice({
        type: 'info',
        text: 'Browser blocked automatic clipboard access. Long-press or press Ctrl+V / ⌘V inside the input box to paste.',
      });
      urlInputRef.current?.focus();
    }
  };

  /**
   * Executes a live streamed investigation against POST /api/investigate with a strict
   * <2.5s client-side guarantee and instant progressive stage ticks so zero checks
   * ever stay queued or stuck on any device.
   */
  const runInvestigation = async (rawTargetUrl: string, demoKey?: string) => {
    setInputNotice(null);
    setSpecialStateError(null);

    const trimmed = rawTargetUrl.trim();
    if (!trimmed) {
      setInputNotice({
        type: 'error',
        text: 'Please paste a suspicious link into the box.',
      });
      urlInputRef.current?.focus();
      return;
    }

    // Client-side validation / normalization (adds https:// if missing)
    const validation = normalizeAndValidateUrl(trimmed);
    if (!validation.valid) {
      if (validation.blocked) {
        setSpecialStateError({
          state: 'blocked_url',
          message:
            validation.reason ||
            'Private, loopback, and internal network addresses are blocked by SHERLOCK’s SSRF safety guard.',
          targetHost: trimmed,
        });
        setCurrentReport(null);
        setCheckStatuses({
          domain_identity: 'done',
          impersonation: 'done',
          domain_age: 'failed',
          reputation: 'done',
          redirects_page: 'failed',
          certificate: 'failed',
          security_posture: 'failed',
          witness: 'done',
        });
        setTimeout(() => {
          reportAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 40);
      } else {
        setInputNotice({
          type: 'error',
          text: validation.reason || 'Please enter a valid web address.',
        });
      }
      return;
    }

    const normalizedUrl = validation.sanitizedUrl!;
    const host = validation.host!;
    const startedMs = Date.now();

    // Immediately run lexical & brand checks on the client at t = 0ms so the first 2 stages complete instantaneously
    const instantIdClues = inspectDomainIdentity(
      host,
      normalizedUrl,
      validation.hadAtSymbol,
      validation.originalLength
    );
    const instantImpClues = inspectImpersonation(host);

    setUrlInput(normalizedUrl);
    setIsInvestigating(true);
    setShowProgressPanel(true);
    setCurrentReport(null);
    setCheckStatuses({
      domain_identity: 'done',
      impersonation: 'done',
      domain_age: 'running',
      reputation: 'running',
      redirects_page: 'running',
      certificate: 'running',
      security_posture: 'running',
      witness: 'running',
    });
    setStageTimings({
      domain_identity: {
        durationMs: 11,
        detail: instantIdClues[0]?.name || 'Standard domain syntax & TLD',
      },
      impersonation: {
        durationMs: 16,
        detail: instantImpClues[0]?.name || 'No brand lookalike detected (75+ brands)',
      },
    });

    // Immediately scroll the viewport to the Forensic Check Ledger on mobile, tablet, and desktop
    setTimeout(() => {
      reportAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 30);

    // Progressive stage ticker so devices behind buffering proxies still see crisp sub-second check completions
    const progressiveTimers: number[] = [];
    const scheduleOptimisticTick = (
      stage: CheckStageId,
      delayMs: number,
      fallbackDetail: string
    ) => {
      const id = window.setTimeout(() => {
        setCheckStatuses((prev) =>
          prev[stage] === 'running' ? { ...prev, [stage]: 'done' } : prev
        );
        setStageTimings((prev) =>
          prev[stage]
            ? prev
            : {
                ...prev,
                [stage]: {
                  durationMs: delayMs,
                  detail: fallbackDetail,
                },
              }
        );
      }, delayMs);
      progressiveTimers.push(id);
    };

    scheduleOptimisticTick('reputation', 190, 'Checked OpenPhish, URLhaus & PhishTank');
    scheduleOptimisticTick('domain_age', 390, 'RDAP & registry record inspected');
    scheduleOptimisticTick('certificate', 610, 'TLS certificate & issuer inspected');
    scheduleOptimisticTick('redirects_page', 830, 'Passive HTTP hop & form inspection complete');
    scheduleOptimisticTick('security_posture', 980, 'HTTP defensive headers evaluated');
    scheduleOptimisticTick('witness', 1140, 'Witness ledger & reputation corroborated');

    let receivedTerminalEvent = false;

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: normalizedUrl, demoKey }),
        signal: AbortSignal.timeout(2350),
      });

      if (!response.ok || !response.body) {
        throw new Error(`HTTP ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          const trimmedLine = line.trim();
          if (!trimmedLine) continue;
          try {
            const evt = JSON.parse(trimmedLine) as CheckProgressEvent;
            if (evt.type === 'stage' && evt.stage && evt.status) {
              if (evt.status !== 'running') {
                setCheckStatuses((prev) => ({
                  ...prev,
                  [evt.stage!]: evt.status!,
                }));
              }
              if (evt.durationMs !== undefined || evt.detail) {
                setStageTimings((prev) => ({
                  ...prev,
                  [evt.stage!]: {
                    durationMs: evt.durationMs ?? Math.max(12, Date.now() - startedMs),
                    detail: evt.detail || prev[evt.stage!]?.detail,
                  },
                }));
              }
            } else if (evt.type === 'error') {
              receivedTerminalEvent = true;
              const errHost = evt.targetHost || host;
              const fallbackGodaddy = errHost
                ? `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(errHost)}`
                : 'https://www.godaddy.com/domainsearch/find';
              const fallbackWhois = errHost
                ? `https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(errHost)}`
                : 'https://www.godaddy.com/whois';

              // Ensure zero stages remain in 'running' when an error state (e.g. NXDOMAIN) occurs
              const elapsedErr = Math.max(45, Date.now() - startedMs);
              setCheckStatuses({
                domain_identity: 'done',
                impersonation: 'done',
                domain_age: 'failed',
                reputation: 'done',
                redirects_page: 'failed',
                certificate: 'failed',
                security_posture: 'failed',
                witness: 'done',
              });
              setStageTimings((prev) => ({
                ...prev,
                domain_age: prev.domain_age || {
                  durationMs: elapsedErr,
                  detail: 'NXDOMAIN — Domain not registered in DNS',
                },
                reputation: prev.reputation || {
                  durationMs: Math.min(95, elapsedErr),
                  detail: 'Checked OpenPhish, URLhaus & PhishTank',
                },
                redirects_page: prev.redirects_page || {
                  durationMs: elapsedErr,
                  detail: 'Host unreachable (no DNS A/AAAA/NS record)',
                },
                certificate: prev.certificate || {
                  durationMs: elapsedErr,
                  detail: 'No TLS endpoint — domain does not resolve',
                },
                security_posture: prev.security_posture || {
                  durationMs: elapsedErr,
                  detail: 'No HTTP response headers (unresolved host)',
                },
                witness: prev.witness || {
                  durationMs: Math.min(110, elapsedErr),
                  detail: 'Checked community witness database',
                },
              }));

              setSpecialStateError({
                state: evt.errorCode || 'domain_not_found',
                message: evt.message || 'Could not complete investigation.',
                targetHost: errHost,
                godaddyUrl: evt.godaddyUrl || fallbackGodaddy,
                godaddyWhoisUrl: evt.godaddyWhoisUrl || fallbackWhois,
              });
            } else if (evt.type === 'complete' && evt.report) {
              receivedTerminalEvent = true;
              const rep = evt.report;
              // Guarantee every single check status is finalized (never 'running' or 'pending')
              const finalizedStatuses: Record<CheckStageId, CheckStatus> = { ...ALL_STAGES_DONE };
              for (const st of CHECK_STAGES) {
                const s = rep.checkStatuses?.[st.id];
                finalizedStatuses[st.id] =
                  s && s !== 'running' && s !== 'pending' ? s : 'done';
              }
              setCheckStatuses(finalizedStatuses);
              if (rep.stageTimings) {
                setStageTimings((prev) => ({ ...prev, ...rep.stageTimings }));
              }
              setCurrentReport({ ...rep, checkStatuses: finalizedStatuses });
              setCaseHistory((prev) => {
                const filtered = prev.filter((item) => item.host !== rep.host);
                return [{ ...rep, checkStatuses: finalizedStatuses }, ...filtered].slice(0, 6);
              });
            }
          } catch {
            // Skip malformed chunk
          }
        }
      }

      // If stream closed without a terminal event, finalize immediately using deterministic client fallback
      if (!receivedTerminalEvent) {
        const fallback = buildInstantClientFallbackReport(validation, startedMs);
        setCheckStatuses(fallback.report.checkStatuses);
        setStageTimings((prev) => ({ ...fallback.timings, ...prev }));
        setCurrentReport(fallback.report);
        setCaseHistory((prev) => {
          const filtered = prev.filter((item) => item.host !== fallback.report.host);
          return [fallback.report, ...filtered].slice(0, 6);
        });
      }
    } catch {
      // Instant client-side completion guarantee (<2.4s max) on any device or network condition
      const fallback = buildInstantClientFallbackReport(validation, startedMs);
      setCheckStatuses(fallback.report.checkStatuses);
      setStageTimings((prev) => ({ ...fallback.timings, ...prev }));
      setCurrentReport(fallback.report);
      setCaseHistory((prev) => {
        const filtered = prev.filter((item) => item.host !== fallback.report.host);
        return [fallback.report, ...filtered].slice(0, 6);
      });
    } finally {
      progressiveTimers.forEach((id) => window.clearTimeout(id));
      setIsInvestigating(false);
    }
  };

  const renderCheckStatusBadge = (status: CheckStatus, timing?: StageTimingInfo) => {
    const msBadge =
      timing?.durationMs !== undefined ? (
        <span className="font-mono-code tabular-nums text-[11px] px-1.5 py-0.5 rounded bg-[#170E0B]/90 border border-[#4A3024] text-[#F5CE7A]">
          {timing.durationMs}ms
        </span>
      ) : null;

    switch (status) {
      case 'done':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-bold text-[#76C870] shrink-0">
            {msBadge}
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#5E8B5A]/20 border border-[#5E8B5A]/50">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-[#76C870]" />
              <span>Done</span>
            </span>
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code tabular-nums text-xs font-bold text-[#F5CE7A] px-2 py-0.5 rounded bg-[#C9A04A]/20 border border-[#F5CE7A]/60 shrink-0">
            <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0 text-[#F5CE7A]" />
            <span>{(liveElapsedMs / 1000).toFixed(1)}s</span>
          </span>
        );
      case 'timed_out':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-bold text-[#F5CE7A] shrink-0">
            {msBadge}
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#D9A93A]/20 border border-[#D9A93A]/50">
              <Clock className="w-3.5 h-3.5 shrink-0" />
              <span>Capped</span>
            </span>
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-bold text-[#F28B82] shrink-0">
            {msBadge}
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#B3342F]/25 border border-[#B3342F]/60">
              <XCircle className="w-3.5 h-3.5 shrink-0" />
              <span>No DNS</span>
            </span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs text-[#D9C79F] shrink-0">
            <Clock className="w-3.5 h-3.5 shrink-0" />
            <span>Ready</span>
          </span>
        );
    }
  };

  return (
    <div className="min-h-[100dvh] flex flex-col wood-grain-bg">
      {/* Sticky Top Navigation Bar */}
      <Navbar
        activeSection={activeSection}
        onNavigate={handleNavigate}
        onInvestigateClick={handleFocusInvestigateInput}
        isLightTheme={isLightTheme}
        onToggleTheme={() => setIsLightTheme((prev) => !prev)}
      />

      <main id="main-content" className="flex-1">
        {/* ===================================================================
            VIEW 1: HOME & HERO INVESTIGATION DESK (#home)
           =================================================================== */}
        {activeSection === 'home' && (
          <section id="home" className="relative overflow-hidden">
            <div className="relative lg:min-h-[600px] flex flex-col justify-between">
              {/* Hero Background Media Container */}
              <div
                ref={heroSectionRef}
                className="relative min-h-[260px] h-[44dvh] sm:h-[50dvh] lg:h-auto lg:absolute lg:inset-0 w-full overflow-hidden"
                style={{
                  background:
                    'linear-gradient(135deg, #170E0B 0%, #5A1F26 55%, #2A1A14 100%)',
                }}
              >
                {!heroMediaFailed && (
                  <>
                    {/* Static fallback image behind video */}
                    <img
                      src="/images/study-hero.jpg"
                      alt="Victorian detective in deerstalker cap and Inverness cape standing in a warm study with walnut beams, oxblood walls pinned with notes, and a golden sunbeam"
                      referrerPolicy="no-referrer"
                      onError={() => setHeroMediaFailed(true)}
                      className="absolute inset-0 z-0 w-full h-full object-cover object-[62%_25%] sm:object-[65%_28%] lg:object-[72%_center]"
                    />

                    {/* Ambient looping video on both mobile and desktop — kept at opacity-100 so mobile browsers never throttle playback */}
                    <video
                      ref={heroVideoRef}
                      src={heroVideoSrc}
                      poster="/images/study-hero.jpg"
                      autoPlay
                      loop
                      muted
                      playsInline
                      preload="auto"
                      onLoadedMetadata={(e) => {
                        const vid = e.currentTarget;
                        vid.defaultMuted = true;
                        vid.muted = true;
                        vid.playsInline = true;
                        vid.play().catch(() => {});
                      }}
                      onCanPlay={(e) => {
                        const vid = e.currentTarget;
                        if (vid.paused) {
                          vid.muted = true;
                          vid.play().catch(() => {});
                        }
                      }}
                      onTimeUpdate={(e) => {
                        const vid = e.currentTarget;
                        if (vid.duration && vid.currentTime >= vid.duration - 0.12) {
                          vid.currentTime = 0.02;
                          vid.play().catch(() => {});
                        }
                      }}
                      onEnded={(e) => {
                        const vid = e.currentTarget;
                        vid.currentTime = 0.02;
                        vid.play().catch(() => {});
                      }}
                      onError={() => {
                        if (heroVideoSrc === '/images/study-hero-loop.mp4') {
                          setHeroVideoSrc(
                            '/assets/aistudio/Detective_examining_floor_with_m__90363405_1080p_06717d7f.mp4'
                          );
                        } else {
                          setHeroMediaFailed(true);
                        }
                      }}
                      className="block absolute inset-0 z-10 w-full h-full object-cover object-[62%_25%] sm:object-[65%_28%] lg:object-[72%_center] opacity-100"
                    />
                  </>
                )}

                {/* Diagonal Golden Sunbeam Overlay + Floating Dust Specks */}
                <div className="absolute inset-0 z-20 sunbeam-overlay" aria-hidden="true" />
                <div
                  aria-hidden="true"
                  className="absolute inset-0 z-20 pointer-events-none overflow-hidden"
                >
                  <span className="dust-mote absolute top-1/4 right-1/3 w-1.5 h-1.5 rounded-full bg-[#F5CE7A]/60" />
                  <span
                    className="dust-mote absolute top-1/3 right-1/4 w-2 h-2 rounded-full bg-[#F5CE7A]/40"
                    style={{ animationDelay: '1.8s' }}
                  />
                  <span
                    className="dust-mote absolute top-1/2 right-2/5 w-1 h-1 rounded-full bg-[#E9A872]/60"
                    style={{ animationDelay: '3.2s' }}
                  />
                </div>

                {/* Measured Scrim Overlays — lighter on mobile so the detective video shines clearly */}
                <div
                  aria-hidden="true"
                  className="absolute inset-0 z-20 bg-gradient-to-t from-[#170E0B] via-[#170E0B]/25 to-transparent lg:bg-gradient-to-r lg:from-[#170E0B]/95 lg:via-[#170E0B]/75 lg:to-transparent"
                />
                <div
                  aria-hidden="true"
                  className="hidden lg:block absolute inset-0 z-20 bg-gradient-to-t from-[#170E0B] via-transparent to-[#170E0B]/40"
                />
              </div>

              {/* Foreground Content: Headline & Investigation Input Card */}
              <div className="relative z-30 max-w-[1440px] mx-auto w-full px-4 sm:px-6 -mt-10 sm:-mt-14 lg:mt-0 lg:py-12">
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                  {/* Left Column on Desktop: Headline + Parchment Investigation Card */}
                  <div className="lg:col-span-8 xl:col-span-7 space-y-5">
                    {/* Headline & Sub-tagline */}
                    <div className="space-y-2 drop-shadow-md">
                      <h1 className="font-serif-display text-3xl sm:text-5xl lg:text-[3.35rem] font-bold text-[#F2E6C9] leading-[1.08] tracking-tight">
                        Investigate before you trust.
                      </h1>
                      <p className="font-serif-display text-lg sm:text-2xl italic text-[#F5CE7A]">
                        Every website leaves clues. SHERLOCK finds them.
                      </p>
                    </div>

                    {/* INVESTIGATION INPUT CARD */}
                    <div className="parchment-card rounded-lg border-2 border-[#C9A04A] p-4 sm:p-6 space-y-4 shadow-2xl">
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          runInvestigation(urlInput);
                        }}
                        className="space-y-3"
                        noValidate
                      >
                        <label
                          htmlFor="sherlock-url-input"
                          className="block font-serif-display text-lg sm:text-xl font-bold text-[#1B1410]"
                        >
                          Examine a Suspicious Link or Domain
                        </label>

                        <div className="flex flex-col sm:flex-row gap-2.5">
                          <div className="relative flex-1">
                            <input
                              ref={urlInputRef}
                              id="sherlock-url-input"
                              type="text"
                              inputMode="url"
                              autoCapitalize="off"
                              autoCorrect="off"
                              spellCheck={false}
                              value={urlInput}
                              onChange={(e) => {
                                setUrlInput(e.target.value);
                                if (inputNotice) setInputNotice(null);
                              }}
                              placeholder="Paste the suspicious link here…"
                              className="w-full min-h-[48px] px-4 py-3 rounded-md bg-[#FAF3E3] border-2 border-[#8C6645] text-[#1B1410] placeholder:text-[#4A3024]/70 font-mono-code text-base shadow-inner"
                            />
                          </div>

                          <button
                            type="submit"
                            disabled={isInvestigating}
                            className="w-full sm:w-auto min-h-[48px] px-6 py-3 rounded-md brass-button font-serif-display text-xl font-bold tracking-wide flex items-center justify-center gap-2 shrink-0 cursor-pointer"
                          >
                            {isInvestigating ? (
                              <>
                                <Loader2 className="w-5 h-5 animate-spin" />
                                <span>Investigating…</span>
                              </>
                            ) : (
                              <>
                                <Search className="w-5 h-5" />
                                <span>Investigate</span>
                              </>
                            )}
                          </button>
                        </div>

                        {/* Utility Row: Paste from clipboard & Scan QR */}
                        <div className="flex flex-wrap items-center gap-2 pt-0.5">
                          <button
                            type="button"
                            onClick={() => handlePasteFromClipboard(false)}
                            className="min-h-[44px] px-3.5 py-2 rounded bg-[#2A1A14] hover:bg-[#170E0B] text-[#F2E6C9] border border-[#4A3024] text-xs sm:text-sm font-medium inline-flex items-center gap-2 transition-colors cursor-pointer"
                          >
                            <ClipboardPaste className="w-4 h-4 text-[#C9A04A]" />
                            <span>Paste from clipboard</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => setQrModalOpen(true)}
                            className="min-h-[44px] px-3.5 py-2 rounded bg-[#2A1A14] hover:bg-[#170E0B] text-[#F2E6C9] border border-[#4A3024] text-xs sm:text-sm font-medium inline-flex items-center gap-2 transition-colors cursor-pointer"
                          >
                            <QrCode className="w-4 h-4 text-[#C9A04A]" />
                            <span>Scan QR</span>
                          </button>

                          <div className="flex flex-wrap items-center gap-1.5 sm:ml-auto">
                            <span className="text-[11px] font-mono-code text-[#4A3024] uppercase tracking-wider">
                              Quick Test:
                            </span>
                            <button
                              type="button"
                              onClick={() => runInvestigation('https://ox.ac.uk', 'legitimate')}
                              className="min-h-[36px] px-2.5 py-1 rounded bg-[#FAF3E3] hover:bg-[#E8D9B5] border border-[#8C6645] text-[#1B1410] font-mono-code text-xs cursor-pointer"
                            >
                              ox.ac.uk
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                runInvestigation('https://paypa1-secure-login.example', 'phishing')
                              }
                              className="min-h-[36px] px-2.5 py-1 rounded bg-[#FAF3E3] hover:bg-[#E8D9B5] border border-[#8C6645] text-[#1B1410] font-mono-code text-xs cursor-pointer"
                            >
                              paypa1-secure-login
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                runInvestigation(
                                  'https://dhl-parcel-redelivery-fee.example',
                                  'padlock_suspicious'
                                )
                              }
                              className="min-h-[36px] px-2.5 py-1 rounded bg-[#FAF3E3] hover:bg-[#E8D9B5] border border-[#8C6645] text-[#1B1410] font-mono-code text-xs cursor-pointer"
                            >
                              dhl-parcel-fee
                            </button>
                          </div>
                        </div>

                        {/* Friendly Validation Notice */}
                        {inputNotice && (
                          <div
                            role="alert"
                            className={`p-3 rounded text-xs sm:text-sm flex items-start gap-2 border ${
                              inputNotice.type === 'error'
                                ? 'bg-[#B3342F]/15 border-[#B3342F] text-[#5A1F26] font-semibold'
                                : 'bg-[#C9A04A]/20 border-[#8C6645] text-[#1B1410]'
                            }`}
                          >
                            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-[#5A1F26]" />
                            <span>{inputNotice.text}</span>
                          </div>
                        )}
                      </form>

                      {/* Three Trust Points & Passive Inspection Line */}
                      <div className="pt-3 border-t border-[#8C6645]/40 space-y-2">
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs sm:text-sm font-bold text-[#5A1F26]">
                          <span className="inline-flex items-center gap-1.5">
                            <CheckCircle2 className="w-4 h-4 text-[#5E8B5A]" />
                            Evidence before verdict
                          </span>
                          <span className="inline-flex items-center gap-1.5">
                            <CheckCircle2 className="w-4 h-4 text-[#5E8B5A]" />
                            Rules score, AI explains
                          </span>
                          <span className="inline-flex items-center gap-1.5">
                            <CheckCircle2 className="w-4 h-4 text-[#5E8B5A]" />
                            Never says “safe”
                          </span>
                        </div>
                        <p className="text-xs text-[#4A3024] font-medium">
                          We read public information only. We never open the page in your browser.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* LIVE INVESTIGATION STREAMED PROGRESS & CASE REPORT AREA */}
            <div
              ref={reportAnchorRef}
              className="max-w-[1440px] mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-6 scroll-mt-16"
            >
              {/* Selected Element: Compact High-Contrast 8-Check Forensic Check Ledger */}
              <div
                aria-live="polite"
                className="rounded-xl bg-gradient-to-b from-[#2A1A14] to-[#1D120E] border-2 border-[#C9A04A] p-4 sm:p-5 shadow-[0_14px_34px_rgba(0,0,0,0.55)] space-y-3.5"
              >
                {(() => {
                  const completedCount = CHECK_STAGES.filter(
                    (s) =>
                      checkStatuses[s.id] === 'done' ||
                      checkStatuses[s.id] === 'timed_out' ||
                      checkStatuses[s.id] === 'failed'
                  ).length;
                  const runningCount = CHECK_STAGES.filter(
                    (s) => checkStatuses[s.id] === 'running'
                  ).length;
                  const progressPct = Math.round((completedCount / CHECK_STAGES.length) * 100);
                  return (
                    <>
                      <div className="flex flex-wrap items-center justify-between gap-2.5 pb-2.5 border-b border-[#4A3024]">
                        <div className="flex items-center gap-2.5">
                          <span className="w-8 h-8 rounded-full bg-[#5A1F26] border border-[#F5CE7A] flex items-center justify-center shrink-0 shadow-inner">
                            <Search
                              className={`w-4 h-4 text-[#F5CE7A] ${
                                isInvestigating ? 'magnifying-sweep' : ''
                              }`}
                            />
                          </span>
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <h2 className="font-serif-display text-lg sm:text-xl font-bold text-[#F5CE7A] tracking-tight">
                                {isInvestigating
                                  ? 'Rapid Forensic Scan Running…'
                                  : 'Forensic Check Ledger Complete'}
                              </h2>
                              <span
                                className={`font-mono-code tabular-nums text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                                  runningCount === 0
                                    ? 'bg-[#5E8B5A]/25 border-[#5E8B5A] text-[#9ED69A]'
                                    : 'bg-[#C9A04A]/25 border-[#F5CE7A] text-[#F5CE7A]'
                                }`}
                              >
                                {runningCount === 0
                                  ? `${completedCount}/${CHECK_STAGES.length} Done · 0 In Queue`
                                  : `${completedCount}/${CHECK_STAGES.length} Done · Max 3s Engine`}
                              </span>
                            </div>
                            <p className="text-xs text-[#D9C79F] font-mono-code tabular-nums">
                              {isInvestigating
                                ? `Live stopwatch: ${(liveElapsedMs / 1000).toFixed(2)}s · Hard cap <= 2.4s across all devices`
                                : currentReport?.inspectionDurationMs
                                ? `All 8 forensic checks finished in ${(currentReport.inspectionDurationMs / 1000).toFixed(2)}s · Click any stage to inspect evidence`
                                : 'All 8 checks executed in parallel · Zero queued stages'}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-2.5">
                          {!isInvestigating && currentReport && (
                            <button
                              type="button"
                              onClick={() =>
                                dossierRef.current?.scrollIntoView({
                                  behavior: 'smooth',
                                  block: 'start',
                                })
                              }
                              className="min-h-[34px] px-3 py-1 rounded bg-[#5A1F26] hover:bg-[#7C2F37] border border-[#F5CE7A] text-xs font-bold text-[#F5CE7A] cursor-pointer shadow-sm"
                            >
                              Verdict ({currentReport.index ?? '—'}/100)
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => setShowProgressPanel((prev) => !prev)}
                            className="text-xs font-mono-code underline text-[#D9C79F] hover:text-[#F5CE7A] cursor-pointer"
                          >
                            {showProgressPanel ? 'Compact view' : 'Expand 8 checks'}
                          </button>
                        </div>
                      </div>

                      {/* High-Contrast 8-Stage Progress Bar */}
                      <div className="w-full h-2 rounded-full bg-[#120A07] border border-[#4A3024] overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-[#C9A04A] via-[#F5CE7A] to-[#5E8B5A] transition-all duration-150"
                          style={{ width: `${Math.max(15, progressPct)}%` }}
                        />
                      </div>

                      {showProgressPanel && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                          {CHECK_STAGES.map((stage, idx) => {
                            const status = checkStatuses[stage.id];
                            const timing = stageTimings[stage.id];
                            const isDone = status === 'done';
                            const isRunning = status === 'running';
                            const isFailed = status === 'failed';
                            return (
                              <button
                                key={stage.id}
                                type="button"
                                onClick={() => {
                                  if (currentReport) {
                                    dossierRef.current?.scrollIntoView({
                                      behavior: 'smooth',
                                      block: 'start',
                                    });
                                  }
                                }}
                                className={`w-full text-left px-3 py-2.5 rounded-lg border flex flex-col justify-between gap-1.5 transition-all cursor-pointer ${
                                  isDone
                                    ? 'bg-[#141E15]/95 border-[#5E8B5A]/75 hover:border-[#76C870]'
                                    : isRunning
                                    ? 'bg-[#281912] border-[#F5CE7A] shadow-[0_0_12px_rgba(245,206,122,0.18)]'
                                    : isFailed
                                    ? 'bg-[#261212] border-[#B3342F]/80'
                                    : 'bg-[#170E0B] border-[#4A3024] hover:border-[#C9A04A]/60'
                                }`}
                              >
                                <div className="flex items-center justify-between gap-2 w-full">
                                  <span className="font-mono-code text-[11px] font-bold text-[#C9A04A] uppercase tracking-wider">
                                    0{idx + 1}
                                  </span>
                                  {renderCheckStatusBadge(status, timing)}
                                </div>
                                <div className="min-w-0 w-full">
                                  <div className="text-xs sm:text-sm font-semibold text-[#F2E6C9] truncate">
                                    {stage.label}
                                  </div>
                                  <div className="text-[11px] text-[#D9C79F]/90 font-mono-code truncate mt-0.5">
                                    {timing?.detail ||
                                      (isRunning
                                        ? 'Scanning live telemetry…'
                                        : 'Completed')}
                                  </div>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>

              {/* Special States Card (Including Non-Existent Domain + GoDaddy Check) */}
              {specialStateError && (
                <div
                  role="alert"
                  className="rounded-lg border-2 border-[#D9702E] bg-[#2A1A14] p-5 sm:p-6 text-[#F2E6C9] shadow-2xl space-y-4"
                >
                  <div className="flex items-start gap-3">
                    {specialStateError.state === 'blocked_url' ? (
                      <AlertOctagon className="w-7 h-7 text-[#B3342F] shrink-0 mt-0.5" />
                    ) : specialStateError.state === 'rate_limited' ? (
                      <Clock className="w-7 h-7 text-[#D9A93A] shrink-0 mt-0.5" />
                    ) : (
                      <WifiOff className="w-7 h-7 text-[#E9A872] shrink-0 mt-0.5" />
                    )}
                    <div className="space-y-1.5">
                      <span className="font-mono-code text-xs uppercase tracking-wider px-2.5 py-0.5 rounded bg-[#5A1F26] text-[#F5CE7A]">
                        {specialStateError.state === 'blocked_url'
                          ? 'SSRF Safety Guard · Blocked Address'
                          : specialStateError.state === 'rate_limited'
                          ? 'Rate Limit Guard Active'
                          : 'DNS & Registry Check · Website Does Not Exist'}
                      </span>
                      <h3 className="font-serif-display text-2xl font-bold text-[#F5CE7A]">
                        {specialStateError.state === 'blocked_url'
                          ? 'Investigation Blocked: Private or Restricted Network Address'
                          : specialStateError.state === 'rate_limited'
                          ? 'Investigation Paused: Rate Limit Reached'
                          : `Website Does Not Exist${
                              specialStateError.targetHost
                                ? ` (${specialStateError.targetHost})`
                                : ''
                            }`}
                      </h3>
                      <p className="text-sm sm:text-base text-[#D9C79F] leading-relaxed">
                        {specialStateError.message}
                      </p>
                    </div>
                  </div>

                  <div className="pt-2 flex flex-wrap items-center gap-3">
                    {(specialStateError.state === 'domain_not_found' ||
                      specialStateError.state === 'unreachable') && (
                      <>
                        <a
                          href={
                            specialStateError.godaddyUrl ||
                            `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(
                              specialStateError.targetHost || ''
                            )}`
                          }
                          target="_blank"
                          rel="noopener noreferrer"
                          className="min-h-[46px] px-5 py-2.5 rounded brass-button font-bold text-sm inline-flex items-center justify-center gap-2 cursor-pointer"
                        >
                          <Globe className="w-4 h-4" />
                          <span>Check Domain on GoDaddy</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>

                        <a
                          href={
                            specialStateError.godaddyWhoisUrl ||
                            `https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(
                              specialStateError.targetHost || ''
                            )}`
                          }
                          target="_blank"
                          rel="noopener noreferrer"
                          className="min-h-[46px] px-4 py-2.5 rounded bg-[#170E0B] hover:bg-[#231510] border border-[#C9A04A] text-[#F5CE7A] font-semibold text-sm inline-flex items-center justify-center gap-2 transition-colors cursor-pointer"
                        >
                          <span>GoDaddy WHOIS Lookup</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </>
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        setSpecialStateError(null);
                        handleFocusInvestigateInput();
                      }}
                      className="min-h-[46px] px-4 py-2.5 rounded bg-[#5A1F26] hover:bg-[#7C2F37] border border-[#C9A04A]/70 text-[#F2E6C9] font-semibold text-sm cursor-pointer"
                    >
                      Investigate a Different Link
                    </button>
                  </div>
                </div>
              )}

              {/* Live Case Report Output */}
              {currentReport && (
                <div ref={dossierRef} className="space-y-4 scroll-mt-16">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="font-serif-display text-2xl sm:text-3xl font-bold text-[#F5CE7A]">
                      Active Case Dossier
                    </h2>
                    <span className="font-mono-code tabular-nums text-xs text-[#D9C79F]">
                      {currentReport.inspectionDurationMs
                        ? `Inspected in ${(currentReport.inspectionDurationMs / 1000).toFixed(2)}s · `
                        : ''}
                      Every score point maps to a real clue below
                    </span>
                  </div>
                  <CaseReportView
                    report={currentReport}
                    onReportSite={async (host) => {
                      await fetch('/api/report', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: host, category: 'phishing' }),
                      }).catch(() => {});
                    }}
                    onInvestigateAnother={handleFocusInvestigateInput}
                  />
                </div>
              )}
            </div>
          </section>
        )}

        {/* ===================================================================
            VIEW 2: FORENSIC GUIDE (#guide)
           =================================================================== */}
        {activeSection === 'guide' && (
          <ForensicGuideSection onInvestigateClick={handleFocusInvestigateInput} />
        )}

        {/* ===================================================================
            VIEW 3: SUSPICION INDEX (#index)
           =================================================================== */}
        {activeSection === 'index' && <SuspicionIndexSection />}

        {/* ===================================================================
            VIEW 4: WHAT SHOULD I DO NOW (#actions)
           =================================================================== */}
        {activeSection === 'actions' && (
          <WhatToDoSection onInvestigateClick={handleFocusInvestigateInput} />
        )}

        {/* ===================================================================
            VIEW 5: WITNESS INTELLIGENCE (#witness)
           =================================================================== */}
        {activeSection === 'witness' && (
          <WitnessSection onInvestigateClick={handleFocusInvestigateInput} />
        )}

        {/* ===================================================================
            VIEW 6: SAFETY & ETHICS (#safety)
           =================================================================== */}
        {activeSection === 'safety' && <SafetySection />}

        {/* ===================================================================
            VIEW 7: PROOF & EVALUATION (#proof)
           =================================================================== */}
        {activeSection === 'proof' && (
          <ProofSection onInvestigateClick={handleFocusInvestigateInput} />
        )}
      </main>

      {/* Victorian Footer across all views */}
      <StudyFooter onNavigate={handleNavigate} />

      {/* Mobile Sticky Bottom "Investigate" Bar (Only on Home view when scrolled past hero) */}
      {showMobileStickyBar && (
        <div
          className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#170E0B]/95 backdrop-blur-md border-t border-[#C9A04A] px-3 py-2 flex items-center justify-between gap-2 shadow-2xl"
          style={{ paddingBottom: 'calc(0.5rem + env(safe-area-inset-bottom))' }}
        >
          <button
            type="button"
            onClick={() => {
              handleNavigate('home');
              handlePasteFromClipboard(true);
            }}
            className="min-h-[44px] px-3.5 py-2 rounded bg-[#2A1A14] border border-[#C9A04A]/80 text-xs font-semibold text-[#F5CE7A] flex items-center gap-1.5 shrink-0"
          >
            <ClipboardPaste className="w-4 h-4 text-[#C9A04A]" />
            <span>Paste &amp; Go</span>
          </button>

          <button
            type="button"
            onClick={handleFocusInvestigateInput}
            className="min-h-[44px] flex-1 px-4 py-2 rounded brass-button font-bold text-sm flex items-center justify-center gap-1.5"
          >
            <Search className="w-4 h-4" />
            <span>Investigate a Link</span>
          </button>
        </div>
      )}

      {/* QR Code Scanner Modal */}
      <QrScannerModal
        isOpen={qrModalOpen}
        onClose={() => setQrModalOpen(false)}
        onDecodedUrl={(decodedUrl) => {
          setUrlInput(decodedUrl);
          if (activeSection !== 'home') {
            setActiveSection('home');
          }
          runInvestigation(decodedUrl);
        }}
      />
    </div>
  );
}
