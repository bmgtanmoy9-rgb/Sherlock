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
  SpecialStateType,
} from './types/sherlock';
import { CHECK_STAGES } from './engine/weightsConfig';
import {
  getWorkedExampleCaseReport,
  normalizeAndValidateUrl,
} from './engine/ruleEngine';
import {
  getLegitimateDemoCase,
  getPadlockSuspiciousDemoCase,
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

const INITIAL_CHECK_STATUSES: Record<CheckStageId, CheckStatus> = {
  domain_identity: 'pending',
  impersonation: 'pending',
  domain_age: 'pending',
  reputation: 'pending',
  redirects_page: 'pending',
  certificate: 'pending',
  security_posture: 'pending',
  witness: 'pending',
};

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
  const [showProgressPanel, setShowProgressPanel] = useState<boolean>(false);
  const [checkStatuses, setCheckStatuses] =
    useState<Record<CheckStageId, CheckStatus>>(INITIAL_CHECK_STATUSES);

  const [currentReport, setCurrentReport] = useState<CaseReportData | null>(null);
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
  const heroVideoRef = useRef<HTMLVideoElement | null>(null);

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
   * Executes a live streamed investigation against POST /api/investigate,
   * updating each of the 8 check stages as NDJSON stream chunks arrive.
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
      } else {
        setInputNotice({
          type: 'error',
          text: validation.reason || 'Please enter a valid web address.',
        });
      }
      return;
    }

    const normalizedUrl = validation.sanitizedUrl!;
    setUrlInput(normalizedUrl);
    setIsInvestigating(true);
    setShowProgressPanel(true);
    setCurrentReport(null);
    setCheckStatuses({
      domain_identity: 'running',
      impersonation: 'pending',
      domain_age: 'pending',
      reputation: 'pending',
      redirects_page: 'pending',
      certificate: 'pending',
      security_posture: 'pending',
      witness: 'pending',
    });

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: normalizedUrl, demoKey }),
      });

      if (!response.body) {
        throw new Error('Streaming response body unavailable');
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
          if (!line.trim()) continue;
          try {
            const evt = JSON.parse(line) as CheckProgressEvent;
            if (evt.type === 'stage' && evt.stage && evt.status) {
              setCheckStatuses((prev) => ({
                ...prev,
                [evt.stage!]: evt.status!,
              }));
            } else if (evt.type === 'error') {
              const errHost = evt.targetHost || validation.host || '';
              const fallbackGodaddy = errHost
                ? `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(errHost)}`
                : 'https://www.godaddy.com/domainsearch/find';
              const fallbackWhois = errHost
                ? `https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(errHost)}`
                : 'https://www.godaddy.com/whois';

              setSpecialStateError({
                state: evt.errorCode || 'domain_not_found',
                message: evt.message || 'Could not complete investigation.',
                targetHost: errHost,
                godaddyUrl: evt.godaddyUrl || fallbackGodaddy,
                godaddyWhoisUrl: evt.godaddyWhoisUrl || fallbackWhois,
              });
              setTimeout(() => {
                reportAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 100);
            } else if (evt.type === 'complete' && evt.report) {
              const rep = evt.report;
              setCheckStatuses(rep.checkStatuses);
              setCurrentReport(rep);
              setCaseHistory((prev) => {
                const filtered = prev.filter((item) => item.host !== rep.host);
                return [rep, ...filtered].slice(0, 6);
              });
              setTimeout(() => {
                reportAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 120);
            }
          } catch {
            // Skip malformed chunk
          }
        }
      }
    } catch {
      const host = validation.host!;
      if (host === 'ox.ac.uk') {
        const fallbackReport = getLegitimateDemoCase();
        setCheckStatuses(fallbackReport.checkStatuses);
        setCurrentReport(fallbackReport);
      } else if (host === 'dhl-parcel-redelivery-fee.example') {
        const fallbackReport = getPadlockSuspiciousDemoCase();
        setCheckStatuses(fallbackReport.checkStatuses);
        setCurrentReport(fallbackReport);
      } else if (host === 'paypa1-secure-login.example') {
        const fallbackReport = getWorkedExampleCaseReport();
        setCheckStatuses(fallbackReport.checkStatuses);
        setCurrentReport(fallbackReport);
      } else {
        setSpecialStateError({
          state: 'domain_not_found',
          message: `The website "${host}" could not be reached or does not exist on the internet. Check GoDaddy below to verify whether this domain is registered.`,
          targetHost: host,
          godaddyUrl: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(host)}`,
          godaddyWhoisUrl: `https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(host)}`,
        });
      }
    } finally {
      setIsInvestigating(false);
    }
  };

  const renderCheckStatusBadge = (status: CheckStatus) => {
    switch (status) {
      case 'done':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-semibold text-[#5E8B5A]">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>Done</span>
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-semibold text-[#F5CE7A]">
            <Loader2 className="w-4 h-4 animate-spin shrink-0" />
            <span>Inspecting…</span>
          </span>
        );
      case 'timed_out':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-semibold text-[#D9A93A]">
            <Clock className="w-4 h-4 shrink-0" />
            <span>Timed out</span>
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs font-semibold text-[#B3342F]">
            <XCircle className="w-4 h-4 shrink-0" />
            <span>Failed</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 font-mono-code text-xs text-[#8A7F72]">
            <Clock className="w-3.5 h-3.5 shrink-0" />
            <span>Pending</span>
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
              className="max-w-[1440px] mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-6"
            >
              {/* Streamed Progress List */}
              {showProgressPanel && (
                <div
                  aria-live="polite"
                  className="rounded-lg bg-[#2A1A14] border-2 border-[#C9A04A] p-4 sm:p-6 shadow-xl space-y-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-[#4A3024]">
                    <div className="flex items-center gap-2.5">
                      <span className="w-8 h-8 rounded-full bg-[#5A1F26] border border-[#C9A04A] flex items-center justify-center">
                        <Search
                          className={`w-4 h-4 text-[#F5CE7A] ${
                            isInvestigating ? 'magnifying-sweep' : ''
                          }`}
                        />
                      </span>
                      <div>
                        <h2 className="font-serif-display text-xl sm:text-2xl font-bold text-[#F5CE7A]">
                          {isInvestigating
                            ? 'Live Forensic Investigation in Progress…'
                            : 'Forensic Check Ledger Complete'}
                        </h2>
                        <p className="text-xs text-[#D9C79F]">
                          8 parallel real-asset checks · Fast 3–5 second full forensic dossier
                          {currentReport?.inspectionDurationMs
                            ? ` · Completed in ${(currentReport.inspectionDurationMs / 1000).toFixed(1)}s`
                            : ''}
                        </p>
                      </div>
                    </div>

                    {!isInvestigating && (
                      <button
                        type="button"
                        onClick={() => setShowProgressPanel(false)}
                        className="text-xs underline text-[#D9C79F] hover:text-[#F5CE7A] cursor-pointer"
                      >
                        Hide check ledger
                      </button>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {CHECK_STAGES.map((stage) => {
                      const status = checkStatuses[stage.id];
                      return (
                        <div
                          key={stage.id}
                          className="px-3.5 py-2.5 rounded bg-[#170E0B] border border-[#4A3024] flex items-center justify-between gap-3"
                        >
                          <span className="text-sm text-[#F2E6C9]">{stage.label}</span>
                          {renderCheckStatusBadge(status)}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

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
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="font-serif-display text-2xl sm:text-3xl font-bold text-[#F5CE7A]">
                      Active Case Dossier
                    </h2>
                    <span className="font-mono-code text-xs text-[#D9C79F]">
                      {currentReport.inspectionDurationMs
                        ? `Inspected in ${(currentReport.inspectionDurationMs / 1000).toFixed(1)}s · `
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
