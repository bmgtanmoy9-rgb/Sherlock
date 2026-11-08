/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseReportData } from '../types/sherlock';

export interface SectionSeoMetadata {
  sectionId: string;
  canonicalPath: string;
  title: string;
  description: string;
  ogTitle: string;
  ogDescription: string;
  breadcrumbName: string;
}

export const CANONICAL_BASE_URL =
  'https://ais-pre-zd6t5bbhqlsgjgzmvqwzgo-226281853003.asia-southeast1.run.app';

export const SECTION_SEO_MAP: Record<string, SectionSeoMetadata> = {
  home: {
    sectionId: 'home',
    canonicalPath: '/',
    title:
      'SHERLOCK — AI Website Scam Checker, Phishing Link Detector & Domain Forensics',
    description:
      'Investigate any suspicious URL, website, or QR code before you trust it. SHERLOCK runs 8 deterministic forensic checks—live DNS, RDAP WHOIS, TLS certificates, brand impersonation, and public user reviews—to expose phishing and scam websites.',
    ogTitle:
      'SHERLOCK — The AI Digital Detective | Website Scam & Phishing Link Forensics',
    ogDescription:
      'Every website leaves clues. Inspect any link or QR code with live DNS, RDAP WHOIS domain age, TLS certificate forensics, and deterministic 0–100 Suspicion Index scoring.',
    breadcrumbName: 'Investigation Desk',
  },
  guide: {
    sectionId: 'guide',
    canonicalPath: '/guide',
    title:
      'How Website Forensics Works — 8-Point Phishing & Domain Inspection Guide | SHERLOCK',
    description:
      'Learn how SHERLOCK investigates suspicious links across 8 forensic dimensions: domain lexical identity, brand typosquatting, RDAP registration age, TLS certificates, redirect chains, HTTP security headers, and witness reports.',
    ogTitle: '8-Point Website Forensic Guide — How SHERLOCK Detects Phishing & Scam Links',
    ogDescription:
      'Explore the 4-stage investigative methodology and 8 forensic evidence categories used by SHERLOCK to separate legitimate businesses from deceptive phishing kits.',
    breadcrumbName: 'Forensic Guide',
  },
  index: {
    sectionId: 'index',
    canonicalPath: '/suspicion-index',
    title:
      '0–100 Website Suspicion Index & Why HTTPS Padlocks Do Not Equal Trust | SHERLOCK',
    description:
      'Understand SHERLOCK’s deterministic 0–100 Suspicion Index scoring rubric, risk bands, point weights, and why over 80% of phishing websites display a valid HTTPS padlock certificate.',
    ogTitle: 'SHERLOCK 0–100 Suspicion Index — Transparent Website Risk Scoring Rubric',
    ogDescription:
      'See how deterministic risk points and verified trust credits combine into an auditable 0–100 Suspicion Index score—and why HTTPS padlocks can still hide deceptive websites.',
    breadcrumbName: 'Suspicion Index',
  },
  actions: {
    sectionId: 'actions',
    canonicalPath: '/what-to-do',
    title:
      'What To Do If You Clicked a Phishing Link or Scam Website — Incident Playbook | SHERLOCK',
    description:
      'Step-by-step cybersecurity response checklist if you visited a suspicious website, entered a password, scanned a malicious QR code, or authorized a payment to a suspected scammer.',
    ogTitle: 'Phishing & Scam Incident Response Playbook — What To Do Next | SHERLOCK',
    ogDescription:
      'Practical, calm protective actions to secure your accounts, freeze unauthorized payments, revoke active sessions, and document forensic evidence.',
    breadcrumbName: 'What To Do',
  },
  witness: {
    sectionId: 'witness',
    canonicalPath: '/witness-intelligence',
    title:
      'Community Witness Intelligence — Crowdsourced Scam & Phishing Reports | SHERLOCK',
    description:
      'Discover how first-hand witness reports of fake login prompts, UPI/crypto payment traps, and SMS phishing lures strengthen SHERLOCK’s real-time domain investigations with anti-abuse safeguards.',
    ogTitle: 'Community Witness Network — Real-Time Scam Sightings & Threat Intelligence',
    ogDescription:
      'Crowdsourced scam evidence with strict rate-limiting and anti-brigading validation to protect internet users from emerging zero-hour phishing domains.',
    breadcrumbName: 'Witness Intelligence',
  },
  safety: {
    sectionId: 'safety',
    canonicalPath: '/safety-ethics',
    title:
      'Safety, Privacy & Ethical Forensics Charter — Passive URL Inspection | SHERLOCK',
    description:
      'Read SHERLOCK’s ethical cybersecurity charter: passive-only network inspection, DNS-pinned SSRF protection, zero password harvesting, and transparent open-methodology scoring.',
    ogTitle: 'SHERLOCK Safety, Privacy & Ethical Forensics Charter',
    ogDescription:
      'How SHERLOCK investigates suspicious websites safely using passive DNS/RDAP/TLS telemetry, strict SSRF guards, and transparent forensic rules.',
    breadcrumbName: 'Safety & Ethics',
  },
};

export function resolveSectionFromLocation(pathname: string, hash: string): string {
  const cleanHash = hash.replace(/^#/, '').trim().toLowerCase();
  if (cleanHash === 'how' || cleanHash === 'evidence') return 'guide';
  if (cleanHash && SECTION_SEO_MAP[cleanHash]) {
    return cleanHash;
  }

  const cleanPath = pathname.replace(/\/+$/, '').toLowerCase();
  switch (cleanPath) {
    case '/guide':
    case '/how-it-works':
    case '/features':
      return 'guide';
    case '/suspicion-index':
    case '/scoring':
      return 'index';
    case '/what-to-do':
    case '/incident-response':
      return 'actions';
    case '/witness-intelligence':
    case '/community-reports':
      return 'witness';
    case '/safety-ethics':
    case '/privacy':
    case '/about':
    case '/faq':
      return 'safety';
    default:
      return 'home';
  }
}

function setMetaTag(selector: string, attribute: string, value: string): void {
  const el = document.querySelector(selector);
  if (el) {
    el.setAttribute(attribute, value);
  }
}

export function applyDynamicSeo(
  activeSection: string,
  activeReport?: CaseReportData | null
): void {
  if (typeof document === 'undefined') return;

  const baseMeta = SECTION_SEO_MAP[activeSection] || SECTION_SEO_MAP.home;
  const origin =
    typeof window !== 'undefined' && window.location.origin
      ? window.location.origin
      : CANONICAL_BASE_URL;

  let title = baseMeta.title;
  let description = baseMeta.description;
  let ogTitle = baseMeta.ogTitle;
  let ogDescription = baseMeta.ogDescription;
  let canonicalUrl = `${origin}${baseMeta.canonicalPath === '/' ? '/' : baseMeta.canonicalPath}`;

  // If user is actively viewing a specific investigated domain on the Home desk, enrich title & meta
  if (activeSection === 'home' && activeReport && activeReport.host) {
    const scoreDisplay =
      activeReport.index !== null ? `${activeReport.index}/100` : 'Unverified';
    const levelLabel = activeReport.level.replace(/_/g, ' ');
    const deductionSnippet =
      activeReport.deduction?.text || `${scoreDisplay} Suspicion Index`;
    title = `${activeReport.host} Scam & Safety Investigation (${scoreDisplay} — ${levelLabel}) | SHERLOCK`;
    description = `Forensic investigation dossier for ${activeReport.host}: Suspicion Index ${scoreDisplay} (${levelLabel}). ${deductionSnippet}`;
    ogTitle = `Case File ${activeReport.id}: ${activeReport.host} (${scoreDisplay}) — SHERLOCK`;
    ogDescription = description;
  }

  document.title = title;

  setMetaTag('meta[name="description"]', 'content', description);
  setMetaTag('meta[property="og:title"]', 'content', ogTitle);
  setMetaTag('meta[property="og:description"]', 'content', ogDescription);
  setMetaTag('meta[property="og:url"]', 'content', canonicalUrl);
  setMetaTag('meta[name="twitter:title"]', 'content', ogTitle);
  setMetaTag('meta[name="twitter:description"]', 'content', ogDescription);

  const canonicalEl = document.querySelector('link[rel="canonical"]');
  if (canonicalEl) {
    canonicalEl.setAttribute('href', canonicalUrl);
  }
}
