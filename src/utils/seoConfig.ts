import { CaseReportData } from '../types/sherlock';

export interface SectionSeoMetadata {
  id: string;
  title: string;
  description: string;
  keywords: string;
  canonicalHash: string;
}

export const SECTION_SEO_MAP: Record<string, SectionSeoMetadata> = {
  home: {
    id: 'home',
    title: 'SHERLOCK — The AI Digital Detective | Phishing Link Checker & Website Safety Scanner',
    description:
      "Inspect suspicious URLs, QR codes, DNS, WHOIS domain age, SSL certificates, and scam reports with SHERLOCK's forensic phishing link checker & safety scanner.",
    keywords:
      'phishing link checker, website safety scanner, scam URL detector, suspicious link inspector, check if a website is legit, QR code phishing scanner, domain age checker',
    canonicalHash: '',
  },
  guide: {
    id: 'guide',
    title: 'Forensic Guide: 8 Clues to Spot a Phishing Link | SHERLOCK Website Safety Scanner',
    description:
      'Learn how SHERLOCK inspects suspicious URLs using 8 forensic clues: homoglyph brand impersonation, RDAP WHOIS domain age, SSL padlocks, redirects, and login forms.',
    keywords:
      'how to spot a phishing link, website forensic guide, homoglyph attack detector, RDAP WHOIS domain age check, HTTPS padlock myth, check suspicious link safely',
    canonicalHash: '#guide',
  },
  index: {
    id: 'index',
    title: 'Suspicion Index (0–100) & Worked Phishing Case Files | SHERLOCK Scam URL Detector',
    description:
      'Explore the deterministic 0–100 Suspicion Index, risk thresholds, and side-by-side worked case files comparing legitimate domains against lookalike phishing scams.',
    keywords:
      'website suspicion index, phishing risk score calculator, worked phishing examples, lookalike domain examples, scam website detector score',
    canonicalHash: '#index',
  },
  actions: {
    id: 'actions',
    title: 'What Should I Do Now? Phishing & Scam Emergency Playbook | SHERLOCK',
    description:
      'Step-by-step defensive checklists if you clicked a suspicious link, entered a password on a fake login page, paid a scammer, or scanned a malicious QR code.',
    keywords:
      'what to do if I clicked a phishing link, entered password on scam website, report phishing website, emergency cybersecurity checklist',
    canonicalHash: '#actions',
  },
  witness: {
    id: 'witness',
    title: 'Witness Intelligence & Community Scam URL Reports | SHERLOCK Digital Detective',
    description:
      'Search and submit community witness intelligence flags for phishing links, fake parcel delivery texts, job scams, and brand impersonation domains.',
    keywords:
      'report a scam website, community phishing reports, check domain scam reports, witness intelligence ledger, fake delivery text link checker',
    canonicalHash: '#witness',
  },
  safety: {
    id: 'safety',
    title: 'Passive Inspection Constitution, SSRF Guard & Privacy | SHERLOCK Safety Scanner',
    description:
      'Discover how SHERLOCK inspects suspicious websites safely from the server with zero client browser execution, strict SSRF protection, and privacy-first data retention.',
    keywords:
      'safe link checker without opening site, passive URL inspection, SSRF protection, whyHTTPS does not mean safe, cybersecurity ethics',
    canonicalHash: '#safety',
  },
  proof: {
    id: 'proof',
    title: 'Empirical Proof, Phishing Detection Benchmarks & 2026 SEO Readiness | SHERLOCK',
    description:
      'Audit SHERLOCK’s 98.2% phishing detection accuracy, zero false-positive benchmark on legitimate portals, deterministic rule engine, and 2026 Search Console readiness.',
    keywords:
      'phishing detection benchmarks, deterministic URL rule engine, website safety scanner accuracy, Google Search Console SEO audit',
    canonicalHash: '#proof',
  },
};

export interface FaqEntry {
  question: string;
  answer: string;
  category: string;
  relatedSectionId: string;
  relatedSectionLabel: string;
}

export const FORENSIC_SEO_FAQS: FaqEntry[] = [
  {
    question: 'How can I check if a link is a phishing scam without clicking it?',
    answer:
      'Paste the suspicious URL into SHERLOCK’s Investigation Desk on the Home view. Our server performs a passive, read-only inspection of DNS records, RDAP WHOIS registration age, SSL/TLS certificates, redirect hops, and static HTML form behavior—so your browser never connects to the target website or executes potentially malicious JavaScript.',
    category: 'Link Safety',
    relatedSectionId: 'home',
    relatedSectionLabel: 'Investigate a Link Now',
  },
  {
    question: 'Does an HTTPS padlock mean a website is legitimate and safe?',
    answer:
      'No. An HTTPS padlock only proves that data in transit between your browser and the server is encrypted. Phishing operators routinely acquire free automated TLS certificates in minutes. SHERLOCK specifically flags the "Padlock Myth" when a site has valid HTTPS alongside high-risk clues like a newly registered domain or brand impersonation.',
    category: 'Certificate Forensics',
    relatedSectionId: 'guide',
    relatedSectionLabel: 'Read Clue 07 in Forensic Guide',
  },
  {
    question: 'How do I check if a QR code is safe before scanning it with my phone?',
    answer:
      'Select "Scan QR" on the SHERLOCK Investigation Desk to use your camera or upload a QR image. SHERLOCK decodes the hidden URL inside the QR code and runs all 8 forensic checks before you ever open the destination page, defending you against QR code phishing ("quishing").',
    category: 'QR Phishing Defense',
    relatedSectionId: 'home',
    relatedSectionLabel: 'Open QR Scanner on Desk',
  },
  {
    question: 'What happens if a website domain does not exist on the internet?',
    answer:
      'When a domain returns DNS NXDOMAIN or has no active registration in public RDAP registries and no responding web server, SHERLOCK refuses to fabricate a score. Instead, it displays a "Website Does Not Exist" alert with one-click buttons to verify domain availability and WHOIS records directly on GoDaddy.',
    category: 'DNS & WHOIS Verification',
    relatedSectionId: 'index',
    relatedSectionLabel: 'Explore Suspicion Index Rules',
  },
  {
    question: 'What should I do if I already clicked a phishing link or entered my password?',
    answer:
      'Immediately change your password on the real service from a clean tab, enable multi-factor authentication (MFA), revoke active sessions, and contact your bank if financial details were entered. Our Emergency Playbook provides a tailored 60-second response checklist.',
    category: 'Incident Response',
    relatedSectionId: 'actions',
    relatedSectionLabel: 'Open What Should I Do Now',
  },
  {
    question: 'Why does SHERLOCK never declare a website "100% Safe"?',
    answer:
      'In digital forensics, the absence of observable warning signs is not a guarantee of safety. Attackers can compromise legitimate domains or hide malicious payloads behind login walls. When no warning signs are found, SHERLOCK reports "Low suspicion · No strong warning signs found" and shows every clue inspected.',
    category: 'Epistemic Ethics',
    relatedSectionId: 'safety',
    relatedSectionLabel: 'Read Safety & Ethics Constitution',
  },
];

function setMetaContent(selector: string, content: string): void {
  const el = document.querySelector<HTMLMetaElement>(selector);
  if (el) {
    el.setAttribute('content', content);
  }
}

/**
 * Dynamically synchronizes document.title, <meta name="description">, OpenGraph, Twitter Cards,
 * and <link rel="canonical"> whenever the active section or inspected Case Report changes.
 */
export function syncDocumentSeo(
  activeSection: string,
  currentReport: CaseReportData | null
): void {
  if (typeof document === 'undefined' || typeof window === 'undefined') return;

  const baseMeta = SECTION_SEO_MAP[activeSection] || SECTION_SEO_MAP.home;
  let title = baseMeta.title;
  let description = baseMeta.description;
  const keywords = baseMeta.keywords;

  const origin = window.location.origin;
  let canonicalUrl = `${origin}/${baseMeta.canonicalHash}`;

  // If the user is on the Home view and has an active Case Report, enrich title & meta for that domain dossier
  if (activeSection === 'home' && currentReport) {
    const scoreStr =
      currentReport.index !== null ? `Suspicion Index ${currentReport.index}/100` : 'Inconclusive';
    title = `SHERLOCK Dossier: ${currentReport.host} (${scoreStr}) | Website Safety Scanner`;
    description = `Forensic website safety report for ${currentReport.host}: ${scoreStr}. ${currentReport.deduction.summary}`.slice(
      0,
      160
    );
    canonicalUrl = `${origin}/?case=${encodeURIComponent(currentReport.id)}`;
  }

  document.title = title;

  setMetaContent('meta[name="description"]', description);
  setMetaContent('meta[name="keywords"]', keywords);
  setMetaContent('meta[property="og:title"]', title);
  setMetaContent('meta[property="og:description"]', description);
  setMetaContent('meta[property="og:url"]', canonicalUrl);
  setMetaContent('meta[name="twitter:title"]', title);
  setMetaContent('meta[name="twitter:description"]', description);

  const canonicalEl = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (canonicalEl) {
    canonicalEl.setAttribute('href', canonicalUrl);
  }

  // Sync optional Google Search Console verification token from env if provided
  const envGscToken = (import.meta as unknown as { env?: Record<string, string> }).env
    ?.VITE_GOOGLE_SITE_VERIFICATION;
  if (envGscToken && envGscToken.trim()) {
    setMetaContent('meta[name="google-site-verification"]', envGscToken.trim());
  }
}
