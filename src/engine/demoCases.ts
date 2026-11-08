import type {
  CaseReportData,
  CheckStageId,
  CheckStatus,
  Clue,
  WitnessReportEntry,
  WitnessSummary,
} from '../types/sherlock.ts';
import {
  buildGoDaddyUrls,
  buildTemplateDeduction,
  computeSuspicionScore,
  getWorkedExampleCaseReport,
} from './ruleEngine.ts';

const ALL_DONE: Record<CheckStageId, CheckStatus> = {
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
 * Demo Case 2: Legitimate established institution (🟢 Low suspicion, 0/100)
 * Demonstrates that SHERLOCK never says "safe", only "No strong warning signs found".
 */
export function getLegitimateDemoCase(): CaseReportData {
  const host = 'ox.ac.uk';
  const clues: Clue[] = [
    {
      id: 'legit-age',
      code: 'CLUE-AGE-00',
      name: 'Long-standing institutional domain registration',
      finding: 'Domain belongs to the regulated .ac.uk academic registry and has multi-decade registration history.',
      severity: 'info',
      explanation:
        'Long-established academic and organizational domains with consistent registration records carry low domain-age suspicion.',
      howChecked: 'Queried RDAP / registry history and verified public suffix governance.',
      points: 0,
      category: 'domain_age',
    },
    {
      id: 'legit-cert',
      code: 'CLUE-CERT-00',
      name: 'Valid TLS certificate matching host',
      finding: 'HTTPS connection is encrypted with a valid certificate matching ox.ac.uk.',
      severity: 'info',
      explanation:
        'A valid certificate confirms the connection is encrypted in transit, though encryption alone never guarantees a site is trustworthy.',
      howChecked: 'Inspected X.509 peer certificate subject alternative names and validity dates.',
      points: 0,
      category: 'certificate',
    },
    {
      id: 'legit-headers',
      code: 'CLUE-SEC-00',
      name: 'Standard browser security headers present',
      finding: 'Strict-Transport-Security (HSTS) and frame-protection headers are properly configured.',
      severity: 'info',
      explanation: 'Well-maintained institutional servers enforce HSTS and framing protections.',
      howChecked: 'Inspected HTTP response headers from a passive HEAD/GET request.',
      points: 0,
      category: 'security_headers',
    },
  ];

  const scored = computeSuspicionScore(clues, ALL_DONE, true);
  const deduction = buildTemplateDeduction(host, scored.level, scored.confidence, scored.sortedClues, true);

  return {
    id: 'CASE-221B-1042',
    host,
    sanitizedUrl: 'https://ox.ac.uk',
    createdAt: new Date().toISOString(),
    index: scored.index, // 0
    level: scored.level, // low
    confidence: scored.confidence, // high
    clues: scored.sortedClues,
    categoryBreakdown: scored.categoryBreakdown,
    scoreTally: scored.scoreTally,
    deduction,
    witness: {
      host,
      totalReports: 0,
      byCategory: {
        phishing: 0,
        financial_fraud: 0,
        fake_recruitment: 0,
        shopping_scam: 0,
        brand_impersonation: 0,
        other: 0,
      },
      firstReported: null,
      lastReported: null,
      corroborated: false,
    },
    internetAssets: {
      resolvedIps: ['129.67.242.154', '129.67.242.155'],
      registrar: 'Jisc Services Limited (.ac.uk Registry)',
      registeredAt: '1988-02-11T00:00:00.000Z',
      expiresAt: '2030-02-11T00:00:00.000Z',
      domainAgeDays: 14150,
      tlsIssuer: 'Sectigo RSA Organization Validation Secure Server CA',
      tlsSubject: 'ox.ac.uk',
      tlsValidFrom: '2026-03-01T00:00:00.000Z',
      tlsValidTo: '2027-03-31T23:59:59.000Z',
      tlsProtocol: 'TLSv1.3',
      httpStatus: 200,
      serverHeader: 'Apache / Oxford Institutional Edge',
      redirectChain: ['https://www.ox.ac.uk/'],
      pageTitle: 'University of Oxford',
      metaDescription:
        'Welcome to the official website of the University of Oxford — admissions, research, colleges, and academic divisions.',
      formsDetected: 1,
      hasPasswordInput: false,
      presentSecurityHeaders: ['HSTS', 'X-Frame-Options', 'Referrer-Policy'],
      missingSecurityHeaders: ['CSP'],
      ...buildGoDaddyUrls(host),
    },
    webExperience: {
      sentiment: 'positive',
      summary:
        'Across global academic directories, student forums, and public web indices, ox.ac.uk is universally recognized as the official domain of the University of Oxford with decades of institutional history.',
      highlights: [
        'Governed under the restricted UK academic (.ac.uk) registry operated by Jisc.',
        'Long-standing institutional reputation with zero corroborated phishing or scam reports.',
        'Standard HSTS and organization-validated TLS encryption active.',
      ],
      sources: [
        {
          title: 'University of Oxford — Official Website',
          url: 'https://www.ox.ac.uk',
        },
      ],
    },
    checkStatuses: ALL_DONE,
    specialState: 'none',
    hasValidHttps: true,
    isDemo: true,
  };
}

/**
 * Demo Case 3: "Padlock but suspicious" (🟠 High risk, 69/100)
 * Teaches the core lesson: "The padlock is not proof — most phishing sites have valid HTTPS."
 */
export function getPadlockSuspiciousDemoCase(): CaseReportData {
  const host = 'dhl-parcel-redelivery-fee.example';
  const clues: Clue[] = [
    {
      id: 'padlock-imp',
      code: 'CLUE-IMP-03',
      name: 'Protected courier brand combined with fee keywords',
      finding:
        'The address embeds "dhl" alongside "-parcel-redelivery-fee" on an unrelated root domain instead of dhl.com.',
      severity: 'high',
      explanation:
        'Delivery scams frequently register hyphenated domains combining a trusted courier name with urgent words like "redelivery" or "customs-fee".',
      howChecked: 'Matched hostname tokens against SHERLOCK’s protected courier brand list and lure keyword rules.',
      points: 20,
      category: 'impersonation',
    },
    {
      id: 'padlock-page',
      code: 'CLUE-PAGE-02',
      name: 'Payment & card collection form on brand-mismatched domain',
      finding:
        'The page displays courier branding and requests payment card details + OTP on a domain not owned by the courier.',
      severity: 'critical',
      explanation:
        'When a webpage displays a well-known company’s logo and asks for card details while hosted on an unrelated address, it strongly indicates a payment trap.',
      howChecked: 'Parsed static HTML title and form input fields passively without executing JavaScript.',
      points: 22,
      category: 'page_behavior',
    },
    {
      id: 'padlock-age',
      code: 'CLUE-AGE-02',
      name: 'Domain registered 14 days ago',
      finding: 'RDAP records indicate this domain was registered 14 days ago.',
      severity: 'high',
      explanation: 'Domains under 30 days old requesting parcel fees or banking details warrant strong caution.',
      howChecked: 'Checked RDAP domain registration timestamp.',
      points: 14,
      category: 'domain_age',
    },
    {
      id: 'padlock-url',
      code: 'CLUE-ID-06',
      name: 'Multiple high-pressure lure keywords in hostname',
      finding: 'Hostname strings together "parcel", "redelivery", and "fee".',
      severity: 'caution',
      explanation: 'Multiple hyphenated urgency words are a classic hallmark of SMS parcel lures.',
      howChecked: 'Evaluated hostname token density against social-engineering vocabulary.',
      points: 6,
      category: 'url_structure',
    },
    {
      id: 'padlock-cert',
      code: 'CLUE-CERT-01',
      name: 'Valid HTTPS padlock issued 2 days ago (Encryption ≠ Trust)',
      finding:
        'The site has a valid, browser-trusted HTTPS certificate issued 48 hours ago—showing a padlock icon despite suspicious indicators.',
      severity: 'caution',
      explanation:
        'Over 80% of modern phishing sites use valid HTTPS certificates obtained automatically for free. The padlock only proves traffic is encrypted in transit, NOT who runs the site.',
      howChecked: 'Verified TLS certificate chain and noticed the recent issuance date (2 days old).',
      points: 4,
      category: 'certificate',
    },
    {
      id: 'padlock-witness',
      code: 'CLUE-WIT-02',
      name: 'Three recent SMS parcel scam reports from witnesses',
      finding: 'Reported 3 times by users who received an unexpected "missed parcel fee" text message.',
      severity: 'caution',
      explanation: 'Community reports corroborate the technical impersonation and newly registered domain signals.',
      howChecked: 'Matched sanitized hostname against Witness Intelligence reports.',
      points: 3,
      category: 'community_reports',
    },
  ];

  const scored = computeSuspicionScore(clues, ALL_DONE, true);

  return {
    id: 'CASE-221B-6903',
    host,
    sanitizedUrl: 'https://dhl-parcel-redelivery-fee.example',
    createdAt: new Date().toISOString(),
    index: scored.index, // 69
    level: scored.level, // high_risk
    confidence: scored.confidence, // high
    clues: scored.sortedClues,
    categoryBreakdown: scored.categoryBreakdown,
    scoreTally: scored.scoreTally,
    deduction: {
      summary:
        'Despite displaying a valid HTTPS padlock, this site shows strong indicators of a parcel redelivery fee trap.',
      keyReasons: [
        'Combines a well-known courier brand ("dhl") with "-parcel-redelivery-fee" on an unofficial domain (+20 pts).',
        'Requests payment card details on a domain registered only 14 days ago (+22 pts page behavior, +14 pts age).',
        'Uses a 2-day-old HTTPS certificate (+4 pts) — proving encryption, not legitimacy.',
      ],
      recommendedActions: [
        'Close the page and do not enter payment card details, addresses, or SMS passcodes.',
        'Check tracking numbers only by typing the courier’s official website address yourself.',
        'Delete or report the SMS message that sent this link.',
      ],
      uncertaintyNote:
        'A valid certificate proves the connection is encrypted, not that the site is trustworthy.',
      text: 'Despite showing a valid browser padlock, this address shows strong indicators of impersonating a courier service: it bolts "-parcel-redelivery-fee" onto a known brand name, was registered only two weeks ago, and asks for card details. The padlock only proves your connection is encrypted—anyone can get a free certificate for a lookalike domain in minutes. Do not enter payment details or OTPs; track parcels directly on the courier’s official website.',
      source: 'template',
    },
    witness: {
      host,
      totalReports: 3,
      byCategory: {
        phishing: 1,
        financial_fraud: 0,
        fake_recruitment: 0,
        shopping_scam: 2,
        brand_impersonation: 0,
        other: 0,
      },
      firstReported: '2026-11-05T09:15:00.000Z',
      lastReported: '2026-11-07T21:40:00.000Z',
      corroborated: true,
    },
    internetAssets: {
      resolvedIps: ['198.51.100.89'],
      registrar: 'Namecheap, Inc. (Synthetic Demo Registry)',
      registeredAt: '2026-10-25T11:30:00.000Z',
      expiresAt: '2027-10-25T11:30:00.000Z',
      domainAgeDays: 14,
      tlsIssuer: 'Google Trust Services LLC (WE1 DV)',
      tlsSubject: 'dhl-parcel-redelivery-fee.example',
      tlsValidFrom: '2026-11-06T04:00:00.000Z',
      tlsValidTo: '2027-02-04T03:59:59.000Z',
      tlsProtocol: 'TLSv1.3',
      httpStatus: 200,
      serverHeader: 'cloudflare',
      redirectChain: ['https://dhl-parcel-redelivery-fee.example/track-fee'],
      pageTitle: 'DHL Express — Action Required: Unpaid Parcel Redelivery Fee (£1.99)',
      metaDescription: 'Enter your billing address and card details to schedule parcel redelivery.',
      formsDetected: 1,
      hasPasswordInput: false,
      presentSecurityHeaders: ['HSTS'],
      missingSecurityHeaders: ['CSP', 'X-Frame-Options', 'Referrer-Policy'],
      ...buildGoDaddyUrls(host),
    },
    webExperience: {
      sentiment: 'negative',
      summary:
        'Public consumer forums and scam-reporting boards describe widespread SMS "missed parcel fee" messages directing recipients to newly registered lookalike courier domains with valid HTTPS padlocks.',
      highlights: [
        'Recipients report unsolicited text messages demanding a small (£1.99 / $2.50) customs or redelivery charge.',
        'Uses a valid 2-day-old HTTPS certificate so browsers display a padlock icon.',
        'Official DHL parcel tracking is conducted on dhl.com, never on hyphenated fee domains.',
      ],
      sources: [
        {
          title: 'DHL Official Fraud Awareness & Phishing Guide',
          url: 'https://www.dhl.com/global-en/home/footer/fraud-awareness.html',
        },
      ],
    },
    checkStatuses: ALL_DONE,
    specialState: 'none',
    hasValidHttps: true,
    isDemo: true,
  };
}

export const SEEDED_WITNESS_REPORTS: WitnessReportEntry[] = [
  {
    id: 'WIT-901',
    host: 'paypa1-secure-login.example',
    category: 'phishing',
    note: 'Received SMS claiming my account was limited and asking to sign in here.',
    createdAt: '2026-11-07T19:05:00.000Z',
  },
  {
    id: 'WIT-902',
    host: 'paypa1-secure-login.example',
    category: 'brand_impersonation',
    note: 'Uses number 1 instead of letter l in the domain name.',
    createdAt: '2026-11-06T14:22:00.000Z',
  },
  {
    id: 'WIT-903',
    host: 'paypa1-secure-login.example',
    category: 'phishing',
    note: 'Login form redirects to an unfamiliar domain.',
    createdAt: '2026-11-04T18:10:00.000Z',
  },
  {
    id: 'WIT-904',
    host: 'paypa1-secure-login.example',
    category: 'phishing',
    note: 'Unexpected invoice alert email linked to this address.',
    createdAt: '2026-11-03T11:20:00.000Z',
  },
  {
    id: 'WIT-905',
    host: 'dhl-parcel-redelivery-fee.example',
    category: 'shopping_scam',
    note: 'Text message asking for a 1.99 redelivery fee with a valid HTTPS padlock.',
    createdAt: '2026-11-07T21:40:00.000Z',
  },
  {
    id: 'WIT-906',
    host: 'dhl-parcel-redelivery-fee.example',
    category: 'shopping_scam',
    note: 'Fake customs charge page asking for credit card and OTP.',
    createdAt: '2026-11-06T08:12:00.000Z',
  },
  {
    id: 'WIT-907',
    host: 'dhl-parcel-redelivery-fee.example',
    category: 'phishing',
    note: 'Lookalike parcel tracking portal.',
    createdAt: '2026-11-05T09:15:00.000Z',
  },
  {
    id: 'WIT-908',
    host: 'chevening-grant-portal-verify.top',
    category: 'fake_recruitment',
    note: 'WhatsApp message promising fast-track scholarship approval for an application fee.',
    createdAt: '2026-11-07T16:30:00.000Z',
  },
  {
    id: 'WIT-909',
    host: 'workday-remote-onboarding-check.xyz',
    category: 'fake_recruitment',
    note: 'Recruiter on Telegram asked for bank details for direct deposit setup.',
    createdAt: '2026-11-07T12:05:00.000Z',
  },
  {
    id: 'WIT-910',
    host: 'hsbc-security-device-sync.support',
    category: 'financial_fraud',
    note: 'Automated call and SMS asking to synchronize security token.',
    createdAt: '2026-11-06T20:45:00.000Z',
  },
];

export interface ThreatFeedEntry {
  host: string;
  source: 'OpenPhish' | 'URLhaus' | 'PhishTank';
  category: string;
  firstSeen: string;
}

export const SEEDED_FEED_ENTRIES: ThreatFeedEntry[] = [
  {
    host: 'confirmed-phish-login-portal.example',
    source: 'OpenPhish',
    category: 'Confirmed credential harvesting kit',
    firstSeen: '2026-11-06T04:00:00.000Z',
  },
  {
    host: 'rnicrosoft-office365-sso.xyz',
    source: 'PhishTank',
    category: 'Cloud account homoglyph phishing',
    firstSeen: '2026-11-05T15:30:00.000Z',
  },
  {
    host: 'invoice-loader-drop.top',
    source: 'URLhaus',
    category: 'Malware payload distribution',
    firstSeen: '2026-11-07T02:15:00.000Z',
  },
];

export function buildWitnessSummaryForHost(
  host: string,
  reports: WitnessReportEntry[],
  corroborated = false
): WitnessSummary {
  const cleanHost = host.toLowerCase().replace(/^www\./, '');
  const matching = reports.filter((r) => r.host.toLowerCase().replace(/^www\./, '') === cleanHost);

  const byCategory: WitnessSummary['byCategory'] = {
    phishing: 0,
    financial_fraud: 0,
    fake_recruitment: 0,
    shopping_scam: 0,
    brand_impersonation: 0,
    other: 0,
  };

  for (const r of matching) {
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  }

  const sortedDates = matching
    .map((r) => r.createdAt)
    .sort((a, b) => new Date(a).getTime() - new Date(b).getTime());

  return {
    host: cleanHost,
    totalReports: matching.length,
    byCategory,
    firstReported: sortedDates[0] ?? null,
    lastReported: sortedDates[sortedDates.length - 1] ?? null,
    corroborated,
    recentReports: matching.slice(0, 6),
  };
}

export const DEMO_PRESETS: Record<string, () => CaseReportData> = {
  'paypa1-secure-login.example': getWorkedExampleCaseReport,
  'ox.ac.uk': getLegitimateDemoCase,
  'dhl-parcel-redelivery-fee.example': getPadlockSuspiciousDemoCase,
};
