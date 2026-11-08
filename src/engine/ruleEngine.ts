import type {
  CaseReportData,
  CategoryBreakdown,
  CheckStageId,
  CheckStatus,
  Clue,
  ConfidenceLevel,
  ScoreTallySummary,
  SherlockDeduction,
  SuspicionLevel,
} from '../types/sherlock.ts';
import {
  CATEGORY_WEIGHTS,
  CONFUSABLE_CHAR_MAP,
  LEVEL_METADATA,
  PROTECTED_BRANDS,
  RISKY_TLDS,
  SUSPICIOUS_KEYWORDS,
} from './weightsConfig.ts';

export interface NormalizedUrlResult {
  valid: boolean;
  blocked?: boolean;
  reason?: string;
  sanitizedUrl?: string;
  host?: string;
  protocol?: 'http:' | 'https:';
  hadAtSymbol?: boolean;
  originalLength?: number;
}

/**
 * Checks whether an IPv4/IPv6 literal, hex/octal/decimal IP encoding, or hostname
 * belongs to private, loopback, link-local, or cloud metadata ranges (SSRF guard).
 */
export function isPrivateOrReservedHost(host: string): boolean {
  const clean = host.toLowerCase().trim().replace(/^\[|\]$/g, '').replace(/\.$/, '');

  if (
    !clean ||
    clean === 'localhost' ||
    clean.endsWith('.localhost') ||
    clean.endsWith('.local') ||
    clean.endsWith('.localdomain') ||
    clean.endsWith('.internal') ||
    clean.endsWith('.home.arpa') ||
    clean.endsWith('.corp') ||
    clean.endsWith('.lan') ||
    clean === '0.0.0.0' ||
    clean === '255.255.255.255' ||
    clean === '::1' ||
    clean === '::' ||
    clean === '0:0:0:0:0:0:0:1' ||
    clean === '0:0:0:0:0:0:0:0' ||
    clean === 'metadata.google.internal' ||
    clean === 'metadata' ||
    clean === 'instance-data' ||
    clean === 'kubernetes.default' ||
    clean.endsWith('.kubernetes.default.svc')
  ) {
    return true;
  }

  // Block integer/hex/octal encoded IP literals (e.g. 2130706433, 0x7f000001, 0177.0.0.1)
  if (/^\d+$/.test(clean) || /^0x[0-9a-f]+$/i.test(clean)) {
    return true;
  }

  const dotParts = clean.split('.');
  if (
    dotParts.length <= 4 &&
    dotParts.every((p) => /^\d+$/.test(p) || /^0x[0-9a-f]+$/i.test(p))
  ) {
    // Any octal (leading zero like 0177) or hex octet in an IP literal is blocked as SSRF evasion
    if (dotParts.some((p) => /^0x/i.test(p) || (p.length > 1 && p.startsWith('0')))) {
      return true;
    }
    // Shorthand IPv4 (e.g., 127.1 or 10.1.1)
    if (dotParts.length < 4) {
      return true;
    }
  }

  // IPv6 private, loopback, link-local, documentation, multicast, or IPv4-mapped ranges
  if (clean.includes(':')) {
    if (
      clean.startsWith('fe80:') ||
      clean.startsWith('feb0:') ||
      clean.startsWith('fc00:') ||
      clean.startsWith('fd') ||
      clean.startsWith('ff') ||
      clean.startsWith('2001:db8:') ||
      clean.startsWith('::ffff:127.') ||
      clean.startsWith('::ffff:10.') ||
      clean.startsWith('::ffff:0.') ||
      clean.startsWith('::ffff:192.168.') ||
      clean.startsWith('::ffff:169.254.') ||
      /^::ffff:172\.(1[6-9]|2\d|3[01])\./.test(clean) ||
      clean.startsWith('::127.') ||
      clean.startsWith('::10.') ||
      clean.startsWith('::192.168.')
    ) {
      return true;
    }
  }

  // Standard IPv4 literal check
  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, aStr, bStr, cStr, dStr] = ipv4Match;
    const a = Number(aStr);
    const b = Number(bStr);
    const c = Number(cStr);
    const d = Number(dStr);
    if (a > 255 || b > 255 || c > 255 || d > 255) return true;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Cloud metadata / link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // IETF protocol / TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
    if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // Multicast / reserved
  }

  return false;
}

export function isIpLiteral(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, '');
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) return true;
  if (clean.includes(':')) return true;
  return false;
}

/**
 * Normalizes user input URL, enforces http/https on standard ports,
 * strips query strings and fragments for privacy, and blocks SSRF and injection vectors.
 */
export function normalizeAndValidateUrl(rawInput: string): NormalizedUrlResult {
  if (typeof rawInput !== 'string') {
    return { valid: false, reason: 'Invalid URL input format.' };
  }

  // Strip null bytes and invisible control characters
  const cleanedInput = rawInput.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  if (!cleanedInput) {
    return { valid: false, reason: 'Please paste a website link or domain name to investigate.' };
  }

  if (cleanedInput.length > 2048) {
    return {
      valid: false,
      blocked: true,
      reason: 'URL exceeds the maximum safe length of 2,048 characters.',
    };
  }

  // Block dangerous schemes before adding default https://
  if (/^(javascript|data|vbscript|file|ftp|gopher|ws|wss|dict|ldap|jar|mailto|tel):/i.test(cleanedInput)) {
    return {
      valid: false,
      blocked: true,
      reason: 'Non-HTTP scheme is blocked by the security guard.',
    };
  }

  const hadAtSymbol = cleanedInput.includes('@');
  const withProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(cleanedInput)
    ? cleanedInput
    : `https://${cleanedInput}`;

  let parsed: URL;
  try {
    parsed = new URL(withProtocol);
  } catch {
    return {
      valid: false,
      reason: 'That address does not look like a valid website URL. Check for typos or spaces.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      blocked: true,
      reason: 'Only standard web links (HTTP and HTTPS) can be investigated.',
    };
  }

  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    return {
      valid: false,
      blocked: true,
      reason: `Non-standard network port (:${parsed.port}) is blocked by the SSRF safety guard.`,
    };
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253 || (!host.includes('.') && !isIpLiteral(host))) {
    return {
      valid: false,
      reason: 'Please enter a full domain name (for example, example.com).',
    };
  }

  // Reject hostnames with suspicious shell/HTML/script characters
  if (/[<>'"`;\\{}|\s^]/.test(host)) {
    return {
      valid: false,
      blocked: true,
      reason: 'Hostname contains disallowed characters blocked by the security guard.',
    };
  }

  if (isPrivateOrReservedHost(host)) {
    return {
      valid: false,
      blocked: true,
      reason:
        'Private, loopback, internal network, and cloud metadata addresses are blocked by SHERLOCK’s SSRF safety guard.',
    };
  }

  // Strip query string and fragment before storing or sharing
  const cleanPathname =
    parsed.pathname === '/'
      ? ''
      : parsed.pathname.replace(/[<>"'`]/g, '').replace(/\/+$/, '');
  const sanitizedUrl = `${parsed.protocol}//${host}${cleanPathname}`;

  return {
    valid: true,
    sanitizedUrl,
    host,
    protocol: parsed.protocol as 'http:' | 'https:',
    hadAtSymbol: hadAtSymbol || Boolean(parsed.username || parsed.password),
    originalLength: cleanedInput.length,
  };
}

/**
 * Computes Levenshtein edit distance between two strings.
 */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

export function normalizeHomoglyphs(input: string): string {
  const multiReplaced = input
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd');

  return Array.from(multiReplaced)
    .map((ch) => CONFUSABLE_CHAR_MAP[ch] ?? ch)
    .join('');
}

/**
 * Inspects URL structure & domain identity (Check 1).
 */
export function inspectDomainIdentity(
  host: string,
  sanitizedUrl: string,
  hadAtSymbol = false,
  originalLength = sanitizedUrl.length
): Clue[] {
  const clues: Clue[] = [];
  const labels = host.split('.');

  if (isIpLiteral(host)) {
    clues.push({
      id: 'url-ip-host',
      code: 'CLUE-ID-01',
      name: 'Raw IP address used instead of domain name',
      finding: `The link points directly to a numeric IP address (${host}) rather than a named organization.`,
      severity: 'high',
      explanation:
        'Legitimate banking, retail, and university portals use registered domain names. Phishing kits often use raw IP addresses to avoid domain takedowns.',
      howChecked: 'Parsed the hostname from the URL and tested whether it is a numeric IPv4/IPv6 literal.',
      points: 12,
      category: 'url_structure',
    });
  }

  if (hadAtSymbol) {
    clues.push({
      id: 'url-at-symbol',
      code: 'CLUE-ID-02',
      name: 'Deceptive "@" credential prefix in URL',
      finding: 'The link contains an "@" character before the actual destination host.',
      severity: 'high',
      explanation:
        'In web addresses, everything before "@" is treated as a username and ignored when routing, allowing attackers to disguise the real destination.',
      howChecked: 'Inspected raw URL syntax for userinfo components or "@" characters.',
      points: 10,
      category: 'url_structure',
    });
  }

  if (host.includes('xn--')) {
    clues.push({
      id: 'url-punycode',
      code: 'CLUE-ID-03',
      name: 'Punycode / Internationalized Domain Name (IDN)',
      finding: `The domain (${host}) uses Punycode encoding ("xn--") to display non-Latin characters.`,
      severity: 'caution',
      explanation:
        'While many legitimate international sites use IDNs, lookalike scams also use Cyrillic or Greek letters that appear identical to Latin letters.',
      howChecked: 'Checked domain labels for the ASCII Compatible Encoding prefix "xn--".',
      points: 8,
      category: 'url_structure',
    });
  }

  if (labels.length >= 4 && !host.endsWith('.ac.uk') && !host.endsWith('.co.uk') && !host.endsWith('.gov.uk')) {
    clues.push({
      id: 'url-subdomains',
      code: 'CLUE-ID-04',
      name: 'Unusually deep subdomain chain',
      finding: `The hostname contains ${labels.length - 2} subdomain levels (${host}).`,
      severity: 'caution',
      explanation:
        'Deceptive links often stack subdomains (such as "login.secure.brand.random-host.example") so mobile address bars cut off the real domain at the end.',
      howChecked: 'Counted dot-separated hostname labels excluding standard public suffixes.',
      points: 5,
      category: 'url_structure',
    });
  }

  const matchedRiskyTld = RISKY_TLDS.find((tld) => host.endsWith(tld));
  if (matchedRiskyTld) {
    clues.push({
      id: 'url-risky-tld',
      code: 'CLUE-ID-05',
      name: `High-abuse top-level domain (${matchedRiskyTld})`,
      finding: `The address ends in "${matchedRiskyTld}", a top-level extension frequently used for disposable campaigns.`,
      severity: 'caution',
      explanation:
        'Low-cost domains like .xyz, .top, .click, and .zip see disproportionately high volumes of automated phishing registrations.',
      howChecked: 'Matched the top-level domain against SHERLOCK’s curated high-abuse TLD list.',
      points: 5,
      category: 'url_structure',
    });
  }

  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((kw) => host.includes(kw));
  if (matchedKeywords.length >= 1) {
    const pts = Math.min(8, matchedKeywords.length * 4);
    clues.push({
      id: 'url-keywords',
      code: 'CLUE-ID-06',
      name: 'Urgency or credential keywords inside hostname',
      finding: `Hostname includes high-pressure terms: ${matchedKeywords.slice(0, 4).join(', ')}.`,
      severity: matchedKeywords.length >= 2 ? 'caution' : 'low',
      explanation:
        'Real organizations rarely register separate domains with words like "-secure-login" or "-redelivery-fee" bolted onto the main domain name.',
      howChecked: 'Scanned the hostname tokens against common social-engineering lure vocabulary.',
      points: pts,
      category: 'url_structure',
    });
  }

  if (originalLength > 85) {
    clues.push({
      id: 'url-long',
      code: 'CLUE-ID-07',
      name: 'Abnormally long web address',
      finding: `The original link is ${originalLength} characters long, making the true host harder to inspect on a phone screen.`,
      severity: 'low',
      explanation: 'Long URLs can hide redirection parameters or push the real domain out of view.',
      howChecked: 'Measured character length of the submitted link before query sanitization.',
      points: 3,
      category: 'url_structure',
    });
  }

  return clues;
}

/**
 * Inspects hostname for brand impersonation, homoglyphs, and brand+keyword patterns (Check 2).
 */
export function inspectImpersonation(host: string): Clue[] {
  const clues: Clue[] = [];
  const labels = host.split('.');
  const cleanHost = host.replace(/^www\./, '');

  // If the host is an official domain of any protected brand, return zero impersonation clues
  const isOfficial = PROTECTED_BRANDS.some((b) =>
    b.officialDomains.some((off) => cleanHost === off || cleanHost.endsWith(`.${off}`))
  );
  if (isOfficial) {
    return [];
  }

  const registrablePart = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  const tokens = cleanHost.split(/[\-.]/).filter(Boolean);
  const deconfoundedRegistrable = normalizeHomoglyphs(registrablePart);

  for (const brand of PROTECTED_BRANDS) {
    // 1. Homoglyph or close edit distance on tokens
    for (const token of tokens) {
      const normalizedToken = normalizeHomoglyphs(token);
      const dist = editDistance(token, brand.token);
      const normDist = editDistance(normalizedToken, brand.token);

      if (
        (normalizedToken === brand.token && token !== brand.token) ||
        (brand.token.length >= 5 && (dist === 1 || normDist === 1) && token !== brand.token)
      ) {
        const hasKeyword = SUSPICIOUS_KEYWORDS.some((kw) => cleanHost.includes(kw));
        clues.push({
          id: `imp-homoglyph-${brand.token}`,
          code: 'CLUE-IMP-01',
          name: `Homoglyph lookalike of ${brand.name}`,
          finding: `"${token}" in ${host} closely imitates "${brand.token}" (${brand.name})${
            hasKeyword ? ' and combines it with security/login wording' : ''
          }.`,
          severity: 'critical',
          explanation:
            'Lookalike domains swap visually similar characters (such as the number "1" for "l", "0" for "o", or "rn" for "m") to trick rapid glances on mobile screens.',
          howChecked:
            'Compared hostname tokens against 75+ protected brands using homoglyph normalization and Levenshtein edit distance.',
          points: hasKeyword ? 28 : 26,
          category: 'impersonation',
        });
        return clues;
      }
    }

    // 2. Exact brand name embedded with hyphenated keywords or as a deceptive subdomain
    if (tokens.includes(brand.token) || deconfoundedRegistrable.includes(brand.token)) {
      const isSubdomainDeception = labels.slice(0, -2).some((sub) => sub.includes(brand.token));
      const hasKeyword = SUSPICIOUS_KEYWORDS.some((kw) => cleanHost.includes(kw));

      if (isSubdomainDeception) {
        clues.push({
          id: `imp-subdomain-${brand.token}`,
          code: 'CLUE-IMP-02',
          name: `${brand.name} placed in a deceptive subdomain`,
          finding: `"${brand.name}" appears at the start of ${host}, but the actual controlling domain at the end is unrelated.`,
          severity: 'high',
          explanation:
            'Anyone can create a subdomain named after a famous bank or courier on their own domain. Only the root domain before the first single slash controls the website.',
          howChecked:
            'Separated the registrable root domain from leading subdomains and checked for protected brand names.',
          points: 24,
          category: 'impersonation',
        });
        return clues;
      }

      if (hasKeyword || registrablePart !== brand.token) {
        clues.push({
          id: `imp-combo-${brand.token}`,
          code: 'CLUE-IMP-03',
          name: `${brand.name} combined with lure keywords`,
          finding: `The domain combines the brand "${brand.name}" with extra words in "${host}" instead of using ${brand.officialDomains[0]}.`,
          severity: 'high',
          explanation:
            'Impersonators register domains like "brand-support-verify.com" when the real brand domain is already owned.',
          howChecked:
            'Checked whether a protected brand token appears alongside hyphenated lure keywords outside its official domain list.',
          points: 20,
          category: 'impersonation',
        });
        return clues;
      }
    }
  }

  return clues;
}

/**
 * Pure deterministic rule engine that computes the Suspicion Index (0-100),
 * applies the reputation override rule and community corroboration rule,
 * and determines Level and Confidence.
 */
export function computeSuspicionScore(
  clues: Clue[],
  checkStatuses: Record<CheckStageId, CheckStatus>,
  hasValidHttps = true
): {
  index: number | null;
  level: SuspicionLevel;
  confidence: ConfidenceLevel;
  sortedClues: Clue[];
  categoryBreakdown: CategoryBreakdown[];
  scoreTally: ScoreTallySummary;
  overrideTriggered: boolean;
} {
  // Count completed checks
  const statuses = Object.values(checkStatuses);
  const completedCount = statuses.filter((s) => s === 'done').length;

  let confidence: ConfidenceLevel = 'high';
  if (completedCount <= 4) {
    confidence = 'low';
  } else if (completedCount <= 6) {
    confidence = 'medium';
  }

  // Check if a trusted reputation feed triggered the Override rule
  const overrideClue = clues.find((c) => c.isOverride || c.category === 'reputation_override');
  const overrideTriggered = Boolean(overrideClue);

  // Determine whether any non-community, non-security-header category also fired
  const hasCorroboratingSignal =
    overrideTriggered ||
    clues.some(
      (c) =>
        c.points > 0 &&
        c.category !== 'community_reports' &&
        c.category !== 'security_headers'
    );

  // Sum points per category and clamp to each category's maximum weight
  const categoryBreakdown: CategoryBreakdown[] = CATEGORY_WEIGHTS.map((def) => {
    const categoryClues = clues.filter((c) => c.category === def.category);
    const positiveCategoryClues = categoryClues.filter((c) => c.points > 0);
    const rawSum = categoryClues.reduce((sum, c) => sum + Math.max(0, c.points), 0);

    let effectiveSum = rawSum;
    if (def.category === 'community_reports' && !hasCorroboratingSignal) {
      // Community reports are counted fully only if another category also fires
      effectiveSum = Math.min(rawSum, 3);
    }

    const clampedPoints = Math.min(def.maxPoints, effectiveSum);
    return {
      category: def.category,
      label: def.label,
      points: clampedPoints,
      rawPoints: rawSum,
      maxPoints: def.maxPoints,
      examples: def.examples,
      clueCount: positiveCategoryClues.length,
    };
  });

  // Sort clues so override clue is always first, then by points descending
  const sortedClues = [...clues].sort((a, b) => {
    if (a.isOverride && !b.isOverride) return -1;
    if (!a.isOverride && b.isOverride) return 1;
    return b.points - a.points;
  });

  const rawTotal = categoryBreakdown.reduce((acc, row) => acc + row.points, 0);
  const rawUnclampedTotal = categoryBreakdown.reduce(
    (acc, row) => acc + (row.rawPoints ?? row.points),
    0
  );
  const maxPossibleCategorySum = CATEGORY_WEIGHTS.reduce((acc, row) => acc + row.maxPoints, 0);

  // If too few checks succeeded (< 4) and no strong signal or override was found,
  // return Inconclusive rather than a falsely reassuring low score.
  if (completedCount < 4 && rawTotal < 50 && !overrideTriggered) {
    return {
      index: null,
      level: 'inconclusive',
      confidence: 'low',
      sortedClues,
      categoryBreakdown,
      scoreTally: {
        categoryPointsSum: rawTotal,
        rawCategoryPointsSum: rawUnclampedTotal,
        maxPossibleCategorySum,
        overrideActive: false,
        overrideAdjustment: 0,
        clampingAdjustment: 0,
        finalIndex: null,
      },
      overrideTriggered: false,
    };
  }

  const clampedTotal = Math.min(100, rawTotal);
  const clampingAdjustment = rawTotal > 100 ? rawTotal - 100 : 0;
  let finalIndex = clampedTotal;
  let overrideAdjustment = 0;

  if (overrideTriggered) {
    if (finalIndex < 90) {
      overrideAdjustment = 90 - finalIndex;
      finalIndex = 90;
    }
  }

  let level: SuspicionLevel = 'low';
  if (finalIndex >= 75) {
    level = 'highly_suspicious';
  } else if (finalIndex >= 50) {
    level = 'high_risk';
  } else if (finalIndex >= 25) {
    level = 'caution';
  } else {
    level = 'low';
  }

  // Keep parameter referenced for future posture checks
  void hasValidHttps;

  return {
    index: finalIndex,
    level,
    confidence,
    sortedClues,
    categoryBreakdown,
    scoreTally: {
      categoryPointsSum: rawTotal,
      rawCategoryPointsSum: rawUnclampedTotal,
      maxPossibleCategorySum,
      overrideActive: overrideTriggered,
      overrideAdjustment,
      clampingAdjustment,
      finalIndex,
    },
    overrideTriggered,
  };
}

export function buildGoDaddyUrls(host: string): {
  godaddyCheckUrl: string;
  godaddyWhoisUrl: string;
} {
  const cleanHost = host.trim().toLowerCase().replace(/^www\./, '');
  return {
    godaddyCheckUrl: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(cleanHost)}`,
    godaddyWhoisUrl: `https://www.godaddy.com/whois/results.aspx?domain=${encodeURIComponent(cleanHost)}`,
  };
}

/**
 * Ensures any CaseReportData object (including cached or stored records) has
 * a freshly reconciled categoryBreakdown and scoreTally summary.
 */
export function reconcileCaseReport(report: CaseReportData): CaseReportData {
  const scored = computeSuspicionScore(
    report.clues || [],
    report.checkStatuses,
    report.hasValidHttps
  );
  const urls = buildGoDaddyUrls(report.host);
  return {
    ...report,
    index: report.specialState === 'inconclusive' ? null : scored.index,
    level: report.specialState === 'inconclusive' ? 'inconclusive' : scored.level,
    categoryBreakdown: scored.categoryBreakdown,
    scoreTally: scored.scoreTally,
    overrideTriggered: scored.overrideTriggered,
    internetAssets: report.internetAssets
      ? {
          ...report.internetAssets,
          godaddyCheckUrl: report.internetAssets.godaddyCheckUrl || urls.godaddyCheckUrl,
          godaddyWhoisUrl: report.internetAssets.godaddyWhoisUrl || urls.godaddyWhoisUrl,
        }
      : undefined,
  };
}

/**
 * Builds a deterministic, hedged template deduction strictly from the existing clues.
 * Never claims a site is "safe" or definitively "is a scam".
 */
export function buildTemplateDeduction(
  host: string,
  level: SuspicionLevel,
  confidence: ConfidenceLevel,
  clues: Clue[],
  hasValidHttps: boolean
): SherlockDeduction {
  if (level === 'inconclusive') {
    const text = `Several forensic checks could not be completed for ${host}, so SHERLOCK marks this investigation as Inconclusive rather than guessing a low score. An unreachable or cloaked server is not proof of legitimacy. Do not enter sensitive information unless you can verify the address through an official channel.`;
    return {
      summary: `Too few checks completed for ${host} to reach a reliable conclusion.`,
      keyReasons: [
        'Multiple network or registry checks timed out or were unreachable.',
        'SHERLOCK never issues a reassuring score when evidence is incomplete.',
      ],
      recommendedActions: [
        'Do not enter passwords, payment details, or one-time passcodes.',
        'Navigate to the organization by typing its known official address yourself.',
      ],
      uncertaintyNote: 'Confidence is Low because several live checks did not complete.',
      text,
      source: 'template',
    };
  }

  const positiveClues = clues.filter((c) => c.points > 0 || c.isOverride);

  if (level === 'low' && positiveClues.length === 0) {
    const text = `Our passive inspection of ${host} found no strong warning signs of domain lookalikes, newly registered throwaway domains, or suspicious credential forms. However, the absence of warning signs is not a guarantee of safety, and a valid HTTPS padlock only means your connection is encrypted. Still take care before sharing sensitive details if the link arrived unexpectedly.`;
    return {
      summary: `No strong warning signs were identified on ${host} across our passive checks.`,
      keyReasons: [
        'The domain does not closely imitate a protected brand on our watch list.',
        'No deceptive cross-domain login forms or reputation alerts were triggered.',
      ],
      recommendedActions: [
        'If the link arrived unexpectedly by SMS or email, confirm with the sender through another channel.',
        'Still verify the address bar before entering passwords or financial details.',
      ],
      uncertaintyNote: `Confidence is ${confidence}. Absence of evidence is not a guarantee of safety.`,
      text,
      source: 'template',
    };
  }

  const topFindings = positiveClues.slice(0, 3).map((c) => c.name.toLowerCase());
  const padlockSentence = hasValidHttps
    ? ' The padlock only means the connection is encrypted; it does not prove the site is genuine.'
    : '';

  const actionSentence =
    level === 'highly_suspicious' || level === 'high_risk'
      ? ' Do not enter passwords, card details or OTPs. If you need to use the service, open it by typing the official address yourself.'
      : ' Verify the address through an official channel before entering any personal or login details.';

  const text = `This site (${host}) shows indicators warranting ${
    LEVEL_METADATA[level].badgeText.toLowerCase()
  }, including ${topFindings.join(', ')}.${padlockSentence}${actionSentence}`;

  return {
    summary: `${host} exhibits ${positiveClues.length} warning clue${
      positiveClues.length === 1 ? '' : 's'
    } associated with ${LEVEL_METADATA[level].badgeText.toLowerCase()}.`,
    keyReasons: positiveClues.slice(0, 3).map((c) => c.finding),
    recommendedActions:
      level === 'highly_suspicious' || level === 'high_risk'
        ? [
            'Close the page and do not enter passwords, payment card numbers, or OTPs.',
            'Open the service by typing its official web address yourself or using the official mobile app.',
            'If you already entered details, follow the 5-step recovery checklist immediately.',
          ]
        : [
            'Do not enter sensitive information until you verify the link via an official channel.',
            'Contact the organization using a number listed on its official website, not the message.',
          ],
    uncertaintyNote: `Confidence is ${confidence}. Based strictly on public indicators; never a definitive legal determination.`,
    text,
    source: 'template',
  };
}

/**
 * Static Worked Example (paypa1-secure-login.example -> 87/100 🔴 Highly suspicious)
 * Used in both the #index Worked Example and #sample Case Report sections, and as Demo Case 1.
 */
export function getWorkedExampleCaseReport(): CaseReportData {
  const checkStatuses: Record<CheckStageId, CheckStatus> = {
    domain_identity: 'done',
    impersonation: 'done',
    domain_age: 'done',
    reputation: 'done',
    redirects_page: 'done',
    certificate: 'done',
    security_posture: 'done',
    witness: 'done',
  };

  const clues: Clue[] = [
    {
      id: 'worked-impersonation',
      code: 'CLUE-IMP-01',
      name: 'Brand lookalike with security keyword',
      finding:
        '"paypa1" substitutes the numeral "1" for the letter "l" in PayPal and pairs it with "-secure-login".',
      severity: 'critical',
      explanation:
        'Attackers replace "l" with "1" (a homoglyph) and add reassuring words like "secure-login" so hurried readers mistake the address for an official login portal.',
      howChecked:
        'Normalized homoglyphs in hostname tokens and calculated Levenshtein edit distance against SHERLOCK’s protected brand list.',
      points: 28,
      category: 'impersonation',
    },
    {
      id: 'worked-page-behavior',
      code: 'CLUE-PAGE-01',
      name: 'Login form posts credentials to a different domain',
      finding:
        'The page displays a password input form whose action attribute submits data to an unrelated external host (collector-auth-gate.example).',
      severity: 'critical',
      explanation:
        'Legitimate sign-in pages submit credentials to their own verified authentication domain. Sending form data to a third-party domain is a strong indicator of credential harvesting.',
      howChecked:
        'Fetched raw HTML passively without executing scripts and inspected <form action="..."> and <input type="password"> elements.',
      points: 25,
      category: 'page_behavior',
    },
    {
      id: 'worked-domain-age',
      code: 'CLUE-AGE-01',
      name: 'Domain registered 6 days ago',
      finding: 'RDAP registry records show this domain was registered only 6 days ago.',
      severity: 'high',
      explanation:
        'Established payment services have domains registered for many years. Newly registered domains (< 7 days old) are frequently used for short-lived phishing campaigns.',
      howChecked: 'Queried the authoritative RDAP registration record for the domain creation timestamp.',
      points: 20,
      category: 'domain_age',
    },
    {
      id: 'worked-redirects',
      code: 'CLUE-RED-01',
      name: 'Two redirects, one cross-domain',
      finding: 'The initial link bounced through 2 HTTP redirects, crossing onto a different domain before landing.',
      severity: 'caution',
      explanation:
        'Cross-domain redirect hops are often used to hide the final destination behind tracking links or compromised redirectors.',
      howChecked: 'Followed HTTP 301/302 Location headers up to 5 hops while re-validating SSRF safety at each hop.',
      points: 4,
      category: 'redirects',
    },
    {
      id: 'worked-witness',
      code: 'CLUE-WIT-01',
      name: 'Four community witness reports on file',
      finding: 'Reported 4 times by community witnesses for phishing and brand impersonation (corroborated by technical clues).',
      severity: 'caution',
      explanation:
        'Multiple independent users flagged this host after receiving suspicious payment verification messages.',
      howChecked: 'Queried SHERLOCK Witness Intelligence for deduplicated reports matching this hostname.',
      points: 4,
      category: 'community_reports',
    },
    {
      id: 'worked-certificate',
      code: 'CLUE-CERT-01',
      name: 'TLS certificate issued 5 days ago (HTTPS padlock present)',
      finding:
        'The site serves a valid DV TLS certificate issued 5 days ago. The browser shows a padlock, proving encryption only—not ownership.',
      severity: 'low',
      explanation:
        'Free automated certificates take seconds to issue for any domain. A valid padlock only means traffic between you and the site is encrypted, not that the site is trustworthy.',
      howChecked: 'Inspected the TLS handshake X.509 certificate validity window and issuer metadata.',
      points: 3,
      category: 'certificate',
    },
    {
      id: 'worked-headers',
      code: 'CLUE-SEC-01',
      name: 'Missing CSP and HSTS security headers',
      finding: 'The response omits Content-Security-Policy (CSP) and Strict-Transport-Security (HSTS) headers.',
      severity: 'low',
      explanation:
        'Major financial platforms enforce strict browser security headers; hastily deployed lookalike kits typically omit them.',
      howChecked: 'Inspected HTTP response headers from the passive page fetch.',
      points: 3,
      category: 'security_headers',
    },
  ];

  const scored = computeSuspicionScore(clues, checkStatuses, true);

  // Exact deduction text required by the prompt specification
  const exactDeductionText =
    'This site shows several signs of impersonating a payment service: its address closely resembles a well-known brand, it was registered only days ago, and its login form sends data to a different website. The padlock only means the connection is encrypted; it does not prove the site is genuine. Do not enter passwords, card details or OTPs. If you need to use the service, open it by typing the official address yourself.';

  return {
    id: 'CASE-221B-8701',
    host: 'paypa1-secure-login.example',
    sanitizedUrl: 'https://paypa1-secure-login.example',
    createdAt: '2026-11-08T07:45:00.000Z',
    index: scored.index, // 87
    level: scored.level, // highly_suspicious
    confidence: scored.confidence, // high
    clues: scored.sortedClues,
    categoryBreakdown: scored.categoryBreakdown,
    scoreTally: scored.scoreTally,
    deduction: {
      summary:
        'This site shows several signs of impersonating a payment service: its address closely resembles a well-known brand, it was registered only days ago, and its login form sends data to a different website.',
      keyReasons: [
        'Address uses the homoglyph "paypa1" with "-secure-login" to imitate PayPal (+28 pts).',
        'Password form submits credentials to a different external domain (+25 pts).',
        'Domain was registered only 6 days ago (+20 pts) with a 5-day-old TLS certificate (+3 pts).',
      ],
      recommendedActions: [
        'Do not enter passwords, card details or OTPs.',
        'If you need to use the service, open it by typing the official address yourself.',
        'Report or delete the message that delivered this link.',
      ],
      uncertaintyNote:
        'The padlock only means the connection is encrypted; it does not prove the site is genuine.',
      text: exactDeductionText,
      source: 'template',
    },
    witness: {
      host: 'paypa1-secure-login.example',
      totalReports: 4,
      byCategory: {
        phishing: 3,
        financial_fraud: 0,
        fake_recruitment: 0,
        shopping_scam: 0,
        brand_impersonation: 1,
        other: 0,
      },
      firstReported: '2026-11-03T11:20:00.000Z',
      lastReported: '2026-11-07T19:05:00.000Z',
      corroborated: true,
    },
    internetAssets: {
      resolvedIps: ['198.51.100.44'],
      registrar: 'NameSilo, LLC (Synthetic Demo Registry)',
      registeredAt: '2026-11-02T09:14:00.000Z',
      expiresAt: '2027-11-02T09:14:00.000Z',
      domainAgeDays: 6,
      tlsIssuer: "Let's Encrypt (R3 DV Automated)",
      tlsSubject: 'paypa1-secure-login.example',
      tlsValidFrom: '2026-11-03T00:00:00.000Z',
      tlsValidTo: '2027-02-01T23:59:59.000Z',
      tlsProtocol: 'TLSv1.3',
      httpStatus: 200,
      serverHeader: 'nginx',
      redirectChain: [
        'https://paypa1-secure-login.example/verify',
        'https://auth-session-gate.example/login',
      ],
      pageTitle: 'PayPal: Confirm Your Identity & Security Key',
      metaDescription: 'Please sign in to restore full access to your wallet.',
      formsDetected: 1,
      hasPasswordInput: true,
      presentSecurityHeaders: ['X-Content-Type-Options'],
      missingSecurityHeaders: ['HSTS', 'CSP', 'X-Frame-Options', 'Referrer-Policy'],
      ...buildGoDaddyUrls('paypa1-secure-login.example'),
    },
    webExperience: {
      sentiment: 'negative',
      summary:
        'Public user reports and security forums flag this lookalike address as an SMS and email credential-harvesting lure that substitutes the number "1" for the letter "l" in PayPal.',
      highlights: [
        'Multiple users report receiving urgent "account restricted" SMS links pointing to this domain.',
        'Domain registration is only 6 days old despite displaying official payment brand logos.',
        'Login form transmits credentials to an external collection server.',
      ],
      sources: [
        {
          title: 'PayPal Official Security Center — Recognizing Phishing Links',
          url: 'https://www.paypal.com/us/security/learn/phishing',
        },
      ],
    },
    checkStatuses,
    specialState: 'none',
    hasValidHttps: true,
    isDemo: true,
  };
}
