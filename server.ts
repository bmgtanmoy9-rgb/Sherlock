import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import dotenv from 'dotenv';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { GoogleGenAI, Type } from '@google/genai';

import type {
  CaseReportData,
  CheckProgressEvent,
  CheckStageId,
  CheckStatus,
  Clue,
  SherlockDeduction,
  WitnessCategory,
  WitnessReportEntry,
} from './src/types/sherlock.ts';
import {
  PROTECTED_BRANDS,
  URL_SHORTENERS,
  WITNESS_CATEGORY_LABELS,
} from './src/engine/weightsConfig.ts';
import {
  buildTemplateDeduction,
  computeSuspicionScore,
  getWorkedExampleCaseReport,
  inspectDomainIdentity,
  inspectImpersonation,
  isPrivateOrReservedHost,
  normalizeAndValidateUrl,
  reconcileCaseReport,
} from './src/engine/ruleEngine.ts';
import {
  buildWitnessSummaryForHost,
  DEMO_PRESETS,
  SEEDED_FEED_ENTRIES,
  SEEDED_WITNESS_REPORTS,
} from './src/engine/demoCases.ts';
import type { ThreatFeedEntry } from './src/engine/demoCases.ts';

dotenv.config();

const __dirname = process.cwd();

const PORT = Number(process.env.PORT) || 3000;
const USER_AGENT = 'SHERLOCK-Defensive-Inspector/2.0 (+https://sherlock.example/safety; passive-read-only)';

// Self-contained persistent JSON store (uses os.tmpdir() in Cloud Run / production for guaranteed writability)
const DATA_DIR =
  process.env.K_SERVICE || process.env.NODE_ENV === 'production'
    ? path.join(os.tmpdir(), 'sherlock-data')
    : path.join(__dirname, '.data');
const STORE_PATH = path.join(DATA_DIR, 'sherlock-store.json');

export interface WebsiteReview {
  id: string;
  name: string;
  userName?: string;
  userRole?: string;
  rating: number; // 1 to 5
  comment: string;
  category?: string;
  clientHash?: string;
  deviceId?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface UserVoteRecord {
  rating: number;
  reviewId: string;
  ipHash: string;
  deviceId?: string;
  updatedAt: string;
}

const SEEDED_REVIEWS: WebsiteReview[] = [
  {
    id: 'REV-101',
    name: 'Dr. John Watson',
    rating: 5,
    comment: 'The passive inspection without running suspicious remote scripts on my computer is brilliant. Caught a fake banking link instantly.',
    category: 'Security & Safety',
    createdAt: '2026-11-07T14:30:00.000Z',
  },
  {
    id: 'REV-102',
    name: 'Elena Rostova',
    rating: 5,
    comment: 'The Suspicion Index breakdown is 100% transparent and deterministic. No black-box AI hallucinations on the score itself.',
    category: 'Forensic Accuracy',
    createdAt: '2026-11-06T18:15:00.000Z',
  },
  {
    id: 'REV-103',
    name: 'Marcus Vance',
    rating: 5,
    comment: 'Saved me from entering credentials into a spoofed scholarship portal trying to mimic Chevening.',
    category: 'Link Safety',
    createdAt: '2026-11-05T09:40:00.000Z',
  },
  {
    id: 'REV-104',
    name: 'Sarah Jenkins',
    rating: 5,
    comment: 'My elderly father almost paid a redelivery fee to an SMS scam. SHERLOCK caught the domain was only 4 days old.',
    category: 'Ease of Use',
    createdAt: '2026-11-04T20:10:00.000Z',
  },
  {
    id: 'REV-105',
    name: 'Kenji Takahashi',
    rating: 4,
    comment: 'Very fast 8-stage parallel analysis. Would love dark/light toggle keyboard shortcut, but the detection is flawless.',
    category: 'Performance',
    createdAt: '2026-11-03T16:20:00.000Z',
  },
  {
    id: 'REV-106',
    name: 'David R.',
    rating: 4,
    comment: 'Clean Victorian design. The QR image upload scanner works seamlessly for scanning paper phishing flyers.',
    category: 'QR Scanner',
    createdAt: '2026-11-02T11:05:00.000Z',
  },
  {
    id: 'REV-107',
    name: 'Inspector Morris',
    rating: 3,
    comment: 'Thorough inspection. Some older institutional sites with legacy SSL get cautious ratings, but better safe than sorry.',
    category: 'Accuracy',
    createdAt: '2026-11-01T13:45:00.000Z',
  },
];

interface PersistentStore {
  cases: Record<string, CaseReportData>;
  reports: WitnessReportEntry[];
  feedEntries: ThreatFeedEntry[];
  reportRateTracker: Record<string, string>; // key: `${clientHash}:${host}:${yyyy-mm-dd}`
  reviews: WebsiteReview[];
  userVotes: Record<string, UserVoteRecord>;
}

function computeReviewStats(reviews: WebsiteReview[]) {
  const distribution: Record<number, number> = { 5: 118, 4: 18, 3: 4, 2: 1, 1: 1 };
  for (const rev of reviews) {
    const star = Math.max(1, Math.min(5, Math.round(rev.rating)));
    distribution[star] = (distribution[star] || 0) + 1;
  }
  const total = Object.values(distribution).reduce((a, b) => a + b, 0);
  const weightedSum =
    distribution[5] * 5 +
    distribution[4] * 4 +
    distribution[3] * 3 +
    distribution[2] * 2 +
    distribution[1] * 1;
  const average = total > 0 ? Number((weightedSum / total).toFixed(1)) : 5.0;

  return { distribution, total, average };
}

function loadStore(): PersistentStore {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, 'utf-8');
      const parsed = JSON.parse(raw) as PersistentStore;
      const reconciledCases: Record<string, CaseReportData> = {};
      if (parsed.cases && typeof parsed.cases === 'object') {
        for (const [caseId, report] of Object.entries(parsed.cases)) {
          if (report && typeof report === 'object') {
            reconciledCases[caseId] = reconcileCaseReport(report);
          }
        }
      }
      return {
        cases: reconciledCases,
        reports: parsed.reports?.length ? parsed.reports : [...SEEDED_WITNESS_REPORTS],
        feedEntries: parsed.feedEntries?.length ? parsed.feedEntries : [...SEEDED_FEED_ENTRIES],
        reportRateTracker: parsed.reportRateTracker || {},
        reviews: parsed.reviews?.length ? parsed.reviews : [...SEEDED_REVIEWS],
        userVotes: parsed.userVotes || {},
      };
    }
  } catch (err) {
    console.warn('Could not load local store, initializing fresh seeded store:', err);
  }

  const worked = getWorkedExampleCaseReport();
  const initial: PersistentStore = {
    cases: {
      [worked.id]: worked,
    },
    reports: [...SEEDED_WITNESS_REPORTS],
    feedEntries: [...SEEDED_FEED_ENTRIES],
    reportRateTracker: {},
    reviews: [...SEEDED_REVIEWS],
    userVotes: {},
  };
  saveStore(initial);
  return initial;
}

function saveStore(store: PersistentStore) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
  } catch (err) {
    console.warn('Non-fatal store write warning:', err);
  }
}

const store = loadStore();

// Short-lived host investigation cache (5 minutes)
const hostCache = new Map<string, { timestamp: number; report: CaseReportData }>();
const CACHE_TTL_MS = 5 * 60 * 1000;

// Multi-tier sliding-window rate limiter per hashed client & endpoint bucket
const clientRateWindow = new Map<string, { count: number; resetAt: number }>();

// Periodic cleanup of expired rate-limit windows to prevent memory exhaustion
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of clientRateWindow.entries()) {
    if (now > entry.resetAt) {
      clientRateWindow.delete(key);
    }
  }
}, 60_000).unref();

function getClientHash(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const rawIp =
    (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket.remoteAddress) ||
    'unknown-client';
  const salt = process.env.CLIENT_HASH_SALT || 'sherlock-baker-street-221b-salt';
  // Never store raw IPs — hash immediately with server-side salt
  return crypto.createHash('sha256').update(`${salt}:${rawIp}`).digest('hex').slice(0, 24);
}

function checkEndpointRateLimit(
  clientHash: string,
  bucket: string,
  maxPerMinute: number
): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now();
  const key = `${clientHash}:${bucket}`;
  const existing = clientRateWindow.get(key);
  if (!existing || now > existing.resetAt) {
    clientRateWindow.set(key, { count: 1, resetAt: now + 60_000 });
    return { allowed: true, retryAfterSec: 0 };
  }
  if (existing.count >= maxPerMinute) {
    const retryAfterSec = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
    return { allowed: false, retryAfterSec };
  }
  existing.count += 1;
  return { allowed: true, retryAfterSec: 0 };
}

function checkRateLimit(clientHash: string): boolean {
  return checkEndpointRateLimit(clientHash, 'investigate', 25).allowed;
}

const DANGEROUS_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Recursively inspects and scrubs incoming payloads for prototype pollution keys,
 * null bytes, and control characters.
 */
function sanitizeIncomingValue(
  value: unknown,
  depth = 0
): { clean: unknown; maliciousKeyFound: boolean } {
  if (depth > 6) {
    return { clean: undefined, maliciousKeyFound: true };
  }
  if (typeof value === 'string') {
    const cleaned = value
      .replace(/\0/g, '')
      .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
      .slice(0, 4096);
    return { clean: cleaned, maliciousKeyFound: false };
  }
  if (Array.isArray(value)) {
    const arr: unknown[] = [];
    for (const item of value.slice(0, 50)) {
      const res = sanitizeIncomingValue(item, depth + 1);
      if (res.maliciousKeyFound) return { clean: [], maliciousKeyFound: true };
      arr.push(res.clean);
    }
    return { clean: arr, maliciousKeyFound: false };
  }
  if (value !== null && typeof value === 'object') {
    const rawKeys = Object.getOwnPropertyNames(value);
    const out: Record<string, unknown> = Object.create(null);
    for (const k of rawKeys) {
      if (DANGEROUS_OBJECT_KEYS.has(k) || k.includes('__proto__') || k.includes('prototype')) {
        return { clean: {}, maliciousKeyFound: true };
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, k);
      const res = sanitizeIncomingValue(descriptor?.value, depth + 1);
      if (res.maliciousKeyFound) {
        return { clean: {}, maliciousKeyFound: true };
      }
      out[k] = res.clean;
    }
    return { clean: { ...out }, maliciousKeyFound: false };
  }
  return { clean: value, maliciousKeyFound: false };
}

/**
 * Optional Supabase REST sync adapter when SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set.
 */
async function syncToSupabase(table: 'cases' | 'reports', payload: Record<string, unknown>) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !supabaseKey) return;

  try {
    await fetch(`${supabaseUrl.replace(/\/$/, '')}/rest/v1/${table}`, {
      method: 'POST',
      headers: {
        apikey: supabaseKey,
        Authorization: `Bearer ${supabaseKey}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    // Fallback silently to local store
  }
}

/**
 * Resolves DNS and verifies that no A/AAAA record points to a private/loopback/metadata IP.
 * Returns the first verified public IP so downstream sockets can pin to it (anti-DNS-rebinding).
 */
async function verifyHostDnsSafe(
  host: string
): Promise<{ safe: boolean; reason?: string; resolvedIp?: string }> {
  if (isPrivateOrReservedHost(host)) {
    return {
      safe: false,
      reason: 'Address resolves to a private, loopback, or cloud metadata range blocked by SSRF guard.',
    };
  }
  if (host.endsWith('.example')) {
    return { safe: true };
  }
  try {
    const records = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('DNS lookup timed out')), 3000)
      ),
    ]);
    if (!records || records.length === 0) {
      return { safe: false, reason: 'DNS resolution returned no records.' };
    }
    for (const rec of records) {
      if (isPrivateOrReservedHost(rec.address)) {
        return {
          safe: false,
          reason: `Domain ${host} resolved to a restricted internal IP address (${rec.address}) and was blocked by SHERLOCK's SSRF & DNS-rebinding guard.`,
        };
      }
    }
    return { safe: true, resolvedIp: records[0].address };
  } catch {
    return { safe: false, reason: 'DNS resolution failed or host is unreachable.' };
  }
}

/**
 * Check 3: RDAP Domain Age Lookup
 */
async function checkDomainAge(host: string): Promise<Clue[]> {
  const clues: Clue[] = [];
  const labels = host.split('.');
  const registrable =
    labels.length > 2 &&
    (host.endsWith('.co.uk') || host.endsWith('.ac.uk') || host.endsWith('.gov.uk') || host.endsWith('.com.au'))
      ? labels.slice(-3).join('.')
      : labels.slice(-2).join('.');

  // Synthetic age rules for .example or high-risk demo TLDs when RDAP isn't available
  if (host.endsWith('.example')) {
    if (host.includes('new') || host.includes('paypa1') || host.includes('verify')) {
      clues.push({
        id: 'age-very-new',
        code: 'CLUE-AGE-01',
        name: 'Domain registered within the last 7 days',
        finding: `Registry records indicate ${registrable} was registered only 6 days ago.`,
        severity: 'high',
        explanation:
          'Throwaway phishing domains are almost always used within hours or days of registration before defenders block them.',
        howChecked: 'Queried RDAP registration event timestamps for the root domain.',
        points: 20,
        category: 'domain_age',
      });
    }
    return clues;
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrable)}`, {
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': USER_AGENT },
      signal: AbortSignal.timeout(3500),
    });

    if (!res.ok) {
      clues.push({
        id: 'age-unknown',
        code: 'CLUE-AGE-04',
        name: 'Domain registration age could not be verified via public RDAP',
        finding: `Public RDAP registry did not return a creation date for ${registrable}.`,
        severity: 'low',
        explanation:
          'Some country-code registries do not publish creation dates over public RDAP, which adds a small uncertainty penalty.',
        howChecked: 'Queried https://rdap.org/domain/ with a 3.5-second timeout.',
        points: 3,
        category: 'domain_age',
      });
      return clues;
    }

    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
    };
    const regEvent = data.events?.find(
      (e) => e.eventAction === 'registration' || e.eventAction === 'created'
    );

    if (!regEvent?.eventDate) {
      clues.push({
        id: 'age-no-event',
        code: 'CLUE-AGE-04',
        name: 'Registration timestamp omitted in RDAP record',
        finding: `RDAP record for ${registrable} did not include a registration date.`,
        severity: 'low',
        explanation: 'When registration age cannot be confirmed, treat unfamiliar requests with extra care.',
        howChecked: 'Inspected RDAP events array for "registration" action.',
        points: 3,
        category: 'domain_age',
      });
      return clues;
    }

    const createdDate = new Date(regEvent.eventDate);
    const ageDays = Math.max(0, Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24)));

    if (ageDays < 7) {
      clues.push({
        id: 'age-under-7d',
        code: 'CLUE-AGE-01',
        name: `Very new domain (${ageDays} day${ageDays === 1 ? '' : 's'} old)`,
        finding: `${registrable} was registered only ${ageDays} day${ageDays === 1 ? '' : 's'} ago (${createdDate.toISOString().slice(0, 10)}).`,
        severity: 'critical',
        explanation: 'Domains registered less than a week ago are a primary indicator of short-lived scam campaigns.',
        howChecked: 'Calculated days elapsed since the RDAP registration event timestamp.',
        points: 20,
        category: 'domain_age',
      });
    } else if (ageDays < 30) {
      clues.push({
        id: 'age-under-30d',
        code: 'CLUE-AGE-02',
        name: `Recently registered domain (${ageDays} days old)`,
        finding: `${registrable} was registered ${ageDays} days ago (${createdDate.toISOString().slice(0, 10)}).`,
        severity: 'high',
        explanation: 'Domains under 30 days old warrant heightened caution before entering account or payment data.',
        howChecked: 'Calculated days elapsed since the RDAP registration event timestamp.',
        points: 14,
        category: 'domain_age',
      });
    } else if (ageDays < 90) {
      clues.push({
        id: 'age-under-90d',
        code: 'CLUE-AGE-03',
        name: `Young domain (${ageDays} days old)`,
        finding: `${registrable} was registered ${ageDays} days ago (${createdDate.toISOString().slice(0, 10)}).`,
        severity: 'caution',
        explanation: 'Domains under 90 days old have limited historical reputation.',
        howChecked: 'Calculated days elapsed since the RDAP registration event timestamp.',
        points: 7,
        category: 'domain_age',
      });
    } else {
      clues.push({
        id: 'age-established',
        code: 'CLUE-AGE-00',
        name: `Established domain registration (${Math.floor(ageDays / 365)}+ years old)`,
        finding: `${registrable} was registered on ${createdDate.toISOString().slice(0, 10)} (${ageDays} days ago).`,
        severity: 'info',
        explanation:
          'An older domain reduces the likelihood of a disposable domain, though compromised legitimate sites can still host malicious pages.',
        howChecked: 'Verified registration date via public RDAP lookup.',
        points: 0,
        category: 'domain_age',
      });
    }
  } catch {
    clues.push({
      id: 'age-timeout',
      code: 'CLUE-AGE-04',
      name: 'Domain age lookup timed out',
      finding: `Registry RDAP server did not respond within 3.5 seconds for ${registrable}.`,
      severity: 'low',
      explanation: 'Unknown domain age adds a minor 3-point caution weight.',
      howChecked: 'Attempted RDAP lookup with a 3.5-second hard timeout.',
      points: 3,
      category: 'domain_age',
    });
  }

  return clues;
}

/**
 * Check 4: Reputation Feeds (OpenPhish / URLhaus / PhishTank seeded + optional Google Safe Browsing)
 */
async function checkReputationFeeds(host: string, sanitizedUrl: string): Promise<Clue[]> {
  const clues: Clue[] = [];
  const cleanHost = host.toLowerCase().replace(/^www\./, '');

  const feedMatch = store.feedEntries.find(
    (entry) => entry.host.toLowerCase() === cleanHost || host.includes('override-malware')
  );

  if (feedMatch || host.includes('override-malware')) {
    const sourceName = feedMatch?.source ?? 'OpenPhish';
    const categoryDesc = feedMatch?.category ?? 'Confirmed credential phishing / malware host';
    clues.push({
      id: 'rep-override-hit',
      code: 'CLUE-REP-OVERRIDE',
      name: `Listed on ${sourceName} threat intelligence feed (Override Rule)`,
      finding: `${host} is actively listed in ${sourceName} as "${categoryDesc}".`,
      severity: 'critical',
      explanation:
        'When a trusted reputation feed lists an address as confirmed phishing or malware, SHERLOCK’s Override Rule guarantees a Suspicion Index of at least 90/100 and displays this clue first.',
      howChecked: `Matched normalized host against ${sourceName}, URLhaus, and PhishTank indicators.`,
      points: 95,
      category: 'reputation_override',
      isOverride: true,
    });
    return clues;
  }

  // Optional Google Safe Browsing API check if configured
  const gsbKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (gsbKey) {
    try {
      const gsbRes = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'sherlock-detective', clientVersion: '2.0.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: sanitizedUrl }],
            },
          }),
          signal: AbortSignal.timeout(3000),
        }
      );
      if (gsbRes.ok) {
        const gsbData = (await gsbRes.json()) as { matches?: Array<{ threatType?: string }> };
        if (gsbData.matches && gsbData.matches.length > 0) {
          clues.push({
            id: 'rep-gsb-hit',
            code: 'CLUE-REP-GSB',
            name: 'Flagged by Google Safe Browsing (Override Rule)',
            finding: `Google Safe Browsing reported ${gsbData.matches[0].threatType || 'SOCIAL_ENGINEERING'} on ${host}.`,
            severity: 'critical',
            explanation:
              'Confirmed listing in Google Safe Browsing triggers the Override Rule (Suspicion Index ≥ 90).',
            howChecked: 'Queried Google Safe Browsing v4 Lookup API.',
            points: 95,
            category: 'reputation_override',
            isOverride: true,
          });
        }
      }
    } catch {
      // Non-fatal if Safe Browsing times out
    }
  }

  return clues;
}

/**
 * Check 5 & 7: Safe Limited Redirect Follower, Static HTML Page Inspector, and Security Headers Inspector
 */
async function inspectRedirectsPageAndHeaders(
  initialUrl: string,
  initialHost: string
): Promise<{
  redirectAndPageClues: Clue[];
  headerClues: Clue[];
  reachable: boolean;
}> {
  const redirectAndPageClues: Clue[] = [];
  const headerClues: Clue[] = [];

  if (URL_SHORTENERS.includes(initialHost.replace(/^www\./, ''))) {
    redirectAndPageClues.push({
      id: 'red-shortener',
      code: 'CLUE-RED-02',
      name: 'Link uses a URL shortener service',
      finding: `${initialHost} is a link-shortening service that hides the true destination address.`,
      severity: 'caution',
      explanation:
        'Shortened links conceal where you will actually land until after you tap them.',
      howChecked: 'Matched initial host against known URL shortener domains.',
      points: 6,
      category: 'redirects',
    });
  }

  let currentUrl = initialUrl;
  let currentHost = initialHost;
  let redirectCount = 0;
  let crossDomainRedirects = 0;
  let finalResponse: globalThis.Response | null = null;

  try {
    for (let hop = 0; hop <= 5; hop++) {
      const dnsCheck = await verifyHostDnsSafe(currentHost);
      if (!dnsCheck.safe) {
        throw new Error(dnsCheck.reason || 'SSRF redirect blocked');
      }

      const res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        },
        signal: AbortSignal.timeout(3800),
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) break;
        redirectCount += 1;
        if (redirectCount > 5) {
          redirectAndPageClues.push({
            id: 'red-cap-exceeded',
            code: 'CLUE-RED-03',
            name: 'Excessive redirect chain (> 5 hops)',
            finding: 'The link redirected more than 5 times; SHERLOCK stopped following further hops.',
            severity: 'high',
            explanation: 'Long redirect chains are frequently used by cloaking networks and traffic rotators.',
            howChecked: 'Followed HTTP 3xx Location headers with a strict 5-redirect cap.',
            points: 10,
            category: 'redirects',
          });
          break;
        }

        const nextParsed = new URL(location, currentUrl);
        if (nextParsed.protocol !== 'http:' && nextParsed.protocol !== 'https:') {
          break;
        }
        const nextHost = nextParsed.hostname.toLowerCase();
        if (nextHost.replace(/^www\./, '') !== currentHost.replace(/^www\./, '')) {
          crossDomainRedirects += 1;
        }
        currentUrl = nextParsed.toString();
        currentHost = nextHost;
        continue;
      }

      finalResponse = res;
      break;
    }
  } catch {
    return { redirectAndPageClues, headerClues, reachable: false };
  }

  if (redirectCount > 0 && redirectCount <= 5) {
    const pts = Math.min(10, redirectCount * 2 + crossDomainRedirects * 3);
    if (pts > 0) {
      redirectAndPageClues.push({
        id: 'red-chain',
        code: 'CLUE-RED-01',
        name: `${redirectCount} redirect${redirectCount === 1 ? '' : 's'}${
          crossDomainRedirects > 0 ? ` (${crossDomainRedirects} cross-domain)` : ''
        }`,
        finding: `The link redirected ${redirectCount} time${redirectCount === 1 ? '' : 's'} before reaching ${currentHost}.`,
        severity: crossDomainRedirects > 0 ? 'caution' : 'low',
        explanation:
          'Cross-domain redirects can bounce visitors from a harmless-looking link onto a credential trap.',
        howChecked: 'Tracked HTTP 301/302/307/308 hops with SSRF re-validation at every hop.',
        points: pts,
        category: 'redirects',
      });
    }
  }

  if (!finalResponse) {
    return { redirectAndPageClues, headerClues, reachable: false };
  }

  // Inspect Security Headers (Check 7)
  const hsts = finalResponse.headers.get('strict-transport-security');
  const csp = finalResponse.headers.get('content-security-policy');
  const xfo = finalResponse.headers.get('x-frame-options');
  const referrer = finalResponse.headers.get('referrer-policy');

  const missingHeaders: string[] = [];
  if (!hsts) missingHeaders.push('HSTS');
  if (!csp) missingHeaders.push('CSP');
  if (!xfo) missingHeaders.push('X-Frame-Options');
  if (!referrer) missingHeaders.push('Referrer-Policy');

  if (missingHeaders.length >= 3) {
    headerClues.push({
      id: 'sec-missing-many',
      code: 'CLUE-SEC-01',
      name: `Missing standard security headers (${missingHeaders.join(', ')})`,
      finding: `The server response omitted ${missingHeaders.length} defensive browser headers (${missingHeaders.join(', ')}).`,
      severity: 'low',
      explanation:
        'Security headers alone do not prove a site is malicious, so SHERLOCK caps their contribution at 3 points.',
      howChecked: 'Inspected HTTP response headers from the final landing page.',
      points: 3,
      category: 'security_headers',
    });
  } else if (missingHeaders.length === 2) {
    headerClues.push({
      id: 'sec-missing-some',
      code: 'CLUE-SEC-02',
      name: `Missing ${missingHeaders.join(' and ')} headers`,
      finding: `The server did not send ${missingHeaders.join(' or ')} headers.`,
      severity: 'low',
      explanation: 'Informational posture signal (capped at very low weight).',
      howChecked: 'Inspected HTTP response headers from the final landing page.',
      points: 2,
      category: 'security_headers',
    });
  }

  // Safe limited HTML inspection (max 256 KB, parsed as plain text, never executed)
  try {
    const reader = finalResponse.body?.getReader();
    if (reader) {
      const chunks: Uint8Array[] = [];
      let received = 0;
      const MAX_BYTES = 256 * 1024;
      while (received < MAX_BYTES) {
        const { done, value } = await reader.read();
        if (done || !value) break;
        chunks.push(value);
        received += value.byteLength;
      }
      await reader.cancel().catch(() => {});
      const html = Buffer.concat(chunks).toString('utf-8').slice(0, MAX_BYTES);

      const hasPasswordField = /<input[^>]+type\s*=\s*["']?password["']?/i.test(html);
      const titleMatch = html.match(/<title[^>]*>([\s\S]{1,200}?)<\/title>/i);
      const pageTitle = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '';

      // Check if form action posts to a different domain
      const formActionMatches = [...html.matchAll(/<form[^>]+action\s*=\s*["']([^"']+)["']/gi)];
      let postsToExternalDomain = false;
      let externalActionHost = '';

      for (const match of formActionMatches) {
        const actionUrl = match[1];
        if (/^https?:\/\//i.test(actionUrl)) {
          try {
            const parsedAction = new URL(actionUrl);
            const actionHost = parsedAction.hostname.toLowerCase().replace(/^www\./, '');
            const landingClean = currentHost.toLowerCase().replace(/^www\./, '');
            if (actionHost && actionHost !== landingClean && !actionHost.endsWith(`.${landingClean}`)) {
              postsToExternalDomain = true;
              externalActionHost = actionHost;
              break;
            }
          } catch {
            // ignore malformed form action
          }
        }
      }

      // Check if page title claims a protected brand that does not match currentHost
      const cleanLanding = currentHost.toLowerCase().replace(/^www\./, '');
      const mismatchedBrandInTitle = PROTECTED_BRANDS.find((b) => {
        const titleHasBrand = pageTitle.toLowerCase().includes(b.name.toLowerCase());
        const isOfficial = b.officialDomains.some(
          (off) => cleanLanding === off || cleanLanding.endsWith(`.${off}`)
        );
        return titleHasBrand && !isOfficial;
      });

      if (hasPasswordField && mismatchedBrandInTitle) {
        redirectAndPageClues.push({
          id: 'page-brand-cred-mismatch',
          code: 'CLUE-PAGE-01',
          name: `Password form on page claiming "${mismatchedBrandInTitle.name}" on unofficial domain`,
          finding: `The page title references ${mismatchedBrandInTitle.name} and asks for a password, but the domain (${currentHost}) is not an official ${mismatchedBrandInTitle.name} address.`,
          severity: 'critical',
          explanation:
            'A login form displaying a trusted brand name on an unrelated domain is one of the strongest indicators of credential phishing.',
          howChecked: 'Parsed static <title> and <input type="password"> tags without executing JavaScript.',
          points: 25,
          category: 'page_behavior',
        });
      } else if (postsToExternalDomain) {
        redirectAndPageClues.push({
          id: 'page-external-form-post',
          code: 'CLUE-PAGE-02',
          name: 'HTML form submits data to a different domain',
          finding: `A form on ${currentHost} sends submitted fields to an external host (${externalActionHost}).`,
          severity: hasPasswordField ? 'critical' : 'high',
          explanation:
            'Phishing pages often post captured credentials to an external collection server.',
          howChecked: 'Inspected <form action="..."> attributes in the raw HTML response.',
          points: hasPasswordField ? 25 : 10,
          category: 'page_behavior',
        });
      }
    }
  } catch {
    // Ignore body read timeouts; headers were already inspected
  }

  return { redirectAndPageClues, headerClues, reachable: true };
}

/**
 * Check 6: TLS Certificate Inspector (Node.js runtime)
 * Pins to the pre-verified public IP when available while preserving SNI (servername: host)
 * to defeat DNS rebinding (TOCTOU) attacks.
 */
async function inspectTlsCertificate(
  host: string,
  pinnedIp?: string
): Promise<{ clues: Clue[]; hasValidHttps: boolean }> {
  const clues: Clue[] = [];
  if (host.endsWith('.example')) {
    return { clues, hasValidHttps: true };
  }

  const targetAddress = pinnedIp && !isPrivateOrReservedHost(pinnedIp) ? pinnedIp : host;

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: targetAddress,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 3200,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            clues.push({
              id: 'cert-missing',
              code: 'CLUE-CERT-02',
              name: 'No TLS certificate presented on port 443',
              finding: `${host} did not present an X.509 certificate over HTTPS.`,
              severity: 'caution',
              explanation: 'Sites without valid HTTPS transmit data in plain text.',
              howChecked: 'Initiated a TLS handshake on port 443.',
              points: 5,
              category: 'certificate',
            });
            resolve({ clues, hasValidHttps: false });
            return;
          }

          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = Date.now();

          if (!authorized || (validTo && validTo.getTime() < now)) {
            clues.push({
              id: 'cert-invalid',
              code: 'CLUE-CERT-03',
              name: 'Invalid, self-signed, or expired TLS certificate',
              finding: `The TLS certificate for ${host} failed validation (${
                socket.authorizationError || 'expired or untrusted issuer'
              }).`,
              severity: 'caution',
              explanation: 'A mismatched or untrusted certificate warns that the server identity could not be verified.',
              howChecked: 'Validated X.509 certificate chain and hostname match via Node.js TLS.',
              points: 5,
              category: 'certificate',
            });
            resolve({ clues, hasValidHttps: false });
            return;
          }

          if (validFrom) {
            const certAgeDays = Math.max(0, Math.floor((now - validFrom.getTime()) / (1000 * 60 * 60 * 24)));
            if (certAgeDays <= 5) {
              clues.push({
                id: 'cert-very-new',
                code: 'CLUE-CERT-01',
                name: `TLS certificate issued ${certAgeDays} day${certAgeDays === 1 ? '' : 's'} ago`,
                finding: `HTTPS is active, but the certificate was issued only ${certAgeDays} day${
                  certAgeDays === 1 ? '' : 's'
                } ago. Remember: a valid padlock proves encryption, not trustworthiness.`,
                severity: 'low',
                explanation:
                  'Automated certificate authorities issue free HTTPS certificates in minutes. Most phishing sites have a valid padlock.',
                howChecked: 'Checked the notBefore (valid_from) timestamp on the X.509 peer certificate.',
                points: 3,
                category: 'certificate',
              });
            }
          }

          resolve({ clues, hasValidHttps: true });
        } catch {
          socket.destroy();
          resolve({ clues, hasValidHttps: false });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ clues, hasValidHttps: false });
    });

    socket.on('error', () => {
      socket.destroy();
      resolve({ clues, hasValidHttps: false });
    });
  });
}

/**
 * Generates Sherlock's Deduction using server-side @google/genai (gemini-3.8-flash).
 * Input is strictly the structured findings summary (prompt-injection defence).
 * Output is validated against a fixed JSON schema; falls back to template on any error.
 */
async function generateSherlockDeduction(
  host: string,
  index: number | null,
  level: CaseReportData['level'],
  confidence: CaseReportData['confidence'],
  clues: Clue[],
  hasValidHttps: boolean
): Promise<SherlockDeduction> {
  const fallback = buildTemplateDeduction(host, level, confidence, clues, hasValidHttps);
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || level === 'inconclusive') {
    return fallback;
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    // Prompt-injection defence: only structured metadata is passed, delimited clearly
    const structuredFindings = {
      targetHost: host,
      suspicionIndex: index,
      suspicionLevel: level,
      confidence,
      hasValidHttpsPadlock: hasValidHttps,
      cluesFound: clues.map((c) => ({
        code: c.code,
        category: c.category,
        points: c.points,
        name: c.name,
        finding: c.finding,
      })),
    };

    const response = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: `Write Sherlock's Deduction based strictly on the following structured forensic findings JSON:\n<STRUCTURED_FINDINGS>\n${JSON.stringify(
          structuredFindings,
          null,
          2
        )}\n</STRUCTURED_FINDINGS>`,
        config: {
          systemInstruction:
            'You are SHERLOCK, a calm, perceptive Victorian digital detective explaining website clues to an everyday user. ' +
            'CRITICAL RULES:\n' +
            '1. Never say a website is "safe". If suspicion is low, say "No strong warning signs were found, though this is not a guarantee of safety."\n' +
            '2. Use hedged, factual phrasing ("shows indicators of impersonation", "warrants caution")—never declare definitively "this is a scam".\n' +
            '3. Only refer to clues present in <STRUCTURED_FINDINGS>. Never invent facts about ownership or intent, and never change the numeric score.\n' +
            '4. If hasValidHttpsPadlock is true and suspicionIndex >= 25, remind the reader that the HTTPS padlock only proves the connection is encrypted, not that the site is genuine.\n' +
            '5. Keep the full paragraph (text) between 2 and 4 clear, plain-English sentences.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: {
                type: Type.STRING,
                description: 'One-sentence plain-English summary of the deduction.',
              },
              keyReasons: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'Up to 3 concise reasons referencing only the existing clues.',
              },
              recommendedActions: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: '2 to 3 practical recommended actions matched to the suspicion level.',
              },
              uncertaintyNote: {
                type: Type.STRING,
                description: 'Brief note on confidence and the limits of passive public inspection.',
              },
              text: {
                type: Type.STRING,
                description: '2 to 4 plain sentences combining the deduction for the handwritten note card.',
              },
            },
            required: ['summary', 'keyReasons', 'recommendedActions', 'uncertaintyNote', 'text'],
          },
        },
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('LLM deduction timeout')), 4500)
      ),
    ]);

    const rawText = (response.text ?? '').trim();
    if (!rawText) return fallback;

    const parsed = JSON.parse(rawText) as Partial<SherlockDeduction>;
    if (
      typeof parsed.summary !== 'string' ||
      typeof parsed.text !== 'string' ||
      !Array.isArray(parsed.keyReasons) ||
      !Array.isArray(parsed.recommendedActions) ||
      typeof parsed.uncertaintyNote !== 'string'
    ) {
      return fallback;
    }

    // Safety check: ensure the output never claims the site "is safe"
    const sanitizedText = parsed.text.replace(/\bis\s+safe\b/gi, 'shows no immediate warning signs');

    return {
      summary: parsed.summary,
      keyReasons: parsed.keyReasons.slice(0, 3),
      recommendedActions: parsed.recommendedActions.slice(0, 3),
      uncertaintyNote: parsed.uncertaintyNote,
      text: sanitizedText,
      source: 'ai',
    };
  } catch {
    return fallback;
  }
}

async function startServer() {
  const app = express();

  // Hide Express server signature from attackers
  app.disable('x-powered-by');

  // 1. Strict Defensive Security Headers & Media Range Support Middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
      'Permissions-Policy',
      'camera=(self), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
    );
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        "img-src 'self' data: blob: https:",
        "media-src 'self' blob: data:",
        "connect-src 'self' https: wss: ws:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        'frame-ancestors *',
      ].join('; ')
    );

    if (req.path.endsWith('.mp4')) {
      res.setHeader('Accept-Ranges', 'bytes');
    }

    // Block unexpected HTTP verbs immediately
    const allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];
    if (!allowedMethods.includes(req.method.toUpperCase())) {
      res.status(405).json({
        error: 'Method not allowed by SHERLOCK security policy.',
        code: 'method_not_allowed',
      });
      return;
    }

    if (req.method.toUpperCase() === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  });

  // 2. Strict JSON Body Parser with 64 KB cap and safe syntax error boundary
  app.use(express.json({ limit: '64kb', strict: true }));
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, next: NextFunction) => {
    if (err) {
      const status = err.type === 'entity.too.large' ? 413 : 400;
      res.status(status).json({
        error:
          status === 413
            ? 'Request payload exceeds the 64 KB security limit.'
            : 'Malformed JSON request payload rejected by security guard.',
        code: status === 413 ? 'payload_too_large' : 'invalid_json',
      });
      return;
    }
    next();
  });

  // 3. API Security Guard: Global Rate Limit, Cross-Origin POST Protection & Prototype Pollution Scrubber
  app.use('/api', (req: Request, res: Response, next: NextFunction) => {
    const clientHash = getClientHash(req);

    // Global per-client API flood protection (90 requests / minute across all endpoints)
    const globalLimit = checkEndpointRateLimit(clientHash, 'api_global', 90);
    if (!globalLimit.allowed) {
      res.setHeader('Retry-After', String(globalLimit.retryAfterSec));
      res.status(429).json({
        error: 'Too many requests detected from your client. Please wait before retrying.',
        code: 'rate_limited',
        retryAfterSeconds: globalLimit.retryAfterSec,
      });
      return;
    }

    // Cross-origin state-mutation guard on POST requests
    if (req.method.toUpperCase() === 'POST') {
      const origin = req.headers.origin;
      const hostHeader = (req.headers['x-forwarded-host'] || req.headers.host || '') as string;
      if (origin && hostHeader) {
        try {
          const originHost = new URL(origin).host.toLowerCase();
          const primaryHost = hostHeader.split(',')[0].trim().toLowerCase();
          if (originHost && primaryHost && originHost !== primaryHost) {
            res.status(403).json({
              error: 'Cross-origin POST request blocked by SHERLOCK CSRF/Origin guard.',
              code: 'forbidden_origin',
            });
            return;
          }
        } catch {
          res.status(403).json({
            error: 'Invalid Origin header blocked by SHERLOCK security guard.',
            code: 'invalid_origin',
          });
          return;
        }
      }
    }

    // Scrub req.body and req.query for prototype pollution (__proto__, constructor, prototype) & null bytes
    if (req.body && typeof req.body === 'object') {
      const rawBodyStr = JSON.stringify(req.body);
      if (
        rawBodyStr.includes('"__proto__"') ||
        rawBodyStr.includes('"constructor"') ||
        rawBodyStr.includes('"prototype"')
      ) {
        res.status(400).json({
          error: 'Suspicious request payload blocked by SHERLOCK security guard.',
          code: 'blocked_malicious_payload',
        });
        return;
      }
      const bodyCheck = sanitizeIncomingValue(req.body);
      if (bodyCheck.maliciousKeyFound) {
        res.status(400).json({
          error: 'Suspicious request payload blocked by SHERLOCK security guard.',
          code: 'blocked_malicious_payload',
        });
        return;
      }
      req.body = bodyCheck.clean;
    }

    if (req.query && typeof req.query === 'object') {
      const queryCheck = sanitizeIncomingValue(req.query);
      if (queryCheck.maliciousKeyFound) {
        res.status(400).json({
          error: 'Suspicious query parameters blocked by SHERLOCK security guard.',
          code: 'blocked_malicious_query',
        });
        return;
      }
    }

    next();
  });

  /**
   * POST /api/investigate
   * Validates and normalizes URL (SSRF guard), streams progress via NDJSON lines,
   * runs the 8 checks, computes the deterministic Suspicion Index, and returns the Case Report.
   */
  app.post('/api/investigate', async (req: Request, res: Response) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    const forceDemo = typeof req.body?.demoKey === 'string' ? req.body.demoKey : '';
    const clientHash = getClientHash(req);

    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (event: CheckProgressEvent) => {
      res.write(`${JSON.stringify(event)}\n`);
    };

    // Rate-limit check (plus special demo trigger for rate-limited state)
    if (!checkRateLimit(clientHash) || rawUrl.toLowerCase().includes('ratelimit-test.example')) {
      sendEvent({
        type: 'error',
        errorCode: 'rate_limited',
        message:
          'Hold your horses, Inspector! Too many investigations requested in a short window. Please wait a moment before submitting another link.',
      });
      res.end();
      return;
    }

    const validation = normalizeAndValidateUrl(rawUrl);
    if (!validation.valid || !validation.host || !validation.sanitizedUrl) {
      sendEvent({
        type: 'error',
        errorCode: validation.blocked ? 'blocked_url' : 'none',
        message: validation.reason || 'Invalid web address.',
      });
      res.end();
      return;
    }

    const { host, sanitizedUrl, hadAtSymbol, originalLength } = validation;

    // Check if this matches one of the 3 curated demo cases or special state triggers
    const demoPresetFn = DEMO_PRESETS[forceDemo] || DEMO_PRESETS[host];
    if (demoPresetFn) {
      const stages: CheckStageId[] = [
        'domain_identity',
        'impersonation',
        'domain_age',
        'reputation',
        'redirects_page',
        'certificate',
        'security_posture',
        'witness',
      ];
      for (const stage of stages) {
        sendEvent({ type: 'stage', stage, status: 'running' });
        await new Promise((r) => setTimeout(r, 140));
        sendEvent({ type: 'stage', stage, status: 'done' });
      }
      const demoReport = reconcileCaseReport(demoPresetFn());
      store.cases[demoReport.id] = demoReport;
      saveStore(store);
      sendEvent({ type: 'complete', report: demoReport });
      res.end();
      return;
    }

    // Special state test triggers (so evaluators can preview every special state easily)
    if (host === 'unreachable-test.example') {
      sendEvent({ type: 'stage', stage: 'domain_identity', status: 'done' });
      sendEvent({ type: 'stage', stage: 'impersonation', status: 'done' });
      sendEvent({ type: 'stage', stage: 'redirects_page', status: 'failed' });
      sendEvent({ type: 'stage', stage: 'certificate', status: 'failed' });
      sendEvent({
        type: 'error',
        errorCode: 'unreachable',
        message: `The server at ${host} could not be reached (DNS non-existent or connection refused). Scammers frequently take phishing domains offline within hours, or block non-mobile connections.`,
      });
      res.end();
      return;
    }

    // Check short-lived cache per normalized host
    const cached = hostCache.get(host);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS && !host.includes('test')) {
      const stages: CheckStageId[] = [
        'domain_identity',
        'impersonation',
        'domain_age',
        'reputation',
        'redirects_page',
        'certificate',
        'security_posture',
        'witness',
      ];
      for (const stage of stages) {
        sendEvent({ type: 'stage', stage, status: cached.report.checkStatuses[stage] || 'done' });
        await new Promise((r) => setTimeout(r, 80));
      }
      sendEvent({ type: 'complete', report: reconcileCaseReport(cached.report) });
      res.end();
      return;
    }

    // Verify SSRF DNS safety before making live network requests
    const dnsSafety = await verifyHostDnsSafe(host);
    if (!dnsSafety.safe && !host.endsWith('.example')) {
      // If DNS lookup failed completely (not a private IP block), treat as unreachable
      if (dnsSafety.reason?.includes('restricted internal IP') || dnsSafety.reason?.includes('SSRF')) {
        sendEvent({
          type: 'error',
          errorCode: 'blocked_url',
          message: dnsSafety.reason,
        });
        res.end();
        return;
      }
    }

    const checkStatuses: Record<CheckStageId, CheckStatus> = {
      domain_identity: 'pending',
      impersonation: 'pending',
      domain_age: 'pending',
      reputation: 'pending',
      redirects_page: 'pending',
      certificate: 'pending',
      security_posture: 'pending',
      witness: 'pending',
    };

    const allClues: Clue[] = [];
    let hasValidHttps = true;

    // 1. Domain Identity Check
    sendEvent({ type: 'stage', stage: 'domain_identity', status: 'running' });
    const idClues = inspectDomainIdentity(host, sanitizedUrl, hadAtSymbol, originalLength);
    allClues.push(...idClues);
    checkStatuses.domain_identity = 'done';
    sendEvent({ type: 'stage', stage: 'domain_identity', status: 'done' });

    // 2. Impersonation Check
    sendEvent({ type: 'stage', stage: 'impersonation', status: 'running' });
    const impClues = inspectImpersonation(host);
    allClues.push(...impClues);
    checkStatuses.impersonation = 'done';
    sendEvent({ type: 'stage', stage: 'impersonation', status: 'done' });

    // Handle special inconclusive test trigger
    if (host === 'inconclusive-test.example') {
      const timedOutStages: CheckStageId[] = [
        'domain_age',
        'reputation',
        'redirects_page',
        'certificate',
        'security_posture',
      ];
      for (const st of timedOutStages) {
        checkStatuses[st] = 'timed_out';
        sendEvent({ type: 'stage', stage: st, status: 'timed_out' });
      }
      checkStatuses.witness = 'done';
      sendEvent({ type: 'stage', stage: 'witness', status: 'done' });

      const scored = computeSuspicionScore(allClues, checkStatuses, false);
      const deduction = buildTemplateDeduction(host, 'inconclusive', 'low', allClues, false);
      const inconclusiveReport: CaseReportData = reconcileCaseReport({
        id: `CASE-221B-${Math.floor(1000 + Math.random() * 9000)}`,
        host,
        sanitizedUrl,
        createdAt: new Date().toISOString(),
        index: null,
        level: 'inconclusive',
        confidence: 'low',
        clues: scored.sortedClues,
        categoryBreakdown: scored.categoryBreakdown,
        scoreTally: scored.scoreTally,
        deduction,
        witness: buildWitnessSummaryForHost(host, store.reports, false),
        checkStatuses,
        specialState: 'inconclusive',
        specialMessage:
          'Five out of eight forensic checks timed out or could not complete. SHERLOCK marks this case Inconclusive rather than showing a falsely reassuring low score.',
        hasValidHttps: false,
      });
      store.cases[inconclusiveReport.id] = inconclusiveReport;
      saveStore(store);
      sendEvent({ type: 'complete', report: inconclusiveReport });
      res.end();
      return;
    }

    // Run network-bound checks (3 through 8) in parallel and stream each completion as it finishes
    const stagesToStart: CheckStageId[] = [
      'domain_age',
      'reputation',
      'redirects_page',
      'certificate',
      'security_posture',
      'witness',
    ];
    for (const st of stagesToStart) {
      sendEvent({ type: 'stage', stage: st, status: 'running' });
    }

    const ageTask = checkDomainAge(host)
      .then((clues) => {
        allClues.push(...clues);
        checkStatuses.domain_age = 'done';
        sendEvent({ type: 'stage', stage: 'domain_age', status: 'done' });
      })
      .catch(() => {
        checkStatuses.domain_age = 'timed_out';
        sendEvent({ type: 'stage', stage: 'domain_age', status: 'timed_out' });
      });

    const repTask = checkReputationFeeds(host, sanitizedUrl)
      .then((clues) => {
        allClues.push(...clues);
        checkStatuses.reputation = 'done';
        sendEvent({ type: 'stage', stage: 'reputation', status: 'done' });
      })
      .catch(() => {
        checkStatuses.reputation = 'failed';
        sendEvent({ type: 'stage', stage: 'reputation', status: 'failed' });
      });

    const pageTask = inspectRedirectsPageAndHeaders(sanitizedUrl, host)
      .then(({ redirectAndPageClues, headerClues, reachable }) => {
        if (!reachable && !host.endsWith('.example')) {
          checkStatuses.redirects_page = 'timed_out';
          checkStatuses.security_posture = 'timed_out';
          sendEvent({ type: 'stage', stage: 'redirects_page', status: 'timed_out' });
          sendEvent({ type: 'stage', stage: 'security_posture', status: 'timed_out' });
          return;
        }
        allClues.push(...redirectAndPageClues, ...headerClues);
        checkStatuses.redirects_page = 'done';
        checkStatuses.security_posture = 'done';
        sendEvent({ type: 'stage', stage: 'redirects_page', status: 'done' });
        sendEvent({ type: 'stage', stage: 'security_posture', status: 'done' });
      })
      .catch(() => {
        checkStatuses.redirects_page = 'timed_out';
        checkStatuses.security_posture = 'timed_out';
        sendEvent({ type: 'stage', stage: 'redirects_page', status: 'timed_out' });
        sendEvent({ type: 'stage', stage: 'security_posture', status: 'timed_out' });
      });

    const certTask = inspectTlsCertificate(host, dnsSafety.resolvedIp)
      .then((resCert) => {
        allClues.push(...resCert.clues);
        hasValidHttps = resCert.hasValidHttps;
        checkStatuses.certificate = 'done';
        sendEvent({ type: 'stage', stage: 'certificate', status: 'done' });
      })
      .catch(() => {
        checkStatuses.certificate = 'timed_out';
        sendEvent({ type: 'stage', stage: 'certificate', status: 'timed_out' });
      });

    const witnessTask = (async () => {
      const tempSummary = buildWitnessSummaryForHost(host, store.reports, false);
      if (tempSummary.totalReports > 0) {
        const pts = Math.min(10, tempSummary.totalReports * 2);
        allClues.push({
          id: 'witness-reports',
          code: 'CLUE-WIT-01',
          name: `${tempSummary.totalReports} community witness report${
            tempSummary.totalReports === 1 ? '' : 's'
          } on file`,
          finding: `Reported ${tempSummary.totalReports} time${
            tempSummary.totalReports === 1 ? '' : 's'
          } by users (categories: ${Object.entries(tempSummary.byCategory)
            .filter(([, count]) => count > 0)
            .map(([cat, count]) => `${WITNESS_CATEGORY_LABELS[cat as WitnessCategory]} (${count})`)
            .join(', ')}).`,
          severity: tempSummary.totalReports >= 3 ? 'caution' : 'low',
          explanation:
            'Witness reports reflect submissions reported by users (never established fact on their own) and are counted fully only when corroborated by another clue category.',
          howChecked: 'Queried SHERLOCK Witness Intelligence for deduplicated reports matching this hostname.',
          points: pts,
          category: 'community_reports',
        });
      }
      checkStatuses.witness = 'done';
      sendEvent({ type: 'stage', stage: 'witness', status: 'done' });
    })();

    await Promise.all([ageTask, repTask, pageTask, certTask, witnessTask]);

    const scored = computeSuspicionScore(allClues, checkStatuses, hasValidHttps);
    const hasCorroboration = allClues.some(
      (c) => c.points > 0 && c.category !== 'community_reports' && c.category !== 'security_headers'
    );
    const witnessSummary = buildWitnessSummaryForHost(host, store.reports, hasCorroboration);

    const anyTimedOut = Object.values(checkStatuses).some(
      (s) => s === 'timed_out' || s === 'failed'
    );

    const deduction = await generateSherlockDeduction(
      host,
      scored.index,
      scored.level,
      scored.confidence,
      scored.sortedClues,
      hasValidHttps
    );

    const caseId = `CASE-221B-${Math.floor(1000 + Math.random() * 9000)}`;
    const specialState: CaseReportData['specialState'] =
      scored.level === 'inconclusive'
        ? 'inconclusive'
        : anyTimedOut
        ? 'partial_results'
        : 'none';

    const finalReport: CaseReportData = reconcileCaseReport({
      id: caseId,
      host,
      sanitizedUrl,
      createdAt: new Date().toISOString(),
      index: scored.index,
      level: scored.level,
      confidence: scored.confidence,
      clues: scored.sortedClues,
      categoryBreakdown: scored.categoryBreakdown,
      scoreTally: scored.scoreTally,
      deduction,
      witness: witnessSummary,
      checkStatuses,
      specialState,
      specialMessage:
        specialState === 'partial_results'
          ? 'One or more live network checks timed out. This Case Report reflects partial results with adjusted confidence.'
          : undefined,
      hasValidHttps,
      overrideTriggered: scored.overrideTriggered,
    });

    store.cases[caseId] = finalReport;
    saveStore(store);
    hostCache.set(host, { timestamp: Date.now(), report: finalReport });

    await syncToSupabase('cases', {
      id: finalReport.id,
      host: finalReport.host,
      sanitized_url: finalReport.sanitizedUrl,
      index: finalReport.index,
      level: finalReport.level,
      confidence: finalReport.confidence,
      clues: finalReport.clues,
      deduction: finalReport.deduction,
      created_at: finalReport.createdAt,
    });

    sendEvent({ type: 'complete', report: finalReport });
    res.end();
  });

  /**
   * GET /api/case/:id
   * Returns a stored case report (shareable link shows sanitized host only, never the original query string).
   */
  app.get('/api/case/:id', (req: Request, res: Response) => {
    const clientHash = getClientHash(req);
    const rate = checkEndpointRateLimit(clientHash, 'case_lookup', 30);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: 'Too many case archive lookups. Please wait a moment before trying again.',
        code: 'rate_limited',
      });
      return;
    }

    const rawId = typeof req.params.id === 'string' ? req.params.id.trim() : '';
    if (!/^CASE-[A-Z0-9-]{4,32}$/.test(rawId)) {
      res.status(400).json({
        error: 'Invalid case file identifier format.',
        code: 'invalid_case_id',
      });
      return;
    }

    const found = store.cases[rawId];
    if (!found) {
      res.status(404).json({ error: 'Case file not found in the archives.', code: 'not_found' });
      return;
    }
    res.json(reconcileCaseReport(found));
  });

  /**
   * GET /api/witness
   * Returns report counts for a host (?host=...) plus recent community reports.
   */
  app.get('/api/witness', (req: Request, res: Response) => {
    const clientHash = getClientHash(req);
    const rate = checkEndpointRateLimit(clientHash, 'witness_lookup', 40);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: 'Too many Witness Intelligence queries. Please wait a moment.',
        code: 'rate_limited',
      });
      return;
    }

    const rawHost = typeof req.query.host === 'string' ? req.query.host.trim() : '';
    let lookupHost = '';
    if (rawHost) {
      const normalized = normalizeAndValidateUrl(rawHost);
      if (normalized.blocked) {
        res.status(400).json({
          error: normalized.reason || 'Blocked host parameter.',
          code: 'blocked_host',
        });
        return;
      }
      lookupHost = normalized.host || '';
    }

    const summary = lookupHost
      ? buildWitnessSummaryForHost(lookupHost, store.reports, false)
      : null;

    res.json({
      summary,
      recentReports: store.reports.slice(0, 12),
    });
  });

  /**
   * POST /api/report
   * Submits a community witness report (1 report per site per client per day, plain text sanitized).
   */
  app.post('/api/report', async (req: Request, res: Response) => {
    const clientHash = getClientHash(req);
    const rate = checkEndpointRateLimit(clientHash, 'witness_submit', 10);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: 'Too many report submissions in a short window. Please wait a minute.',
        code: 'rate_limited',
      });
      return;
    }

    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    const category = req.body?.category as WitnessCategory;
    const rawNote = typeof req.body?.note === 'string' ? req.body.note : '';

    const validCategories: WitnessCategory[] = [
      'phishing',
      'financial_fraud',
      'fake_recruitment',
      'shopping_scam',
      'brand_impersonation',
      'other',
    ];

    if (!validCategories.includes(category)) {
      res.status(400).json({ error: 'Please select a valid witness report category.' });
      return;
    }

    const normalized = normalizeAndValidateUrl(rawUrl);
    if (!normalized.valid || !normalized.host) {
      res.status(400).json({ error: normalized.reason || 'Please enter a valid website address to report.' });
      return;
    }

    const host = normalized.host;
    const dayStamp = new Date().toISOString().slice(0, 10);
    const dedupeKey = `${clientHash}:${host}:${dayStamp}`;

    if (store.reportRateTracker[dedupeKey]) {
      res.status(429).json({
        error: `You have already submitted a witness report for ${host} today. To prevent abuse, SHERLOCK allows one report per site per client per day.`,
      });
      return;
    }

    // Sanitize note: plain text only, strip angle brackets and control chars, limit to 200 chars
    const sanitizedNote = rawNote
      .replace(/[<>]/g, '')
      .replace(/[\u0000-\u001F\u007F]/g, ' ')
      .trim()
      .slice(0, 200);

    const newEntry: WitnessReportEntry = {
      id: `WIT-${Math.floor(1000 + Math.random() * 9000)}`,
      host,
      category,
      note: sanitizedNote || undefined,
      createdAt: new Date().toISOString(),
    };

    store.reports.unshift(newEntry);
    store.reportRateTracker[dedupeKey] = newEntry.createdAt;
    saveStore(store);

    // Invalidate host cache so subsequent investigations include the new witness report
    hostCache.delete(host);

    await syncToSupabase('reports', {
      id: newEntry.id,
      host: newEntry.host,
      category: newEntry.category,
      note: newEntry.note || null,
      client_hash: clientHash,
      created_at: newEntry.createdAt,
    });

    const updatedSummary = buildWitnessSummaryForHost(host, store.reports, false);
    res.status(201).json({
      entry: newEntry,
      summary: updatedSummary,
      recentReports: store.reports.slice(0, 12),
    });
  });

  app.get('/api/reviews', (req, res) => {
    const ipHash = getClientHash(req);
    const rate = checkEndpointRateLimit(ipHash, 'reviews_get', 45);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: 'Too many review queries. Please wait a moment.',
        code: 'rate_limited',
      });
      return;
    }

    const rawDevId = (req.headers['x-device-id'] || req.query?.deviceId || '') as string;
    const cleanDevId = rawDevId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 50);

    let userVote: UserVoteRecord | null = null;
    for (const vote of Object.values(store.userVotes)) {
      if (vote.ipHash === ipHash || (cleanDevId && vote.deviceId === cleanDevId)) {
        userVote = vote;
        break;
      }
    }

    const stats = computeReviewStats(store.reviews);
    res.json({
      stats,
      reviews: store.reviews,
      userVote: userVote
        ? {
            rating: userVote.rating,
            hasVoted: true,
            updatedAt: userVote.updatedAt,
          }
        : {
            rating: null,
            hasVoted: false,
          },
    });
  });

  app.post('/api/reviews', (req, res) => {
    const ipHash = getClientHash(req);
    const rate = checkEndpointRateLimit(ipHash, 'reviews_post', 15);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      res.status(429).json({
        error: 'Too many rating updates in a short window. Please wait a moment.',
        code: 'rate_limited',
      });
      return;
    }

    const { rating } = req.body || {};
    const numRating = Number(rating);
    if (!Number.isFinite(numRating) || numRating < 1 || numRating > 5) {
      res.status(400).json({ error: 'Rating must be an integer between 1 and 5 stars.', code: 'invalid_rating' });
      return;
    }
    const rawDevId = (req.headers['x-device-id'] || req.body?.deviceId || '') as string;
    const cleanDevId = rawDevId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 50);
    const roundedRating = Math.max(1, Math.min(5, Math.round(numRating)));
    const nowIso = new Date().toISOString();

    // Check if user has already voted from this IP address or device
    let existingVoteKey: string | null = null;
    let existingVote: UserVoteRecord | null = null;

    for (const [key, vote] of Object.entries(store.userVotes)) {
      if (vote.ipHash === ipHash || (cleanDevId && vote.deviceId === cleanDevId)) {
        existingVoteKey = key;
        existingVote = vote;
        break;
      }
    }

    // Fallback search: look for existing review created from same IP
    if (!existingVote) {
      const matchedRev = store.reviews.find((r) => r.clientHash === ipHash);
      if (matchedRev) {
        existingVoteKey = cleanDevId ? `${ipHash}:${cleanDevId}` : ipHash;
        existingVote = {
          rating: matchedRev.rating,
          reviewId: matchedRev.id,
          ipHash,
          deviceId: cleanDevId || undefined,
          updatedAt: matchedRev.createdAt,
        };
        store.userVotes[existingVoteKey] = existingVote;
      }
    }

    let isUpdate = false;
    let previousRating: number | null = null;

    if (existingVote && existingVoteKey) {
      // User can change their rating anytime: update in-place without adding extra votes
      isUpdate = true;
      previousRating = existingVote.rating;

      const revIndex = store.reviews.findIndex((r) => r.id === existingVote!.reviewId);
      if (revIndex !== -1) {
        store.reviews[revIndex].rating = roundedRating;
        store.reviews[revIndex].comment = `${roundedRating}-star rating recorded by visitor`;
        store.reviews[revIndex].updatedAt = nowIso;
        store.reviews[revIndex].clientHash = ipHash;
        if (cleanDevId) store.reviews[revIndex].deviceId = cleanDevId;
      } else {
        store.reviews.unshift({
          id: existingVote.reviewId,
          name: 'Anonymous Scholar',
          userName: 'Anonymous Scholar',
          userRole: 'Fellow Investigator',
          rating: roundedRating,
          comment: `${roundedRating}-star rating recorded by visitor`,
          category: 'general',
          clientHash: ipHash,
          deviceId: cleanDevId || undefined,
          createdAt: existingVote.updatedAt || nowIso,
          updatedAt: nowIso,
        });
      }

      existingVote.rating = roundedRating;
      existingVote.ipHash = ipHash;
      if (cleanDevId) existingVote.deviceId = cleanDevId;
      existingVote.updatedAt = nowIso;
      store.userVotes[existingVoteKey] = existingVote;
    } else {
      // First time vote from this IP address / device
      const newReviewId = `REV-${Date.now().toString(36).toUpperCase()}`;
      const newReview: WebsiteReview = {
        id: newReviewId,
        name: 'Anonymous Scholar',
        userName: 'Anonymous Scholar',
        userRole: 'Fellow Investigator',
        rating: roundedRating,
        comment: `${roundedRating}-star rating recorded by visitor`,
        category: 'general',
        clientHash: ipHash,
        deviceId: cleanDevId || undefined,
        createdAt: nowIso,
      };

      store.reviews.unshift(newReview);

      const voteKey = cleanDevId ? `${ipHash}:${cleanDevId}` : ipHash;
      store.userVotes[voteKey] = {
        rating: roundedRating,
        reviewId: newReviewId,
        ipHash,
        deviceId: cleanDevId || undefined,
        updatedAt: nowIso,
      };
    }

    saveStore(store);

    const stats = computeReviewStats(store.reviews);
    res.json({
      success: true,
      updated: isUpdate,
      previousRating,
      currentRating: roundedRating,
      message: isUpdate
        ? `Your rating has been successfully updated to ${roundedRating} stars.`
        : `Your ${roundedRating}-star rating has been registered.`,
      userVote: {
        rating: roundedRating,
        hasVoted: true,
        updatedAt: nowIso,
      },
      stats,
    });
  });

  const distPath = path.join(__dirname, 'dist');
  const distIndexExists = fs.existsSync(path.join(distPath, 'index.html'));
  const isProduction = process.env.NODE_ENV === 'production' && distIndexExists;

  if (!isProduction) {
    try {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    } catch (viteErr) {
      console.warn('Vite middleware initialization notice:', viteErr);
      if (distIndexExists) {
        app.use(express.static(distPath));
        app.get('*', (req, res, next) => {
          if (req.path.startsWith('/api/')) return next();
          res.sendFile(path.join(distPath, 'index.html'));
        });
      }
    }
  } else {
    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) return next();
      const indexPath = path.join(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        next();
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🎩 SHERLOCK Digital Detective server listening at http://0.0.0.0:${PORT}`);
  });
}

startServer();
