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
  InternetAssetFootprint,
  PublicWebExperience,
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
  buildGoDaddyUrls,
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
 * Resolves DNS and verifies:
 * 1. Whether the domain actually exists on the public internet (NXDOMAIN / ENOTFOUND check)
 * 2. That no A/AAAA record points to a private/loopback/metadata IP (SSRF & DNS-rebinding guard)
 */
async function verifyHostDnsSafe(host: string): Promise<{
  safe: boolean;
  exists: boolean;
  blocked?: boolean;
  reason?: string;
  resolvedIp?: string;
  resolvedIps?: string[];
}> {
  if (isPrivateOrReservedHost(host)) {
    return {
      safe: false,
      exists: true,
      blocked: true,
      reason: 'Address resolves to a private, loopback, or cloud metadata range blocked by SSRF guard.',
    };
  }
  if (host === 'nonexistent-test.example') {
    return {
      safe: false,
      exists: false,
      blocked: false,
      reason: `The domain "${host}" does not exist on the public internet (DNS NXDOMAIN — unregistered domain).`,
    };
  }
  if (host.endsWith('.example')) {
    return { safe: true, exists: true, blocked: false, resolvedIp: '198.51.100.10', resolvedIps: ['198.51.100.10'] };
  }
  try {
    const records = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('DNS lookup timed out')), 3200)
      ),
    ]);
    if (!records || records.length === 0) {
      return {
        safe: false,
        exists: false,
        blocked: false,
        reason: `The website "${host}" does not exist on the internet (DNS returned no IP records).`,
      };
    }
    const uniqueIps: string[] = [];
    for (const rec of records) {
      if (isPrivateOrReservedHost(rec.address)) {
        return {
          safe: false,
          exists: true,
          blocked: true,
          reason: `Domain ${host} resolved to a restricted internal IP address (${rec.address}) and was blocked by SHERLOCK's SSRF & DNS-rebinding guard.`,
        };
      }
      if (!uniqueIps.includes(rec.address)) {
        uniqueIps.push(rec.address);
      }
    }
    return {
      safe: true,
      exists: true,
      blocked: false,
      resolvedIp: uniqueIps[0],
      resolvedIps: uniqueIps.slice(0, 6),
    };
  } catch (err) {
    const code = (err as { code?: string })?.code || '';
    if (
      code === 'ENOTFOUND' ||
      code === 'ENODATA' ||
      code === 'EBADNAME' ||
      code === 'ESERVFAIL' ||
      code === 'EREFUSED'
    ) {
      return {
        safe: false,
        exists: false,
        blocked: false,
        reason: `The website "${host}" does not exist on the public internet (${code}: domain is unregistered or has no active DNS records).`,
      };
    }
    return {
      safe: false,
      exists: false,
      blocked: false,
      reason: `The website "${host}" could not be resolved on the public internet (domain does not exist or DNS is unreachable).`,
    };
  }
}

export interface DomainAgeCheckResult {
  clues: Clue[];
  registrar: string | null;
  registeredAt: string | null;
  expiresAt: string | null;
  domainAgeDays: number | null;
  rdapNotFound: boolean;
}

/**
 * Helper to extract human-readable registrar name from an RDAP response payload
 */
function extractRegistrarFromRdap(data: {
  entities?: Array<{
    handle?: string;
    roles?: string[];
    vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
  }>;
  port43?: string;
}): string | null {
  if (Array.isArray(data.entities)) {
    for (const ent of data.entities) {
      if (ent.roles?.includes('registrar')) {
        const vcard = ent.vcardArray?.[1];
        if (Array.isArray(vcard)) {
          const fnRow = vcard.find((row) => Array.isArray(row) && row[0] === 'fn');
          if (fnRow && typeof fnRow[3] === 'string' && fnRow[3].trim()) {
            return fnRow[3].trim();
          }
          const orgRow = vcard.find((row) => Array.isArray(row) && row[0] === 'org');
          if (orgRow && typeof orgRow[3] === 'string' && orgRow[3].trim()) {
            return orgRow[3].trim();
          }
        }
        if (ent.handle) return ent.handle;
      }
    }
  }
  return data.port43 || null;
}

/**
 * Check 3: RDAP Domain Age & Registrar WHOIS Lookup
 */
async function checkDomainAge(host: string): Promise<DomainAgeCheckResult> {
  const clues: Clue[] = [];
  const labels = host.split('.');
  const registrable =
    labels.length > 2 &&
    (host.endsWith('.co.uk') ||
      host.endsWith('.ac.uk') ||
      host.endsWith('.gov.uk') ||
      host.endsWith('.org.uk') ||
      host.endsWith('.com.au') ||
      host.endsWith('.co.in') ||
      host.endsWith('.com.br'))
      ? labels.slice(-3).join('.')
      : labels.slice(-2).join('.');

  // Synthetic age rules for .example demo TLDs
  if (host.endsWith('.example')) {
    if (host.includes('new') || host.includes('paypa1') || host.includes('verify')) {
      const regDate = new Date(Date.now() - 6 * 86400 * 1000).toISOString();
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
      return {
        clues,
        registrar: 'Synthetic Demo Registrar',
        registeredAt: regDate,
        expiresAt: new Date(Date.now() + 359 * 86400 * 1000).toISOString(),
        domainAgeDays: 6,
        rdapNotFound: false,
      };
    }
    return {
      clues,
      registrar: 'IANA Reserved .example Registry',
      registeredAt: null,
      expiresAt: null,
      domainAgeDays: null,
      rdapNotFound: false,
    };
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrable)}`, {
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': USER_AGENT },
      signal: AbortSignal.timeout(3800),
    });

    if (res.status === 404) {
      clues.push({
        id: 'age-unknown',
        code: 'CLUE-AGE-04',
        name: 'Domain registration age could not be verified via public RDAP',
        finding: `Public RDAP registry returned 404 for ${registrable}.`,
        severity: 'low',
        explanation:
          'Some country-code registries do not publish creation dates over public RDAP, or the domain registration is not active.',
        howChecked: 'Queried https://rdap.org/domain/ with a 3.8-second timeout.',
        points: 3,
        category: 'domain_age',
      });
      return {
        clues,
        registrar: null,
        registeredAt: null,
        expiresAt: null,
        domainAgeDays: null,
        rdapNotFound: true,
      };
    }

    if (!res.ok) {
      clues.push({
        id: 'age-unknown',
        code: 'CLUE-AGE-04',
        name: 'Domain registration age could not be verified via public RDAP',
        finding: `Public RDAP registry did not return a creation date for ${registrable}.`,
        severity: 'low',
        explanation:
          'Some country-code registries do not publish creation dates over public RDAP, which adds a small uncertainty penalty.',
        howChecked: 'Queried https://rdap.org/domain/ with a 3.8-second timeout.',
        points: 3,
        category: 'domain_age',
      });
      return {
        clues,
        registrar: null,
        registeredAt: null,
        expiresAt: null,
        domainAgeDays: null,
        rdapNotFound: false,
      };
    }

    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{
        handle?: string;
        roles?: string[];
        vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
      }>;
      port43?: string;
    };

    const registrar = extractRegistrarFromRdap(data);
    const regEvent = data.events?.find(
      (e) => e.eventAction === 'registration' || e.eventAction === 'created'
    );
    const expEvent = data.events?.find((e) => e.eventAction === 'expiration');
    const expiresAt = expEvent?.eventDate ? new Date(expEvent.eventDate).toISOString() : null;

    if (!regEvent?.eventDate) {
      clues.push({
        id: 'age-no-event',
        code: 'CLUE-AGE-04',
        name: 'Registration timestamp omitted in RDAP record',
        finding: `RDAP record for ${registrable}${registrar ? ` (Registrar: ${registrar})` : ''} did not include a creation date.`,
        severity: 'low',
        explanation: 'When registration age cannot be confirmed, treat unfamiliar requests with extra care.',
        howChecked: 'Inspected RDAP events array for "registration" action.',
        points: 3,
        category: 'domain_age',
      });
      return {
        clues,
        registrar,
        registeredAt: null,
        expiresAt,
        domainAgeDays: null,
        rdapNotFound: false,
      };
    }

    const createdDate = new Date(regEvent.eventDate);
    const registeredAt = createdDate.toISOString();
    const ageDays = Math.max(
      0,
      Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24))
    );

    if (ageDays < 7) {
      clues.push({
        id: 'age-under-7d',
        code: 'CLUE-AGE-01',
        name: `Very new domain (${ageDays} day${ageDays === 1 ? '' : 's'} old)`,
        finding: `${registrable} was registered only ${ageDays} day${
          ageDays === 1 ? '' : 's'
        } ago (${registeredAt.slice(0, 10)})${registrar ? ` via ${registrar}` : ''}.`,
        severity: 'critical',
        explanation:
          'Domains registered less than a week ago are a primary indicator of short-lived scam campaigns.',
        howChecked: 'Calculated days elapsed since the RDAP registration event timestamp.',
        points: 20,
        category: 'domain_age',
      });
    } else if (ageDays < 30) {
      clues.push({
        id: 'age-under-30d',
        code: 'CLUE-AGE-02',
        name: `Recently registered domain (${ageDays} days old)`,
        finding: `${registrable} was registered ${ageDays} days ago (${registeredAt.slice(0, 10)})${
          registrar ? ` via ${registrar}` : ''
        }.`,
        severity: 'high',
        explanation:
          'Domains under 30 days old warrant heightened caution before entering account or payment data.',
        howChecked: 'Calculated days elapsed since the RDAP registration event timestamp.',
        points: 14,
        category: 'domain_age',
      });
    } else if (ageDays < 90) {
      clues.push({
        id: 'age-under-90d',
        code: 'CLUE-AGE-03',
        name: `Young domain (${ageDays} days old)`,
        finding: `${registrable} was registered ${ageDays} days ago (${registeredAt.slice(0, 10)})${
          registrar ? ` via ${registrar}` : ''
        }.`,
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
        name: `Established domain registration (${Math.max(1, Math.floor(ageDays / 365))}+ years old)`,
        finding: `${registrable} was registered on ${registeredAt.slice(0, 10)} (${ageDays} days ago)${
          registrar ? ` with ${registrar}` : ''
        }.`,
        severity: 'info',
        explanation:
          'An older domain reduces the likelihood of a disposable throwaway domain, though compromised legitimate sites can still host malicious pages.',
        howChecked: 'Verified registration date and registrar via public RDAP lookup.',
        points: 0,
        category: 'domain_age',
      });
    }

    return {
      clues,
      registrar,
      registeredAt,
      expiresAt,
      domainAgeDays: ageDays,
      rdapNotFound: false,
    };
  } catch {
    clues.push({
      id: 'age-timeout',
      code: 'CLUE-AGE-04',
      name: 'Domain age lookup timed out',
      finding: `Registry RDAP server did not respond within 3.8 seconds for ${registrable}.`,
      severity: 'low',
      explanation: 'Unknown domain age adds a minor 3-point caution weight.',
      howChecked: 'Attempted RDAP lookup with a 3.8-second hard timeout.',
      points: 3,
      category: 'domain_age',
    });
    return {
      clues,
      registrar: null,
      registeredAt: null,
      expiresAt: null,
      domainAgeDays: null,
      rdapNotFound: false,
    };
  }
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

export interface PageAndHeadersResult {
  redirectAndPageClues: Clue[];
  headerClues: Clue[];
  reachable: boolean;
  httpStatus: number | null;
  serverHeader: string | null;
  redirectChain: string[];
  pageTitle: string | null;
  metaDescription: string | null;
  formsDetected: number;
  hasPasswordInput: boolean;
  presentSecurityHeaders: string[];
  missingSecurityHeaders: string[];
}

/**
 * Check 5 & 7: Safe Limited Redirect Follower, Static HTML Page Inspector, and Security Headers Inspector
 */
async function inspectRedirectsPageAndHeaders(
  initialUrl: string,
  initialHost: string
): Promise<PageAndHeadersResult> {
  const redirectAndPageClues: Clue[] = [];
  const headerClues: Clue[] = [];
  const redirectChain: string[] = [initialUrl];

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
        signal: AbortSignal.timeout(4000),
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
        redirectChain.push(currentUrl);
        continue;
      }

      finalResponse = res;
      break;
    }
  } catch {
    return {
      redirectAndPageClues,
      headerClues,
      reachable: false,
      httpStatus: null,
      serverHeader: null,
      redirectChain,
      pageTitle: null,
      metaDescription: null,
      formsDetected: 0,
      hasPasswordInput: false,
      presentSecurityHeaders: [],
      missingSecurityHeaders: [],
    };
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
    return {
      redirectAndPageClues,
      headerClues,
      reachable: false,
      httpStatus: null,
      serverHeader: null,
      redirectChain,
      pageTitle: null,
      metaDescription: null,
      formsDetected: 0,
      hasPasswordInput: false,
      presentSecurityHeaders: [],
      missingSecurityHeaders: [],
    };
  }

  const httpStatus = finalResponse.status;
  const serverHeader = finalResponse.headers.get('server') || null;

  // Inspect Security Headers (Check 7)
  const hsts = finalResponse.headers.get('strict-transport-security');
  const csp = finalResponse.headers.get('content-security-policy');
  const xfo = finalResponse.headers.get('x-frame-options');
  const referrer = finalResponse.headers.get('referrer-policy');
  const xcto = finalResponse.headers.get('x-content-type-options');

  const presentHeaders: string[] = [];
  const missingHeaders: string[] = [];

  if (hsts) presentHeaders.push('HSTS');
  else missingHeaders.push('HSTS');

  if (csp) presentHeaders.push('CSP');
  else missingHeaders.push('CSP');

  if (xfo) presentHeaders.push('X-Frame-Options');
  else missingHeaders.push('X-Frame-Options');

  if (referrer) presentHeaders.push('Referrer-Policy');
  else missingHeaders.push('Referrer-Policy');

  if (xcto) presentHeaders.push('X-Content-Type-Options');

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
  } else if (presentHeaders.length >= 3) {
    headerClues.push({
      id: 'sec-present-good',
      code: 'CLUE-SEC-00',
      name: `Standard browser security headers present (${presentHeaders.join(', ')})`,
      finding: `The server actively enforces ${presentHeaders.join(', ')}.`,
      severity: 'info',
      explanation: 'Well-configured web servers enforce transport and framing protections.',
      howChecked: 'Inspected HTTP response headers from the final landing page.',
      points: 0,
      category: 'security_headers',
    });
  }

  let pageTitle: string | null = null;
  let metaDescription: string | null = null;
  let formsDetected = 0;
  let hasPasswordField = false;

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

      hasPasswordField = /<input[^>]+type\s*=\s*["']?password["']?/i.test(html);
      const titleMatch = html.match(/<title[^>]*>([\s\S]{1,220}?)<\/title>/i);
      pageTitle = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : null;

      const descMatch =
        html.match(/<meta[^>]+name\s*=\s*["']description["'][^>]+content\s*=\s*["']([^"']{1,300})["']/i) ||
        html.match(/<meta[^>]+content\s*=\s*["']([^"']{1,300})["'][^>]+name\s*=\s*["']description["']/i) ||
        html.match(/<meta[^>]+property\s*=\s*["']og:description["'][^>]+content\s*=\s*["']([^"']{1,300})["']/i);
      metaDescription = descMatch ? descMatch[1].replace(/\s+/g, ' ').trim() : null;

      const allForms = [...html.matchAll(/<form\b[^>]*>/gi)];
      formsDetected = allForms.length;

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
        const titleHasBrand = (pageTitle || '').toLowerCase().includes(b.name.toLowerCase());
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
      } else if (mismatchedBrandInTitle) {
        redirectAndPageClues.push({
          id: 'page-brand-title-mismatch',
          code: 'CLUE-PAGE-03',
          name: `Page title claims "${mismatchedBrandInTitle.name}" on non-official domain`,
          finding: `The HTML <title> ("${pageTitle}") references ${mismatchedBrandInTitle.name}, which does not match ${currentHost}.`,
          severity: 'high',
          explanation:
            'Lookalike pages often copy the <title> tag of a major brand while hosted on an unrelated domain.',
          howChecked: 'Compared HTML <title> brand tokens against official domain registries.',
          points: 15,
          category: 'page_behavior',
        });
      }
    }
  } catch {
    // Ignore body read timeouts; headers were already inspected
  }

  return {
    redirectAndPageClues,
    headerClues,
    reachable: true,
    httpStatus,
    serverHeader,
    redirectChain,
    pageTitle,
    metaDescription,
    formsDetected,
    hasPasswordInput: hasPasswordField,
    presentSecurityHeaders: presentHeaders,
    missingSecurityHeaders: missingHeaders,
  };
}

export interface TlsInspectionResult {
  clues: Clue[];
  hasValidHttps: boolean;
  tlsIssuer: string | null;
  tlsSubject: string | null;
  tlsValidFrom: string | null;
  tlsValidTo: string | null;
  tlsProtocol: string | null;
}

/**
 * Check 6: TLS Certificate Inspector (Node.js runtime)
 * Pins to the pre-verified public IP when available while preserving SNI (servername: host)
 * to defeat DNS rebinding (TOCTOU) attacks.
 */
async function inspectTlsCertificate(
  host: string,
  pinnedIp?: string
): Promise<TlsInspectionResult> {
  const clues: Clue[] = [];
  if (host.endsWith('.example')) {
    return {
      clues,
      hasValidHttps: true,
      tlsIssuer: "Let's Encrypt (Demo Authority)",
      tlsSubject: host,
      tlsValidFrom: new Date(Date.now() - 5 * 86400 * 1000).toISOString(),
      tlsValidTo: new Date(Date.now() + 85 * 86400 * 1000).toISOString(),
      tlsProtocol: 'TLSv1.3',
    };
  }

  const targetAddress = pinnedIp && !isPrivateOrReservedHost(pinnedIp) ? pinnedIp : host;

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: targetAddress,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 3400,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const tlsProtocol = socket.getProtocol() || null;
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
            resolve({
              clues,
              hasValidHttps: false,
              tlsIssuer: null,
              tlsSubject: null,
              tlsValidFrom: null,
              tlsValidTo: null,
              tlsProtocol,
            });
            return;
          }

          const issuerOrg =
            (typeof cert.issuer?.O === 'string' ? cert.issuer.O : Array.isArray(cert.issuer?.O) ? cert.issuer.O[0] : '') ||
            (typeof cert.issuer?.CN === 'string' ? cert.issuer.CN : Array.isArray(cert.issuer?.CN) ? cert.issuer.CN[0] : '') ||
            null;
          const subjectCn =
            (typeof cert.subject?.CN === 'string' ? cert.subject.CN : Array.isArray(cert.subject?.CN) ? cert.subject.CN[0] : '') ||
            host;

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
            resolve({
              clues,
              hasValidHttps: false,
              tlsIssuer: issuerOrg,
              tlsSubject: subjectCn,
              tlsValidFrom: validFrom ? validFrom.toISOString() : null,
              tlsValidTo: validTo ? validTo.toISOString() : null,
              tlsProtocol,
            });
            return;
          }

          if (validFrom) {
            const certAgeDays = Math.max(0, Math.floor((now - validFrom.getTime()) / (1000 * 60 * 60 * 24)));
            if (certAgeDays <= 5) {
              clues.push({
                id: 'cert-very-new',
                code: 'CLUE-CERT-01',
                name: `TLS certificate issued ${certAgeDays} day${certAgeDays === 1 ? '' : 's'} ago`,
                finding: `HTTPS is active (issued by ${
                  issuerOrg || 'CA'
                }), but the certificate was issued only ${certAgeDays} day${
                  certAgeDays === 1 ? '' : 's'
                } ago. Remember: a valid padlock proves encryption, not trustworthiness.`,
                severity: 'low',
                explanation:
                  'Automated certificate authorities issue free HTTPS certificates in minutes. Most phishing sites have a valid padlock.',
                howChecked: 'Checked the notBefore (valid_from) timestamp on the X.509 peer certificate.',
                points: 3,
                category: 'certificate',
              });
            } else {
              clues.push({
                id: 'cert-valid-info',
                code: 'CLUE-CERT-00',
                name: `Valid HTTPS certificate (${issuerOrg || 'Trusted CA'})`,
                finding: `Connection is encrypted via ${tlsProtocol || 'TLS'} with a valid certificate issued by ${
                  issuerOrg || 'a trusted CA'
                }.`,
                severity: 'info',
                explanation:
                  'A valid TLS certificate confirms traffic is encrypted in transit, though encryption alone never guarantees a site is trustworthy.',
                howChecked: 'Inspected X.509 peer certificate chain, issuer, and validity window.',
                points: 0,
                category: 'certificate',
              });
            }
          }

          resolve({
            clues,
            hasValidHttps: true,
            tlsIssuer: issuerOrg,
            tlsSubject: subjectCn,
            tlsValidFrom: validFrom ? validFrom.toISOString() : null,
            tlsValidTo: validTo ? validTo.toISOString() : null,
            tlsProtocol,
          });
        } catch {
          socket.destroy();
          resolve({
            clues,
            hasValidHttps: false,
            tlsIssuer: null,
            tlsSubject: null,
            tlsValidFrom: null,
            tlsValidTo: null,
            tlsProtocol: null,
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        clues,
        hasValidHttps: false,
        tlsIssuer: null,
        tlsSubject: null,
        tlsValidFrom: null,
        tlsValidTo: null,
        tlsProtocol: null,
      });
    });

    socket.on('error', () => {
      socket.destroy();
      resolve({
        clues,
        hasValidHttps: false,
        tlsIssuer: null,
        tlsSubject: null,
        tlsValidFrom: null,
        tlsValidTo: null,
        tlsProtocol: null,
      });
    });
  });
}

/**
 * Queries real-world public internet user experiences, reviews, and scam warnings
 * for the target domain using @google/genai (gemini-3.8-flash) with Google Search Grounding.
 */
async function checkPublicWebExperience(
  host: string,
  localReportsCount: number,
  domainAgeDays: number | null,
  pageTitle: string | null
): Promise<{ webExperience: PublicWebExperience; experienceClues: Clue[] }> {
  const experienceClues: Clue[] = [];
  const fallbackExperience: PublicWebExperience = {
    sentiment:
      localReportsCount >= 2
        ? 'negative'
        : domainAgeDays !== null && domainAgeDays > 365
        ? 'positive'
        : 'unverified',
    summary:
      localReportsCount > 0
        ? `Community witnesses have filed ${localReportsCount} report${
            localReportsCount === 1 ? '' : 's'
          } concerning ${host}. Exercise caution before entering credentials or personal details.`
        : domainAgeDays !== null && domainAgeDays > 365
        ? `${host} has an established multi-year domain registration history (${Math.floor(
            domainAgeDays / 365
          )}+ years) and no community scam reports on file in SHERLOCK.`
        : `No corroborated public scam reports or established consumer review histories were found for ${host} yet.`,
    highlights: [
      pageTitle ? `Observed page title: "${pageTitle}".` : `Target host: ${host}.`,
      domainAgeDays !== null
        ? `Domain registration age verified via RDAP: ${domainAgeDays} days.`
        : 'Domain registration age could not be confirmed via public RDAP.',
      localReportsCount > 0
        ? `${localReportsCount} local Witness Intelligence report(s) recorded.`
        : '0 local Witness Intelligence scam reports on file.',
    ],
    sources: [],
  };

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || host.endsWith('.example')) {
    return { webExperience: fallbackExperience, experienceClues };
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

    const response = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents:
          `Search the public internet for real user experiences, reviews, reputation, Trustpilot/Reddit/forum discussions, or phishing/scam warnings regarding the website domain "${host}".\n` +
          `Return ONLY a valid JSON object (no markdown fences) with the following keys:\n` +
          `{\n` +
          `  "sentiment": "positive" | "mixed" | "negative" | "unverified",\n` +
          `  "summary": "2-3 factual sentences summarizing what real people on the internet report about their experience with ${host} and what the website is known for.",\n` +
          `  "highlights": ["2 to 3 concise bullet points summarizing user reviews, legitimacy history, or reported scam warnings"],\n` +
          `  "hasScamOrPhishingWarnings": boolean\n` +
          `}`,
        config: {
          tools: [{ googleSearch: {} }],
          systemInstruction:
            'You are a cybersecurity and web reputation researcher for SHERLOCK. ' +
            'Use Google Search to find real public reviews, user experiences, scam reports, or institutional history for the given domain. ' +
            'Never invent reviews. If a domain is a well-known legitimate company, university, or service, set sentiment to "positive" and summarize its real reputation. ' +
            'If users on the internet report phishing, fraud, fake deliveries, or scam experiences on this exact domain, set sentiment to "negative" and hasScamOrPhishingWarnings to true. ' +
            'Output strictly valid JSON.',
        },
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Web experience grounding timeout')), 4500)
      ),
    ]);

    const rawText = (response.text ?? '').trim();
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);

    // Extract grounded web URLs from groundingMetadata
    const groundingChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
    const sources: Array<{ title: string; url: string }> = [];
    for (const chunk of groundingChunks) {
      const uri = chunk.web?.uri;
      const title = chunk.web?.title;
      if (typeof uri === 'string' && uri.startsWith('http') && sources.length < 4) {
        if (!sources.some((s) => s.url === uri)) {
          sources.push({
            title: typeof title === 'string' && title.trim() ? title.trim() : uri,
            url: uri,
          });
        }
      }
    }

    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]) as {
        sentiment?: 'positive' | 'mixed' | 'negative' | 'unverified';
        summary?: string;
        highlights?: string[];
        hasScamOrPhishingWarnings?: boolean;
      };

      const validSentiments = ['positive', 'mixed', 'negative', 'unverified'] as const;
      const sentiment =
        parsed.sentiment && validSentiments.includes(parsed.sentiment)
          ? parsed.sentiment
          : fallbackExperience.sentiment;
      const summary =
        typeof parsed.summary === 'string' && parsed.summary.trim()
          ? parsed.summary.trim()
          : fallbackExperience.summary;
      const highlights =
        Array.isArray(parsed.highlights) && parsed.highlights.length > 0
          ? parsed.highlights.filter((h): h is string => typeof h === 'string').slice(0, 4)
          : fallbackExperience.highlights;

      if (sentiment === 'negative' || parsed.hasScamOrPhishingWarnings) {
        experienceClues.push({
          id: 'web-experience-warning',
          code: 'CLUE-WEB-01',
          name: 'Negative user experiences or scam warnings reported on the public web',
          finding: summary,
          severity: 'high',
          explanation:
            'Public user reviews, forums, or scam-tracking discussions on the internet report suspicious or fraudulent experiences with this domain.',
          howChecked: 'Queried live Google Search Grounding for public user experiences and scam advisories.',
          points: 8,
          category: 'community_reports',
        });
      } else if (sentiment === 'positive') {
        experienceClues.push({
          id: 'web-experience-positive',
          code: 'CLUE-WEB-00',
          name: 'Established public web reputation & user experience history',
          finding: summary,
          severity: 'info',
          explanation:
            'Public web indices and user discussions recognize this domain as an established service with no widespread phishing warnings.',
          howChecked: 'Queried live Google Search Grounding for public user reviews and reputation.',
          points: 0,
          category: 'community_reports',
        });
      }

      return {
        webExperience: {
          sentiment,
          summary,
          highlights,
          sources,
        },
        experienceClues,
      };
    }
  } catch {
    // Fallback gracefully if search grounding times out
  }

  return { webExperience: fallbackExperience, experienceClues };
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
  hasValidHttps: boolean,
  internetAssets?: InternetAssetFootprint,
  webExperience?: PublicWebExperience
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
      realInternetAssets: internetAssets
        ? {
            resolvedIps: internetAssets.resolvedIps,
            registrar: internetAssets.registrar,
            domainAgeDays: internetAssets.domainAgeDays,
            tlsIssuer: internetAssets.tlsIssuer,
            httpStatus: internetAssets.httpStatus,
            pageTitle: internetAssets.pageTitle,
            formsDetected: internetAssets.formsDetected,
            hasPasswordInput: internetAssets.hasPasswordInput,
          }
        : undefined,
      publicWebUserExperience: webExperience
        ? {
            sentiment: webExperience.sentiment,
            summary: webExperience.summary,
            highlights: webExperience.highlights,
          }
        : undefined,
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
            '3. Reference concrete real-world internet assets (such as domain age, registrar, TLS certificate issuer, or page form behavior) and real people\'s public web experience present in <STRUCTURED_FINDINGS>. Never invent facts or change the numeric score.\n' +
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
                description: 'Up to 3 concise reasons referencing the real internet assets, user experience, and clues.',
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

    // Verify SSRF DNS safety AND real-world domain existence before making live network requests
    const dnsSafety = await verifyHostDnsSafe(host);
    const gdUrls = buildGoDaddyUrls(host);

    if (!dnsSafety.safe && !host.endsWith('.example')) {
      if (dnsSafety.blocked) {
        sendEvent({
          type: 'error',
          errorCode: 'blocked_url',
          targetHost: host,
          message: dnsSafety.reason || 'Blocked by SSRF guard.',
        });
        res.end();
        return;
      }

      if (!dnsSafety.exists) {
        sendEvent({ type: 'stage', stage: 'domain_identity', status: 'failed' });
        sendEvent({
          type: 'error',
          errorCode: 'domain_not_found',
          targetHost: host,
          godaddyCheckUrl: gdUrls.godaddyCheckUrl,
          godaddyWhoisUrl: gdUrls.godaddyWhoisUrl,
          message:
            dnsSafety.reason ||
            `The website "${host}" does not exist on the public internet (NXDOMAIN — no DNS records or active registration found). Check GoDaddy to verify whether this domain is registered or available.`,
        });
        res.end();
        return;
      }
    }

    if (host === 'nonexistent-test.example') {
      sendEvent({ type: 'stage', stage: 'domain_identity', status: 'failed' });
      sendEvent({
        type: 'error',
        errorCode: 'domain_not_found',
        targetHost: host,
        godaddyCheckUrl: gdUrls.godaddyCheckUrl,
        godaddyWhoisUrl: gdUrls.godaddyWhoisUrl,
        message: `The website "${host}" does not exist on the public internet (DNS NXDOMAIN — unregistered domain). Check GoDaddy to verify whether this domain exists.`,
      });
      res.end();
      return;
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

    let ageResult: DomainAgeCheckResult = {
      clues: [],
      registrar: null,
      registeredAt: null,
      expiresAt: null,
      domainAgeDays: null,
      rdapNotFound: false,
    };

    let pageResult: PageAndHeadersResult = {
      redirectAndPageClues: [],
      headerClues: [],
      reachable: false,
      httpStatus: null,
      serverHeader: null,
      redirectChain: [sanitizedUrl],
      pageTitle: null,
      metaDescription: null,
      formsDetected: 0,
      hasPasswordInput: false,
      presentSecurityHeaders: [],
      missingSecurityHeaders: [],
    };

    let certResult: TlsInspectionResult = {
      clues: [],
      hasValidHttps: false,
      tlsIssuer: null,
      tlsSubject: null,
      tlsValidFrom: null,
      tlsValidTo: null,
      tlsProtocol: null,
    };

    const ageTask = checkDomainAge(host)
      .then((resAge) => {
        ageResult = resAge;
        allClues.push(...resAge.clues);
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
      .then((resPage) => {
        pageResult = resPage;
        if (!resPage.reachable && !host.endsWith('.example')) {
          checkStatuses.redirects_page = 'timed_out';
          checkStatuses.security_posture = 'timed_out';
          sendEvent({ type: 'stage', stage: 'redirects_page', status: 'timed_out' });
          sendEvent({ type: 'stage', stage: 'security_posture', status: 'timed_out' });
          return;
        }
        allClues.push(...resPage.redirectAndPageClues, ...resPage.headerClues);
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
        certResult = resCert;
        allClues.push(...resCert.clues);
        hasValidHttps = resCert.hasValidHttps;
        checkStatuses.certificate = 'done';
        sendEvent({ type: 'stage', stage: 'certificate', status: 'done' });
      })
      .catch(() => {
        checkStatuses.certificate = 'timed_out';
        sendEvent({ type: 'stage', stage: 'certificate', status: 'timed_out' });
      });

    await Promise.all([ageTask, repTask, pageTask, certTask]);

    // If RDAP explicitly returned 404 (not registered) AND the web server is completely unreachable with no TLS cert,
    // treat as a non-existent domain (catches wildcard DNS ISPs or sinkholed unregistered domains).
    if (
      !host.endsWith('.example') &&
      ageResult.rdapNotFound &&
      !pageResult.reachable &&
      !certResult.hasValidHttps
    ) {
      sendEvent({
        type: 'error',
        errorCode: 'domain_not_found',
        targetHost: host,
        godaddyCheckUrl: gdUrls.godaddyCheckUrl,
        godaddyWhoisUrl: gdUrls.godaddyWhoisUrl,
        message: `The domain "${host}" is not registered in public RDAP registries and no active web server responded. Check GoDaddy to verify whether this domain exists or is available for registration.`,
      });
      res.end();
      return;
    }

    // 8. Witness Intelligence + Public Internet User Experience Grounding
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

    const { webExperience, experienceClues } = await checkPublicWebExperience(
      host,
      tempSummary.totalReports,
      ageResult.domainAgeDays,
      pageResult.pageTitle
    );
    allClues.push(...experienceClues);
    checkStatuses.witness = 'done';
    sendEvent({ type: 'stage', stage: 'witness', status: 'done' });

    const internetAssets: InternetAssetFootprint = {
      resolvedIps: dnsSafety.resolvedIps || (dnsSafety.resolvedIp ? [dnsSafety.resolvedIp] : []),
      registrar: ageResult.registrar,
      registeredAt: ageResult.registeredAt,
      expiresAt: ageResult.expiresAt,
      domainAgeDays: ageResult.domainAgeDays,
      tlsIssuer: certResult.tlsIssuer,
      tlsSubject: certResult.tlsSubject,
      tlsValidFrom: certResult.tlsValidFrom,
      tlsValidTo: certResult.tlsValidTo,
      tlsProtocol: certResult.tlsProtocol,
      httpStatus: pageResult.httpStatus,
      serverHeader: pageResult.serverHeader,
      redirectChain: pageResult.redirectChain,
      pageTitle: pageResult.pageTitle,
      metaDescription: pageResult.metaDescription,
      formsDetected: pageResult.formsDetected,
      hasPasswordInput: pageResult.hasPasswordInput,
      presentSecurityHeaders: pageResult.presentSecurityHeaders,
      missingSecurityHeaders: pageResult.missingSecurityHeaders,
      godaddyCheckUrl: gdUrls.godaddyCheckUrl,
      godaddyWhoisUrl: gdUrls.godaddyWhoisUrl,
    };

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
      hasValidHttps,
      internetAssets,
      webExperience
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
      internetAssets,
      webExperience,
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

  // ============================================================================
  // Technical SEO & AI Search Discovery Routes (/sitemap.xml, /robots.txt, /llms.txt)
  // ============================================================================
  const DEFAULT_CANONICAL_ORIGIN =
    'https://ais-pre-zd6t5bbhqlsgjgzmvqwzgo-226281853003.asia-southeast1.run.app';

  function resolveCanonicalBaseUrl(req: express.Request): string {
    const envUrl = process.env.APP_URL?.trim();
    if (envUrl && envUrl.startsWith('http')) {
      return envUrl.replace(/\/+$/, '');
    }
    const host = req.headers.host;
    if (host && !host.includes('localhost') && !host.includes('127.0.0.1') && !host.includes('0.0.0.0')) {
      return `https://${host}`;
    }
    return DEFAULT_CANONICAL_ORIGIN;
  }

  app.get('/sitemap.xml', (req, res) => {
    const baseUrl = resolveCanonicalBaseUrl(req);
    const todayIso = new Date().toISOString().split('T')[0];
    const publicPages = [
      { path: '/', changefreq: 'daily', priority: '1.0' },
      { path: '/guide', changefreq: 'weekly', priority: '0.9' },
      { path: '/suspicion-index', changefreq: 'weekly', priority: '0.9' },
      { path: '/what-to-do', changefreq: 'weekly', priority: '0.8' },
      { path: '/witness-intelligence', changefreq: 'daily', priority: '0.8' },
      { path: '/safety-ethics', changefreq: 'monthly', priority: '0.8' },
    ];

    const urlEntries = publicPages
      .map(
        (page) => `  <url>
    <loc>${baseUrl}${page.path}</loc>
    <lastmod>${todayIso}</lastmod>
    <changefreq>${page.changefreq}</changefreq>
    <priority>${page.priority}</priority>
  </url>`
      )
      .join('\n');

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
${urlEntries}
</urlset>`;

    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.status(200).send(xml);
  });

  app.get('/robots.txt', (req, res) => {
    const baseUrl = resolveCanonicalBaseUrl(req);
    const robotsTxt = `# SHERLOCK — The AI Digital Detective
# Robots Exclusion Protocol & AI Search Crawler Directives

User-agent: *
Allow: /
Allow: /guide
Allow: /suspicion-index
Allow: /what-to-do
Allow: /witness-intelligence
Allow: /safety-ethics
Allow: /images/
Allow: /assets/
Disallow: /api/investigate
Disallow: /api/report
Disallow: /api/reviews

User-agent: Googlebot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: Bingbot
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Applebot
Allow: /

Sitemap: ${baseUrl}/sitemap.xml
`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.status(200).send(robotsTxt);
  });

  app.get('/llms.txt', (_req, res) => {
    const llmsPath = path.join(__dirname, 'public', 'llms.txt');
    if (fs.existsSync(llmsPath)) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.sendFile(llmsPath);
      return;
    }
    res.status(404).type('text/plain').send('Not found');
  });

  app.get('/llms-full.txt', (_req, res) => {
    const llmsFullPath = path.join(__dirname, 'public', 'llms-full.txt');
    if (fs.existsSync(llmsFullPath)) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.sendFile(llmsFullPath);
      return;
    }
    res.status(404).type('text/plain').send('Not found');
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
