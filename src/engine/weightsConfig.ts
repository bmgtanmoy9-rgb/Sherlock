import type { CheckStageId, ClueCategory, SuspicionLevel, WitnessCategory } from '../types/sherlock.ts';

export interface CategoryWeightDefinition {
  category: Exclude<ClueCategory, 'reputation_override'>;
  label: string;
  maxPoints: number;
  examples: string;
}

/**
 * Starting weights for the Suspicion Index.
 * Maximums add up to more than 100 on purpose (118 total); the final index is clamped to 100.
 */
export const CATEGORY_WEIGHTS: CategoryWeightDefinition[] = [
  {
    category: 'impersonation',
    label: 'Impersonation',
    maxPoints: 30,
    examples: 'Close lookalike: up to 30. Brand + keyword: up to 20',
  },
  {
    category: 'page_behavior',
    label: 'Page behavior',
    maxPoints: 25,
    examples: 'Credential form on page whose brand does not match domain: up to 25. Form posts to different domain: +10',
  },
  {
    category: 'domain_age',
    label: 'Domain age',
    maxPoints: 20,
    examples: '<7 days: 20. <30 days: 14. <90 days: 7. Unknown: 3',
  },
  {
    category: 'url_structure',
    label: 'URL structure',
    maxPoints: 15,
    examples: 'IP host, many subdomains, punycode, risky TLD, suspicious keywords',
  },
  {
    category: 'redirects',
    label: 'Redirects',
    maxPoints: 10,
    examples: 'Long or cross-domain chain, URL shortener',
  },
  {
    category: 'community_reports',
    label: 'Community reports',
    maxPoints: 10,
    examples: 'Scales with count; counted fully only if another category also fires',
  },
  {
    category: 'certificate',
    label: 'Certificate',
    maxPoints: 5,
    examples: 'Domain mismatch or issued within the last few days',
  },
  {
    category: 'security_headers',
    label: 'Security headers',
    maxPoints: 3,
    examples: 'Several basics missing',
  },
];

export const CHECK_STAGES: { id: CheckStageId; label: string; source: string; role: string }[] = [
  {
    id: 'domain_identity',
    label: 'Examining domain identity…',
    source: 'URL parser & syntax rules',
    role: 'Medium (up to 15 pts)',
  },
  {
    id: 'impersonation',
    label: 'Checking for impersonation…',
    source: 'Curated brand list & homoglyph confusables map',
    role: 'High (up to 30 pts)',
  },
  {
    id: 'domain_age',
    label: 'Looking up domain age…',
    source: 'RDAP registry registration records',
    role: 'High (up to 20 pts)',
  },
  {
    id: 'reputation',
    label: 'Consulting reputation feeds…',
    source: 'Google Safe Browsing & open threat feeds (OpenPhish, URLhaus, PhishTank)',
    role: 'Override (sets index ≥ 90)',
  },
  {
    id: 'redirects_page',
    label: 'Following redirects and inspecting the page…',
    source: 'Safe limited HTTP fetch & static HTML parser (never executed)',
    role: 'High (Redirects up to 10 pts, Page up to 25 pts)',
  },
  {
    id: 'certificate',
    label: 'Inspecting certificate…',
    source: 'Node.js TLS handshake & X.509 peer certificate',
    role: 'Low, mostly informational (up to 5 pts)',
  },
  {
    id: 'security_posture',
    label: 'Reviewing security posture…',
    source: 'HTTP response headers (HSTS, CSP, X-Frame-Options, Referrer-Policy)',
    role: 'Very low, capped (up to 3 pts)',
  },
  {
    id: 'witness',
    label: 'Gathering witness intelligence…',
    source: 'Corroborated community witness reports',
    role: 'Capped (up to 10 pts, requires corroboration)',
  },
];

export interface LevelMeta {
  level: SuspicionLevel;
  range: string;
  badgeText: string;
  shortLabel: string;
  iconSymbol: string;
  colorHex: string;
  description: string;
}

export const LEVEL_METADATA: Record<SuspicionLevel, LevelMeta> = {
  low: {
    level: 'low',
    range: '0–24',
    badgeText: 'Low suspicion',
    shortLabel: 'No strong warning signs found',
    iconSymbol: '🟢',
    colorHex: '#5E8B5A',
    description: 'No strong warning signs found. This is not a guarantee of safety.',
  },
  caution: {
    level: 'caution',
    range: '25–49',
    badgeText: 'Caution advised',
    shortLabel: 'Caution advised',
    iconSymbol: '🟡',
    colorHex: '#D9A93A',
    description: 'Verify through an official channel before sharing information.',
  },
  high_risk: {
    level: 'high_risk',
    range: '50–74',
    badgeText: 'High risk',
    shortLabel: 'High risk',
    iconSymbol: '🟠',
    colorHex: '#D9702E',
    description: 'Do not enter passwords, payment details or OTPs.',
  },
  highly_suspicious: {
    level: 'highly_suspicious',
    range: '75–100',
    badgeText: 'Highly suspicious',
    shortLabel: 'Highly suspicious',
    iconSymbol: '🔴',
    colorHex: '#B3342F',
    description: 'Strong evidence of phishing or impersonation; do not interact.',
  },
  inconclusive: {
    level: 'inconclusive',
    range: '—',
    badgeText: 'Inconclusive',
    shortLabel: 'Inconclusive',
    iconSymbol: '⚪',
    colorHex: '#8A7F72',
    description: 'Too few checks completed to form a reliable index. Treat with caution and verify independently.',
  },
};

export const WITNESS_CATEGORY_LABELS: Record<WitnessCategory, string> = {
  phishing: 'Phishing & credential harvesting',
  financial_fraud: 'Financial or banking fraud',
  fake_recruitment: 'Fake recruitment or scholarship',
  shopping_scam: 'Fake shop or parcel fee scam',
  brand_impersonation: 'Brand or institution lookalike',
  other: 'Other suspicious activity',
};

/**
 * Local brand list (75 brands relevant to students, job seekers, banks, parcels, payments, and everyday tools).
 */
export interface BrandTarget {
  name: string;
  token: string;
  officialDomains: string[];
  sector: 'payment' | 'bank' | 'parcel' | 'jobs' | 'education' | 'tech' | 'government' | 'retail';
}

export const PROTECTED_BRANDS: BrandTarget[] = [
  // Payments & Crypto
  { name: 'PayPal', token: 'paypal', officialDomains: ['paypal.com', 'paypal.me'], sector: 'payment' },
  { name: 'Stripe', token: 'stripe', officialDomains: ['stripe.com'], sector: 'payment' },
  { name: 'Wise', token: 'wise', officialDomains: ['wise.com'], sector: 'payment' },
  { name: 'Revolut', token: 'revolut', officialDomains: ['revolut.com'], sector: 'payment' },
  { name: 'Venmo', token: 'venmo', officialDomains: ['venmo.com'], sector: 'payment' },
  { name: 'Cash App', token: 'cashapp', officialDomains: ['cash.app'], sector: 'payment' },
  { name: 'Zelle', token: 'zelle', officialDomains: ['zellepay.com'], sector: 'payment' },
  { name: 'Coinbase', token: 'coinbase', officialDomains: ['coinbase.com'], sector: 'payment' },
  { name: 'Binance', token: 'binance', officialDomains: ['binance.com'], sector: 'payment' },
  { name: 'Kraken', token: 'kraken', officialDomains: ['kraken.com'], sector: 'payment' },

  // Banks
  { name: 'Chase', token: 'chase', officialDomains: ['chase.com', 'jpmorganchase.com'], sector: 'bank' },
  { name: 'HSBC', token: 'hsbc', officialDomains: ['hsbc.com', 'hsbc.co.uk'], sector: 'bank' },
  { name: 'Barclays', token: 'barclays', officialDomains: ['barclays.co.uk', 'barclays.com'], sector: 'bank' },
  { name: 'Wells Fargo', token: 'wellsfargo', officialDomains: ['wellsfargo.com'], sector: 'bank' },
  { name: 'Citibank', token: 'citibank', officialDomains: ['citi.com', 'citibank.com'], sector: 'bank' },
  { name: 'Bank of America', token: 'bankofamerica', officialDomains: ['bankofamerica.com'], sector: 'bank' },
  { name: 'Capital One', token: 'capitalone', officialDomains: ['capitalone.com'], sector: 'bank' },
  { name: 'American Express', token: 'americanexpress', officialDomains: ['americanexpress.com', 'amex.com'], sector: 'bank' },
  { name: 'Santander', token: 'santander', officialDomains: ['santander.co.uk', 'santander.com'], sector: 'bank' },
  { name: 'Lloyds Bank', token: 'lloydsbank', officialDomains: ['lloydsbank.com'], sector: 'bank' },
  { name: 'NatWest', token: 'natwest', officialDomains: ['natwest.com'], sector: 'bank' },
  { name: 'Monzo', token: 'monzo', officialDomains: ['monzo.com'], sector: 'bank' },
  { name: 'Starling Bank', token: 'starlingbank', officialDomains: ['starlingbank.com'], sector: 'bank' },
  { name: 'DBS Bank', token: 'dbs', officialDomains: ['dbs.com', 'dbs.com.sg'], sector: 'bank' },
  { name: 'Standard Chartered', token: 'sc', officialDomains: ['sc.com'], sector: 'bank' },

  // Parcels & Logistics
  { name: 'DHL', token: 'dhl', officialDomains: ['dhl.com', 'dhl.de', 'dhl.co.uk'], sector: 'parcel' },
  { name: 'FedEx', token: 'fedex', officialDomains: ['fedex.com'], sector: 'parcel' },
  { name: 'UPS', token: 'ups', officialDomains: ['ups.com'], sector: 'parcel' },
  { name: 'USPS', token: 'usps', officialDomains: ['usps.com'], sector: 'parcel' },
  { name: 'Royal Mail', token: 'royalmail', officialDomains: ['royalmail.com'], sector: 'parcel' },
  { name: 'Evri', token: 'evri', officialDomains: ['evri.com'], sector: 'parcel' },
  { name: 'DPD', token: 'dpd', officialDomains: ['dpd.co.uk', 'dpd.com'], sector: 'parcel' },
  { name: 'Australia Post', token: 'auspost', officialDomains: ['auspost.com.au'], sector: 'parcel' },
  { name: 'Canada Post', token: 'canadapost', officialDomains: ['canadapost-postescanada.ca'], sector: 'parcel' },
  { name: 'SingPost', token: 'singpost', officialDomains: ['singpost.com'], sector: 'parcel' },

  // Job Seekers & Recruitment
  { name: 'LinkedIn', token: 'linkedin', officialDomains: ['linkedin.com'], sector: 'jobs' },
  { name: 'Indeed', token: 'indeed', officialDomains: ['indeed.com'], sector: 'jobs' },
  { name: 'Glassdoor', token: 'glassdoor', officialDomains: ['glassdoor.com'], sector: 'jobs' },
  { name: 'Workday', token: 'workday', officialDomains: ['workday.com', 'myworkdayjobs.com'], sector: 'jobs' },
  { name: 'Greenhouse', token: 'greenhouse', officialDomains: ['greenhouse.io'], sector: 'jobs' },
  { name: 'Lever', token: 'lever', officialDomains: ['lever.co'], sector: 'jobs' },
  { name: 'Monster', token: 'monster', officialDomains: ['monster.com'], sector: 'jobs' },
  { name: 'Upwork', token: 'upwork', officialDomains: ['upwork.com'], sector: 'jobs' },
  { name: 'Fiverr', token: 'fiverr', officialDomains: ['fiverr.com'], sector: 'jobs' },

  // Students, Scholarships & Education
  { name: 'FAFSA', token: 'fafsa', officialDomains: ['studentaid.gov'], sector: 'education' },
  { name: 'Chevening', token: 'chevening', officialDomains: ['chevening.org'], sector: 'education' },
  { name: 'Fulbright', token: 'fulbright', officialDomains: ['fulbrightonline.org'], sector: 'education' },
  { name: 'UCAS', token: 'ucas', officialDomains: ['ucas.com'], sector: 'education' },
  { name: 'Canvas LMS', token: 'instructure', officialDomains: ['instructure.com'], sector: 'education' },
  { name: 'Blackboard', token: 'blackboard', officialDomains: ['blackboard.com'], sector: 'education' },
  { name: 'Coursera', token: 'coursera', officialDomains: ['coursera.org'], sector: 'education' },
  { name: 'edX', token: 'edx', officialDomains: ['edx.org'], sector: 'education' },

  // Tech & Cloud Accounts
  { name: 'Microsoft', token: 'microsoft', officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'], sector: 'tech' },
  { name: 'Google', token: 'google', officialDomains: ['google.com', 'gmail.com', 'accounts.google.com'], sector: 'tech' },
  { name: 'Apple', token: 'apple', officialDomains: ['apple.com', 'icloud.com'], sector: 'tech' },
  { name: 'GitHub', token: 'github', officialDomains: ['github.com'], sector: 'tech' },
  { name: 'GitLab', token: 'gitlab', officialDomains: ['gitlab.com'], sector: 'tech' },
  { name: 'Dropbox', token: 'dropbox', officialDomains: ['dropbox.com'], sector: 'tech' },
  { name: 'DocuSign', token: 'docusign', officialDomains: ['docusign.com', 'docusign.net'], sector: 'tech' },
  { name: 'Adobe', token: 'adobe', officialDomains: ['adobe.com'], sector: 'tech' },
  { name: 'Zoom', token: 'zoom', officialDomains: ['zoom.us', 'zoom.com'], sector: 'tech' },
  { name: 'Slack', token: 'slack', officialDomains: ['slack.com'], sector: 'tech' },
  { name: 'Netflix', token: 'netflix', officialDomains: ['netflix.com'], sector: 'tech' },
  { name: 'Spotify', token: 'spotify', officialDomains: ['spotify.com'], sector: 'tech' },
  { name: 'Steam', token: 'steampowered', officialDomains: ['steampowered.com', 'steamcommunity.com'], sector: 'tech' },
  { name: 'Discord', token: 'discord', officialDomains: ['discord.com', 'discordapp.com'], sector: 'tech' },
  { name: 'WhatsApp', token: 'whatsapp', officialDomains: ['whatsapp.com'], sector: 'tech' },
  { name: 'Telegram', token: 'telegram', officialDomains: ['telegram.org', 't.me'], sector: 'tech' },
  { name: 'Instagram', token: 'instagram', officialDomains: ['instagram.com'], sector: 'tech' },

  // Retail & E-Commerce
  { name: 'Amazon', token: 'amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de'], sector: 'retail' },
  { name: 'Shopify', token: 'shopify', officialDomains: ['shopify.com', 'myshopify.com'], sector: 'retail' },
  { name: 'eBay', token: 'ebay', officialDomains: ['ebay.com', 'ebay.co.uk'], sector: 'retail' },
  { name: 'Walmart', token: 'walmart', officialDomains: ['walmart.com'], sector: 'retail' },
  { name: 'Booking.com', token: 'booking', officialDomains: ['booking.com'], sector: 'retail' },
  { name: 'Airbnb', token: 'airbnb', officialDomains: ['airbnb.com'], sector: 'retail' },

  // Government & Tax
  { name: 'GOV.UK', token: 'govuk', officialDomains: ['gov.uk'], sector: 'government' },
  { name: 'IRS', token: 'irs', officialDomains: ['irs.gov'], sector: 'government' },
];

export const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verification',
  'secure',
  'security',
  'account',
  'update',
  'wallet',
  'reward',
  'claim',
  'bonus',
  'grant',
  'scholarship',
  'redelivery',
  'parcel',
  'customs',
  'fee',
  'billing',
  'invoice',
  'suspend',
  'unlock',
  'confirm',
  'auth',
  'sso',
  'portal',
  'helpdesk',
];

export const RISKY_TLDS = [
  '.xyz',
  '.top',
  '.click',
  '.loan',
  '.work',
  '.gq',
  '.tk',
  '.ml',
  '.cf',
  '.ga',
  '.buzz',
  '.icu',
  '.monster',
  '.rest',
  '.fit',
  '.zip',
  '.mov',
  '.support',
];

export const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'rb.gy',
];

/**
 * Confusables map for de-obfuscating homoglyphs (e.g., paypa1 -> paypal, rnicrosoft -> microsoft).
 */
export const CONFUSABLE_CHAR_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  'а': 'a', // Cyrillic
  'е': 'e',
  'о': 'o',
  'р': 'p',
  'с': 'c',
  'у': 'y',
  'х': 'x',
  'і': 'i',
};
