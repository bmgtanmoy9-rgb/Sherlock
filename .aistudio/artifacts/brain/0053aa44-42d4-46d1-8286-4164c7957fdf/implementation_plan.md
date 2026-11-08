# Complete 2026 Website SEO & Search Engine Ranking Plan — SHERLOCK

## 1. Executive Summary & SEO Strategy

We will execute a comprehensive Search Engine Optimization (SEO) upgrade across **SHERLOCK (221B Digital Link Forensics)** aligned with the **Complete Website SEO Guide (2026)**. The goal is to maximize organic search visibility, crawlability, semantic authority, and rich-result eligibility on Google and modern AI search engines while preserving the Victorian 221B detective aesthetic and strict evidence-based safety framing.

### Primary & Secondary Keyword Strategy
- **Primary Keyword Cluster**: `phishing link checker`, `website safety scanner`, `scam URL detector`
- **High-Intent Secondary Keywords**: `suspicious link inspector`, `check if a website is legit`, `QR code phishing scanner`, `domain age and SSL checker`, `WHOIS RDAP lookup tool`, `fake login page detector`
- **Search Intent Alignment**: Informational ("how to spot a phishing link", "what is lookalike domain spoofing") + Transactional/Utility ("scan a suspicious URL or QR code immediately without opening it").

---

## 2. SEO Architecture & Search Crawler Pipeline

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     SEARCH ENGINES & SOCIAL CRAWLERS                         │
│        (Googlebot, Google Search Console, Bingbot, X/Twitter, OpenGraph)     │
└───────────────┬──────────────────────────────────────────────┬───────────────┘
                │                                              │
                ▼                                              ▼
┌─────────────────────────────────────────┐  ┌─────────────────────────────────┐
│     SERVER-SIDE TECHNICAL SEO           │  │     DOCUMENT HEAD & SCHEMA      │
│  • GET /robots.txt                      │  │  • Optimized <title> & <meta>   │
│    - Crawl rules & /api/ protections    │  │  • Canonical URL resolution     │
│    - Dynamic Sitemap URL pointer        │  │  • OpenGraph & Twitter Cards    │
│  • GET /sitemap.xml                     │  │  • Google Search Console tag    │
│    - Dynamic XML <urlset> generation    │  │  • Schema.org JSON-LD @graph:   │
│    - All 7 Study Sections + Case URLs   │  │    - WebApplication             │
│  • GET /api/seo-audit                   │  │    - Organization               │
│    - Live 2026 SEO Checklist & Score    │  │    - HowTo (Link Inspection)    │
└───────────────┬─────────────────────────┘  │    - FAQPage (High-Intent Q&A)  │
                │                            └─────────────────┬───────────────┘
                ▼                                              │
┌──────────────────────────────────────────────────────────────┴───────────────┐
│                   CLIENT-SIDE SEMANTIC & CONTENT SEO ENGINE                  │
│  • Dynamic Per-Section Metadata Synchronizer (#home, #guide, #index, etc.)   │
│    - Updates document.title, meta description, canonical, & OG tags live     │
│    - Updates title & meta dynamically when inspecting a specific domain      │
│  • Semantic HTML5 & Accessibility Hierarchy                                  │
│    - Strict H1 → H2 → H3 hierarchy, <main>, <article>, <section>, <nav>      │
│    - Image SEO: descriptive alt text, explicit dimensions, lazy decoding     │
│  • Internal Cross-Linking & High-Intent Forensic FAQ + SEO Audit Ledger      │
│    - Contextual anchor links connecting all 7 investigative rooms            │
│    - Interactive Search Console Readiness & 2026 SEO Score Dossier           │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Implementation Pillars

### Pillar 1: Technical SEO & Google Search Console Readiness
- **Dynamic `/robots.txt` Endpoint**:
  - Serves `text/plain` instructions welcoming all search engine crawlers (`User-agent: *`, `Allow: /`) while disallowing raw private mutation endpoints (`Disallow: /api/report`) and dynamically advertising `Sitemap: <origin>/sitemap.xml`.
- **Dynamic `/sitemap.xml` Endpoint**:
  - Serves valid `application/xml` with `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`.
  - Automatically indexes the root application (`/`), all 7 investigative rooms (`/#home`, `/#guide`, `/#index`, `/#actions`, `/#witness`, `/#safety`, `/#proof`), and active public shared case reports (`/?case=<caseId>`) with accurate `<lastmod>`, `<changefreq>`, and `<priority>` attributes.
- **Google Search Console Verification & Crawler Directives**:
  - Adds `<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />` and `<meta name="googlebot" ... />`.
  - Supports `<meta name="google-site-verification" ... />` via environment configuration (`VITE_GOOGLE_SITE_VERIFICATION`) plus an interactive Search Console Setup & Verification helper inside the Study Ledger so site owners can copy their verification tag or inspect live `/sitemap.xml` and `/robots.txt` endpoints directly.
- **Live Technical SEO Audit Endpoint (`GET /api/seo-audit`)**:
  - Evaluates the live application against the 2026 SEO Checklist (Sitemap, Robots.txt, HTTPS/HSTS, Metadata, Schema.org JSON-LD, Semantic Headings, Internal Linking, Image Optimization, Mobile Responsiveness, and Fast Load headers) and returns a structured audit summary, keyword opportunities, and overall SEO score.

### Pillar 2: Document Head, OpenGraph, Twitter Cards & Schema.org JSON-LD
- **Title & Meta Description Synchronization**:
  - Primary Title: `SHERLOCK — Phishing Link Checker, Website Safety Scanner & Scam URL Detector`
  - Primary Description (154 chars): `Inspect suspicious URLs, QR codes, DNS, WHOIS domain age, SSL certificates, and community scam reports with SHERLOCK's forensic website safety scanner.`
- **Social Sharing Cards**:
  - Full OpenGraph (`og:title`, `og:description`, `og:type`, `og:url`, `og:site_name`, `og:image`, `og:image:alt`, `og:locale`) and Twitter (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`, `twitter:image:alt`) metadata.
- **Rich Schema.org Structured Data (`application/ld+json`)**:
  - Multi-entity `@graph` combining:
    1. **`WebApplication`**: Categorized as `SecurityApplication` with `featureList` covering DNS/RDAP WHOIS lookup, X.509 SSL inspection, QR code decoding, homograph detection, and Google Search-grounded scam analysis.
    2. **`Organization`**: Branding and authority signals for `SHERLOCK — 221B Digital Link Forensics`.
    3. **`HowTo`**: Step-by-step structured guide on *"How to Check if a Website or Link is a Phishing Scam Before Clicking"*.
    4. **`FAQPage`**: Rich-snippet eligible Q&A targeting high-ranking queries (*"How do I check if a link is safe without clicking it?"*, *"How does a QR code phishing scanner work?"*, *"Can a phishing website have a valid HTTPS padlock?"*, *"How do I check when a website domain was registered?"*).

### Pillar 3: Dynamic Per-Section & Per-Case SEO Synchronizer
- **View-Aware Head Updates**:
  - Navigating across the 7 rooms (`#home`, `#guide`, `#index`, `#actions`, `#witness`, `#safety`, `#proof`) or inspecting a live domain report dynamically updates `document.title`, `<meta name="description">`, `<link rel="canonical">`, `og:title`, and `og:description` to match the active section or inspected domain (`e.g., "SHERLOCK Dossier: paypaI-secure-update.com — Risk 92/100 | Website Safety Scanner"`).

### Pillar 4: Content SEO, Semantic HTML, Image SEO & Internal Linking
- **Semantic Heading & Landmark Hierarchy**:
  - Enforces a single authoritative `<h1>` per active view, structured `<h2>` and `<h3>` subheadings enriched with natural forensic and security keywords, and semantic `<main>`, `<section>`, `<article>`, `<nav>`, and `<footer>` landmarks.
- **Image & Media SEO**:
  - Adds descriptive keyword-rich `alt` attributes, explicit `width` and `height` attributes to prevent Cumulative Layout Shift (CLS), and `loading="lazy"` / `decoding="async"` on non-hero visual assets.
- **Internal Cross-Linking & High-Intent FAQ + 2026 SEO Readiness Ledger**:
  - Adds contextual internal anchor links between the Case Desk, Field Guide, Threat Index, Emergency Actions, Witness Ledger, Safety Disclaimers, and Forensic Proof sections.
  - Adds a dedicated **Frequently Asked Questions & Search Engine Verification Ledger** inside the study sections featuring the live 2026 SEO Audit Score, keyword opportunity matrix, direct links to `/sitemap.xml` and `/robots.txt`, and structured FAQ accordion/cards.
