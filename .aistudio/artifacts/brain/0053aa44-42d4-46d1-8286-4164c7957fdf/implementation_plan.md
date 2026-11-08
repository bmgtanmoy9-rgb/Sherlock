# Backend Score Tally Synchronization & Full-Spectrum Anti-Hacker Hardening

This update synchronizes the deterministic score breakdown and arithmetic tally metadata across all backend investigation and archive endpoints while hardening the server against web attacks—including SSRF DNS rebinding, injection/XSS payloads, prototype pollution, brute-force scraping, and cross-origin abuse.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and security decisions reflect your confirmed choices before implementation begins:

- **Confirmed Decision 1 — Full Score Tally Metadata in All API Responses**: Every backend case response (live investigations, cached reports, demo presets, and archived case lookups) will include structured `scoreTally` reconciliation metadata (`categoryPointsSum`, `maxPossibleSum`, `overrideAdjustment`, `clampingAdjustment`, `finalIndex`, and enriched `categoryBreakdown` rows with `rawPoints` and `clueCount`).
- **Confirmed Decision 2 — Four-Layer Backend Security Hardening**:
  1. **Strict HTTP Security Headers & CORS**: Enforces Content-Security-Policy (CSP), HTTP Strict-Transport-Security (HSTS), `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and strict origin/method validation, plus HTTP `Range` support for smooth mobile video streaming.
  2. **Enhanced SSRF & DNS Rebinding Guard**: Expands IPv4/IPv6/decimal/octal/hex literal blocking and pins resolved public DNS addresses during outbound inspection and TLS checks to prevent TOCTOU (Time-of-Check to Time-of-Use) DNS rebinding attacks.
  3. **Strict Input Sanitization & Payload Validation**: Strips prototype pollution keys (`__proto__`, `constructor`, `prototype`), null bytes, control characters, and SQL/script injection vectors across all query parameters, route parameters, headers, and JSON bodies.
  4. **Multi-Tier API Rate Limiting & Brute-Force Protection**: Enforces sliding-window rate limits per salted cryptographic client hash across `/api/investigate`, `/api/report`, `/api/reviews`, and `/api/case/:id` to stop automated flood or enumeration attacks.
- **Confirmed Decision 3 — Safe JSON Error Responses**: Whenever the backend blocks a malicious payload, disallowed origin, SSRF vector, or rate-limit violation, it immediately halts processing and returns a sanitized, non-leaking JSON error response without exposing stack traces or internal server details.

---

## 1. Overview & Core Concept

- **What It Does**:
  1. **Server-Authoritative Score Tally**: Computes and attaches complete category breakdown and tally proof metadata on the backend so any client or shared report link receives pre-verified arithmetic reconciliation.
  2. **Defense-in-Depth Server Hardening**: Protects the backend server and its outbound passive fetcher against SSRF, DNS rebinding, header/body injection, XSS, prototype pollution, and automated DoS/brute-force attacks.
- **Target Audience / Persona**: Security-conscious users and evaluators who rely on SHERLOCK to inspect untrusted URLs safely without exposing the backend infrastructure or user browsers to exploitation.
- **Key Value**: Guarantees that backend API outputs match the frontend deterministic score breakdown 1:1 while locking down every attack surface of the server.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Live & Shared Case Dossiers**: Whether a user runs a fresh investigation or opens a shared `?case=CASE-...` link, the backend automatically enriches and validates the full `categoryBreakdown` and `scoreTally` object so the **Deterministic Score Breakdown by Category** and **Forensic Score Calculation Tally** render with verified server calculations.
  2. **Defensive Interception of Malicious Requests**: If an attacker or automated script submits malformed payloads, private/encoded IP literals (e.g., hex/octal localhost, IPv6 mapped loopback, cloud metadata), or rapid-fire brute-force requests, the server intercepts the request at the middleware boundary and returns a clean, structured JSON error (`400`, `403`, or `429`).
- **Visual Identity & Theme**:
  - Preserves the Victorian Detective Study aesthetic (`#170E0B` walnut, `#5A1F26` oxblood, `#C9A04A` antique brass, `#F2E6C9` parchment) and displays blocked or rate-limited responses in the existing defensive notice cards.
- **Interactive Feedback & Motion**:
  - Instant server validation responses (`< 10ms` for blocked inputs) and seamless byte-range video streaming for mobile and desktop hero media.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Server-Side Score Tally Enrichment on Both New and Stored Cases**
  - *Chosen Approach*: Add a pure `computeScoreTally` helper in the rule engine and invoke it in all backend case-generation and retrieval routes, automatically upgrading any legacy cached or stored case records on read.
  - *Why*: Ensures 100% consistency across cached cases, demo cases, and live investigations without requiring manual database migrations.
- **Decision 2: Zero-Leakage Security Middleware Pipeline**
  - *Chosen Approach*: Implement custom zero-dependency security middleware directly in the backend request pipeline (security headers, CORS check, prototype-pollution & control-char scrubber, per-endpoint rate limiters, and global error sanitizer).
  - *Why*: Avoids external middleware version conflicts while giving full control over NDJSON streaming endpoints and Vite asset serving.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         Incoming Client / API Request                     │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    Layer 1: Security & Hardening Middleware                │
│  ├─ Defensive Headers (CSP, HSTS, X-Frame-Options, nosniff, Permissions)  │
│  ├─ Strict CORS & HTTP Method Guard + Safe JSON Error Boundary            │
│  ├─ Payload Sanitizer (Prototype Pollution, Null Bytes, XSS/Control Chars)│
│  └─ Multi-Tier Rate Limiter (Per-Endpoint Salted SHA-256 Sliding Windows) │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    Layer 2: Outbound SSRF & Network Guard                  │
│  ├─ Strict URL Parser (Blocks Hex/Octal/Decimal IPs, Bad Ports, Userinfo) │
│  ├─ DNS Resolution & IP Pinning Verifier (Blocks Rebinding & RFC1918/LL)  │
│  └─ Air-Gapped Fetcher (256KB Cap, 5-Hop Manual Redirect Re-verification) │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│             Layer 3: Deterministic Rule Engine & Tally Assembler          │
│  ├─ 8 Category Weights + Raw/Clamped Point Sums + Triggered Clue Counts   │
│  ├─ Reputation Override & 100-Point Ceiling Reconciliation (`scoreTally`) │
│  └─ Sanitized Case Archive & Salted Vote/Report Persistence               │
└───────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State**:
  - `ScoreTallySummary` interface added to `CaseReportData`:
    - `categoryPointsSum`: Sum of clamped points across the 8 forensic categories (`0–118`).
    - `rawCategoryPointsSum`: Unclamped sum of all clue points across the 8 categories.
    - `maxPossibleCategorySum`: Fixed `118` maximum category weight sum.
    - `overrideActive`: Boolean indicating whether a threat feed override (`≥ 90`) fired.
    - `overrideAdjustment`: Points added by the Reputation Override rule (`0` or `90 - categoryPointsSum`).
    - `clampingAdjustment`: Points subtracted by the 100-point ceiling (`0` or `categoryPointsSum - 100`).
    - `finalIndex`: Final Suspicion Index (`0–100` or `null` when inconclusive).
- **Interactive Component & State Mapping**:
  - **`POST /api/investigate`**: Validates input against SSRF/injection guards, streams 8 check stages, computes `categoryBreakdown` and `scoreTally`, and returns the complete `CaseReportData`.
  - **`GET /api/case/:id`**: Validates `:id` format (`^CASE-[A-Z0-9-]+$`), rate-limits enumeration attempts, upgrades stored case records with fresh `categoryBreakdown` and `scoreTally` metadata, and returns safe JSON.
  - **`POST /api/report` & `POST /api/reviews`**: Enforces strict schema validation, strips HTML/script tags and control characters, applies per-endpoint rate limits, and returns structured JSON responses.
