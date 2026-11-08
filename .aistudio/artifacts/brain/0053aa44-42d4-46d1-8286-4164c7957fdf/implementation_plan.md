# Real Internet Asset Forensics, Public Web Experience Grounding & Non-Existent Domain GoDaddy Verification

This update upgrades SHERLOCK to base every ranking, clue, and descriptive deduction on verifiable real-world internet assets (live DNS records, RDAP WHOIS registrar data, X.509 TLS certificate chains, HTTP headers, and static HTML/form metadata) combined with real people's experiences found across the public internet via Google Search Grounding. When a queried domain does not exist (`NXDOMAIN` / unregistered), SHERLOCK immediately halts the investigation, displays a dedicated **Website Does Not Exist** alert card, and provides a one-click **GoDaddy Domain Check** action so users can verify whether the domain is registered.

---

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and UX decisions incorporate your confirmed preferences from the clarification step:

- **Confirmed Decision 1 — Non-Existent Domain Detection & GoDaddy Verification**: When DNS resolution (`A`, `AAAA`, or `NS` lookup) and RDAP registry checks confirm a domain does not exist on the public internet (`ENOTFOUND` / `NXDOMAIN`), SHERLOCK immediately halts scoring rather than generating a synthetic score. It displays a dedicated **Website Does Not Exist** card with a prominent button that opens GoDaddy's Domain Search (`godaddy.com/domainsearch/find?domainToCheck=...`) and WHOIS lookup to verify registration status.
- **Confirmed Decision 2 — Real Internet Asset Profiling**: Live investigations capture and display actual network and asset telemetry—resolved IP addresses, RDAP registrar and creation/expiration timestamps, TLS certificate issuer and validity window, redirect chain hops, HTTP response headers, and parsed HTML `<title>`, meta description, and credential form behaviors.
- **Confirmed Decision 3 — Public Internet User Experience Grounding**: SHERLOCK queries live web search grounding (`gemini-3.8-flash` with `googleSearch`) alongside community Witness Intelligence to gather real people's experiences, scam warnings, and public review sentiment from across the internet, integrating those findings into both the descriptive Case Report and the community corroboration signals.

---

## 1. Overview & Core Concept

- **What It Does**:
  1. **Strict Existence Gate (`NXDOMAIN` Check)**: Distinguishes between domains that do not exist at all (`domain_not_found`) and existing domains whose web servers are temporarily down (`unreachable`). Non-existent domains trigger an immediate error card with a direct GoDaddy verification button.
  2. **Live Internet Asset Inspection**: Collects real technical asset data from DNS, RDAP/WHOIS, TLS port 443 handshakes, and HTTP/HTML responses, using those concrete signals to drive the deterministic Suspicion Index and displaying them in an inspectable **Live Internet Asset Footprint** ledger.
  3. **Internet-Wide User Experience & Review Intelligence**: Uses server-side Google Search Grounding (`googleSearch`) to synthesize real users' experiences, public review sentiment, and scam reports found on the internet for the target domain, complete with clickable web source citations.
- **Target Audience / Persona**: Everyday users, students, and security-conscious investigators verifying unfamiliar links who need factual, evidence-backed rankings grounded in real internet infrastructure and real human experiences.
- **Key Value**: Eliminates false scores on non-existent domains, provides instant GoDaddy domain existence verification, and enriches every valid domain's Case Report with real technical asset telemetry and internet-wide user experience evidence.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Investigating a Non-Existent Domain (e.g., an unregistered or mistyped domain)**:
     - The user submits a link in the Hero Investigation Desk.
     - SHERLOCK performs a live DNS & registry existence check. Upon detecting `ENOTFOUND` / `NXDOMAIN`, the progress stream stops immediately and renders the **Website Does Not Exist** alert card.
     - The card clearly states that the domain is not registered or has no DNS records on the internet, and provides a primary **"Verify Domain on GoDaddy"** button (`target="_blank" rel="noopener noreferrer"`) plus a secondary **"GoDaddy WHOIS Lookup"** button.
  2. **Investigating a Live Internet Website**:
     - All 8 forensic check stages run against live internet infrastructure (DNS, Impersonation rules, RDAP WHOIS, Threat Feeds, HTTP Redirects & HTML DOM, TLS X.509 Certificate, Security Headers, and Public Web Experience + Witness Intelligence).
     - The resulting Case Dossier displays:
       - **Suspicion Index & Deterministic Category Breakdown**: Driven by real findings and reconciled with the Forensic Score Calculation Tally.
       - **Sherlock's Deduction**: Plain-English synthesis incorporating both technical asset clues and real-world user experiences found on the internet.
       - **Live Internet Asset Footprint Panel**: Clean tabular ledger showing Resolved IPs, Registrar & Registration Date, TLS Issuer & Validity Dates, HTTP Status & Redirect Hops, and Page Title / Form Analysis.
       - **Public Internet Experience & Web Reviews Panel**: Summarizes how people across the internet describe their experience with the domain (e.g., established institution, widespread phishing complaints, delivery scam reports, or mixed consumer reviews), accompanied by verified source links and local Witness Intelligence reports.
- **Visual Identity & Theme**:
  - Preserves the **221B Digital Detective Study** palette (`--walnut-900: #170E0B`, `--walnut-800: #2A1A14`, `--parchment-100: #F2E6C9`, `--brass-500: #C9A04A`, `--oxblood-700: #5A1F26`).
  - Uses `Fraunces` for editorial headers, `Plus Jakarta Sans` for readable prose, and `JetBrains Mono` (`tabular-nums`) for DNS IPs, RDAP timestamps, certificate serial/validity dates, and score tallies.
  - Adheres to single-elevation card depth, clean unboxed metadata with typographic separators (`·`), and WCAG AA contrast across both Dark and Light study themes.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Distinguishing Non-Existent Domains (`domain_not_found`) from Offline Servers (`unreachable`)**
  - *Chosen Approach*: Inspect Node.js DNS error codes (`ENOTFOUND`, `ENODATA`, `EBADNAME`) and verify against RDAP (`404 Not Found`) before running downstream checks. If the domain has no DNS records and no RDAP registration, classify it as `domain_not_found` and surface the GoDaddy verification action.
  - *Why*: Users need to know immediately if a website does not exist at all versus if an existing domain's web server refused a connection. Redirecting/linking to GoDaddy gives users an authoritative registrar check in one click.
- **Decision 2: Server-Side Google Search Grounding for Real User Experience Intelligence**
  - *Chosen Approach*: Query `gemini-3.8-flash` on the backend with `tools: [{ googleSearch: {} }]` during live investigations to gather real public reviews, scam reports, and user experiences across the web, while keeping a strict 4.5-second timeout and deterministic fallback if offline.
  - *Why*: Local community reports in a single app instance only cover sites reported inside that instance; combining local Witness Intelligence with Google Search Grounding surfaces real-world human experiences across the entire internet.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     CLIENT: INVESTIGATION DESK & DOSSIER                     │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ URL Input / QR Scanner  ──► POST /api/investigate (NDJSON Stream)      │  │
│  └───────────────┬────────────────────────────────────────┬───────────────┘  │
│                  │ If errorCode === 'domain_not_found'    │ If 'complete'    │
│                  ▼                                        ▼                  │
│  ┌───────────────────────────────────────┐ ┌──────────────────────────────┐  │
│  │ "Website Does Not Exist" Error Card   │ │ Active Case Dossier View     │  │
│  │ • Explains NXDOMAIN / Unregistered    │ │ • Suspicion Index & Tally    │  │
│  │ • [Check Domain on GoDaddy] CTA       │ │ • Live Internet Assets Panel │  │
│  │ • [GoDaddy WHOIS Lookup] Link         │ │ • Public Web Experience Card │  │
│  └───────────────────────────────────────┘ └──────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                                       ▲
                                       │ NDJSON Events & Reconciled CaseReportData
┌──────────────────────────────────────┴───────────────────────────────────────┐
│                     SERVER: REAL INTERNET FORENSIC ENGINE                    │
│                                                                              │
│  1. DNS & Registry Existence Gate                                            │
│     ├─ dns.lookup(host, { all: true }) + dns.resolveNs(registrable)          │
│     └─ If ENOTFOUND / NXDOMAIN ──► Emit 'domain_not_found' + GoDaddy URLs    │
│                                                                              │
│  2. Parallel Real Internet Asset Collectors                                  │
│     ├─ RDAP WHOIS Inspector: Registrar, Created/Expiry Dates, Domain Age     │
│     ├─ TLS X.509 Inspector: Issuer, Subject SANs, ValidFrom/ValidTo, Age     │
│     ├─ HTTP & HTML Inspector: Status, Redirect Chain, Title, Meta, Forms     │
│     └─ Web Experience Grounding (gemini-3.8-flash + googleSearch):           │
│        Extracts public user experience summary, sentiment & source URLs      │
│                                                                              │
│  3. Deterministic Scoring & Sherlock Deduction Synthesis                     │
│     └─ Combines technical clues + corroborated web experience into 0–100     │
│        Suspicion Index, Score Tally, and grounded plain-English Deduction    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Model & State Additions

- **`SpecialStateType`**: Adds `'domain_not_found'` alongside `'blocked_url'`, `'rate_limited'`, `'unreachable'`, `'inconclusive'`, and `'partial_results'`.
- **`InternetAssetFootprint` (attached to `CaseReportData.internetAssets`)**:
  - `resolvedIps: string[]`
  - `registrar: string | null`
  - `registeredAt: string | null`
  - `expiresAt: string | null`
  - `domainAgeDays: number | null`
  - `tlsIssuer: string | null`
  - `tlsValidFrom: string | null`
  - `tlsValidTo: string | null`
  - `httpStatus: number | null`
  - `serverHeader: string | null`
  - `redirectChain: string[]`
  - `pageTitle: string | null`
  - `metaDescription: string | null`
  - `formsDetected: number`
  - `hasPasswordInput: boolean`
  - `presentSecurityHeaders: string[]`
  - `missingSecurityHeaders: string[]`
- **`PublicWebExperience` (attached to `CaseReportData.webExperience`)**:
  - `sentiment: 'positive' | 'mixed' | 'negative' | 'unverified'`
  - `summary: string` (2–3 sentences summarizing real people's experiences and public reputation found on the internet)
  - `highlights: string[]` (key user experience takeaways or reported warnings)
  - `sources: Array<{ title: string; url: string }>` (verified web citations from Google Search grounding)

### Interactive Component & State Mapping

- **Non-Existent Domain Error Card (`App.tsx`)**:
  - Renders when `specialStateError.state === 'domain_not_found'`.
  - Displays the queried hostname, the exact DNS/registry reason, a primary **"Check Domain on GoDaddy"** button (`https://www.godaddy.com/domainsearch/find?domainToCheck=<host>`), a secondary **"GoDaddy WHOIS Lookup"** button (`https://www.godaddy.com/whois/results.aspx?domain=<host>`), and an **"Investigate a Different Link"** reset action.
- **Live Internet Asset Footprint & Public Web Experience Sections (`CaseReportView.tsx`)**:
  - Displays the real technical infrastructure profile and the internet-wide user experience summary with clickable external source citations and GoDaddy WHOIS verification link on every Case Report.
