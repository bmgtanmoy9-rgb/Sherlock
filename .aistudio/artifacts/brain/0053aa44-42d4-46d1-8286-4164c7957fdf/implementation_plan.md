# SHERLOCK — Ultra-Responsive 2–3s Forensic Check Ledger Across All Devices

Upgrades SHERLOCK's **Forensic Check Ledger** and backend investigation pipeline to deliver immediate visual feedback, live per-check millisecond timings, anti-buffered NDJSON stage streaming, immediate auto-scroll on mobile and desktop, and a unified **2 to 3 second** end-to-end execution budget.

## User Review & Critical Decisions

> [!IMPORTANT]
> The decisions below reflect your confirmed choices from our clarification check.

- **Confirmed Decision 1 — 2 to 3 Second Balanced Mode with Extended Search Grounding**: Launch all 8 forensic checks and Google Search user-experience grounding concurrently at millisecond zero (`t = 0ms`), eliminating sequential handoffs so the entire dossier completes in **2.0 to 2.9 seconds**.
- **Confirmed Decision 2 — Immediate Auto-Scroll & Live Millisecond Timings Per Check**: Automatically scroll the viewport to the **Forensic Check Ledger** the instant **Investigate** is tapped on mobile, tablet, or desktop, and display a live millisecond timer (`tabular-nums`) and progress bar for each of the 8 checks.

---

## 1. Overview & Core Concept

- **What It Does**: Eliminates proxy stream buffering and sequential server waits so every user—on phone, tablet, or desktop—immediately sees the **Forensic Check Ledger** come alive within 50ms of tapping **Investigate**, with each of the 8 checks ticking off with real millisecond timings and delivering the full Case Report within 2 to 3 seconds.
- **Target Audience / Persona**: Mobile, tablet, and desktop users inspecting suspicious links or QR codes who expect instant, transparent visual progress.
- **Key Value**: Zero perceived lag on mobile or desktop, unbuffered real-time stage updates, live millisecond telemetry (`tabular-nums`), and guaranteed 2–3 second dossier delivery.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Instant Mobile & Desktop Auto-Scroll (`t = 0ms`)**: As soon as the user submits a link, selects a sample case, or scans a QR code, the viewport smoothly scrolls straight to the **Forensic Check Ledger** so mobile users never have to scroll past the hero banner to see progress.
  2. **Live 8-Stage Ledger with Millisecond Counters & Progress Bar**:
     - Header displays an animated 0–100% completion progress bar, completed check count (`e.g., 6 / 8 checks complete`), and a live elapsed timer (`1.4s`).
     - Each of the 8 check rows displays its live state (`Inspecting…`, `Done`, `Timed out`, `Failed`), a brief stage summary, and its exact completion duration in monospace tabular figures (`e.g., 180ms`, `640ms`).
     - Interactive stage rows allow clicking any completed check in the ledger to jump directly to the corresponding forensic evidence below.
  3. **Seamless Dossier Reveal (`t = 2.0s–2.9s`)**: As the 8th check finishes, the full Case Report unfolds directly beneath the ledger with the total inspection duration badge.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Victorian Detective Study (`--walnut-900`, `--walnut-850`, `--brass-500`, `--oxblood-700`, `--parchment-100`).
  - *Typography & Hierarchy*: `Cormorant Garamond` display headers, `Source Serif 4` body copy, and `IBM Plex Mono` (`tabular-nums`) for all millisecond counters, stage completion badges, and progress metrics so numbers never jitter during live updates.
  - *Component Styling & Layout*: Responsive 1-column mobile / 2-column desktop ledger grid with minimum `44px` touch targets, single-elevation cards, and clean unboxed metadata.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Defeat Reverse-Proxy Stream Buffering (`X-Accel-Buffering: no` + `res.flushHeaders()` + Padded Chunks)**
  - *Chosen Approach*: Configure `POST /api/investigate` with `X-Accel-Buffering: no`, `Content-Encoding: identity`, immediate `res.flushHeaders()`, and padded NDJSON lines so cloud proxies flush every stage update immediately rather than holding 4 KB buffers until `res.end()`.
  - *Why*: Previously, small 45-byte NDJSON stage lines were buffered by the cloud proxy until the entire request finished, making the Forensic Check Ledger appear frozen until the end.
- **Decision 2: Single-Wave Parallel Pipeline (`t = 0ms` Launch) + Fast Direct RDAP Lookup**
  - *Chosen Approach*: Start DNS verification, RDAP registry lookup (routing `.com`/`.net`/`.org` directly to authoritative RDAP servers before falling back to `rdap.org`), HTTP/HTML inspection, TLS handshake, reputation feeds, and `gemini-3.8-flash` search grounding concurrently in a single parallel wave capped at `1.8s`, followed by an instant or `<= 800ms` bounded deduction.
  - *Why*: Eliminates the sequential `DNS -> Network Checks -> LLM Deduction` chain that previously stacked timeouts to 4–6 seconds, bringing total wall-clock time strictly into the **2 to 3 second** window.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Zero-Latency Streaming Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│               Client Device (Mobile / Tablet / Desktop)                    │
├────────────────────────────────────────────────────────────────────────────┤
│  1. User taps "Investigate" (t = 0ms)                                      │
│     ├── Smoothly scrolls viewport to Forensic Check Ledger immediately     │
│     ├── Starts 60fps requestAnimationFrame / 100ms live elapsed timer      │
│     └── Renders 8-stage progress bar & per-stage tabular-nums ms counters  │
│                                                                            │
│  2. Anti-Buffered NDJSON Stream (POST /api/investigate)                    │
│     ├── Headers: X-Accel-Buffering: no, Cache-Control: no-cache            │
│     ├── Immediate res.flushHeaders() + padded stage chunks                 │
│     └── Emits { type: 'stage', stage, status, durationMs, detail }         │
│                                                                            │
│  3. Unified Parallel Server Wave (t = 0ms to 1,850ms max)                  │
│     ├── Stage 1 & 2: Domain Identity + Brand Impersonation (< 15ms)        │
│     ├── DNS A/AAAA + NS Existence Check (<= 950ms parallel)                │
│     ├── Stage 3: Direct Authoritative RDAP WHOIS Lookup (<= 1,350ms)       │
│     ├── Stage 4: Threat & Phishing Reputation Feeds (<= 1,100ms)           │
│     ├── Stage 5 & 7: HTTP Redirects, HTML DOM & Security Headers (<=1,450ms│
│     ├── Stage 6: TLS X.509 Socket Handshake (<= 1,200ms)                   │
│     └── Stage 8: Witness DB + Gemini 3.8 Flash Search Grounding (<=1,800ms)│
│                                                                            │
│  4. Fast Deduction & Dossier Assembly (Completed in 2.0s – 2.9s total)     │
│     └── Emits { type: 'complete', report } + non-blocking store archival   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Interactive Component & State Mapping

- **Extended `CheckProgressEvent` Telemetry**: Each streamed `stage` event carries `durationMs?: number` and `detail?: string` (e.g., `"2 IPs resolved"`, `"Registrar: MarkMonitor"`, `"TLS 1.3 · Let's Encrypt"`, `"HTTP 200 · 4 headers"`), giving users real-time forensic visibility inside each row of the ledger as checks complete.
- **Interactive Ledger Stage Rows**: Clicking any completed stage row in the Forensic Check Ledger scrolls smoothly to the corresponding section of the Case Report (`Live Internet Assets`, `Clues Found`, or `Public Web Experience`).
- **Client-Side Stream Watchdog (`AbortController`)**: Enforces a hard client-side timeout and automatic progressive stage ticker so slow mobile cellular connections still experience smooth, responsive stage transitions without ever hanging.
