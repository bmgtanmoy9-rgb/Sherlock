# Deterministic Score Breakdown Fix & Mobile-Friendly Hero Video Overhaul

This update resolves the mathematical discrepancy in the **Deterministic Score Breakdown by Category** by adding a transparent calculation tally row that reconciles raw category points, reputation overrides, and 100-point clamping with the final Suspicion Index, while fixing **mobile hero video autoplay** and optimizing **multi-device responsiveness** across phones, tablets, and desktops.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following product and design decisions incorporate your confirmed answers and mobile usability requirements before code execution begins:

- **Confirmed Decision 1 — Score Breakdown Reconciliation**: The category breakdown will include an explicit **Total Score Calculation Tally** at the bottom of the category bars that displays the Raw Category Sum, any active Reputation Blocklist Override (`≥ 90/100`) or Community Corroboration adjustment, and the Final Clamped Suspicion Index (`0–100`) so the numbers always add up transparently.
- **Confirmed Decision 2 — Reputation Override & Active Category Visibility**: When a threat intelligence override is triggered, an explicit **Reputation Feed Override** indicator row will appear in the breakdown alongside the 8 core forensic categories, and each category row will indicate how many clues fired in that category.
- **Confirmed Decision 3 — Mobile Hero Video Playback Fix**: The hero background video will remain at full DOM visibility (`opacity-100`) with a native `poster` attribute, direct MP4 source binding, and multi-event mobile unlock listeners (`touchstart`, `pointerdown`, `scroll`, and section re-entry) so iOS Safari and Android Chrome never throttle or pause playback.
- **Confirmed Decision 4 — Full Cross-Device Responsiveness**: All 7 views, data tables, forensic cards, navigation drawers, and footer rating widgets will be responsive across small mobile screens (`360px–430px`), tablets (`768px–1024px`), and widescreen desktops (`1440px`), adhering to `44px×44px` minimum touch targets and the 15% mobile sticky height cap.

---

## 1. Overview & Core Concept

- **What It Does**:
  1. **Transparent Forensic Math**: Ensures every point in the Suspicion Index dial is visibly accounted for in the category breakdown, showing individual category contributions, active clue counts per category, override rules, and a final summation ledger row.
  2. **Reliable Mobile Hero Video**: Fixes mobile browser power-saving and WebKit autoplay blocks so the Victorian detective study loop plays smoothly inline on mobile phones and tablets, including when navigating back to the Home view from other sections.
  3. **Multi-Device Ergonomics**: Refines viewport spacing, responsive grids, horizontal table scrolling, and touch hitboxes across mobile, tablet, and desktop viewports.
- **Target Audience / Persona**: Everyday mobile and desktop users inspecting suspicious links from SMS, WhatsApp, email, or QR codes who need clear visual proof of how a risk score was calculated and a smooth experience on any screen size.
- **Key Value**: Eliminates confusion when comparing individual category bars against the overall Suspicion Index and ensures a fast, polished mobile-first experience.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Mobile Arrival & Hero Video Experience**: When a user opens SHERLOCK on a smartphone or tablet, the hero detective video plays inline immediately above and behind the investigation card without requiring fullscreen mode or manual unmuting, and resumes automatically if the user switches sections and returns home.
  2. **Inspecting the Score Breakdown**: After investigating a URL, the user scrolls to **Deterministic Score Breakdown by Category**. Each category row shows its earned points (`+X / Max pts`), the number of triggered clues, and a color-coded progress bar. At the bottom of the breakdown, a dedicated **Forensic Tally Ledger** row shows:
     - **Raw Category Points Sum** (e.g., `87 pts` or raw sum prior to cap)
     - **Special Rule Adjustments** (if a Reputation Override `≥ 90` or 100-point cap applies)
     - **Final Suspicion Index** (`87 / 100`) matching the top verdict dial 1:1.
  3. **Cross-Device Navigation & Reading**: On mobile phones (`375px–430px`), complex forensic comparison tables, evaluation matrices, and case headers stack cleanly or provide smooth horizontal scroll containers without clipping or horizontal page overflow.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Warm Victorian Detective Study meets modern defensive security dossier.
  - *Color Palette & Mood*: Deep walnut (`#170E0B`, `#2A1A14`), oxblood (`#5A1F26`), antique brass (`#C9A04A`, `#F5CE7A`), warm parchment (`#F2E6C9`), and semantic severity accents (`#5E8B5A` low, `#D9A93A` caution, `#D9702E` high, `#B3342F` critical).
  - *Typography & Hierarchy*: `Cormorant Garamond` for display headings, `Source Serif 4` for readable body prose, and `IBM Plex Mono` (`tabular-nums`) for aligned score columns and point tallies.
- **Interactive Feedback & Motion**:
  - Clicking or tapping a category row with active points smoothly highlights or filters the matching clues.
  - All touch buttons maintain a minimum `44px × 44px` hit target with instant press feedback (`≤ 150ms`).

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Explicit Total Tally Ledger + Override Row in Category Breakdown**
  - *Chosen Approach*: Add a structured summary footer inside the breakdown card showing the exact arithmetic (`Category Points Sum` → `Override / Cap Adjustment` → `Final Suspicion Index / 100`), plus an explicit override row whenever a blocklist feed forces the score to `≥ 90`.
  - *Why*: Category weights sum to a theoretical maximum of 118 points (clamped to 100) and reputation overrides can raise a low category sum to 90+. Showing both the raw sum and the final clamped/overridden score removes any perceived math bug while preserving the deterministic rule weights.
  - *Alternatives Considered*: Rescaling all category weights to 100 was passed over because individual clue weights are calibrated by forensic severity.
- **Decision 2: Always-Visible DOM Video Layer with Native Poster on Mobile**
  - *Chosen Approach*: Remove `opacity-0` hiding on the `<video>` element and instead use the native `poster` image with direct source binding, React lifecycle re-initialization on section changes, and multi-event touch/scroll playback recovery.
  - *Why*: Mobile Safari (iOS) and mobile Chrome aggressively pause `<video>` elements rendered with `opacity: 0`, preventing the `playing` event from ever firing. Keeping the video element visible in the compositor layer allows immediate hardware-accelerated inline playback.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        Responsive Application Shell                       │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ Top Navigation Bar (Brand + Investigate CTA + 3-Line Slide Drawer)  │  │
│  └──────────────────────────────────┬──────────────────────────────────┘  │
│                                     ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ Mobile & Desktop Hero Section                                       │  │
│  │  ├─ Inline Autoplay Video Layer (Always-visible + Poster + Loop)    │  │
│  │  ├─ Lifecycle & Touch/Scroll Unlock Controller (Re-runs on #home)   │  │
│  │  └─ Responsive Parchment Investigation Card (Paste / URL / QR)      │  │
│  └──────────────────────────────────┬──────────────────────────────────┘  │
│                                     ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ Deterministic Rule Engine & Case Report Dossier                     │  │
│  │  ├─ 8 Category Breakdown Bars (Points, Max Weight, Matched Clues)   │  │
│  │  ├─ Conditional Reputation Override Row (When Override ≥ 90 Active) │  │
│  │  └─ Total Forensic Tally Row (Raw Sum + Cap/Override = Final Index) │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State**:
  - `CategoryBreakdown` entries track `category`, `label`, `points` (clamped per category), `rawPoints` (unclamped sum of clues in that category), `maxPoints`, and `clueCount` (number of triggered clues in that category).
  - The Score Breakdown view computes `rawCategorySum` across all categories, checks `report.overrideTriggered` and `100`-point clamping, and renders the step-by-step arithmetic reconciliation in the Total Tally Row.
- **Interactive Component & State Mapping**:
  - **Hero Video Controller**: Re-binds whenever the active view switches to `home`, sets `muted`, `defaultMuted`, `playsInline`, and `webkit-playsinline` synchronously on mount, calls `.play()`, and attaches passive `touchstart`, `pointerdown`, and `scroll` listeners to recover playback if mobile Low Power Mode or Data Saver initially defers autoplay.
  - **Score Breakdown Interactive Rows**: Displays triggered clue badges on each category row and renders the bottom **Total Suspicion Index Tally** bar matching `report.index`.
  - **Responsive Viewport Layout**: Adjusts mobile hero height and scrim contrast so the video is clearly visible on phones, wraps wide forensic tables in touch-scrollable containers, and ensures all cards, modals, and footer sections adapt cleanly from `360px` to `1440px`.
