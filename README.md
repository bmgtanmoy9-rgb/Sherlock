# SHERLOCK — The AI Digital Detective

> **“Investigate before you trust. Every website leaves clues. SHERLOCK finds them.”**

SHERLOCK is a mobile-first, single-page defensive web investigation application themed inside a warm Victorian detective’s study. It inspects suspicious links passively—evaluating domain identity, homoglyph brand impersonation, RDAP registration age, reputation feeds, redirect chains, TLS certificates, security headers, and corroborated community witness reports—using a deterministic rule engine to compute a 0–100 **Suspicion Index** while server-side AI translates the structured evidence into plain, hedged English.

---

## Features & Architecture

1. **Victorian Detective’s Study Visual Identity**:
   - Crafted around `--walnut-900`, `--oxblood-700`, `--brass-500`, `--sunbeam`, and `--parchment-100` CSS tokens with an optional **Daylight Study** light theme toggle.
   - Full-bleed Hero section featuring the Victorian detective study reference (`/public/images/study-hero.jpg` and ambient video `/public/assets/aistudio/Detective_examining_floor_with_m__90363405_1080p_06717d7f.mp4`), diagonal golden sunbeam, brass nameplate navigation, and pinned-note evidence cards.
2. **Deterministic Rule Engine (`src/engine/ruleEngine.ts`)**:
   - Every point on the 0–100 Suspicion Index links to a visible clue card.
   - Reputation Feed Override Rule guarantees an index of `≥ 90` when a trusted feed lists the URL as confirmed phishing or malware.
   - Never declares a website “safe”—lowest level reads `🟢 Low suspicion: No strong warning signs found. This is not a guarantee of safety.`
   - Returns `⚪ Inconclusive` when too few checks complete rather than showing a falsely reassuring score.
3. **Server-Side Gemini Deduction (`server.ts`)**:
   - Uses `@google/genai` (`gemini-3.8-flash`) strictly on the server with a fixed JSON `responseSchema`.
   - Prompt-injection defence: only structured findings are passed to the model, never raw untrusted webpage HTML.
   - Automatic fallback to a deterministic template deduction if the API key is missing or the model call times out.
4. **SSRF Guard & Privacy by Default**:
   - Strips query strings (`?...`) and fragments (`#...`) before storage or sharing.
   - Resolves DNS and blocks private, loopback, link-local, and cloud-metadata IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 local ranges) before initial connection and after every redirect hop (capped at 5 hops).
   - Hashes client identifiers with a server-side salt; raw IP addresses are never stored.

---

## Setup & Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and configure as needed (all external keys are optional—SHERLOCK works end to end in self-contained mode out of the box):
```bash
cp .env.example .env
```

| Variable | Description |
| :--- | :--- |
| `GEMINI_API_KEY` | Server-side Gemini API key for Sherlock's Deduction (falls back to deterministic template if omitted). |
| `SUPABASE_URL` | Optional Supabase project URL for syncing `cases`, `reports`, and `feed_entries`. |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional Supabase service role key (server-side only). |
| `GOOGLE_SAFE_BROWSING_KEY` | Optional Google Safe Browsing v4 API key. |
| `CLIENT_HASH_SALT` | Secret salt for one-way client ID hashing (rate limits & witness report deduplication). |

### 3. Run Unit Tests for the Rule Engine
```bash
npm test
```

### 4. Start the Full-Stack Development Server
```bash
npm run dev
```
The server starts on `http://localhost:3000`.
