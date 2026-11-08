# SHERLOCK — Permanent Vite WebSocket & Preview Stability Fix

Permanently eliminates the `Error: WebSocket closed without opened.` runtime failure caused by `/@vite/client` attempting to open an HMR WebSocket connection in the cloud preview environment, ensuring uninterrupted interaction across the entire application.

## User Review & Critical Decisions

> [!IMPORTANT]
> The decisions below incorporate your confirmed preferences from our clarification check.

- **Confirmed Decision 1 — Safe Vite Client Stub & HTTP Server Attachment**: Intercept requests to `/@vite/client` in the Express middleware pipeline to serve a lightweight, WebSocket-free ESM runtime stub (`createHotContext`, `updateStyle`, `removeStyle`, `injectQuery`) while also binding the underlying Node `http.Server` instance to Vite middleware mode.
- **Confirmed Decision 2 — Silent Early Suppression of Dev WebSocket Errors**: Inject a zero-dependency guard as the very first script in `<head>` (before Vite's module scripts execute) to intercept dev-only WebSocket instantiation and silently suppress any non-critical dev WebSocket rejections.

---

## 1. Overview & Core Concept

- **What It Does**: Prevents Vite's injected client script (`/@vite/client`) from attempting a broken WebSocket handshake over the cloud proxy (`wss://ais-dev-.../@vite/client`) that triggers an unhandled promise rejection and blocks user interaction.
- **Target Audience / Persona**: Every visitor and evaluator opening SHERLOCK in the AI Studio preview or shared Cloud Run URL.
- **Key Value**: 100% crash-free startup with zero WebSocket error overlays, preserving the fast 3–5 second website investigation experience.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Zero-Error Application Startup**: When the user loads or refreshes SHERLOCK, the browser receives a clean, WebSocket-free `/@vite/client` module and immediately renders the Victorian Detective Study without any runtime error overlay.
  2. **Uninterrupted Investigation Desk**: Users can type or paste any link, click **Investigate**, inspect real internet assets, or verify non-existent domains on GoDaddy without background WebSocket rejections interrupting the UI.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Victorian Detective Study (`--walnut-900`, `--walnut-850`, `--brass-500`, `--oxblood-700`, `--parchment-100`).
  - *Typography & Hierarchy*: `Cormorant Garamond` display headers, `Source Serif 4` body copy, and `IBM Plex Mono` (`tabular-nums`) for technical asset telemetry and timestamps.
  - *Component Styling & Layout*: Single-elevation dossier cards with 1px brass hairline borders, responsive mobile/desktop layout, and clean unboxed metadata.
- **Interactive Feedback & Motion**: Smooth NDJSON streaming progress updates during the 3–5 second parallel investigation without UI freezes or overlays.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Intercept `/@vite/client` with a Safe ESM Stub in Express**
  - *Chosen Approach*: Register a dedicated Express route for `/@vite/client` before `vite.middlewares` that returns a valid ES module exporting Vite's client hooks (`createHotContext`, `updateStyle`, `removeStyle`, `injectQuery`) as safe no-op functions without opening a `new WebSocket(...)`.
  - *Why*: In Vite 8 middleware mode, Vite's `transformIndexHtml` automatically prepends `<script type="module" src="/@vite/client"></script>` to the top of `<head>`, which runs before any `<body>` scripts and throws an unhandled rejection when the cloud proxy closes the WebSocket. Serving a WebSocket-free stub for `/@vite/client` stops the faulty WebSocket from ever being created while keeping CSS injection and React module imports working seamlessly.
  - *Alternatives Considered*: Relying solely on `hmr: false` in `vite.config.ts` was insufficient because Vite 8's client script still initializes its server-connection WebSocket unless `/@vite/client` itself is stubbed or pre-guarded.
- **Decision 2: First-in-`<head>` WebSocket & Unhandled Rejection Shield**
  - *Chosen Approach*: Place an inline `<script>` at the very top of `<head>` (line 4 of the HTML document) that wraps `window.WebSocket` for Vite HMR subprotocols (`vite-hmr` / `vite-ping`) and registers `unhandledrejection` and `error` listeners before any module script executes.
  - *Why*: Guarantees that even if the browser has a cached copy of `/@vite/client`, any `vite-hmr` WebSocket call or rejection is neutralized before it can trigger an error overlay.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Request Pipeline Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        Browser Startup & Request Flow                      │
├────────────────────────────────────────────────────────────────────────────┤
│  1. GET / (HTML Document)                                                  │
│     └── Top-of-<head> Inline Shield initializes BEFORE any module scripts: │
│         ├── Wraps window.WebSocket for 'vite-hmr' / 'vite-ping' protocols  │
│         └── Suppresses 'WebSocket closed without opened' rejections        │
│                                                                            │
│  2. GET /@vite/client (Intercepted by Express before Vite Middleware)      │
│     └── Returns safe ESM no-op stub (createHotContext, updateStyle, etc.)  │
│         └── Zero WebSocket connections opened by @vite/client              │
│                                                                            │
│  3. Node HTTP Server + Vite Middleware + Fast 3–5s Investigation API       │
│     ├── http.createServer(app) bound to port 3000                          │
│     ├── CSS & React TSX transforms served cleanly via vite.middlewares     │
│     └── POST /api/investigate streams 8-stage real asset & review checks   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Interactive Component & State Mapping

- **Express `/@vite/client` Interceptor**: Responds with `Content-Type: application/javascript; charset=utf-8` and `Cache-Control: no-store`, exporting `createHotContext`, `updateStyle`, `removeStyle`, and `injectQuery` so all Vite-transformed React and Tailwind CSS modules execute with zero WebSocket activity.
- **Top-of-`<head>` Browser Guard**: Intercepts `new WebSocket(url, protocols)` when `protocols` is `vite-hmr` or `vite-ping`, returning an inert event-target mock so cached Vite client scripts never throw `WebSocket closed without opened`.
- **Vite Config & HTTP Server Binding**: Aligns `vite.config.ts` (`hmr: false`, `watch: null`) and `http.createServer(app)` in the backend server so dev and production modes behave identically without port or WebSocket conflicts.
