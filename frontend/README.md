# Netra (नेTRA SIH26106) Frontend

Production Next.js (React + JavaScript) frontend for the **Netra Email Threat Intelligence & Forensic Platform**, styled with Tailwind CSS and designed directly according to the SIH26106 specification mockups.

## Features & Views

1. **Home (`/`)**:
   - Headline: `See Beyond the Email.`
   - 4 High-impact Metrics: Volume Processed, Model Precision, Latency Speed, Zero-Retention Privacy.
   - 6-Stage Deterministic Pipeline visual walkthrough.
   - Quick sample investigation loader.

2. **Analyze Email (`/analyze`)**:
   - Dual Ingestion Modes: File Upload (`.eml`, `.msg`, `.mbox`) & Raw RFC 822 text editor.
   - Quick presets: `⚡ BEC Spear-Phish` and `⚡ Invoice Fraud`.
   - Real-time 7-stage evaluation pipeline tracker with cumulative latency callout.
   - Client integrity hashing and air-gapped buffer indicators.

3. **Result (`/result`)**:
   - 94/100 Circular Threat Risk Gauge with animated SVG stroke.
   - Authentication Protocols breakdown: SPF, DKIM, and DMARC checks.
   - Extracted IOC Artifacts with one-click clipboard copying.
   - Estimated Infrastructure Geolocation map (Frankfurt, DE - Hetzner Online GmbH).
   - Correlation Attack Graph with 5 stages (`Email` → `Spoof FQDN` → `Relay IP` → `Auth URL` → `Payload Stealer Bin`).

4. **Report & Investigations (`/report`, `/investigations`)**:
   - Case dossier (`Case #2026-0891: Financial BEC Impersonation`) with Polygon PoS blockchain anchor.
   - 4-Hop Relay Traversal Analysis (Origin → Proxy → Perimeter → Sinkhole).
   - Searchable Case Archive table with severity filter dropdown and direct dossier links.
   - 1-click JSON Schema Export & printable PDF Forensic Dossier generation.

5. **Shared Shell**:
   - Top navigation bar with Indian Devanagari brand identity (`नेTRA SIH26106`).
   - Persistent `Light`, `Dark`, and `Sys` segmented theme switcher.
   - Operational status footer with live heartbeats.

## Running Locally

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Production Build

```bash
npm run build
npm start
```
