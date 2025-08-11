# ReconDrop

**ReconDrop** is a Tampermonkey userscript that scans any visited webpage for:
- Asset paths
- API endpoints
- Secrets (API keys, tokens, etc.)
- Inline event handlers
- DOM XSS sinks
- Detected JavaScript frameworks

It is triggered via a floating "Run Recon" button injected into the page.

---

## Features
- **Path Extraction** – Finds relative/absolute URLs from scripts.
- **API Detection** – Detects fetch, XHR, and ajax calls.
- **Secret Scanning** – Identifies API keys, JWTs, access tokens, etc.
- **Inline Event Detection** – Highlights elements with `onclick`, `onerror`, etc.
- **DOM Sink Detection** – Flags `.innerHTML`, `eval`, `document.write` usages.
- **Framework Detection** – Identifies common JS frameworks and libraries.
- **JSON Export** – Allows exporting scan results as a JSON file.

---

## Installation
1. Install **[Tampermonkey](https://www.tampermonkey.net/)** browser extension.
2. Click the Tampermonkey icon → **Create a new script**.
3. Paste the contents of [`ReconDrop.user.js`](./ReconDrop.user.js) into the editor.
4. Save the script.

---

## Usage
1. Navigate to any webpage you want to analyze.
2. Click the **🔍 Run Recon** button at the bottom-right corner.
3. Wait for the scan to complete.
4. View results in the bottom panel:
   - Frameworks
   - Paths
   - API Endpoints
   - Secrets
   - Inline Events
   - DOM Sinks
5. Click **Export JSON** to save results locally.
6. Click **Close Panel** to hide the output.

---

## Disclaimer
This tool is for **educational and security testing purposes only**.  
Do not use on sites you do not own or have permission to test.

---

**Author: Faizad Khan  
**License: MIT
