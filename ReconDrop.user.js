// ==UserScript==
// @name         ReconDrop
// @namespace    http://tampermonkey.net/
// @version      1.6
// @description  Scans web pages for assets, secrets, endpoints, DOM XSS sinks & frameworks. Triggered via floating button.
// @author       Faizad Khan
// @match        *://*/*
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function () {
    'use strict';

    const panel = document.createElement('div');
    panel.style = `
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        max-height: 60%;
        overflow-y: auto;
        background-color: #f9f9f9;
        color: #333;
        padding: 10px;
        z-index: 9999;
        border-top: 2px solid #ccc;
        font-family: monospace;
        display: none;
    `;
    document.body.appendChild(panel);

    const uniquePaths = new Set();
    const scanned = new Set();
    const endpoints = new Set();
    const secrets = new Set();
    const inlineEvents = new Set();
    const domSinks = new Set();
    const frameworks = [];

    function absoluteURL(path) {
        try {
            return new URL(path, location.href).href;
        } catch {
            return null;
        }
    }

    function extractPaths(text) {
        return [...text.matchAll(/['"]((?:\/|\.\.\/|\.\/)[^'"<>{}\s]+)['"]/g)]
            .map(match => absoluteURL(match[1]))
            .filter(Boolean);
    }

    function extractAPIs(text) {
        return [...text.matchAll(/(?:fetch|XMLHttpRequest|ajax)\(["'`](https?:\/\/[^"'`]+)["'`]\)/g)]
            .map(match => match[1]);
    }

    function extractSecrets(text) {
        const regexes = [
            /sk_live_[0-9a-zA-Z]+/g,
            /AIzaSy[0-9A-Za-z-_]+/g,
            /ghp_[0-9a-zA-Z]+/g,
            /eyJ[0-9a-zA-Z._-]+/g,
            /AKIA[0-9A-Z]{16}/g,
            /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
            /SK[0-9a-fA-F]{32}/g
        ];
        return regexes.flatMap(rx => [...text.matchAll(rx)].map(m => m[0]));
    }

    function extractInlineEvents() {
        const events = ["onclick", "onmouseover", "onerror", "onload"];
        events.forEach(evt => {
            document.querySelectorAll("*").forEach(el => {
                if (el.hasAttribute(evt)) {
                    inlineEvents.add(`${evt}="${el.getAttribute(evt)}"`);
                    el.style.outline = "2px solid red";
                }
            });
        });
    }

    function extractDOMSinks(text) {
        const sinkPatterns = [
            /\.innerHTML\s*=/g,
            /document\.write\s*\(/g,
            /eval\s*\(/g
        ];
        sinkPatterns.forEach(rx => {
            [...text.matchAll(rx)].forEach(m => domSinks.add(m[0]));
        });
    }

    function detectFrameworks() {
        const checks = [
            { name: "React", check: () => window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__ },
            { name: "Angular", check: () => window.angular || document.querySelector('[ng-app]') },
            { name: "Vue", check: () => window.Vue || document.querySelector('[data-v-app]') },
            { name: "Svelte", check: () => document.querySelector('[data-svelte]') },
            { name: "Ember", check: () => window.Ember },
            { name: "Backbone", check: () => window.Backbone },
            { name: "Alpine.js", check: () => window.Alpine },
            { name: "jQuery", check: () => window.jQuery },
            { name: "Next.js", check: () => window.__NEXT_DATA__ },
            { name: "Nuxt.js", check: () => window.__NUXT__ },
            { name: "Express", check: () => window.express },
            { name: "Koa", check: () => window.koa },
            { name: "NestJS", check: () => window.nest },
            { name: "Hapi", check: () => window.hapi },
            { name: "Django", check: () => window.django },
            { name: "Flask", check: () => window.flask },
            { name: "FastAPI", check: () => window.fastapi },
            { name: "Laravel", check: () => window.laravel },
            { name: "Symfony", check: () => window.symfony },
            { name: "Spring", check: () => window.spring },
            { name: "ASP.NET", check: () => window.aspnet },
            { name: "Rails", check: () => window.rails },
            { name: "Gin", check: () => window.gin },
            { name: "Fiber", check: () => window.fiber },
            { name: "Revel", check: () => window.revel },
            { name: "Ionic", check: () => window.Ionic },
            { name: "Cordova", check: () => window.cordova },
            { name: "Capacitor", check: () => window.Capacitor },
            { name: "React Native", check: () => window.ReactNativeWebView },
            { name: "Electron", check: () => window.process?.versions?.electron },
            { name: "Redux", check: () => window.__REDUX_DEVTOOLS_EXTENSION__ },
            { name: "jQuery UI", check: () => window.jQuery?.ui },
            { name: "Bootstrap", check: () => document.querySelector('[class*="bootstrap"]') },
            { name: "Tailwind CSS", check: () => document.querySelector('[class*="tw-"]') },
            { name: "Chart.js", check: () => window.Chart },
            { name: "Three.js", check: () => window.THREE },
            { name: "GSAP", check: () => window.gsap },
            { name: "Anime.js", check: () => window.anime },
            { name: "Moment.js", check: () => window.moment },
            { name: "D3.js", check: () => window.d3 },
            { name: "Socket.IO", check: () => window.io },
            { name: "Webpack", check: () => window.webpackChunk || window.__webpack_require__ },
            { name: "Babel", check: () => window.Babel },
            { name: "Gulp", check: () => window.gulp },
            { name: "Grunt", check: () => window.grunt },
            { name: "TypeORM", check: () => window.TypeORM },
            { name: "Sequelize", check: () => window.Sequelize },
            { name: "Prisma", check: () => window.PrismaClient }
        ];

        checks.forEach(fw => {
            try {
                if (fw.check()) frameworks.push(fw.name);
            } catch (e) {}
        });
    }

    async function fetchAndScan(url) {
        if (scanned.has(url)) return;
        scanned.add(url);
        try {
            const res = await fetch(url);
            const type = res.headers.get('Content-Type') || '';
            if (!res.ok || (!type.includes('text') && !type.includes('javascript'))) return;
            const txt = await res.text();
            extractPaths(txt).forEach(p => uniquePaths.add(p));
            extractAPIs(txt).forEach(api => endpoints.add(api));
            extractSecrets(txt).forEach(secret => secrets.add(secret));
            extractDOMSinks(txt);
        } catch (e) {
            console.warn('Failed to fetch:', url, e);
        }
    }

    async function runScanner() {
        panel.style.display = "block";
        panel.innerHTML = `<h4>Scanning in progress...</h4>`;

        const resources = performance.getEntriesByType("resource").map(res => res.name);
        for (const res of resources) await fetchAndScan(res);

        extractInlineEvents();
        detectFrameworks();

        document.querySelectorAll("script").forEach(s => {
            if (!s.src) extractDOMSinks(s.innerHTML);
        });

        const result = {
            frameworks,
            uniquePaths: [...uniquePaths],
            endpoints: [...endpoints],
            secrets: [...secrets],
            inlineEvents: [...inlineEvents],
            domSinks: [...domSinks]
        };

        const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
        const exportUrl = URL.createObjectURL(blob);

        panel.innerHTML = `
            <h4>Recon Results</h4>
            <p><strong>Detected Frameworks:</strong> ${frameworks.join(", ") || "None"}</p>
            <h5>Paths:</h5><ul>${[...uniquePaths].map(p => `<li>${p}</li>`).join("")}</ul>
            <h5>API Endpoints:</h5><ul>${[...endpoints].map(p => `<li>${p}</li>`).join("")}</ul>
            <h5>Secrets:</h5><ul>${[...secrets].map(p => `<li>${p}</li>`).join("")}</ul>
            <h5>Inline Events:</h5><ul>${[...inlineEvents].map(p => `<li>${p}</li>`).join("")}</ul>
            <h5>DOM Sinks:</h5><ul>${[...domSinks].map(p => `<li>${p}</li>`).join("")}</ul>
        `;

        const exportBtn = document.createElement("button");
        exportBtn.textContent = "Export JSON";
        exportBtn.style = `
            margin-top: 10px;
            background: #007BFF;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
        `;
        exportBtn.onclick = () => {
            const a = document.createElement("a");
            a.href = exportUrl;
            a.download = "recon-results.json";
            a.click();
        };

        const closeBtn = document.createElement("button");
        closeBtn.textContent = "Close Panel";
        closeBtn.style = `
            margin-left: 10px;
            margin-top: 10px;
            background: #6c757d;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
        `;
        closeBtn.onclick = () => {
            panel.style.display = "none";
        };

        panel.appendChild(exportBtn);
        panel.appendChild(closeBtn);
    }

    const triggerBtn = document.createElement('button');
    triggerBtn.textContent = "🔍 Run Recon";
    triggerBtn.style = `
        position: fixed;
        bottom: 10px;
        right: 10px;
        z-index: 9999;
        padding: 8px 12px;
        font-size: 14px;
        background: #007BFF;
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
    `;
    triggerBtn.onclick = () => {
        console.log('[ReconDrop] Button clicked');
        runScanner();
    };

    document.body.appendChild(triggerBtn);
})();
