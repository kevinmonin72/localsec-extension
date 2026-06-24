const { analyzeHeaders } = require('../lib/analyze-headers');
const { analyzeCookies } = require('../lib/analyze-cookies');
const { analyzeThirdParties } = require('../lib/analyze-third-parties');
const { analyzeScripts } = require('../lib/analyze-scripts');
const { analyzeTechnologies } = require('../lib/analyze-technologies');
const { calculateScore } = require('../lib/score-site');
const { buildRecommendations } = require('../lib/build-recommendations');
const { renderHtmlReport } = require('../lib/render-report');

document.getElementById('audit-btn').addEventListener('click', async () => {
    const btn = document.getElementById('audit-btn');
    const status = document.getElementById('status');
    btn.disabled = true;
    status.textContent = 'Extraction des données...';

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url.startsWith('http')) {
            throw new Error("Impossible d'auditer cette page (seuls http/https sont supportés).");
        }

        const url = new URL(tab.url);

        // Récupérer les cookies
        const cookies = await chrome.cookies.getAll({ url: tab.url });
        const parsedCookies = cookies.map(c => {
            return {
                name: c.name,
                value: c.value,
                secure: c.secure,
                httpOnly: c.httpOnly,
                sameSite: c.sameSite,
                isSession: c.session
            };
        });

        // Injecter un script pour récupérer les headers HTTP (via fetch de la page elle-même) et les scripts DOM
        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: async () => {
                const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
                const domains = new Set(scripts.map(s => { try { return new URL(s).hostname; } catch(e){ return ''; } }).filter(Boolean));
                
                const metaGen = document.querySelector('meta[name="generator"]');
                const technologies = metaGen ? [metaGen.content] : [];

                let headers = {};
                try {
                    const res = await fetch(document.location.href, { method: 'HEAD' });
                    res.headers.forEach((value, key) => {
                        headers[key.toLowerCase()] = value;
                    });
                } catch(e) {}

                return { scripts, domains: Array.from(domains), technologies, headers };
            }
        });

        const pageData = results[0].result;

        status.textContent = 'Analyse de sécurité...';

        // Lancer l'analyse
        const normalizedData = {
            url: tab.url,
            finalUrl: tab.url,
            headers: pageData.headers,
            setCookies: [], // géré par l'API chrome.cookies
            tls: null, // TLS n'est pas facilement accessible via l'API standard, on l'omet
            thirdPartyDomains: pageData.domains,
            thirdPartyScripts: pageData.scripts,
            technologies: pageData.technologies
        };

        let allFindings = [];
        allFindings.push(...analyzeHeaders(normalizedData.headers));
        // Notre analyseur de cookies attend un tableau formatté, on adapte
        allFindings.push(...analyzeCookies(parsedCookies));
        const allThirdPartyStrings = [...normalizedData.thirdPartyDomains, ...normalizedData.thirdPartyScripts];
        allFindings.push(...analyzeThirdParties(allThirdPartyStrings));
        const scriptsInventory = analyzeScripts(normalizedData.thirdPartyScripts);
        const techSummary = analyzeTechnologies(normalizedData.technologies);

        const scoreResult = calculateScore(normalizedData, allFindings);
        const recommendations = buildRecommendations(allFindings);

        const reportResult = {
            siteUrl: normalizedData.finalUrl,
            score: scoreResult.score,
            grade: scoreResult.grade,
            executiveSummary: "Audit réalisé via l'extension Chrome (1-Clic).",
            tlsSummary: "Analyse TLS non supportée dans l'extension.",
            cookies: parsedCookies,
            thirdParties: analyzeThirdParties(allThirdPartyStrings),
            recommendations: recommendations,
            techSummary: techSummary,
            scriptsInventory: scriptsInventory,
            findings: allFindings
        };

        const htmlOutput = renderHtmlReport([reportResult]);

        // Ouvrir dans un nouvel onglet
        const blob = new Blob([htmlOutput], { type: 'text/html' });
        const blobUrl = URL.createObjectURL(blob);
        chrome.tabs.create({ url: blobUrl });

        window.close();

    } catch (e) {
        status.textContent = "Erreur: " + e.message;
        btn.disabled = false;
    }
});
