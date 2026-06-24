const { analyzeHeaders } = require('../offline-security-audit/lib/analyze-headers');
const { analyzeCookies } = require('../offline-security-audit/lib/analyze-cookies');
const { analyzeThirdParties } = require('../offline-security-audit/lib/analyze-third-parties');
const { analyzeScripts } = require('../offline-security-audit/lib/analyze-scripts');
const { analyzeTechnologies } = require('../offline-security-audit/lib/analyze-technologies');
const { calculateScore } = require('../offline-security-audit/lib/score-site');
const { buildRecommendations } = require('../offline-security-audit/lib/build-recommendations');
const { renderHtmlReport } = require('../offline-security-audit/lib/render-report');

const { analyzeDom } = require('../offline-security-audit/lib/analyze-dom');

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

        // Injecter un script pour récupérer les headers HTTP et analyser le DOM (Formulaires, scripts, etc.)
        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: async () => {
                const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
                const domains = new Set(scripts.map(s => { try { return new URL(s).hostname; } catch(e){ return ''; } }).filter(Boolean));
                
                const metaGen = document.querySelector('meta[name="generator"]');
                const technologies = metaGen ? [metaGen.content] : [];

                // Analyse DOM Passive
                const formsData = Array.from(document.querySelectorAll('form')).map(f => {
                    const action = f.getAttribute('action') || window.location.href;
                    const isActionHttps = action.startsWith('https') || action.startsWith('/');
                    const inputs = Array.from(f.querySelectorAll('input, select, textarea')).map(i => i.name || i.id || 'unknown');
                    const hasPasswordField = f.querySelector('input[type="password"]') !== null;
                    return { action, method: f.getAttribute('method') || 'GET', isActionHttps, hasPasswordField, inputs };
                });

                const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]')).map(i => {
                    return { name: i.name || i.id, value: i.value };
                });

                // Analyse Black Hat SEO (Liens cachés)
                const hiddenLinks = Array.from(document.querySelectorAll('a')).filter(a => {
                    if (!a.href) return false;
                    const style = window.getComputedStyle(a);
                    const rect = a.getBoundingClientRect();
                    const isOffScreen = rect.top < -1000 || rect.left < -1000;
                    return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || isOffScreen;
                }).map(a => a.href);

                // Analyse du Code Source / Inspecteur (Commentaires HTML et inline secrets)
                const htmlComments = [];
                const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT, null, false);
                let curNode;
                while (curNode = iterator.nextNode()) {
                    htmlComments.push(curNode.nodeValue);
                }

                const pageSource = document.documentElement.innerHTML || "";
                const potentialApiKeys = (pageSource.match(/(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24})/g) || []);

                let headers = {};
                try {
                    const res = await fetch(document.location.href, { method: 'HEAD' });
                    res.headers.forEach((value, key) => {
                        headers[key.toLowerCase()] = value;
                    });
                } catch(e) {}

                return { 
                    scripts, 
                    domains: Array.from(domains), 
                    technologies, 
                    headers,
                    domAnalysis: {
                        forms: formsData,
                        hiddenInputs: hiddenInputs,
                        hiddenLinks: hiddenLinks,
                        htmlComments: htmlComments,
                        potentialApiKeys: [...new Set(potentialApiKeys)],
                        sensitiveUrl: window.location.search.includes('token=') || window.location.search.includes('key=') || window.location.search.includes('password=')
                    }
                };
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
            tls: null, 
            thirdPartyDomains: pageData.domains,
            thirdPartyScripts: pageData.scripts,
            technologies: pageData.technologies,
            domAnalysis: pageData.domAnalysis
        };

        let allFindings = [];
        allFindings.push(...analyzeHeaders(normalizedData.headers));
        allFindings.push(...analyzeCookies(parsedCookies));
        const allThirdPartyStrings = [...normalizedData.thirdPartyDomains, ...normalizedData.thirdPartyScripts];
        allFindings.push(...analyzeThirdParties(allThirdPartyStrings));
        allFindings.push(...analyzeDom(normalizedData.domAnalysis, normalizedData.url));
        
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

        // Sauvegarder dans le storage local (associé au domaine ou URL)
        // On stocke l'URL de base pour matcher facilement avec la liste
        const baseDomainUrl = new URL(tab.url).origin;
        
        await new Promise((resolve) => {
            const data = {};
            data['report_' + baseDomainUrl] = htmlOutput;
            chrome.storage.local.set(data, () => resolve());
        });

        // --- EXPORT JSON POUR EMAIL COMMERCIAL ---
        const exportData = {
            isLocalsecAudit: true,
            siteUrl: normalizedData.finalUrl,
            score: scoreResult.score,
            grade: scoreResult.grade,
            findings: allFindings
        };
        
        const jsonBlob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const jsonUrl = URL.createObjectURL(jsonBlob);
        
        chrome.downloads.download({
            url: jsonUrl,
            filename: `audit_localsec_${new URL(tab.url).hostname}.json`,
            saveAs: false
        });

        status.textContent = "Rapport synchronisé et JSON téléchargé !";
        
        // Fermer le popup après 1.5s
        setTimeout(() => {
            window.close();
        }, 1500);

    } catch (e) {
        status.textContent = "Erreur: " + e.message;
        btn.disabled = false;
    }
});
