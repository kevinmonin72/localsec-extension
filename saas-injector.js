// Ce script est injecté par l'extension Chrome dans le SaaS (kevinmonin72.github.io/offline-security-audit)

function injectReports() {
    // On récupère tous les liens de la liste d'URLs
    const urlItems = document.querySelectorAll('.url-item a');
    if (urlItems.length === 0) return;

    chrome.storage.local.get(null, (items) => {
        urlItems.forEach(link => {
            try {
                const hostname = new URL(link.href).hostname.replace(/^www\./, '');
                
                // Recherche flexible pour gérer les différences www. et https://
                const reportKey = Object.keys(items).find(k => k.startsWith('report_') && k.includes(hostname));
                const jsonKey = Object.keys(items).find(k => k.startsWith('json_') && k.includes(hostname));
                
                if (reportKey && items[reportKey]) {
                    // Conteneur pour les boutons
                    let btnContainer = link.parentElement.querySelector('.localsec-btns');
                    if (!btnContainer) {
                        btnContainer = document.createElement('div');
                        btnContainer.className = 'localsec-btns';
                        btnContainer.style.marginLeft = 'auto';
                        btnContainer.style.display = 'flex';
                        btnContainer.style.gap = '8px';
                        link.parentElement.appendChild(btnContainer);
                    }

                    // Bouton Rapport Technique
                    if (!btnContainer.querySelector('.view-report-btn')) {
                        const btn = document.createElement('button');
                        btn.className = 'btn secondary view-report-btn';
                        btn.textContent = '📄 Rapport';
                        btn.style.padding = '4px 10px';
                        btn.style.fontSize = '0.85rem';
                        
                        btn.addEventListener('click', (e) => {
                            e.preventDefault();
                            const blob = new Blob([items[reportKey]], { type: 'text/html' });
                            const blobUrl = URL.createObjectURL(blob);
                            window.open(blobUrl, '_blank');
                        });
                        btnContainer.appendChild(btn);
                    }

                    // Bouton Email Prospection
                    if (jsonKey && items[jsonKey] && !btnContainer.querySelector('.view-email-btn')) {
                        const emailBtn = document.createElement('button');
                        emailBtn.className = 'btn primary view-email-btn';
                        emailBtn.textContent = '📧 Email';
                        emailBtn.style.padding = '4px 10px';
                        emailBtn.style.fontSize = '0.85rem';
                        emailBtn.style.backgroundColor = '#8b5cf6'; // Violet pour différencier
                        emailBtn.style.borderColor = '#8b5cf6';
                        
                        emailBtn.addEventListener('click', (e) => {
                            e.preventDefault();
                            // Déclencher un événement global sur la page pour que app.js l'attrape
                            window.dispatchEvent(new CustomEvent('ShowLocalsecEmail', {
                                detail: items[jsonKey]
                            }));
                        });
                        btnContainer.appendChild(emailBtn);
                    }
                }
            } catch(e) {}
        });
    });
}

// Lancer l'injection
injectReports();

// Surveiller les changements dans le DOM (quand la liste se charge asynchronement)
const observer = new MutationObserver(() => {
    injectReports();
});

observer.observe(document.body, { childList: true, subtree: true });

// Écouter les changements dans le storage (si l'utilisateur lance un audit pendant que le SaaS est ouvert)
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local') {
        injectReports();
    }
});
