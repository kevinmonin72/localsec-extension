// Ce script est injecté par l'extension Chrome dans le SaaS (kevinmonin72.github.io/offline-security-audit)

function injectReports() {
    // On récupère tous les liens de la liste d'URLs
    const urlItems = document.querySelectorAll('.url-item a');
    if (urlItems.length === 0) return;

    chrome.storage.local.get(null, (items) => {
        urlItems.forEach(link => {
            try {
                const url = new URL(link.href).origin;
                const reportKey = 'report_' + url;
                
                if (items[reportKey]) {
                    // Si on a un rapport en mémoire et qu'on n'a pas encore injecté le bouton
                    if (!link.parentElement.querySelector('.view-report-btn')) {
                        const btn = document.createElement('button');
                        btn.className = 'btn secondary view-report-btn';
                        btn.textContent = '📄 Voir le Rapport';
                        btn.style.marginLeft = 'auto';
                        btn.style.padding = '4px 10px';
                        btn.style.fontSize = '0.85rem';
                        
                        btn.addEventListener('click', (e) => {
                            e.preventDefault();
                            const blob = new Blob([items[reportKey]], { type: 'text/html' });
                            const blobUrl = URL.createObjectURL(blob);
                            window.open(blobUrl, '_blank');
                        });
                        
                        link.parentElement.appendChild(btn);
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
