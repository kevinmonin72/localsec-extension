const puppeteer = require('puppeteer');

async function run() {
    const extensionPath = '/Users/kevinmonin/Desktop/LocalSec-Extension';
    console.log("Lancement du navigateur avec l'extension...");
    
    const browser = await puppeteer.launch({
        headless: false, 
        args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`
        ]
    });
    
    const page = await browser.newPage();
    await page.goto('https://example.com');
    
    console.log('Page chargée. Titre:', await page.title());
    console.log("Le navigateur reste ouvert pour tester l'extension. Fermez-le manuellement pour terminer le script.");
}
run();