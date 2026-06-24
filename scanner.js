const fs = require('fs');
const puppeteer = require('puppeteer');
const nodemailer = require('nodemailer');
const { Sequelize, DataTypes } = require('sequelize');

// 4. La Persistance des Données (SQLite)
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite',
  logging: false
});

const ScanResult = sequelize.define('ScanResult', {
  domain: DataTypes.STRING,
  score: DataTypes.INTEGER,
  emails: DataTypes.STRING
});

// 5. Le Moteur d'Alerte / E-mail
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.example.com",
  port: process.env.SMTP_PORT || 587,
  auth: { 
      user: process.env.SMTP_USER || "user", 
      pass: process.env.SMTP_PASS || "pass" 
  }
});

async function sendAlertEmail(targetEmail, domain, score) {
  try {
    await transporter.sendMail({
      from: '"Bot Sécurité" <bot@example.com>',
      to: targetEmail,
      subject: `Alerte Sécurité : ${domain}`,
      text: `Bonjour, nous avons analysé ${domain} et détecté un score de sécurité faible (${score}/100).`
    });
    console.log(`[Email] Alerte envoyée à ${targetEmail}`);
  } catch (error) {
    console.error(`[Email] Configuration SMTP manquante ou erreur:`, error.message);
  }
}

// 2. Le Moteur de Navigation Autonome & 3. Extraction de Contacts
async function scanUrl(browser, url) {
  console.log(`\n--- Début du scan: ${url} ---`);
  const page = await browser.newPage();
  let score = 100;
  let emails = new Set();
  
  try {
    const response = await page.goto(url, { waitUntil: 'networkidle2' });
    
    // Logique d'évaluation basique des headers de sécurité
    const headers = response.headers();
    if (!headers['strict-transport-security']) score -= 20;
    if (!headers['content-security-policy']) score -= 20;
    if (!headers['x-frame-options']) score -= 10;
    
    // Extraction d'e-mails via Regex
    const content = await page.content();
    const emailRegex = /[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+/g;
    const found = content.match(emailRegex);
    if (found) found.forEach(e => emails.add(e));
    
    // S'il n'y a pas d'e-mail, chercher la page contact ou mentions légales
    if (emails.size === 0) {
      console.log(`[Scraping] Recherche de la page contact/mentions légales...`);
      const links = await page.$$eval('a', as => as.map(a => a.href).filter(href => 
        href.toLowerCase().includes('contact') || href.toLowerCase().includes('mentions')
      ));
      if (links.length > 0) {
        await page.goto(links[0], { waitUntil: 'networkidle2' });
        const subContent = await page.content();
        const subFound = subContent.match(emailRegex);
        if (subFound) subFound.forEach(e => emails.add(e));
      }
    }
    
    const emailList = Array.from(emails).join(', ');
    console.log(`[Résultat] Score: ${score}/100 | E-mails: ${emailList || 'Aucun trouvé'}`);
    
    // 4. Persistance
    await ScanResult.create({ domain: url, score, emails: emailList });
    
    // 5. Alerte
    if (score < 80 && emails.size > 0) {
      const targetEmail = Array.from(emails)[0];
      await sendAlertEmail(targetEmail, url, score);
    }
  } catch (error) {
    console.error(`[Erreur] Impossible de scanner ${url}:`, error.message);
  } finally {
    await page.close();
  }
}

// 6. Le Gestionnaire de Flux (Queue/Orchestrateur)
async function startScanner() {
  await sequelize.sync(); // Crée la table SQLite si elle n'existe pas
  
  const filePath = 'urls-trouvees.txt';
  if (!fs.existsSync(filePath)) {
    console.log(`Création du fichier de file d'attente ${filePath}...`);
    fs.writeFileSync(filePath, 'https://example.com\nhttps://github.com');
  }

  const urls = fs.readFileSync(filePath, 'utf-8').split('\n').map(l => l.trim()).filter(Boolean);
  
  if (urls.length === 0) {
    console.log('Aucune URL à scanner dans urls-trouvees.txt');
    return;
  }

  // Instanciation du navigateur autonome
  const browser = await puppeteer.launch({ headless: 'new' });
  
  for (const url of urls) {
    await scanUrl(browser, url);
  }
  
  await browser.close();
  console.log('\nScan complet terminé. Les résultats sont sauvegardés dans database.sqlite');
}

startScanner();
