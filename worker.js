const amqp = require('amqplib');
const puppeteer = require('puppeteer');

async function processAudit(url) {
    const extensionPath = '/Users/kevinmonin/Desktop/LocalSec-Extension';
    const browser = await puppeteer.launch({
        headless: false,
        args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`
        ]
    });
    
    const page = await browser.newPage();
    try {
        await page.goto(url);
        console.log(`[Worker] Audit en cours pour : ${url}`);
        // Temps pour laisser l'extension faire son audit
        await new Promise(r => setTimeout(r, 5000));
        console.log(`[Worker] Audit terminé pour : ${url}`);
    } catch (e) {
        console.error(`[Worker] Erreur sur ${url}:`, e.message);
    } finally {
        await browser.close();
    }
}

async function startWorker() {
    const queue = 'audit_queue';
    try {
        // Connexion à RabbitMQ (localhost par défaut)
        const connection = await amqp.connect('amqp://localhost');
        const channel = await connection.createChannel();

        await channel.assertQueue(queue, { durable: true });
        
        // Traiter un seul message à la fois pour ne pas surcharger la machine de navigateurs
        channel.prefetch(1);

        console.log(`[*] Worker prêt. En attente de messages dans ${queue}. Pour quitter: CTRL+C`);

        channel.consume(queue, async (msg) => {
            if (msg !== null) {
                const url = msg.content.toString();
                console.log(`[x] Nouvelle tâche reçue : ${url}`);
                
                try {
                    await processAudit(url);
                    // Accuser réception (Ack) une fois le navigateur fermé
                    channel.ack(msg);
                } catch (error) {
                    console.error("[x] Erreur critique lors du traitement:", error);
                    // Rejeter le message pour le remettre dans la file si nécessaire
                    channel.nack(msg);
                }
            }
        });
    } catch (error) {
        console.error("Erreur de connexion à RabbitMQ. Le service RabbitMQ est-il lancé sur votre machine ?", error.message);
    }
}

startWorker();
