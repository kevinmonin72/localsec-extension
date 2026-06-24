const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require('@aws-sdk/client-sqs');
const puppeteer = require('puppeteer');
const path = require('path');

const sqsClient = new SQSClient({
    region: process.env.AWS_REGION || 'eu-west-3'
});

const QUEUE_URL = process.env.SQS_QUEUE_URL;

async function processAudit(url) {
    // Le chemin de l'extension est la racine du dépôt GitHub (où le script est exécuté par Actions)
    const extensionPath = process.cwd();
    
    // Sur GitHub Actions (Ubuntu), on utilise headless 'new'
    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`
        ]
    });
    
    const page = await browser.newPage();
    try {
        await page.goto(url);
        console.log(`[Worker] Audit en cours pour : ${url}`);
        // Laissez le temps à l'extension d'agir
        await new Promise(r => setTimeout(r, 5000));
        console.log(`[Worker] Audit terminé pour : ${url}`);
    } catch (e) {
        console.error(`[Worker] Erreur sur ${url}:`, e.message);
    } finally {
        await browser.close();
    }
}

async function startWorker() {
    if (!QUEUE_URL) {
        console.error("Erreur: La variable d'environnement SQS_QUEUE_URL n'est pas définie dans les Secrets GitHub.");
        process.exit(1);
    }

    console.log(`Connexion à la file SQS: ${QUEUE_URL}`);

    const receiveParams = {
        QueueUrl: QUEUE_URL,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 5
    };

    try {
        const data = await sqsClient.send(new ReceiveMessageCommand(receiveParams));
        
        if (data.Messages && data.Messages.length > 0) {
            const message = data.Messages[0];
            const url = message.Body;
            console.log(`[x] Nouvelle tâche SQS reçue : ${url}`);
            
            await processAudit(url);
            
            await sqsClient.send(new DeleteMessageCommand({
                QueueUrl: QUEUE_URL,
                ReceiptHandle: message.ReceiptHandle
            }));
            console.log(`[x] Message supprimé de la file SQS avec succès.`);
        } else {
            console.log("Aucun message dans la file d'attente SQS pour le moment.");
        }
    } catch (err) {
        console.error("Erreur avec SQS:", err);
    }
}

startWorker();
