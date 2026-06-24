const amqp = require('amqplib');

async function sendAuditTask(url) {
    const queue = 'audit_queue';
    try {
        const connection = await amqp.connect('amqp://localhost');
        const channel = await connection.createChannel();

        await channel.assertQueue(queue, { durable: true });
        
        // persistent: true indique à RabbitMQ de sauvegarder le message sur le disque en cas de crash
        channel.sendToQueue(queue, Buffer.from(url), { persistent: true });

        console.log(`[x] Tâche d'audit placée dans la file d'attente pour : ${url}`);
        
        setTimeout(() => {
            connection.close();
            process.exit(0);
        }, 500);
    } catch (error) {
        console.error("Erreur de connexion à RabbitMQ:", error.message);
    }
}

const targetUrl = process.argv[2] || 'https://example.com';
sendAuditTask(targetUrl);
