const express = require('express');
const bodyParser = require('body-parser');

const { verifyWebhookSignature } = require('./fal-ai.service.js');

const app = express();

app.use('/api/v1/hook/fal-ai/images', bodyParser.raw({ type: 'application/json' }));

app.post('/api/v1/hook/fal-ai/images', async (req, res) => {
    const rawBody = req.body;
    const requestId = req.header('x-fal-webhook-request-id');
    const userId = req.header('x-fal-webhook-user-id');
    const timestamp = req.header('x-fal-webhook-timestamp');
    const signature = req.header('x-fal-webhook-signature');

    console.log('Received webhook');
    console.log('Raw Body:', rawBody);
    console.log('Request ID:', requestId);
    console.log('User ID:', userId);
    console.log('Timestamp:', timestamp);
    console.log('Signature:', signature);

    if (!requestId || !userId || !timestamp || !signature) {
        console.error('Missing required webhook headers');
        res.status(400).json({ error: 'Missing headers' });
        return;
    }

    const isValid = await verifyWebhookSignature(requestId, userId, timestamp, signature, rawBody);
    console.log('Signature valid:', isValid);

    if (!isValid) {
        res.status(401).json({ error: 'Invalid signature' });
        return;
    }

    res.status(200).json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});
