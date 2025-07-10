import express, { NextFunction, Request, Response } from 'express';
import bodyParser from 'body-parser';
import { verifyWebhookSignature } from './fal-ai.service';

const app = express();

app.use('/api/v1/hook/fal-ai/images', bodyParser.raw({ type: 'application/json' }));

app.post('/api/v1/hook/fal-ai/images', async (req: Request, res: Response) => {
    const rawBody = req.body as Buffer;
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

    let isValid = await verifyWebhookSignature(requestId, userId, timestamp, signature, rawBody);
    console.log('Signature valid:', isValid);

    if (!isValid) {
        res.status(401).json({ error: 'Invalid signature' });
        return;
    }

    res.status(200).json({ ok: true });
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});