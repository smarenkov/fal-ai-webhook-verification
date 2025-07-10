import crypto from 'crypto';
import sodium from 'libsodium-wrappers';
import fetch from 'node-fetch';

// JSON Web Key representation
export interface JwkKey {
    kty: string;
    crv: string;
    x: string;
    kid?: string;
    [key: string]: unknown;
}

const JWKS_URL = 'https://rest.alpha.fal.ai/.well-known/jwks.json';
const JWKS_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24h in ms
let jwksCache: JwkKey[] | null = null;
let jwksCacheTime = 0;

/**
 * Fetch and cache JWKS
 */
export async function fetchJwks(): Promise<JwkKey[]> {
    const now = Date.now();
    if (!jwksCache || now - jwksCacheTime > JWKS_CACHE_DURATION) {
        const res = await fetch(JWKS_URL);
        if (!res.ok) {
            throw new Error(`JWKS fetch failed: ${res.status}`);
        }
        const json = (await res.json()) as { keys?: JwkKey[] };
        jwksCache = json.keys ?? [];
        jwksCacheTime = now;
    }
    return jwksCache;
}

/**
 * Verify Fal.ai webhook signature
 */
export async function verifyWebhookSignature(
    requestId: string,
    userId: string,
    timestamp: string,
    signatureHex: string,
    body: Buffer | string
): Promise<boolean> {
    await sodium.ready;

    // Prepare body buffer
    const bodyBuf = Buffer.isBuffer(body)
        ? body
        : Buffer.from(body, 'utf-8');

    // Construct message parts
    const hashHex = crypto.createHash('sha256').update(bodyBuf).digest('hex');
    const parts = [requestId, userId, timestamp, hashHex];
    if (parts.some(p => !p)) {
        console.error('Missing header value');
        return false;
    }
    const message = parts.join('\n');
    const messageBytes = Buffer.from(message, 'utf-8');

    // Decode signature
    let sigBytes: Buffer;
    try {
        sigBytes = Buffer.from(signatureHex, 'hex');
    } catch {
        console.error('Invalid signature format');
        return false;
    }

    // Fetch public keys
    let keys: JwkKey[];
    try {
        keys = await fetchJwks();
        if (!keys.length) {
            console.error('No public keys');
            return false;
        }
    } catch (err) {
        console.error('Failed to fetch JWKS', err);
        return false;
    }

    // Try verification with each key
    for (const key of keys) {
        if (typeof key.x !== 'string') continue;
        try {
            const pubKey = Buffer.from(key.x, 'base64url');
            const valid = sodium.crypto_sign_verify_detached(
                sigBytes,
                messageBytes,
                pubKey
            );
            if (valid) return true;
        } catch (err) {
            console.warn('Key verification error', err);
        }
    }

    console.error('Signature verification failed');
    return false;
}

/** Example usage */
async function main() {
    console.log('');
    const requestId = '5057fca7-2eb3-468f-b95d-cefe92b0b9d4'
    const userId = '';
    const timestamp = '1752019770';
    const signatureHex = '5d3f11a2d1a63d9af92b8005135b1f8f955aa55fcf6d0d207091402b10ee557483bfcd3a54c7d870434498f1aa05574d169655d50fa4d8a3f0f99e43f19e090e'

    const body = '{"error": null, "gateway_request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "payload": {"has_nsfw_concepts": [false], "images": [{"content_type": "image/jpeg", "height": 1024, "url": "https://v3.fal.media/files/lion/O853qAknYZGU8_2QCbJwd.jpeg", "width": 1024}], "prompt": "dog", "seed": 17454220438242315174, "timings": {"inference": 2.107286686077714}}, "request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "status": "OK"}';
    
    const isValid = await verifyWebhookSignature(
        requestId,
        userId,
        timestamp,
        signatureHex,
        body
    );
    console.log('Signature valid:', isValid);
}

// main(); //TODO(): Uncomment to run example
