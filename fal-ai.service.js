import crypto from 'crypto';
import sodium from 'libsodium-wrappers';
import fetch from 'node-fetch';

const JWKS_URL = 'https://rest.alpha.fal.ai/.well-known/jwks.json';
const JWKS_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
let jwksCache = null;
let jwksCacheTime = 0;

async function fetchJwks() {
    const currentTime = Date.now();
    if (!jwksCache || (currentTime - jwksCacheTime) > JWKS_CACHE_DURATION) {
        const response = await fetch(JWKS_URL, { timeout: 10000 });
        if (!response.ok) throw new Error(`JWKS fetch failed: ${response.status}`);
        jwksCache = (await response.json()).keys || [];
        jwksCacheTime = currentTime;
    }
    return jwksCache;
}

export async function verifyWebhookSignature(requestId, userId, timestamp, signatureHex, body) {
    /*
     * Verify a webhook signature using provided headers and body.
     *
     * @param {string} requestId - Value of x-fal-webhook-request-id header.
     * @param {string} userId - Value of x-fal-webhook-user-id header.
     * @param {string} timestamp - Value of x-fal-webhook-timestamp header.
     * @param {string} signatureHex - Value of x-fal-webhook-signature header (hex-encoded).
     * @param {Buffer} body - Raw request body as a Buffer.
     * @returns {Promise<boolean>} True if the signature is valid, false otherwise.
     */
    await sodium.ready;

    // Validate timestamp (within ±5 minutes)
    // try {
    //     const timestampInt = parseInt(timestamp, 10);
    //     const currentTime = Math.floor(Date.now() / 1000);
    //     if (Math.abs(currentTime - timestampInt) > 300) {
    //         console.error('Timestamp is too old or in the future.');
    //         return false;
    //     }
    // } catch (e) {
    //     console.error('Invalid timestamp format:', e);
    //     return false;
    // }

    // Construct the message to verify
    try {
        const messageParts = [
            requestId,
            userId,
            timestamp,
            crypto.createHash('sha256').update(body).digest('hex')
        ];
        if (messageParts.some(part => part == null)) {
            console.error('Missing required header value.');
            return false;
        }
        const messageToVerify = messageParts.join('\n');
        const messageBytes = Buffer.from(messageToVerify, 'utf-8');

        // Decode signature
        let signatureBytes;
        try {
            signatureBytes = Buffer.from(signatureHex, 'hex');
        } catch (e) {
            console.error('Invalid signature format (not hexadecimal).');
            return false;
        }

        // Fetch public keys
        let publicKeysInfo;
        try {
            publicKeysInfo = await fetchJwks();
            if (!publicKeysInfo.length) {
                console.error('No public keys found in JWKS.');
                return false;
            }
        } catch (e) {
            console.error('Error fetching JWKS:', e);
            return false;
        }

        // Verify signature with each public key
        for (const keyInfo of publicKeysInfo) {
            try {
                const publicKeyB64Url = keyInfo.x;
                if (typeof publicKeyB64Url !== 'string') continue;
                const publicKeyBytes = Buffer.from(publicKeyB64Url, 'base64url');
                const isValid = sodium.crypto_sign_verify_detached(signatureBytes, messageBytes, publicKeyBytes);
                if (isValid) return true;
            } catch (e) {
                console.error('Verification failed with a key:', e);
                continue;
            }
        }

        console.error('Signature verification failed with all keys.');
        return false;
    } catch (e) {
        console.error('Error constructing message:', e);
        return false;
    }
}

async function main() {
    console.log('');
    const requestId = '5057fca7-2eb3-468f-b95d-cefe92b0b9d4'
    const userId = '';
    const timestamp = '1752019770';
    const signatureHex = '5d3f11a2d1a63d9af92b8005135b1f8f955aa55fcf6d0d207091402b10ee557483bfcd3a54c7d870434498f1aa05574d169655d50fa4d8a3f0f99e43f19e090e'

    const body = '{"error": null, "gateway_request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "payload": {"has_nsfw_concepts": [false], "images": [{"content_type": "image/jpeg", "height": 1024, "url": "https://v3.fal.media/files/lion/O853qAknYZGU8_2QCbJwd.jpeg", "width": 1024}], "prompt": "dog", "seed": 17454220438242315174, "timings": {"inference": 2.107286686077714}}, "request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "status": "OK"}';

    const isValid = await verifyWebhookSignature(requestId, userId, timestamp, signatureHex, body)
    console.log('Signature valid:', isValid);
        
}

// main(); //TODO(): Uncomment to run example