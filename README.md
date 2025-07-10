# fal-ai-signature-verification

A Node.js library for verifying Fal.ai webhook signatures. This project provides both JavaScript and TypeScript implementations.

## Installation

```bash
npm install
```

## Usage

### Running the JavaScript version

```bash
node index.js
```

### Running the TypeScript version

```bash
npx ts-node index.ts
```

### Running a local server for webhook testing

You can also run a local Express server to receive and verify webhooks.

To start the server (TypeScript):

```bash
npm run dev
```

The server will listen for POST requests at:

```
POST /api/v1/hook/fal-ai/images
```

It expects raw body and the following headers:
- `x-fal-webhook-request-id`
- `x-fal-webhook-user-id`
- `x-fal-webhook-timestamp`
- `x-fal-webhook-signature`

The server will verify the signature and respond with a 200 status if valid, or 401 if invalid.

## How it works

The library verifies webhook signatures by:

1. Fetching public keys from Fal.ai's JWKS endpoint
2. Constructing the message to verify from request headers and body
3. Verifying the signature

## Example

This is an example of how to use the library for signature verification with sample data:

```javascript
const requestId = '5057fca7-2eb3-468f-b95d-cefe92b0b9d4';
const userId = ''; //Put your userId
const timestamp = '1752019770';
const signatureHex = '5d3f11a2d1a63d9af92b8005135b1f8f955aa55fcf6d0d207091402b10ee557483bfcd3a54c7d870434498f1aa05574d169655d50fa4d8a3f0f99e43f19e090e';
const body = '{"error": null, "gateway_request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", ...}';

const isValid = await verifyWebhookSignature(requestId, userId, timestamp, signatureHex, body);
console.log('Signature valid:', isValid);
```

## Dependencies

- `libsodium-wrappers`: For Ed25519 signature verification
- `node-fetch`: For HTTP requests to JWKS endpoint
- `express` and `body-parser`: For running the webhook server
- `typescript` and `ts-node`: For TypeScript support (dev dependencies)
