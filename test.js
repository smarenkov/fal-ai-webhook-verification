const { verifyWebhookSignature } = require('./fal-ai.service.js');

async function main() {
    const requestId = '5057fca7-2eb3-468f-b95d-cefe92b0b9d4'
    const userId = '';
    const timestamp = '1752019770';
    const signatureHex = '5d3f11a2d1a63d9af92b8005135b1f8f955aa55fcf6d0d207091402b10ee557483bfcd3a54c7d870434498f1aa05574d169655d50fa4d8a3f0f99e43f19e090e'

    const body = '{"error": null, "gateway_request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "payload": {"has_nsfw_concepts": [false], "images": [{"content_type": "image/jpeg", "height": 1024, "url": "https://v3.fal.media/files/lion/O853qAknYZGU8_2QCbJwd.jpeg", "width": 1024}], "prompt": "dog", "seed": 17454220438242315174, "timings": {"inference": 2.107286686077714}}, "request_id": "5057fca7-2eb3-468f-b95d-cefe92b0b9d4", "status": "OK"}';

    const isValid = await verifyWebhookSignature(requestId, userId, timestamp, signatureHex, body)
    console.log('Signature valid:', isValid); 
}

main();