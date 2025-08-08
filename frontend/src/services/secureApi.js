import * as SecureKeyManager from '../utils/SecureKeyManager';

// Unified secure request handler for all middleware requests
export async function secureRequest({ target, payload, pin }) {
    console.log('[secureRequest] Start');
    console.log('[secureRequest] Input:', { target, payload, pin: !!pin });

    let identityKeyPair, publicKeyPem;

    // Step 1: Retrieve or generate identity keypair
    try {
        console.log('[KeyPair] Attempting to fetch encrypted private key...');
        const { encrypted, salt, iv } = await SecureKeyManager.fetchEncryptedPrivateKey();
        console.log('[KeyPair] Encrypted private key fetched:', { encrypted, salt, iv });

        identityKeyPair = await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);
        console.log('[KeyPair] Private key decrypted successfully:', identityKeyPair);

        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        console.log('[KeyPair] Public key PEM exported:', publicKeyPem);
    } catch (err) {
        console.warn('[KeyPair] Failed to fetch/decrypt private key. Generating new keypair. Error:', err);

        identityKeyPair = await SecureKeyManager.generateSigningKeyPair();
        console.log('[KeyPair] New signing keypair generated:', identityKeyPair);

        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        console.log('[KeyPair] Public key PEM exported:', publicKeyPem);

        const { encrypted, salt, iv } = await SecureKeyManager.encryptPrivateKey(identityKeyPair.privateKey, pin);
        console.log('[KeyPair] Private key encrypted:', { encrypted, salt, iv });

        await SecureKeyManager.saveEncryptedPrivateKey(encrypted, salt, iv);
        console.log('[KeyPair] Encrypted private key saved.');
    }

    // Step 2: Fetch server public key
    console.log('[ServerKey] Fetching server public key...');
    const serverPublicKey = await SecureKeyManager.getServerPublicKey();
    console.log('[ServerKey] Server public key imported:', serverPublicKey);

    // Step 3: Generate ephemeral key pair for session
    console.log('[EphemeralKey] Generating ephemeral key pair...');
    const ephemeralKeyPair = await SecureKeyManager.generateEphemeralKeyPair();
    console.log('[EphemeralKey] Ephemeral key pair generated:', ephemeralKeyPair);

    const ephemeralPubkey = SecureKeyManager.toBase64(
        await window.crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey)
    );
    console.log('[EphemeralKey] Ephemeral public key (base64):', ephemeralPubkey);

    // Step 4: Derive shared secret and session key
    console.log('[Session] Deriving shared secret...');
    const sharedSecret = await SecureKeyManager.deriveSharedSecret(
        ephemeralKeyPair.privateKey,
        serverPublicKey
    );
    console.log('[Session] Shared secret derived:', sharedSecret);

    console.log('[Session] Deriving session key...');
    const sessionKey = await SecureKeyManager.deriveSessionKey(sharedSecret);
    console.log('[Session] Session key derived:', sessionKey);

    // Step 5: Prepare payload to sign
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    console.log('[Payload] Timestamp:', timestamp, 'Nonce:', nonce);

    const signPayloadDict = {
        transaction_data: payload,
    };
    console.log('[Payload] Data to sign:', signPayloadDict);

    const canonicalJson = SecureKeyManager.canonicalizeJson(signPayloadDict);
    console.log('[Payload] Canonical JSON to sign:', canonicalJson);

    const clientSignature = await SecureKeyManager.signTransaction(signPayloadDict, identityKeyPair.privateKey);
    console.log('[Payload] Client signature (base64):', clientSignature);

    // Step 6: Build secure payload
    const securePayload = {
        target,
        transaction_data: payload,
        client_signature: clientSignature,
        client_public_key: publicKeyPem,
        nonce,
    };
    console.log('[Payload] Secure payload (before encryption):', securePayload);

    // Step 7: Encrypt payload
    console.log('[Encryption] Encrypting payload...');
    const { ciphertext, iv } = await SecureKeyManager.encryptPayload(securePayload, sessionKey);
    console.log('[Encryption] Encrypted payload:', { ciphertext, iv });

    // Step 8: Send to backend
    const SECURECIPHER_MIDDLEWARE_GATEWAY_URL = 'http://localhost:8000/api/secure/gateway/';
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL) {
        throw new Error('[Config] SECURECIPHER_MIDDLEWARE_GATEWAY_URL is not defined in environment variables');
    }
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL.startsWith('http')) {
        throw new Error('[Config] SECURECIPHER_MIDDLEWARE_GATEWAY_URL must start with http:// or https://');
    }

    console.log('[Network] Sending encrypted payload to backend:', SECURECIPHER_MIDDLEWARE_GATEWAY_URL);
    const res = await fetch(SECURECIPHER_MIDDLEWARE_GATEWAY_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
        body: JSON.stringify({
            ephemeral_pubkey: ephemeralPubkey,
            ciphertext,
            iv
        }),
        credentials: 'same-origin'
    });

    // Step 9: Handle response
    const responseData = await res.json();
    console.log('[Network] Response data from backend:', responseData);

    if (!res.ok) {
        let errorMsg = 'An unknown error occurred.';
        try {
            console.log('[Network] Attempting to decrypt error response...');
            const decryptedError = await SecureKeyManager.decryptResponse(responseData, sessionKey);
            errorMsg = decryptedError.error || errorMsg;
            console.error('[Network] Decrypted error from backend:', decryptedError);
        } catch (e) {
            errorMsg = e.message || errorMsg;
            console.error('[Network] Failed to decrypt error response:', e);
        }
        throw new Error(`[${res.status}] ${errorMsg}`);
    }

    console.log('[Network] Decrypting backend response...');
    const decryptedResponse = await SecureKeyManager.decryptResponse(responseData, sessionKey);
    console.log('[Network] Decrypted response from backend:', decryptedResponse);

    console.log('[secureRequest] End');
    return decryptedResponse;
}