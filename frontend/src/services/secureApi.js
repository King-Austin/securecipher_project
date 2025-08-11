import * as SecureKeyManager from '../utils/SecureKeyManager';
import { API_ENDPOINTS } from '../config/apiConfig';

// Special secure request handler ONLY for registration (can generate new keypairs)
export async function secureRegistrationRequest({ target, payload, pin }) {
    console.log('[secureRegistrationRequest] Start - Registration Only');
    console.log('[secureRegistrationRequest] Input:', { target, payload, pin: !!pin });

    if (target !== 'register') {
        throw new Error('secureRegistrationRequest can only be used for registration');
    }

    let identityKeyPair, publicKeyPem;

    // Step 1: Always generate new keypair for registration (discard any existing key)
    console.log('[KeyPair] Registration: Generating fresh keypair (discarding any existing key)');
    
    // Generate new keypair for registration
    identityKeyPair = await SecureKeyManager.generateSigningKeyPair();
    console.log('[KeyPair] New signing keypair generated for registration');

    publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
    console.log('[KeyPair] Public key PEM exported');

    const { encrypted, salt, iv } = await SecureKeyManager.encryptPrivateKey(identityKeyPair.privateKey, pin);
    console.log('[KeyPair] Private key encrypted with PIN');

    // Clear any existing key data and save the new one atomically
    try {
        await SecureKeyManager.clearAllKeyData();
        console.log('[KeyPair] Existing key cleared to prevent duplicates');
        
        // Wait a moment for database cleanup to complete
        await new Promise(resolve => setTimeout(resolve, 100));
        
        await SecureKeyManager.saveEncryptedPrivateKey(encrypted, salt, iv);
        console.log('[KeyPair] Encrypted private key saved to IndexedDB');
    } catch (saveErr) {
        console.log('[KeyPair] Error during key save, retrying with fresh database connection:', saveErr.message);
        
        // If save fails, try one more time with a fresh connection
        try {
            await SecureKeyManager.saveEncryptedPrivateKey(encrypted, salt, iv);
            console.log('[KeyPair] Encrypted private key saved to IndexedDB (retry successful)');
        } catch (retryErr) {
            console.error('[KeyPair] Failed to save encrypted key after retry:', retryErr);
            throw new Error('Failed to save cryptographic keys. Please try registration again.');
        }
    }

    // Continue with the rest of the secure request process...
    return await performSecureRequest(target, payload, identityKeyPair, publicKeyPem);
}

// Standard secure request handler (NEVER generates new keypairs)
export async function secureRequest({ target, payload, pin }) {
    console.log('[secureRequest] Start');
    console.log('[secureRequest] Input:', { target, payload, pin: !!pin });

    if (target === 'register') {
        throw new Error('Use secureRegistrationRequest for registration, not secureRequest');
    }

    let identityKeyPair, publicKeyPem;

    // Step 1: Retrieve and decrypt identity keypair (never generate new ones)
    try {
        console.log('[KeyPair] Attempting to fetch encrypted private key...');
        const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
        console.log('[KeyPair] Encrypted private key fetched:', { encrypted: !!keyData?.encrypted, salt: !!keyData?.salt, iv: !!keyData?.iv });

        if (!keyData || !keyData.encrypted || !keyData.salt || !keyData.iv) {
            throw new Error('No encrypted key found. Please register or login first.');
        }

        identityKeyPair = await SecureKeyManager.decryptPrivateKey(keyData.encrypted, pin, keyData.salt, keyData.iv);
        console.log('[KeyPair] Private key decrypted successfully');

        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        console.log('[KeyPair] Public key PEM exported:', publicKeyPem);
    } catch (err) {
        console.error('[KeyPair] Failed to fetch/decrypt private key:', err);
        
        // Never generate new keypairs - throw the error to let user retry
        if (err.message.includes('Invalid PIN')) {
            throw new Error('Invalid PIN. Please enter the correct PIN.');
        } else if (err.message.includes('No encrypted key')) {
            throw new Error('No cryptographic keys found. Please register or login first.');
        } else if (err.message.includes('Corrupted key')) {
            throw new Error('Key data is corrupted. Please register again.');
        } else {
            throw new Error('Authentication failed. Please check your PIN and try again.');
        }
    }

    return await performSecureRequest(target, payload, identityKeyPair, publicKeyPem);
}

// Shared function to perform the actual secure request
async function performSecureRequest(target, payload, identityKeyPair, publicKeyPem) {

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
    console.log('[Network] Sending encrypted payload to backend:', API_ENDPOINTS.MIDDLEWARE_GATEWAY);
    const res = await fetch(API_ENDPOINTS.MIDDLEWARE_GATEWAY, {
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
        console.log('[Network] Attempting to decrypt error response...');
        try {
            const decryptedError = await SecureKeyManager.decryptResponse(responseData, sessionKey);
            console.error('[Network] Decrypted error from backend:', decryptedError);
            // Throw the raw payload so frontend can inspect field errors
            throw decryptedError;
        } catch (e) {
            const errorMsg = e.message || 'An unknown error occurred.';
            throw new Error(`HTTP ${res.status}: ${errorMsg}`);
        }
    }

    console.log('[Network] Decrypting backend response...');
    const decryptedResponse = await SecureKeyManager.decryptResponse(responseData, sessionKey);
    console.log('[Network] Decrypted response from backend:', decryptedResponse);

    console.log('[performSecureRequest] End');
    return decryptedResponse;
}