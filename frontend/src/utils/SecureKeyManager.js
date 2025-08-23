// Replace with more robust base64 implementation
export function toBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function fromBase64(base64String) {
  const binaryString = atob(base64String);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// --- Key Generation ---
export async function generateSigningKeyPair() {
    return await window.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify']
    );
}


export async function generateEphemeralKeyPair() {
    return await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        ['deriveKey', 'deriveBits']
    );
}





// --- Key Export/Import ---
export async function exportPublicKeyAsPem(publicKey) {
    const spki = await window.crypto.subtle.exportKey('spki', publicKey);
    const b64 = toBase64(spki);
    return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}
export async function importServerPublicKey(pem) {
    // Remove header/footer and whitespace
    const pemContents = pem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s+/g, '');
    const binaryDer = fromBase64(pemContents);
    return await window.crypto.subtle.importKey(
        'spki',
        binaryDer,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
    );
}

// --- Shared Secret & Session Key ---
export async function deriveSharedSecret(privateKey, publicKey) {
    return await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: publicKey },
        privateKey,
        384
    );
}
export async function deriveSessionKey(sharedSecret) {
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'HKDF' },
        false,
        ['deriveKey']
    );

    
    return await window.crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-384',
            salt: new TextEncoder().encode('secure-session-salt'), // Add proper salt
            info: new TextEncoder().encode('secure-cipher-session-key')
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

// --- Canonical JSON ---
// Recursively sort all keys in an object for canonicalization
function sortKeysRecursively(obj) {
    if (Array.isArray(obj)) {
        return obj.map(sortKeysRecursively);
    } else if (obj !== null && typeof obj === 'object') {
        const sorted = {};
        Object.keys(obj).sort().forEach(key => {
            sorted[key] = sortKeysRecursively(obj[key]);
        });
        return sorted;
    }
    return obj;
}

export function canonicalizeJson(obj) {
    if (obj === null || typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return `[${obj.map(canonicalizeJson).join(',')}]`;
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => `"${k}":${canonicalizeJson(obj[k])}`);
    return `{${pairs.join(',')}}`;
}


// --- Signing ---
export async function signTransaction(payload, privateKey) {
    console.log('signTransaction received payload:', JSON.stringify(payload, null, 2));
    if (payload && payload.transaction_data && Object.keys(payload.transaction_data).length === 0) {
        console.warn('signTransaction: transaction_data is EMPTY!');
    }
    const canonicalJson = canonicalizeJson(payload);
    console.log('Signing data (canonical JSON):', canonicalJson);

    const data = new TextEncoder().encode(canonicalJson);
    console.log('Signing data (UTF-8 bytes):', Array.from(data));

    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('data hash (SHA-384):', hashHex);

    // Sign the data using ECDSA with SHA-384
    const signature = await window.crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-384' } },
        privateKey,
        data
    );
    const signatureBase64 = toBase64(signature);
    console.log('Signature (base64):', signatureBase64);

    return signatureBase64;
}

// --- Encryption/Decryption ---
export async function encryptPayload(payload, sessionKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        sessionKey,
        encodedPayload
    );
    return {
        ciphertext: toBase64(ciphertext),
        iv: toBase64(iv)
    };
}
export async function decryptResponse(encryptedResponse, sessionKey) {
    const iv = fromBase64(encryptedResponse.iv);
    const ciphertext = fromBase64(encryptedResponse.ciphertext);
    const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        sessionKey,
        ciphertext
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
}

// --- Secure Private Key Storage (using idb) ---
import { openDB } from 'idb';

// Function to create/recreate database connection
function createDbConnection() {
    return openDB('secure-cipher-bank', 2, {
        upgrade(db, oldVersion) {
            console.log('Upgrading database from version', oldVersion, 'to version 2');
            if (!db.objectStoreNames.contains('keys')) {
                db.createObjectStore('keys');
                console.log('Created keys object store');
            }
        }
    });
}

// Shared database instance
let dbPromise = createDbConnection();

export async function saveEncryptedPrivateKey(encrypted, salt, iv) {
    try {
        let db = await dbPromise;
        return await db.put('keys', { encrypted, salt, iv }, 'user-private-key');
    } catch (error) {
        console.error('Error saving encrypted private key:', error);
        
        // If the database connection is invalid, recreate it
        if (error.name === 'InvalidStateError' && error.message.includes('closing')) {
            console.log('Database connection was closed, recreating connection...');
            dbPromise = createDbConnection();
            const db = await dbPromise;
            return await db.put('keys', { encrypted, salt, iv }, 'user-private-key');
        }
        
        throw error;
    }
}

export async function fetchEncryptedPrivateKey() {
    try {
        let db = await dbPromise;
        return await db.get('keys', 'user-private-key');
    } catch (error) {
        console.error('Error fetching encrypted private key:', error);
        
        // If the database connection is invalid, recreate it and try again
        if (error.name === 'InvalidStateError' && error.message.includes('closing')) {
            console.log('Database connection was closed, recreating connection...');
            dbPromise = createDbConnection();
            const db = await dbPromise;
            return await db.get('keys', 'user-private-key');
        }
        
        throw error;
    }
}


// --- Encrypt/Decrypt Private Key with PIN ---
export async function deriveEncryptionKey(pin, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(pin),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

export async function encryptPrivateKey(privateKey, pin) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveEncryptionKey(pin, salt);
    const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        pkcs8
    );
    return { encrypted, salt, iv };
}

export async function decryptPrivateKey(encrypted, pin, salt, iv) {
    try {
        
        const key = await deriveEncryptionKey(pin, salt);
        const pkcs8 = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encrypted
        );
        const privateKey = await window.crypto.subtle.importKey(
            'pkcs8',
            pkcs8,
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign']
        );
        
        // Extract the public key from the private key using JWK
        const keyData = await window.crypto.subtle.exportKey('jwk', privateKey);
        
        // Create public key JWK by removing private parts
        const publicKeyJwk = {
            kty: keyData.kty,
            crv: keyData.crv,
            x: keyData.x,
            y: keyData.y,
            use: 'sig',
            key_ops: ['verify']
        };
        
        // Import as public key
        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['verify']
        );
        
        return { privateKey, publicKey };
    } catch (error) {
        if (error.name === 'OperationError' || error.message.includes('decrypt')) {
            throw new Error('Invalid PIN. Please try again.');
        } else if (error.name === 'InvalidAccessError') {
            throw new Error('Corrupted key data. Please re-register.');
        } else {
            throw new Error('Decryption failed. Please try again.');
        }
    }
}

// Import API configuration
import { API_ENDPOINTS } from '../config/apiConfig';

export async function getServerPublicKey() {
    const res = await fetch(API_ENDPOINTS.MIDDLEWARE_PUBLIC_KEY);
    const pem = await res.json();
    return await importServerPublicKey(pem.public_key);
}