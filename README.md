
# SecureCipher – Cryptographic Workflow Audit

## Overview

SecureCipher is a middleware-driven secure transaction pipeline designed to ensure **confidentiality**, **authenticity**, and **integrity** between a banking frontend client, a middleware gateway, and a banking API.

This document presents a structured audit of the system’s payload flow, cryptographic operations, and verification steps.

---

## Workflow Stages

1. **Frontend → Middleware** (encrypted transaction request)
2. **Middleware → Banking API** (verified transaction forwarding)
3. **Banking API → Middleware → Client** (final response)

---

## 1. Frontend → Middleware

### Incoming Encrypted Payload
```json
{
  "ciphertext": "...",
  "iv": "...",
  "ephemeral_pub_key": "..."
}
```

### Decrypted Inner Payload
```json
{
  "transaction_data": "...",
  "nonce": "...",
  "timestamp": "...",
  "client_ECDSA_public_key": "..."
}
```

### Middleware Processing Steps

- **ECDHE Key Exchange**
  - Middleware uses its static private key and the `ephemeral_pub_key` from the client.
  - Derives a shared symmetric key (via HKDF or similar).
  - Uses derived key + iv to decrypt the ciphertext.

- **Signature Verification**
  - Validate the client’s signature against `transaction_data` using `client_ECDSA_public_key`.
  - If verification fails → respond with `SIG_VERIFY_FAIL` (encrypted response back to client).
  - If verification passes → continue.

- **Replay Protection**
  - Validate `nonce` and `timestamp` to prevent replay attacks and nonce reuse.

- **Middleware Signature Generation**
  - Generate `middleware_signature` over the payload.
  - Construct the verified payload for the Banking API:

    ```json
    {
      "transaction_data": "...",
      "client_signature": "...",
      "client_ECDSA_public_key": "...",
      "middleware_signature": "...",
      "middleware_ECDSA_public_key": "..."
    }
    ```

---

## 2. Middleware → Banking API

### Incoming Payload
```json
{
  "transaction_data": "...",
  "client_signature": "...",
  "client_ECDSA_public_key": "...",
  "middleware_signature": "...",
  "middleware_ECDSA_public_key": "..."
}
```

### Banking API Processing Steps

- **Client Signature Verification**
  - Verify `client_signature` against `transaction_data` using `client_ECDSA_public_key`.

- **Middleware Signature Verification**
  - Verify `middleware_signature` against the payload using `middleware_ECDSA_public_key`.

- **Failure Case**
  - If either signature verification fails:
    - Respond with appropriate error code (`CLIENT_SIG_FAIL`, `MIDDLEWARE_SIG_FAIL`, etc.).
    - Transaction is not processed.

- **Success Case**
  - If both signatures are valid:
    - Transaction is marked authentic and untampered.
    - `transaction_data` is processed according to business logic (e.g., transfer, register, withdraw).
    - Final response is generated.

---

## 3. Banking API → Middleware → Client

### Banking API Response
- Construct success or error response based on transaction processing.
- Send back to Middleware.

### Middleware Response Handling
- Encrypt the response payload using a new ephemeral key + ECDHE with client’s public key.
- Construct secure response:

  ```json
  {
    "ciphertext": "...",
    "iv": "...",
    "ephemeral_pub_key": "..."
  }
  ```

- Send encrypted response to client.

### Client Decryption
- Client performs ECDHE with ephemeral key from Middleware.
- Derives symmetric key and decrypts response.
- Displays result to user.

---

## Security Guarantees

- **Confidentiality:** All payloads are encrypted using ephemeral ECDHE keys.
- **Authenticity:** Dual-signature model enforces trust of both client and middleware.
- **Integrity:** Payload tampering is prevented via signature checks.
- **Replay Protection:** Nonce + timestamp verification ensures requests are unique.
- **End-to-End Trust:** Transactions only succeed when both client and middleware are validated by the Banking API.

---

## Project Reference

**THE SECURECIPHER_CIPHER_PROJECT**
