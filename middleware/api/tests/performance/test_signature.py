import base64
import time
import uuid
import pytest
import requests
from cryptography.hazmat.primitives import serialization

from .test_middleware_gateway import (
    generate_ephemeral_key,
    derive_session_key,
    aes_encrypt,
    aes_decrypt,
    ecdsa_sign_transaction_data_only,
)

API_PUBLIC_KEY_URL = "http://localhost:8000/api/public-key"
API_SECURE_GATEWAY = "http://localhost:8000/api/gateway"

def test_tampered_payload_signature_verbose():
    print("\n===  Tampered Payload Signature Test ===")

    # 1. Get middleware public key + session_id
    resp = requests.get(API_PUBLIC_KEY_URL)
    resp.raise_for_status()
    data = resp.json()
    session_id = data["session_id"]
    server_pub_der = base64.b64decode(data["public_key"])
    print(f"[1] Retrieved server public key and session_id: {session_id}")

    # 2. Generate client key + session key
    client_priv, client_pub_der = generate_ephemeral_key()
    session_key = derive_session_key(server_pub_der, client_priv)
    print("[2] Generated client ephemeral key and derived session key ✅")

    # 3. Build original payload
    payload = {
        "transaction_data": {"username": "pytest_user", "amount": 1000},
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "target": "transfer",
    }
    print(f"[3] Built original payload: {payload}")

    # 4. Sign original payload
    payload["client_signature"] = ecdsa_sign_transaction_data_only(payload, client_priv)
    payload["client_public_key"] = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    print("[4] Payload signed with correct private key ✅")

    # 5. 🔥 Tamper payload after signing
    payload["transaction_data"]["amount"] = 999999
    print(f"[5] Tampered payload after signing: {payload}")

    # 6. Encrypt payload
    encrypted = aes_encrypt(payload, session_key)
    body = {
        "ephemeral_pubkey": base64.b64encode(client_pub_der).decode(),
        "ciphertext": encrypted["ciphertext"],
        "iv": encrypted["iv"],
        "session_id": session_id,
    }
    print("[6] Encrypted payload and prepared request body ✅")

    # 7. Send request
    response = requests.post(API_SECURE_GATEWAY, json=body)
    print(f"[7] Sent tampered payload, got HTTP status {response.status_code}")

    # 8. Decrypt server response
    try:
        decrypted = aes_decrypt(response.json(), session_key)
    except Exception:
        decrypted = response.json()
    print(f"[8] Server response (decrypted if possible): {decrypted}")

    # 9. Assert server detected tampering
    assert decrypted.get("error_code") == "INVALID_SIGNATURE", f"Server did not reject tampered payload: {decrypted}"
    print("[9] ✅ Server correctly rejected tampered payload with INVALID_SIGNATURE")

    # === Summary Table ===
    print("\n=== Summary ===")
    print(f"{'Step':<5} | {'Action':<40} | {'Result'}")
    print("-" * 80)
    print(f"1     | Fetch server public key          | session_id={session_id}")
    print(f"2     | Generate client key + session    | OK")
    print(f"3     | Build original payload           | amount=1000")
    print(f"4     | Sign payload                     | signature attached")
    print(f"5     | Tamper payload                   | amount=999999")
    print(f"6     | Encrypt + send to server         | request posted")
    print(f"7     | Server response                  | {response.status_code}")
    print(f"8     | Decrypt response                 | {decrypted.get('message')}")
    print(f"9     | Verification                     | INVALID_SIGNATURE ✅")
