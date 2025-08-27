# tests/system/test_secure_gateway.py
import base64
import json
import os
import time
import uuid
import requests
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


API_PUBLIC_KEY_URL = "http://localhost:8000/api/public-key"
API_SECURE_GATEWAY = "http://localhost:8000/api/gateway"

# ---------- Helpers ---------- #

def generate_ephemeral_key():
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_der

def derive_session_key(peer_pub_der, priv_key):
    peer_pub = serialization.load_der_public_key(peer_pub_der)
    shared = priv_key.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=b"secure-session-salt",
        info=b"secure-cipher-session-key",
    ).derive(shared)

def canonical_json(payload_dict):
    return json.dumps(payload_dict, separators=(",", ":"), sort_keys=True)

def ecdsa_sign_transaction_data_only(full_payload, signing_private_key):
    message = {"transaction_data": full_payload["transaction_data"]}
    msg_bytes = canonical_json(message).encode()
    sig_der = signing_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA384()))
    return base64.b64encode(sig_der).decode()

def aes_encrypt(payload_dict, session_key):
    data = json.dumps(payload_dict).encode()
    iv = os.urandom(12)
    ct = AESGCM(session_key).encrypt(iv, data, None)
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }

def aes_decrypt(envelope, session_key):
    iv = base64.b64decode(envelope["iv"])
    ct = base64.b64decode(envelope["ciphertext"])
    pt = AESGCM(session_key).decrypt(iv, ct, None)
    return json.loads(pt)

# ---------- Core reusable function ---------- #

def run_transaction(username="pytest_user", phone="08012345678", target="register", verbose=True):
    """
    Runs a single full secure-gateway transaction.
    Returns (response, elapsed_time_seconds, decrypted_payload).
    """
    start = time.perf_counter()

    # 1. Fetch middleware's public key
    resp = requests.get(API_PUBLIC_KEY_URL)
    resp.raise_for_status()
    data = resp.json()
    session_id, server_pub_der = data["session_id"], base64.b64decode(data["public_key"])
    if verbose:
        print("\n[STEP 1] Got middleware public key & session_id")
        print("  Session ID:", session_id)
        print("  Server pub key (DER, base64):", data["public_key"][:60], "...")

    # 2. Client ephemeral key
    client_priv, client_pub_der = generate_ephemeral_key()
    session_key = derive_session_key(server_pub_der, client_priv)
    if verbose:
        print("[STEP 2] Generated client ephemeral keypair")
        print("  Client ephemeral pubkey (DER, base64):", base64.b64encode(client_pub_der).decode()[:60], "...")
        print("  Derived session key (hex):", session_key.hex()[:64], "...")

    # 3. Build payload
    payload = {
        "transaction_data": {"username": username, "phonenumber": phone},
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "target": target,
    }
    if verbose:
        print("[STEP 3] Built payload:", json.dumps(payload, indent=2))

    # 4. Sign transaction_data only
    signing_priv = ec.generate_private_key(ec.SECP384R1())
    client_pub_pem = signing_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    payload["client_signature"] = ecdsa_sign_transaction_data_only(payload, signing_priv)
    payload["client_public_key"] = client_pub_pem
    if verbose:
        print("[STEP 4] Signed transaction_data")
        print("  Client pubkey PEM (first 80 chars):", client_pub_pem[:80], "...")
        print("  Signature (b64):", payload["client_signature"][:60], "...")

    # 5. Encrypt
    encrypted = aes_encrypt(payload, session_key)
    body = {
        "ephemeral_pubkey": base64.b64encode(client_pub_der).decode(),
        "ciphertext": encrypted["ciphertext"],
        "iv": encrypted["iv"],
        "session_id": session_id,
    }
    if verbose:
        print("[STEP 5] Encrypted payload")
        print("  Request body:", json.dumps(body, indent=2)[:300], "...")

    # 6. POST request
    resp = requests.post(API_SECURE_GATEWAY, json=body)
    elapsed = time.perf_counter() - start
    if verbose:
        print("[STEP 6] POST request sent")
        print("  HTTP Status:", resp.status_code)
        print("  Raw response JSON:", resp.json())

    # 7. Decrypt response if possible
    try:
        decrypted = aes_decrypt(resp.json(), session_key)
        if verbose:
            print("[STEP 7] Decrypted server response:", json.dumps(decrypted, indent=2))
    except Exception as e:
        decrypted = resp.json()
        if verbose:
            print("[STEP 7] Response decryption failed:", str(e))

    if verbose:
        print(f"\n[RESULT] Elapsed time: {elapsed:.4f}s")

    return resp, elapsed, decrypted

# ---------- Pytest wrapper ---------- #

@pytest.mark.system
def test_secure_gateway_transaction():
    resp, elapsed, decrypted = run_transaction(verbose=True)
    assert resp.status_code == 200
    assert ("transaction_data" in decrypted) or ("message" in decrypted)
