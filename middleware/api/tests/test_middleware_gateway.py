# tests/test_secure_gateway.py
import base64
import json
import os
import time
import uuid
import requests

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

def run_transaction(username="pytest_user", phone="08012345678", target="transfer"):
    """
    Runs a single full secure-gateway transaction.
    Returns (response, elapsed_time_seconds).
    """
    start = time.perf_counter()

    # 1. Fetch middleware's public key
    resp = requests.get(API_PUBLIC_KEY_URL)
    resp.raise_for_status()
    data = resp.json()
    session_id, server_pub_der = data["session_id"], base64.b64decode(data["public_key"])

    # 2. Client ephemeral key
    client_priv, client_pub_der = generate_ephemeral_key()
    session_key = derive_session_key(server_pub_der, client_priv)

    # 3. Build payload
    payload = {
        "transaction_data": {"username": username, "phonenumber": phone},
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "target": target,
    }

    # 4. Sign transaction_data only
    signing_priv = ec.generate_private_key(ec.SECP384R1())
    client_pub_pem = signing_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    payload["client_signature"] = ecdsa_sign_transaction_data_only(payload, signing_priv)
    payload["client_public_key"] = client_pub_pem

    # 5. Encrypt
    encrypted = aes_encrypt(payload, session_key)
    body = {
        "ephemeral_pubkey": base64.b64encode(client_pub_der).decode(),
        "ciphertext": encrypted["ciphertext"],
        "iv": encrypted["iv"],
        "session_id": session_id,
    }

    # 6. POST request
    resp = requests.post(API_SECURE_GATEWAY, json=body)
    elapsed = time.perf_counter() - start

    # 7. Decrypt response if possible
    try:
        decrypted = aes_decrypt(resp.json(), session_key)
    except Exception:
        decrypted = resp.json()

    return resp, elapsed, decrypted

# ---------- Pytest wrapper ---------- #

def test_secure_gateway_transaction():
    resp, elapsed, decrypted = run_transaction()
    assert resp.status_code == 200
    assert ("transaction_data" in decrypted) or ("message" in decrypted)


