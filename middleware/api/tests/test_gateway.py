# test_secure_gateway.py
import base64
import json
import pytest
import requests
from crypto_engine import (
    perform_ecdh,
    derive_session_key_from_peer,
    aes256gcm_encrypt,
    ecdsa_sign
)

API_PUBLIC_KEY_URL = "http://localhost:8000/api/public-key"
API_SECURE_GATEWAY = "http://localhost:8000/api/secure-gateway"

# --- Test Fixtures ---

@pytest.fixture
def middleware_session():
    """Fetch ephemeral public key and session_id from middleware"""
    resp = requests.get(API_PUBLIC_KEY_URL)
    assert resp.status_code == 200
    data = resp.json()
    session_id = data["session_id"]
    middleware_ephemeral_der = base64.b64decode(data["public_key"])
    return session_id, middleware_ephemeral_der

@pytest.fixture
def client_ephemeral_key():
    """Generate ephemeral key pair for testing"""
    priv, pub_der = perform_ecdh()
    return priv, pub_der

# --- Main Test ---

def test_secure_transaction(middleware_session, client_ephemeral_key):
    session_id, middleware_pub_der = middleware_session
    client_priv, client_pub_der = client_ephemeral_key

    # Derive session key (simulate frontend)
    session_key = derive_session_key_from_peer(middleware_pub_der, client_priv)

    # Example transaction payload
    payload = {
        "transaction_data": {"amount": 500, "recipient": "test_user"},
        "client_signature": "",
        "client_public_key": "",  # optional for test
        "nonce": "testnonce123",
        "timestamp": 1692880000,
        "target": "transfer"
    }

    # Sign payload (simulate client)
    TEST_PRIVATE_KEY_PEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGs0cDqC2wK+...
-----END EC PRIVATE KEY-----
"""  # Replace with a valid P-384 test key
    payload["client_signature"] = ecdsa_sign(payload, TEST_PRIVATE_KEY_PEM)

    # Encrypt payload
    envelope = aes256gcm_encrypt(payload, session_key)

    # Prepare request body including session_id
    body = {
        "ephemeral_pubkey": base64.b64encode(client_pub_der).decode(),
        "ciphertext": envelope["ciphertext"],
        "iv": envelope["iv"],
        "session_id": session_id
    }

    # Send request to middleware
    resp = requests.post(API_SECURE_GATEWAY, json=body)
    assert resp.status_code == 200, f"Middleware responded with {resp.status_code}"
    resp_data = resp.json()
    print("Middleware response:", resp_data)
    assert "success" in resp_data or "error" not in resp_data
