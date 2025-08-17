from .crypto_engine import perform_ecdhe, derive_keys
import base64

# --- Simple in-memory key store ---
_key_store = {}

def store_public_key(user_id: str, public_key_pem: str):
    _key_store[user_id] = {"public_key": public_key_pem, "revoked": False}

def retrieve_public_key(user_id: str):
    entry = _key_store.get(user_id)
    return entry["public_key"] if entry else None

def revoke_key(user_id: str):
    if user_id in _key_store:
        _key_store[user_id]["revoked"] = True

def rotate_keys(user_id: str):
    private_key, public_der = perform_ecdhe()
    _key_store[user_id] = {
        "private_key": private_key,
        "public_key": base64.b64encode(public_der).decode(),
        "revoked": False
    }

def export_public_key(user_id: str):
    return _key_store[user_id]["public_key"]

def derive_shared_secret(peer_public_der: bytes, private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    peer_pub = serialization.load_der_public_key(peer_public_der)
    shared_secret = private_key.exchange(ec.ECDH(), peer_pub)
    return shared_secret

def derive_session_key(shared_secret: bytes) -> bytes:
    return derive_keys(shared_secret)
