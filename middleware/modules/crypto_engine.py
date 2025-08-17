# crypto_engine.py
import os
import base64
import json
import time
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SESSION_KEY_INFO = b"secure-cipher-session-key"
AES_GCM_IV_SIZE = 12
ECDH_CURVE = ec.SECP384R1()
SESSION_KEY_LENGTH = 32
TIMESTAMP_WINDOW_SECONDS = 300  # seconds

def hash_data(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data if isinstance(data, bytes) else (data.encode() if isinstance(data, str) else json.dumps(data).encode())).hexdigest()

# ECDSA
def ecdsa_sign(payload: Dict[str, Any], private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def ecdsa_verify(payload: Dict[str, Any], signature_b64: str, public_key_str: str) -> bool:
    try:
        if "-----BEGIN PUBLIC KEY-----" in public_key_str:
            public_key = serialization.load_pem_public_key(public_key_str.encode())
        else:
            public_key = serialization.load_der_public_key(base64.b64decode(public_key_str))
        message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        sig_bytes = base64.b64decode(signature_b64)
        if len(sig_bytes) == 96:
            r = int.from_bytes(sig_bytes[:48], "big")
            s = int.from_bytes(sig_bytes[48:], "big")
            sig_bytes = encode_dss_signature(r, s)
        public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# AES-GCM
def aes256gcm_encrypt(payload: Dict[str, Any], key: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(key)
    iv = os.urandom(AES_GCM_IV_SIZE)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    ciphertext = aesgcm.encrypt(iv, payload_json.encode(), None)
    return {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}

def aes256gcm_decrypt(envelope: Dict[str, str], key: bytes) -> Dict[str, Any]:
    aesgcm = AESGCM(key)
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    decrypted = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(decrypted.decode())

# ECDHE and HKDF
def perform_ecdhe() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    priv = ec.generate_private_key(ECDH_CURVE)
    pub = priv.public_key()
    pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_der

def derive_keys(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=SESSION_KEY_LENGTH, salt=b"", info=SESSION_KEY_INFO).derive(shared_secret)

def derive_session_key_from_peer(peer_public_der: bytes, our_private_key) -> bytes:
    peer_pub = serialization.load_der_public_key(peer_public_der)
    shared = our_private_key.exchange(ec.ECDH(), peer_pub)
    return derive_keys(shared)

def create_downstream_envelope(payload: Dict[str, Any], bank_public_key_pem: str):
    ephemeral_priv, ephemeral_pub_der = perform_ecdhe()
    bank_pub = serialization.load_pem_public_key(bank_public_key_pem.encode())
    if not isinstance(bank_pub.curve, ec.SECP384R1):
        raise ValueError("Bank public key must use SECP384R1")
    shared = ephemeral_priv.exchange(ec.ECDH(), bank_pub)
    session_key = derive_keys(shared)
    envelope = aes256gcm_encrypt(payload, session_key)
    envelope["ephemeral_pubkey"] = base64.b64encode(ephemeral_pub_der).decode()
    return envelope, session_key

def validate_timestamp(timestamp, window_seconds=30):
    # Example: check if timestamp is within allowed window
    import time
    now = int(time.time())
    return abs(now - timestamp) <= window_seconds

    