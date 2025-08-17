import os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

AES_GCM_IV_SIZE = 12
SESSION_KEY_LENGTH = 32
SESSION_KEY_INFO = b'secure-cipher-session-key'

# --- AES256-GCM ---
def aes256gcm_encrypt(payload: dict, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    iv = os.urandom(AES_GCM_IV_SIZE)
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    ciphertext = aesgcm.encrypt(iv, payload_json.encode(), None)
    return {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}

def aes256gcm_decrypt(envelope: dict, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(decrypted_bytes.decode())

# --- ECDSA ---
def ecdsa_sign(payload: dict, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def ecdsa_verify(payload: dict, signature_b64: str, public_key_pem: str) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    message = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    sig_bytes = base64.b64decode(signature_b64)
    if len(sig_bytes) == 96:  # raw r||s
        r = int.from_bytes(sig_bytes[:48], 'big')
        s = int.from_bytes(sig_bytes[48:], 'big')
        sig_bytes = encode_dss_signature(r, s)
    public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
    return True

# --- ECDHE session key derivation ---
def derive_keys(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=SESSION_KEY_LENGTH, salt=b'', info=SESSION_KEY_INFO).derive(shared_secret)

def perform_ecdhe():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_key, public_der
