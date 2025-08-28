# key_manager.py
import base64
import os
from typing import Tuple
from django.db.models import Max
from django.utils import timezone
from django.conf import settings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from api.models import MiddlewareKey, KeyRotationLog, EphemeralKey
from .crypto_engine import generate_ec_keypair
import uuid

# ---------------- Helper ---------------- #
def normalize_pem(pem_str: str) -> str:
    """Remove whitespace and normalize line endings."""
    return "\n".join(line.strip() for line in pem_str.strip().splitlines())

# ---------------- AES-GCM Helper ---------------- #
class AESKeySecurity:
    """
    AES-GCM encryption/decryption helper for private keys.
    Stores encrypted PEM as base64 strings.
    """
    def __init__(self):
        # Should be 32 bytes for AES-256
        key_b64 = getattr(settings, "FIELD_ENCRYPTION_KEY", None)
        if not key_b64:
            raise ValueError("FIELD_ENCRYPTION_KEY not set in settings")
        # Ensure key_b64 is bytes
        if isinstance(key_b64, str):
            # Add padding if needed
            key_b64 += "=" * (-len(key_b64) % 4)
            key_b64 = key_b64.encode("utf-8")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) != 32:
            raise ValueError("AES key must be 32 bytes for AES-256-GCM")
        self.key = key_bytes

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext (string) and return base64 ciphertext."""
        aesgcm = AESGCM(self.key)
        iv = os.urandom(12)
        ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        # Store iv + ciphertext as base64
        return base64.b64encode(iv + ct).decode("utf-8")

    def decrypt(self, token_b64: str) -> str:
        """Decrypt base64 ciphertext and return plaintext string."""
        raw = base64.b64decode(token_b64)
        iv = raw[:12]
        ct = raw[12:]
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(iv, ct, None)
        return plaintext.decode("utf-8")


aes_security = AESKeySecurity()

# ---------------- Middleware Key Management ---------------- #
def get_active_middleware_key() -> MiddlewareKey:
    """
    Fetch or create the active middleware key.
    The private key is always decrypted before returning.
    """
    active = MiddlewareKey.objects.filter(active=True).first()
    if active:
        active.private_key_pem = aes_security.decrypt(active.private_key_pem)
        return active

    # Create new key if none exists
    priv, pub_der = generate_ec_keypair()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("utf-8")
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    priv_pem_enc = aes_security.encrypt(normalize_pem(priv_pem))
    pub_pem = normalize_pem(pub_pem)

    latest_version = MiddlewareKey.objects.aggregate(Max("version"))["version__max"] or 0
    new_version = latest_version + 1

    return MiddlewareKey.objects.create(
        label="auto-generated",
        private_key_pem=priv_pem_enc,
        public_key_pem=pub_pem,
        version=new_version,
        active=True,
    )

def rotate_middleware_key(reason: str = None) -> MiddlewareKey:
    """Rotate active middleware key. Returns decrypted private key on the new key."""
    old = get_active_middleware_key()
    old.active = False
    old.rotated_at = timezone.now()
    old.save()

    priv, pub_der = generate_ec_keypair()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("utf-8")
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    priv_pem_enc = aes_security.encrypt(normalize_pem(priv_pem))
    pub_pem = normalize_pem(pub_pem)

    new_version = (old.version or 1) + 1
    new = MiddlewareKey.objects.create(
        label="active",
        private_key_pem=priv_pem_enc,
        public_key_pem=pub_pem,
        version=new_version,
        active=True,
    )
    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)

    # Decrypt before returning
    new.private_key_pem = priv_pem
    return new

# ---------------- Ephemeral Keys ---------------- #
def create_ephemeral_key(ttl_seconds: int = 300) -> tuple[str, str]:
    """
    Generate ephemeral ECDH key pair and store encrypted private key.
    Returns (public_key_base64, session_id)
    """
    private_key, public_key_der = generate_ec_keypair()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode("utf-8")

    encrypted_private_pem = aes_security.encrypt(priv_pem)

    ephemeral = EphemeralKey.objects.create(
        private_key_pem=encrypted_private_pem,
        ttl_seconds=ttl_seconds
    )

    public_b64 = base64.b64encode(public_key_der).decode("ascii")
    return public_b64, str(ephemeral.session_id)

def fetch_ephemeral_private_key(session_id: str):
    """
    Fetch ephemeral private key by session_id.
    Returns a private key object ready for use.
    """
    try:
        ephemeral = EphemeralKey.objects.get(session_id=session_id)
    except EphemeralKey.DoesNotExist:
        return None

    if ephemeral.is_expired:
        ephemeral.delete()
        return None

    decrypted_pem = aes_security.decrypt(ephemeral.private_key_pem)
    private_key = serialization.load_pem_private_key(decrypted_pem.encode("utf-8"), password=None)
    return private_key
