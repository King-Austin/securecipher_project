# key_manager.py
import base64
from typing import Tuple
from django.db.models import Max
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from venv import logger
from django.utils import timezone
from django.conf import settings
from api.models import MiddlewareKey, KeyRotationLog, EphemeralKey
from .crypto_engine import generate_ec_keypair
import uuid


def normalize_pem(pem_str: str) -> str:
    """
    Remove any trailing whitespace and normalize line endings.
    Ensures PEM works with Postgres/Cloud DBs.
    """
    return "\n".join(line.strip() for line in pem_str.strip().splitlines())




def get_active_middleware_key() -> MiddlewareKey:
    """
    Fetch the active key. If none exists, create a new one.
    Private key is decrypted on access (single source of truth).
    """
    active = MiddlewareKey.objects.filter(active=True).first()
    if active:

        return active

    # Only create new key if no active key exists
    priv, pub_der = generate_ec_keypair()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode('utf-8')
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    priv_pem = normalize_pem(priv_pem)
    pub_pem = normalize_pem(pub_pem)


    latest_version = MiddlewareKey.objects.aggregate(Max('version'))['version__max'] or 0
    new_version = latest_version + 1

    return MiddlewareKey.objects.create(
        label="auto-generated",
        private_key_pem=priv_pem, #Encryption is handled on the db level
        public_key_pem=pub_pem,
        version=new_version,
        active=True
    )




def rotate_middleware_key(reason: str = None) -> MiddlewareKey:
    old = get_active_middleware_key()
    old.active = False
    old.rotated_at = timezone.now()
    old.save()

    priv, pub_der = generate_ec_keypair()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    priv_pem = normalize_pem(priv_pem)
    pub_pem = normalize_pem(pub_pem)


    new_version = (old.version or 1) + 1
    new = MiddlewareKey.objects.create(
        label="active",
        private_key_pem=priv_pem,
        public_key_pem=pub_pem,
        version=new_version,
        active=True
    )
    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)
    return new


def export_public_key_pem() -> str:
    return get_active_middleware_key().public_key_pem

def fetch_ephemeral_private_key(session_id: str):
    """
    Fetch the ephemeral private key by session_id.
    Automatically decrypts and returns the private_key object.
    """
    try:
        ephemeral = EphemeralKey.objects.get(session_id=session_id)
    except EphemeralKey.DoesNotExist:
        return None

    # Check expiration
    if ephemeral.is_expired:
        ephemeral.delete()
        return None

    # The EncryptedTextField automatically decrypts on access
    private_pem = ephemeral.private_key_pem.encode("utf-8")

    # Load PEM into private_key object
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    return private_key

def create_ephemeral_key(ttl_seconds: int = 300) -> tuple[str, str]:
    """
    Generate ephemeral ECDH key pair and store encrypted private key in DB.
    Returns (public_key_b64, session_id).
    """
    # Generate pair
    private_key, public_key_der = generate_ec_keypair()

    # Serialize private key into PEM (for storage)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store encrypted in DB
    ephemeral = EphemeralKey.objects.create(
        private_key_pem=private_pem,
        ttl_seconds=ttl_seconds
    )

    # Encode public key in base64 for JSON transport
    public_b64 = base64.b64encode(public_key_der).decode("ascii")

    return public_b64, str(ephemeral.session_id)