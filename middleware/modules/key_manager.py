# key_manager.py
from typing import Tuple
from django.db.models import Max
from cryptography.hazmat.primitives import serialization
from venv import logger
from django.utils import timezone
from api.models import MiddlewareKey, KeyRotationLog
from .crypto_engine import perform_ecdh, derive_session_key_from_peer


def normalize_pem(pem_str: str) -> str:
    """
    Remove any trailing whitespace and normalize line endings.
    Ensures PEM works with Postgres/Cloud DBs.
    """
    return "\n".join(line.strip() for line in pem_str.strip().splitlines())



def get_active_middleware_key() -> MiddlewareKey:
    active = MiddlewareKey.objects.filter(active=True).first()
    if active:
        return active
    
    # Only create new key if no active key exists
    priv, pub_der = perform_ecdh()
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
    # Get next version number


    latest_version = MiddlewareKey.objects.aggregate(Max('version'))['version__max'] or 0
    new_version = latest_version + 1

    return MiddlewareKey.objects.create(
        label="active", 
        private_key_pem=priv_pem, 
        public_key_pem=pub_pem,
        version=new_version, 
        active=True
    )

def derive_session_key(client_ephemeral_der: bytes) -> bytes:
    """
    Derive session key using active middleware private key + client ephemeral.
    """
    mk = get_active_middleware_key()
    try:
        our_private = serialization.load_pem_private_key(mk.private_key_pem.encode(), password=None)
        return derive_session_key_from_peer(client_ephemeral_der, our_private)
    except ValueError as e:
        logger.error(f"Failed to load private key for middleware key version {mk.version}: {e}")
        # Rotate the key and try again
        rotate_middleware_key("corrupted_private_key_auto_rotation")
        mk = get_active_middleware_key()
        our_private = serialization.load_pem_private_key(mk.private_key_pem.encode(), password=None)
        return derive_session_key_from_peer(client_ephemeral_der, our_private)


def rotate_middleware_key(reason: str = None) -> MiddlewareKey:
    old = get_active_middleware_key()
    old.active = False
    old.rotated_at = timezone.now()
    old.save()

    priv, pub_der = perform_ecdh()
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
        label="active", private_key_pem=priv_pem, public_key_pem=pub_pem,
        version=new_version, active=True
    )
    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)
    return new

def export_public_key_pem() -> str:
    return get_active_middleware_key().public_key_pem

