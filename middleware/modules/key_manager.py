# key_manager.py
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from venv import logger
from django.utils import timezone
from api.models import MiddlewareKey, KeyRotationLog
from .crypto_engine import perform_ecdhe, derive_session_key_from_peer
# ... existing code ...

def get_active_middleware_key() -> MiddlewareKey:
    active = MiddlewareKey.objects.filter(active=True).order_by("-version").first()
    if active:
        # Validate the private key format before returning
        try:
            serialization.load_pem_private_key(active.private_key_pem.encode(), password=None)
            print(active.private_key_pem)
            return active
        except ValueError as e:
            logger.error(f"Corrupted private key for active middleware key version {active.version}: {e}")
            # Mark as inactive and create a new one
            active.active = False
            active.save()
    
    # create new key
    priv, pub_der = perform_ecdhe()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return MiddlewareKey.objects.create(
        label="active", private_key_pem=priv_pem, public_key_pem=pub_pem,
        version=1, active=True
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

    priv, pub_der = perform_ecdhe()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    new_version = (old.version or 1) + 1
    new = MiddlewareKey.objects.create(
        label="active", private_key_pem=priv_pem, public_key_pem=pub_pem,
        version=new_version, active=True
    )
    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)
    return new

def export_public_key_pem() -> str:
    return get_active_middleware_key().public_key_pem

# def derive_session_key(client_ephemeral_der: bytes) -> bytes:
#     """
#     Derive session key using active middleware private key + client ephemeral.
#     """
#     mk = get_active_middleware_key()
#     our_private = serialization.load_pem_private_key(mk.private_key_pem.encode(), password=None)
#     return derive_session_key_from_peer(client_ephemeral_der, our_private)
