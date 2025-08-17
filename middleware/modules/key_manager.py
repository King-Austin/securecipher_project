# key_manager.py
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from .crypto_engine import perform_ecdhe, derive_keys
from django.utils import timezone
from api.models import MiddlewareKey, KeyRotationLog

def get_active_middleware_key() -> MiddlewareKey:
    """
    Return the active MiddlewareKey DB object. If not present create one.
    """
    active = MiddlewareKey.objects.filter(active=True).order_by("-version").first()
    if active:
        return active
    # create new key
    priv, pub_der = perform_ecdhe()
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    mk = MiddlewareKey.objects.create(label="active", private_key_pem=priv_pem, public_key_pem=pub_pem, version=1, active=True)
    return mk

def rotate_middleware_key(reason: str = None) -> MiddlewareKey:
    """
    Rotate the active key: create new key, mark previous active False, log rotation.
    """
    old = get_active_middleware_key()
    old.active = False
    old.rotated_at = timezone.now()
    old.save()

    priv, pub_der = perform_ecdhe()
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    new_version = (old.version or 1) + 1
    new = MiddlewareKey.objects.create(label="active", private_key_pem=priv_pem, public_key_pem=pub_pem, version=new_version, active=True)
    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)
    return new

def export_public_key_pem() -> str:
    mk = get_active_middleware_key()
    return mk.public_key_pem

def derive_session_key(client_ephemeral_der: bytes) -> bytes:
    """
    Derive session key using the active middleware private key and the client's ephemeral public key (DER).
    Returns session key bytes.
    """
    mk = get_active_middleware_key()
    our_private = serialization.load_pem_private_key(mk.private_key_pem.encode(), password=None)
    return derive_keys(our_private.exchange  # not callable; implement properly below
                       )

# Correct implementation for derive_session_key (replace the above incorrect snippet)
def derive_session_key(client_ephemeral_der: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    mk = get_active_middleware_key()
    our_private = serialization.load_pem_private_key(mk.private_key_pem.encode(), password=None)
    peer_pub = serialization.load_der_public_key(client_ephemeral_der)
    shared = our_private.exchange(ec.ECDH(), peer_pub)
    return derive_keys(shared)
