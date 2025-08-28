# key_manager.py
from django.db.models import Max
from django.utils import timezone
from api.models import MiddlewareKey, KeyRotationLog, EphemeralKey
from .crypto_engine import generate_ec_keypair
from cryptography.hazmat.primitives import serialization
import base64

# ---------------- Helper ---------------- #
def normalize_pem(pem_str: str) -> str:
    """Remove whitespace and normalize line endings."""
    return "\n".join(line.strip() for line in pem_str.strip().splitlines())

# ---------------- Middleware Key Management ---------------- #
def get_active_middleware_key() -> MiddlewareKey:
    """
    Fetch the active middleware key from the DB.
    Returns the key object as stored (plain PEM).
    """
    active = MiddlewareKey.objects.filter(active=True).first()
    if active:
        return active

    # If none exists, create a new one
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

    pub_pem = normalize_pem(pub_pem)

    latest_version = MiddlewareKey.objects.aggregate(Max("version"))["version__max"] or 0
    new_version = latest_version + 1

    return MiddlewareKey.objects.create(
        label="auto-generated",
        private_key_pem=normalize_pem(priv_pem),
        public_key_pem=pub_pem,
        version=new_version,
        active=True,
    )


def rotate_middleware_key(reason: str = None) -> MiddlewareKey:
    """Rotate active middleware key and return the new key (plain PEM)."""
    old = get_active_middleware_key()
    old.active = False
    old.rotated_at = timezone.now()
    old.save()

    priv, pub_der = generate_ec_keypair()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    pub_pem = serialization.load_der_public_key(pub_der).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    pub_pem = normalize_pem(pub_pem)

    new_version = (old.version or 1) + 1
    new = MiddlewareKey.objects.create(
        label="active",
        private_key_pem=normalize_pem(priv_pem),
        public_key_pem=pub_pem,
        version=new_version,
        active=True,
    )

    KeyRotationLog.objects.create(old_key=old, new_key=new, reason=reason)
    return new


# ---------------- Ephemeral Keys ---------------- #
def create_ephemeral_key(ttl_seconds: int = 300) -> tuple[str, str]:
    """
    Generate ephemeral ECDH key pair and store in DB (plain PEM).
    Returns (public_key_base64, session_id)
    """
    private_key, public_key_der = generate_ec_keypair()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    ephemeral = EphemeralKey.objects.create(
        private_key_pem=normalize_pem(priv_pem),
        ttl_seconds=ttl_seconds
    )

    public_b64 = base64.b64encode(public_key_der).decode("ascii")
    return public_b64, str(ephemeral.session_id)


def fetch_ephemeral_private_key(session_id: str):
    """
    Fetch ephemeral private key by session_id.
    Returns the private key object.
    """
    try:
        ephemeral = EphemeralKey.objects.get(session_id=session_id)
    except EphemeralKey.DoesNotExist:
        return None

    if ephemeral.is_expired:
        ephemeral.delete()
        return None

    private_key = serialization.load_pem_private_key(
        ephemeral.private_key_pem.encode("utf-8"),
        password=None
    )
    return private_key
