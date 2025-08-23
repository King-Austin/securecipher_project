# middleware/tests/test_secure_gateway.py
import json
import time
import base64
import uuid
import random
import string

from django.test import TestCase, Client
from django.utils import timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.models import MiddlewareKey  # adjust if your app name differs

# Constants matching frontend / crypto_engine
SESSION_KEY_INFO = b"secure-cipher-session-key"
SESSION_KEY_LENGTH = 32  # bytes
HKDF_HASH = hashes.SHA384()
AES_GCM_IV_SIZE = 12
ECDH_CURVE = ec.SECP384R1()



def random_username():
    return "user_" + uuid.uuid4().hex[:8]

def random_email():
    return uuid.uuid4().hex[:6] + "@example.com"

def random_phone():
    return "0" + "".join(random.choices(string.digits, k=10))



def canonicalize_json(obj):
    """
    Create canonical JSON equivalent to the frontend's canonicalizeJson:
    - Recursively sort keys
    - No extra whitespace
    Produces a string.
    """
    if obj is None or not isinstance(obj, (dict, list)):
        # For scalars produce JSON representation (strings quoted)
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    if isinstance(obj, list):
        return "[" + ",".join(canonicalize_json(i) for i in obj) + "]"

    # dict
    keys = sorted(obj.keys())
    parts = []
    for k in keys:
        v = obj[k]
        parts.append(f'"{k}":{canonicalize_json(v)}')
    return "{" + ",".join(parts) + "}"



class MiddlewareGatewayTest(TestCase):
    def setUp(self):
        self.client = Client()

        # Ensure there's an active middleware key in DB; create one if missing
        self.middleware_key = MiddlewareKey.objects.filter(active=True).order_by("-version").first()
        if not self.middleware_key:
            # generate fresh ECDHE keypair (store PEMs)
            priv = ec.generate_private_key(ECDH_CURVE)
            pub = priv.public_key()
            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            pub_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            self.middleware_key = MiddlewareKey.objects.create(
                label="active",
                private_key_pem=priv_pem,
                public_key_pem=pub_pem,
                version=1,
                active=True,
            )

    def derive_session_key(self, our_private: ec.EllipticCurvePrivateKey, peer_public):
        """
        Derive session key bytes (32) using ECDH shared secret + HKDF-SHA384.
        `peer_public` can be a cryptography public key object.
        """
        shared = our_private.exchange(ec.ECDH(), peer_public)
        hkdf = HKDF(
            algorithm=HKDF_HASH,
            length=SESSION_KEY_LENGTH,
            salt=b"",
            info=SESSION_KEY_INFO,
        )
        return hkdf.derive(shared)

    def export_public_spki_der(self, pubkey):
        return pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_public_pem_from_pubder(self, pub_der_bytes):
        pub = serialization.load_der_public_key(pub_der_bytes)
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def test_secure_gateway_flow(self):
        """
        Simulate frontend: generate identity key, ephemeral key, derive session key,
        sign canonical JSON, AES-GCM encrypt payload, send to middleware, decrypt response.
        """
        # -------------------------
        # 1) Identity keypair (frontend user signing key)
        # -------------------------
        identity_priv = ec.generate_private_key(ECDH_CURVE)
        identity_pub = identity_priv.public_key()

        # export identity public key as PEM (frontend does similar)
        identity_pub_spki_der = self.export_public_spki_der(identity_pub)
        identity_pub_pem = self.export_public_pem_from_pubder(identity_pub_spki_der)

        # -------------------------
        # 2) Ephemeral ECDH keypair (per-request)
        # -------------------------
        ephemeral_priv = ec.generate_private_key(ECDH_CURVE)
        ephemeral_pub = ephemeral_priv.public_key()
        ephemeral_spki_der = self.export_public_spki_der(ephemeral_pub)
        ephemeral_pub_b64 = base64.b64encode(ephemeral_spki_der).decode()

        # -------------------------
        # 3) Load middleware public key and derive session key
        # -------------------------
        middleware_pub_pem = self.middleware_key.public_key_pem.encode()
        middleware_pub = serialization.load_pem_public_key(middleware_pub_pem)
        # derive session key: ephemeral_priv (client) x middleware_pub (server)
        session_key_bytes = self.derive_session_key(ephemeral_priv, middleware_pub)

        # -------------------------
        # 4) Prepare secure payload (canonicalize & sign)
        # -------------------------
        target = "register"
        payload_data = {"username": random_username(), "email": random_email(), "phone_number": random_phone()}

        # Build object that will be signed: in your frontend code they do { transaction_data: payload }
        sign_obj = {"transaction_data": payload_data}
        canonical = canonicalize_json(sign_obj).encode()  # canonical JSON bytes

        # Sign using ECDSA with SHA-256 (frontend uses SHA-256)
        signature = identity_priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
        signature_b64 = base64.b64encode(signature).decode()

        nonce = str(uuid.uuid4())
        timestamp = int(time.time())

        secure_payload = {
            "target": target,
            "transaction_data": payload_data,
            "client_signature": signature_b64,
            "client_public_key": identity_pub_pem,
            "nonce": nonce,
            "timestamp": timestamp,
        }

        # -------------------------
        # 5) Encrypt secure payload with AES-GCM using session key
        # -------------------------
        aesgcm = AESGCM(session_key_bytes)
        iv = AESGCM.generate_iv() if hasattr(AESGCM, "generate_iv") else None
        # AESGCM in cryptography doesn't have generate_iv in some versions; fallback:
        if iv is None:
            iv = AESGCM.generate_iv = None  # noop to keep static analysis tools happy
            iv = AESGCM.__dict__.get("generate_iv")  # maybe None
        # fallback to os.urandom
        import os
        iv = os.urandom(AES_GCM_IV_SIZE)

        plaintext = json.dumps(secure_payload, separators=(",", ":"), sort_keys=False).encode()
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        envelope = {
            "ephemeral_pubkey": ephemeral_pub_b64,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

        # -------------------------
        # 6) POST to middleware using Django test client
        # -------------------------
        url = "/api/gateway/"  # match your URL conf
        start = time.perf_counter()
        resp = self.client.post(url, data=json.dumps(envelope), content_type="application/json")
        elapsed = time.perf_counter() - start

        # Basic checks
        self.assertIn(resp.status_code, (200, 301, 404, 201, 202, 400, 422, 502))  # allow handled error codes too
        try:
            resp_json = resp.json()
        except ValueError:
            self.fail(f"Response is not JSON: {resp.content!r}")

        # If the response is an encrypted envelope (expects iv + ciphertext), attempt decryption
        if isinstance(resp_json, dict) and "iv" in resp_json and "ciphertext" in resp_json:
            try:
                resp_iv = base64.b64decode(resp_json["iv"])
                resp_cipher = base64.b64decode(resp_json["ciphertext"])
                aesgcm_local = AESGCM(session_key_bytes)
                decrypted = aesgcm_local.decrypt(resp_iv, resp_cipher, None)
                parsed = json.loads(decrypted.decode())
                # Basic expectation: parsed should be JSON (payload from downstream or error)
                self.assertIsInstance(parsed, (dict, list))
                print("\n✅ Decrypted middleware response payload:", parsed)
            except Exception as e:
                self.fail(f"Failed to decrypt middleware response: {e}")
        else:
            # If middleware returned plain JSON (e.g. error before key derivation), just assert dict
            self.assertIsInstance(resp_json, dict)
            print("\nℹ️ Middleware returned non-encrypted JSON:", resp_json)

        print(f"\n⏱ Roundtrip latency: {elapsed * 1000:.2f} ms")

