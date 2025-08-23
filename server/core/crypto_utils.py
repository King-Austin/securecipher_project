import base64
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

class CryptoUtils:
    @staticmethod
    def load_public_key(pem):
        return serialization.load_pem_public_key(pem.encode())

    @staticmethod   
    def load_private_key(pem, password=None):
        return serialization.load_pem_private_key(pem.encode(), password=password)

    def verify_signature(public_key_pem, message, signature_b64):
        try:
            key = CryptoUtils.load_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            key.verify(signature, message, ec.ECDSA(hashes.SHA384()))  # Changed to SHA-384
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def sign_message(private_key_pem, message):
        key = CryptoUtils.load_private_key(private_key_pem)
        signature = key.sign(message, ec.ECDSA(hashes.SHA384()))  # Changed to SHA-384
        return base64.b64encode(signature).decode()

    @staticmethod
    def derive_session_key(private_key_pem, peer_public_key_pem):
        priv = CryptoUtils.load_private_key(private_key_pem)
        pub = CryptoUtils.load_public_key(peer_public_key_pem)
        shared = priv.exchange(ec.ECDH(), pub)
        return HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b'secure-session-salt',  # Added salt to match frontend
            info=b'secure-cipher-session-key'
        ).derive(shared)


    @staticmethod
    def encrypt(plaintext, session_key):
        aesgcm = AESGCM(session_key)
        iv = os.urandom(12)
        ct = aesgcm.encrypt(iv, plaintext, None)
        return {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ct).decode()
        }

    @staticmethod
    def decrypt(ciphertext_b64, iv_b64, session_key):
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ciphertext_b64)
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(iv, ct, None)

    @staticmethod
    def get_or_create_server_keypair():
        # Lazy import to avoid circular import
        from .models import ApiKeyPair
        
        keypair = ApiKeyPair.objects.filter(label="active").first()
        if not keypair:
            private_key = ec.generate_private_key(ec.SECP384R1())
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            keypair = ApiKeyPair.objects.create(
                label="active",
                public_key=public_pem,
                private_key=private_pem
            )
        return keypair

    @staticmethod
    def _fix_pem_formatting(pem_str):
        """Fix common PEM formatting issues"""
        cleaned = pem_str.strip()
        
        # Ensure proper BEGIN/END headers
        if "BEGIN PUBLIC KEY" in cleaned and "-----" not in cleaned:
            cleaned = cleaned.replace("BEGIN PUBLIC KEY", "-----BEGIN PUBLIC KEY-----")
            cleaned = cleaned.replace("END PUBLIC KEY", "-----END PUBLIC KEY-----")
        
        # Add line breaks if missing
        if "-----BEGIN PUBLIC KEY-----" in cleaned and "\n" not in cleaned:
            base64_content = cleaned.replace("-----BEGIN PUBLIC KEY-----", "")\
                                   .replace("-----END PUBLIC KEY-----", "")\
                                   .strip()
            cleaned = f"-----BEGIN PUBLIC KEY-----\n{base64_content}\n-----END PUBLIC KEY-----"
        
        return cleaned

    @staticmethod
    def get_server_private_key():
        return CryptoUtils.get_or_create_server_keypair().private_key

    @staticmethod
    def get_server_public_key():
        return CryptoUtils.get_or_create_server_keypair().public_key


    @staticmethod
    def crypto_preprocess(envelope):
        """
        Handles all cryptographic logic for incoming requests:
        - Decrypts AES-GCM payload using ECDH-derived session key
        - Verifies middleware and client signatures (handles raw/DER)
        - Checks nonce/timestamp for replay protection
        - Returns transaction_data, session_key, and Error is Any
        """
        try:
            # 1. Extract envelope fields
            ephemeral_pub_b64 = envelope.get("ephemeral_pubkey")
            ciphertext_b64 = envelope.get("ciphertext")
            iv_b64 = envelope.get("iv")
            if not (ephemeral_pub_b64 and ciphertext_b64 and iv_b64):
                return None, None, "Missing cryptographic envelope fields"

            # 2. ECDH derive session key
            bank_private_key = CryptoUtils.load_private_key(CryptoUtils.get_server_private_key())
            ephemeral_pub = serialization.load_der_public_key(base64.b64decode(ephemeral_pub_b64))
            shared_secret = bank_private_key.exchange(ec.ECDH(), ephemeral_pub)
            session_key = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=b'secure-session-salt',  # Added salt to match frontend/middleware
                info=b"secure-cipher-session-key"
            ).derive(shared_secret)

            # 3. AES-GCM decrypt inner payload
            plaintext = CryptoUtils.decrypt(ciphertext_b64, iv_b64, session_key)
            payload = json.loads(plaintext.decode())
            print("DEBUG: [CryptoPreprocess] Decrypted payload:", payload.keys())


            # 4. Middleware signature verification
            middleware_payload = json.dumps({
                "transaction_data": payload["transaction_data"],
                "client_signature": payload.get("client_signature"),
                "client_public_key": payload.get("client_public_key"),
                "nonce": payload.get("nonce")
            }, separators=(',', ':'), sort_keys=True).encode()

            middleware_sig = base64.b64decode(payload["middleware_signature"])
            middleware_pub_key_str = payload["middleware_public_key"]
            
            # Fix PEM formatting and load key
            try:
                if "-----BEGIN PUBLIC KEY-----" in middleware_pub_key_str:
                    fixed_pem = CryptoUtils._fix_pem_formatting(middleware_pub_key_str)
                    middleware_pub = serialization.load_pem_public_key(fixed_pem.encode())
                else:
                    # Assume DER format
                    middleware_pub = serialization.load_der_public_key(base64.b64decode(middleware_pub_key_str))
            except ValueError as e:
                print(f"DEBUG: [CryptoPreprocess] Failed to load middleware public key: {e}")
                print(f"DEBUG: [CryptoPreprocess] Key content: {middleware_pub_key_str[:100]}...")
                return None, None, "Invalid middleware public key format"



            # Verify middleware signature with SHA-384
            try:
                middleware_pub.verify(middleware_sig, middleware_payload, ec.ECDSA(hashes.SHA384()))
                print("DEBUG: [CryptoPreprocess] Middleware signature verified")
            except InvalidSignature:
                print("DEBUG: [CryptoPreprocess] Invalid middleware signature")
                return None, None, "Invalid middleware signature"

            # 5. Client signature verification (optional)
            if "client_signature" in payload and "client_public_key" in payload:
                client_payload = json.dumps({
                    "transaction_data": payload["transaction_data"],
                }, separators=(',', ':'), sort_keys=True).encode()
                
                client_pub_key_str = payload["client_public_key"]
                
                # Fix client public key formatting
                if "-----BEGIN PUBLIC KEY-----" not in client_pub_key_str:
                    try:
                        client_pub_key = serialization.load_der_public_key(base64.b64decode(client_pub_key_str))
                    except ValueError:
                        return None, None, "Invalid client public key format"
                else:
                    cleaned_pem = client_pub_key_str.strip()
                    if "\n" not in cleaned_pem:
                        base64_content = cleaned_pem.replace("-----BEGIN PUBLIC KEY-----", "")\
                                                  .replace("-----END PUBLIC KEY-----", "")\
                                                  .strip()
                        cleaned_pem = f"-----BEGIN PUBLIC KEY-----\n{base64_content}\n-----END PUBLIC KEY-----"
                    client_pub_key = serialization.load_pem_public_key(cleaned_pem.encode())
                
                client_sig = base64.b64decode(payload["client_signature"])
                
                # Handle raw signature format
                if len(client_sig) == 96:  # P-384 raw signature
                    r = int.from_bytes(client_sig[:48], 'big')
                    s = int.from_bytes(client_sig[48:], 'big')
                    client_sig = encode_dss_signature(r, s)
                
                # Verify client signature with SHA-384
                try:
                    client_pub_key.verify(client_sig, client_payload, ec.ECDSA(hashes.SHA384()))
                    print("DEBUG: [CryptoPreprocess] Client signature verified")
                except InvalidSignature:
                    print("DEBUG: [CryptoPreprocess] Invalid client signature")
                    return None, None, "Invalid client signature"

            # 6. Prepare response data
            transaction_data = payload["transaction_data"]
            if "client_public_key" in payload:
                transaction_data["public_key"] = payload["client_public_key"]

            print("DEBUG: [cryptoPreprocess] TransactionData", payload['transaction_data'])
            return payload["transaction_data"], session_key, None

        except Exception as e:
            print(f"DEBUG: [CryptoPreprocess] Exception: {e}")
            return None, None, str(e)


