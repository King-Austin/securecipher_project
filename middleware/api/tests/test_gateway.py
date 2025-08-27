import base64
import json
import os
import time
import uuid
import pytest
import requests
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from django.test import TestCase
from django.conf import settings
from django.core.cache import cache

from ..models import EphemeralKey, UsedNonce, MiddlewareKey
from ..views import SecureGateway, _enc_error

# Test URLs
API_PUBLIC_KEY_URL = "http://localhost:8000/api/public-key"
API_SECURE_GATEWAY = "http://localhost:8000/api/secure-gateway"

# --- Helper functions for crypto --- #

def generate_ephemeral_key():
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_der


def derive_session_key(peer_pub_der, priv_key):
    peer_pub = serialization.load_der_public_key(peer_pub_der)
    shared_key = priv_key.exchange(ec.ECDH(), peer_pub)
    # Derive 32-byte AES key using HKDF-SHA256
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-gateway-session"
    ).derive(shared_key)
    return session_key

def aes_encrypt(payload, session_key):
    """
    payload: dict
    session_key: bytes (32 bytes for AES-256)
    returns: dict with iv and ciphertext as base64
    """
    data = json.dumps(payload).encode()
    aesgcm = AESGCM(session_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, associated_data=None)
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def aes_decrypt(envelope, session_key):
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext)

def ecdsa_sign(payload, priv_pem):
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    data = json.dumps(payload, sort_keys=True).encode()
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def create_test_middleware_key():
    """Create a test middleware key for signing"""
    priv = ec.generate_private_key(ec.SECP384R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return MiddlewareKey.objects.create(
        version="test-v1",
        private_key_pem=priv_pem,
        public_key_pem=pub_pem,
        active=True
    )

# --- Test Classes --- #

class TestSecureGateway(TestCase):
    """Comprehensive test suite for SecureGateway"""

    def setUp(self):
        # Create test middleware key
        self.middleware_key = create_test_middleware_key()
        
        # Create test ephemeral key
        self.ephemeral_priv, self.ephemeral_pub = generate_ephemeral_key()
        self.ephemeral_key = EphemeralKey.objects.create(
            session_id=str(uuid.uuid4()),
            private_key_pem=self.ephemeral_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            ttl_seconds=300
        )
        
        # Generate client keys
        self.client_priv, self.client_pub_der = generate_ephemeral_key()
        self.client_priv_pem = self.client_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Derive session key
        self.session_key = derive_session_key(
            self.ephemeral_pub,
            self.client_priv
        )

    def create_valid_payload(self):
        """Create a valid transaction payload"""
        payload = {
            "transaction_data": {
                "username": "testuser",
                "phonenumber": "08012345678",
                "amount": 1000,
                "currency": "NGN"
            },
            "nonce": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "target": "transfer"
        }
        
        # Add signature
        payload["client_signature"] = ecdsa_sign(payload, self.client_priv_pem)
        
        # Add public key
        payload["client_public_key"] = self.client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return payload

    def create_encrypted_envelope(self, payload):
        """Encrypt payload and create envelope"""
        encrypted = aes_encrypt(payload, self.session_key)
        return {
            "ephemeral_pubkey": base64.b64encode(self.client_pub_der).decode(),
            "ciphertext": encrypted["ciphertext"],
            "iv": encrypted["iv"],
            "session_id": self.ephemeral_key.session_id
        }

    def test_missing_envelope_fields(self):
        """Test missing required envelope fields"""
        view = SecureGateway()
        request = MagicMock()
        request.data = {"session_id": "test"}  # Missing other fields
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "MISSING_FIELDS")

    def test_invalid_session_id(self):
        """Test with expired or invalid session ID"""
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        envelope["session_id"] = "invalid-session-id"
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_code"], "SESSION_EXPIRED")

    def test_expired_ephemeral_key(self):
        """Test with expired ephemeral key"""
        # Create expired key
        expired_key = EphemeralKey.objects.create(
            session_id=str(uuid.uuid4()),
            private_key_pem=self.ephemeral_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            ttl_seconds=-1  # Expired
        )
        
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        envelope["session_id"] = expired_key.session_id
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_code"], "SESSION_EXPIRED")

    def test_invalid_ciphertext_format(self):
        """Test with invalid base64 in ciphertext"""
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        envelope["ciphertext"] = "invalid-base64-!"
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "CIPHERTEXT_B64_DECODE_FAIL")

    def test_decryption_failure(self):
        """Test with invalid decryption (wrong key)"""
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        
        # Corrupt the ciphertext
        corrupted_ciphertext = base64.b64decode(envelope["ciphertext"])
        corrupted_ciphertext = corrupted_ciphertext[:-10] + b"corrupted"
        envelope["ciphertext"] = base64.b64encode(corrupted_ciphertext).decode()
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "DECRYPT_FAIL")

    def test_missing_nonce_timestamp(self):
        """Test missing nonce or timestamp in inner payload"""
        payload = self.create_valid_payload()
        del payload["nonce"]
        del payload["timestamp"]
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "MISSING_INNER_FIELDS")

    def test_stale_timestamp(self):
        """Test with stale timestamp"""
        payload = self.create_valid_payload()
        payload["timestamp"] = int(time.time()) - 3600  # 1 hour old
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "TIMESTAMP_INVALID")

    def test_future_timestamp(self):
        """Test with future timestamp"""
        payload = self.create_valid_payload()
        payload["timestamp"] = int(time.time()) + 3600  # 1 hour in future
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "TIMESTAMP_INVALID")

    def test_nonce_replay_attack(self):
        """Test replay attack detection"""
        payload = self.create_valid_payload()
        
        # First use - should succeed
        envelope = self.create_encrypted_envelope(payload)
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        # Mock downstream to avoid external calls
        with patch('middleware.api.views.downstream_handler.encrypt_and_send_to_bank') as mock_downstream:
            mock_downstream.return_value = ({"status": "success"}, 200, None)
            response1 = view.post(request)
        
        # Second use with same nonce - should fail
        response2 = view.post(request)
        self.assertEqual(response2.status_code, 409)
        self.assertEqual(response2.data["error_code"], "NONCE_REPLAY")

    def test_missing_signature_fields(self):
        """Test missing signature-related fields"""
        payload = self.create_valid_payload()
        del payload["client_signature"]
        del payload["client_public_key"]
        del payload["transaction_data"]
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "MISSING_SIG_FIELDS")

    def test_invalid_client_signature(self):
        """Test with invalid client signature"""
        payload = self.create_valid_payload()
        payload["client_signature"] = "invalid-signature-base64"
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_code"], "INVALID_SIGNATURE")

    def test_missing_target(self):
        """Test missing target field"""
        payload = self.create_valid_payload()
        del payload["target"]
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "MISSING_TARGET")

    def test_unknown_target(self):
        """Test unknown target routing"""
        payload = self.create_valid_payload()
        payload["target"] = "unknown-service"
        
        envelope = self.create_encrypted_envelope(payload)
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "UNKNOWN_TARGET")

    @patch('middleware.api.views.key_manager.get_active_middleware_key')
    def test_no_active_middleware_key(self, mock_get_key):
        """Test when no active middleware key is available"""
        mock_get_key.return_value = None
        
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["error_code"], "NO_ACTIVE_MW_KEY")

    @patch('middleware.api.views.downstream_handler.encrypt_and_send_to_bank')
    def test_downstream_service_error(self, mock_downstream):
        """Test downstream service failure"""
        mock_downstream.side_effect = Exception("Downstream service unavailable")
        
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.data["error_code"], "DOWNSTREAM_ERROR")

    @patch('middleware.api.views.downstream_handler.encrypt_and_send_to_bank')
    def test_successful_transaction(self, mock_downstream):
        """Test successful end-to-end transaction"""
        # Mock downstream response
        mock_response = {
            "status": "success",
            "transaction_id": "txn_12345",
            "message": "Transaction completed"
        }
        mock_downstream.return_value = (mock_response, 200, None)
        
        envelope = self.create_encrypted_envelope(self.create_valid_payload())
        
        view = SecureGateway()
        request = MagicMock()
        request.data = envelope
        
        response = view.post(request)
        self.assertEqual(response.status_code, 200)
        
        # Verify response is encrypted
        self.assertIn("iv", response.data)
        self.assertIn("ciphertext", response.data)

    def test_test_mode_operation(self):
        """Test middleware operation in test mode"""
        # Enable test mode
        original_test_mode = getattr(settings, "TEST_MODE", False)
        settings.TEST_MODE = True
        
        try:
            envelope = self.create_encrypted_envelope(self.create_valid_payload())
            
            view = SecureGateway()
            request = MagicMock()
            request.data = envelope
            
            response = view.post(request)
            self.assertEqual(response.status_code, 200)
            
            # Decrypt response to verify test mode message
            decrypted = aes_decrypt(response.data, self.session_key)
            self.assertEqual(decrypted["message"], "The Request has proven legitimate upto the point of the session key derivation")
            
        finally:
            # Restore original test mode setting
            settings.TEST_MODE = original_test_mode

    def test_response_encryption_failure(self):
        """Test response encryption failure fallback"""
        # Create a scenario where encryption fails
        invalid_session_key = b"invalid-key-to-force-encryption-failure"
        
        # Mock the session key derivation to return invalid key
        with patch('middleware.api.views.crypto_engine.derive_session_key_from_peer') as mock_derive:
            mock_derive.return_value = invalid_session_key
            
            envelope = self.create_encrypted_envelope(self.create_valid_payload())
            
            view = SecureGateway()
            request = MagicMock()
            request.data = envelope
            
            # Mock downstream to return success
            with patch('middleware.api.views.downstream_handler.encrypt_and_send_to_bank') as mock_downstream:
                mock_downstream.return_value = ({"status": "success"}, 200, None)
                
                response = view.post(request)
                
            # Should return plaintext error due to encryption failure
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.data["error_code"], "RESPONSE_ENCRYPT_FAIL")
