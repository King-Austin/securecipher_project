# middleware/tests/test_crypto.py
import pytest
from modules import crypto_engine

def test_encrypt_decrypt_cycle():
    plaintext = b"secure-test-message"
    key="1234"

    cipher_payload = crypto_engine.aes256gcm_encrypt(plaintext, key)
    decrypted = crypto_engine.aes256gcm_decrypt(cipher_payload, key)

    assert decrypted == plaintext


def test_decrypt_invalid_payload():

    with pytest.raises(Exception):
        crypto_engine.aes256gcm_decrypt({"ciphertext": "fake", "iv": "wrong", "ephemeral_public_key": "bad"})
