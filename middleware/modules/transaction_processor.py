from .crypto_engine import aes256gcm_encrypt, aes256gcm_decrypt, ecdsa_sign
from .key_manager import derive_session_key
import time

# --- Process transaction ---
def process_transaction(transaction: dict, client_sig: str, client_pubkey: str):
    """Validate and forward transaction"""
    # Normally validate client signature here (omitted for demo)
    tx_record = {
        "transaction": transaction,
        "client_signature": client_sig,
        "client_public_key": client_pubkey,
        "timestamp": time.time()
    }
    return tx_record

# --- Encrypt and send to bank ---
def encrypt_and_send_to_bank(tx_record: dict, session_key: bytes):
    """Encrypt transaction record before sending downstream"""
    return aes256gcm_encrypt(tx_record, session_key)

# --- Handle response from bank ---
def handle_response_from_bank(encrypted_response: dict, session_key: bytes):
    """Decrypt bank response"""
    return aes256gcm_decrypt(encrypted_response, session_key)
