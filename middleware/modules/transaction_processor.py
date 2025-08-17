# transaction_processor.py
from .crypto_engine import aes256gcm_encrypt, aes256gcm_decrypt, create_downstream_envelope
from .downstream_handler import send_downstream_request, get_target_url, get_bank_public_key

def process_transaction(transaction_data: dict, client_sig: str, client_pubkey_b64: str) -> dict:
    return {
        "transaction_data": transaction_data,
        "client_signature": client_sig,
        "client_public_key": client_pubkey_b64
    }

def encrypt_and_send_to_bank(tx_record: dict, target: str):
    bank_pubkey_pem = get_bank_public_key()
    envelope, downstream_session_key = create_downstream_envelope(tx_record, bank_pubkey_pem)
    downstream_url = get_target_url(target)
    response, status = send_downstream_request("POST", downstream_url, data=envelope)
    return response, status, downstream_session_key

def handle_response_from_bank(response_data: dict, downstream_session_key: bytes):
    if not isinstance(response_data, dict) or "iv" not in response_data or "ciphertext" not in response_data:
        return response_data
    return aes256gcm_decrypt(response_data, downstream_session_key)
