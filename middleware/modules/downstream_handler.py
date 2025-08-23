# transaction_processor.py
import requests
from django.conf import settings
from typing import Tuple, Dict, Any
from .crypto_engine import aes256gcm_encrypt, aes256gcm_decrypt, create_downstream_envelope




def send_downstream_request(method: str, url: str, data: dict = None, headers: dict = None, timeout: int = 30) -> Tuple[dict, int]:
    """
    Send request to downstream service and return (response_data, status_code)
    """
    headers = headers or {
        "Content-Type": "application/json",
        "User-Agent": "SecureCipher-Middleware/1.0",
        "X-Forwarded-By": "SecureCipher"
    }
    
    try:
        resp = requests.request(method=method.upper(), url=url, json=data, headers=headers, timeout=timeout)
        try:
            return resp.json(), resp.status_code
        except ValueError:
            return {"error": "Invalid JSON from downstream", "raw_response": resp.text[:500]}, resp.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}, 502

def get_routing_table() -> Dict[str, str]:
    """Get the routing table from Django settings"""
    return getattr(settings, "ROUTING_TABLE", {})

def get_bank_public_key() -> str:
    """Fetch the banking API's public key"""
    routing_table = get_routing_table()
    url = routing_table.get("public_key")
    if not url:
        raise ValueError("Public key endpoint not configured in ROUTING_TABLE")
    
    result, status = send_downstream_request("GET", url)
    if status != 200:
        raise ValueError(f"Failed to fetch public key from {url}: {status} {result}")
    
    key_pem = result.get("public_key")
    if not key_pem:
        raise ValueError("Banking API public key not found in response")
    
    return key_pem

def get_target_url(target: str) -> str:
    """Get the URL for a specific target from settings"""
    routing_table = get_routing_table()
    url = routing_table.get(target)
    if not url:
        raise ValueError(f"Unknown target: {target}")
    
    return url



def process_transaction(transaction_data: dict, client_sig: str, client_pubkey_b64: str) -> dict:
    """Prepare transaction data for downstream processing"""
    return {
        "transaction_data": transaction_data,
        "client_signature": client_sig,
        "client_public_key": client_pubkey_b64
    }

def encrypt_and_send_to_bank(tx_record: dict, target: str) -> Tuple[dict, int, bytes]:
    """Encrypt and send transaction to banking API"""
    bank_pubkey_pem = get_bank_public_key()
    envelope, downstream_session_key = create_downstream_envelope(tx_record, bank_pubkey_pem)
    downstream_url = get_target_url(target)
    response, status = send_downstream_request("POST", downstream_url, data=envelope)
    return response, status, downstream_session_key

def handle_response_from_bank(response_data: dict, downstream_session_key: bytes) -> dict:
    """Handle and decrypt response from banking API"""
    if not isinstance(response_data, dict) or "iv" not in response_data or "ciphertext" not in response_data:
        return response_data
    return aes256gcm_decrypt(response_data, downstream_session_key)