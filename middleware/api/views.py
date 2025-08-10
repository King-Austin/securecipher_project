import os
import base64
import json
import hashlib
import traceback
import time
import logging
import uuid
from typing import Tuple, Dict, Any, Optional
from functools import wraps

from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.conf import settings

from api.models import MiddlewareKey, UsedNonce, TransactionMetadata
from scripts import generate_keypair
from .crypto_utils import CryptoHandler
from .downstream_handler import (
    send_downstream_request,
    get_bank_public_key,
    get_target_url
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Security logger
security_logger = logging.getLogger('securecipher.security')

# Constants for security
SESSION_KEY_INFO = b'secure-cipher-session-key'
AES_GCM_IV_SIZE = 12
ECDH_CURVE = ec.SECP384R1()
TIMESTAMP_WINDOW_SECONDS = 300  # 5 minutes
SESSION_KEY_LENGTH = 32


def hash_data(data: str) -> str:
    """Generate SHA256 hash of data"""
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def create_transaction_metadata(
    transaction_id: str,
    client_ip: str,
    start_time: float,
    **kwargs
) -> TransactionMetadata:
    """Create and save transaction metadata"""
    processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    
    metadata = TransactionMetadata(
        transaction_id=transaction_id,
        client_ip=client_ip,
        processing_time_ms=processing_time,
        **kwargs
    )
    metadata.save()
    return metadata


def update_transaction_metadata(
    transaction_id: str,
    **kwargs
) -> None:
    """Update existing transaction metadata"""
    try:
        metadata = TransactionMetadata.objects.get(transaction_id=transaction_id)
        for key, value in kwargs.items():
            setattr(metadata, key, value)
        metadata.save()
    except TransactionMetadata.DoesNotExist:
        print(f"WARNING: Transaction metadata not found for ID: {transaction_id}")


def log_transaction_metadata(func):
    """
    Decorator to automatically log transaction metadata for middleware functions
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        transaction_id = str(uuid.uuid4())
        start_time = time.time()
        client_ip = request.META.get('REMOTE_ADDR', 'unknown')
        
        # Store transaction context in request for access in the view
        request.transaction_context = {
            'transaction_id': transaction_id,
            'start_time': start_time,
            'client_ip': client_ip
        }
        
        try:
            response = func(request, *args, **kwargs)
            
            # Log successful transaction
            if hasattr(request, 'transaction_metadata'):
                request.transaction_metadata.update({
                    'status_code': response.status_code,
                    'response_size_bytes': len(str(response.data)) if response.data else 0
                })
                create_transaction_metadata(
                    transaction_id=transaction_id,
                    client_ip=client_ip,
                    start_time=start_time,
                    **request.transaction_metadata
                )
            
            return response
            
        except Exception as e:
            # Log failed transaction
            error_metadata = getattr(request, 'transaction_metadata', {})
            error_metadata.update({
                'status_code': 500,
                'error_message': str(e),
                'error_step': getattr(request, 'current_step', 'unknown')
            })
            
            create_transaction_metadata(
                transaction_id=transaction_id,
                client_ip=client_ip,
                start_time=start_time,
                **error_metadata
            )
            
            raise
    
    return wrapper


def get_or_create_active_key():
    """Get active middleware key or create one if it doesn't exist"""
    try:
        return MiddlewareKey.objects.get(label="active")
    except MiddlewareKey.DoesNotExist:
        print("DEBUG: No active middleware key found, generating new one...")
        generate_keypair.generate()
        return MiddlewareKey.objects.get(label="active")


def verify_signature(payload_dict, signature_b64, public_key_str):
    """
    Unified ECDSA signature verification for both PEM and DER/BASE64 public keys.
    """
    try:
        # Load public key (PEM or DER/BASE64)
        if "-----BEGIN PUBLIC KEY-----" in public_key_str:
            public_key = serialization.load_pem_public_key(public_key_str.encode())
        else:
            public_key = serialization.load_der_public_key(base64.b64decode(public_key_str))

        # Canonical JSON encoding
        message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
        signature_bytes = base64.b64decode(signature_b64)

        # If signature is raw (r||s), convert to DER
        if len(signature_bytes) == 96:
            r = int.from_bytes(signature_bytes[:48], byteorder='big')
            s = int.from_bytes(signature_bytes[48:], byteorder='big')
            signature_bytes = encode_dss_signature(r, s)

        public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"DEBUG: Signature verification failed: {e}")
        return False


def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive session key from ECDH shared secret using HKDF"""
    return HKDF(
        algorithm=hashes.SHA384(),
        length=SESSION_KEY_LENGTH,
        salt=b'',
        info=SESSION_KEY_INFO
    ).derive(shared_secret)


def create_ephemeral_keypair() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate ephemeral ECDH keypair and return private key + DER public key"""
    private_key = ec.generate_private_key(ECDH_CURVE)
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_der


def encrypt_payload(payload: Dict[str, Any], session_key: bytes) -> Dict[str, str]:
    """Encrypt payload using AES-GCM and return base64-encoded envelope"""
    aesgcm = AESGCM(session_key)
    iv = os.urandom(AES_GCM_IV_SIZE)
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    ciphertext = aesgcm.encrypt(iv, payload_json.encode(), None)
    
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_payload(envelope: Dict[str, str], session_key: bytes) -> Dict[str, Any]:
    """Decrypt AES-GCM payload from base64-encoded envelope"""
    aesgcm = AESGCM(session_key)
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(decrypted_bytes.decode())


def establish_downstream_session(bank_public_key_pem: str) -> Tuple[bytes, bytes, bytes]:
    """
    Establish secure session with downstream banking API
    Returns: (session_key, ephemeral_public_der, ephemeral_private_key)
    """
    # Generate ephemeral keypair for downstream
    ephemeral_private, ephemeral_public_der = create_ephemeral_keypair()
    
    # Load bank public key and perform ECDH
    bank_public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())
    if not isinstance(bank_public_key.curve, ec.SECP384R1):
        raise ValueError("Bank public key must use SECP384R1 curve")
    
    # Derive shared secret and session key
    shared_secret = ephemeral_private.exchange(ec.ECDH(), bank_public_key)
    session_key = derive_session_key(shared_secret)
    
    print(f"DEBUG: Downstream session established, session_key: {session_key.hex()}")
    return session_key, ephemeral_public_der, shared_secret


def create_downstream_envelope(payload: Dict[str, Any], bank_public_key_pem: str) -> Tuple[Dict[str, str], bytes]:
    """
    Create encrypted envelope for downstream banking API
    Returns: (envelope, session_key)
    """
    session_key, ephemeral_public_der, _ = establish_downstream_session(bank_public_key_pem)
    
    # Create encrypted envelope
    envelope = encrypt_payload(payload, session_key)
    envelope["ephemeral_pubkey"] = base64.b64encode(ephemeral_public_der).decode()
    
    print(f"DEBUG: Downstream envelope created: {list(envelope.keys())}")
    return envelope, session_key


def validate_timestamp(timestamp: Optional[int]) -> None:
    """Validate timestamp is within acceptable window"""
    if timestamp:
        current_time = int(time.time())
        if abs(current_time - timestamp) > TIMESTAMP_WINDOW_SECONDS:
            raise ValueError(f"Request timestamp outside acceptable window: {timestamp} vs {current_time}")


def validate_nonce(nonce: str) -> None:
    """Validate and store nonce to prevent replay attacks"""
    if not nonce:
        raise ValueError("Nonce is required.")
    
    is_valid, message = UsedNonce.is_nonce_valid(nonce)
    if not is_valid:
        raise ValueError(f"Nonce validation failed: {message}")
    
    UsedNonce.objects.create(nonce=nonce)
    print("DEBUG: Nonce validated and stored.")


def sign_payload(payload_dict: Dict[str, Any], private_key_pem: str) -> str:
    """Sign payload using ECDSA with SHA256"""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def process_downstream_response(response_data: Dict[str, Any], downstream_session_key: bytes, status_code: int) -> Tuple[Dict[str, Any], int]:
    """
    Process and validate response from downstream banking API
    Returns: (business_data, status_code)
    """
    print(f"DEBUG: Processing downstream response with keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Not a dict'}")
    
    if not isinstance(response_data, dict):
        print("ERROR: Banking API response is not a dictionary")
        return response_data, status_code
    
    # Check for encrypted response format
    if "iv" not in response_data or "ciphertext" not in response_data:
        print("ERROR: Missing iv or ciphertext in banking API response")
        return response_data, status_code
    
    try:
        # Decrypt the banking API response
        banking_server_response = decrypt_payload(response_data, downstream_session_key)
        print(f"DEBUG: Banking server response decrypted: {list(banking_server_response.keys()) if isinstance(banking_server_response, dict) else 'Not a dict'}")
        
        # Extract structured response components
        business_payload = banking_server_response.get('payload', {})
        server_signature = banking_server_response.get('signature')
        server_pubkey = banking_server_response.get('server_pubkey')
        
        # Verify server signature if provided
        if server_signature and server_pubkey:
            print("DEBUG: Verifying server signature...")
            try:
                if verify_signature(business_payload, server_signature, server_pubkey):
                    print("DEBUG: Server signature verified successfully")
                else:
                    print("WARNING: Server signature verification failed")
            except Exception as e:
                print(f"WARNING: Server signature verification error: {e}")
        else:
            print("DEBUG: No signature provided, skipping verification")
        
        return business_payload, status_code
        
    except Exception as e:
        print(f"ERROR: Failed to process downstream response: {e}")
        return {"error": f"Response processing failed: {str(e)}"}, 500



@api_view(["GET"])
def get_public_key(request):
    print("DEBUG: Client requesting server public key...")
    middleware_key = get_or_create_active_key()
    print(f"DEBUG: Server public key retrieved: {middleware_key.public_key_pem[:50]}...")
    return Response({"public_key": middleware_key.public_key_pem})


@api_view(["POST"])
@log_transaction_metadata
def secure_gateway(request):
    print("DEBUG: [STEP 0] SecureCipher gateway called")
    
    session_key = None
    transaction_id = request.transaction_context['transaction_id']
    start_time = request.transaction_context['start_time']
    client_ip = request.transaction_context['client_ip']
    
    # Initialize metadata collection
    request.transaction_metadata = {}
    
    print(f"DEBUG: [STEP 0] Transaction ID: {transaction_id}")
    print(f"DEBUG: [STEP 0] Request from IP: {client_ip}")
    
    try:
        # --- Step 1: Parse and validate outer envelope ---
        request.current_step = "envelope_parsing"
        print("DEBUG: [STEP 1] Parsing and validating outer envelope...")
        
        encrypted_payload = request.data
        
        # Input validation
        if not isinstance(encrypted_payload, dict):
            raise ValueError("Invalid payload format: must be JSON object")
            
        print(f"DEBUG: [STEP 1] Incoming payload keys: {list(encrypted_payload.keys())}")
        client_ephemeral_pub_b64 = encrypted_payload.get("ephemeral_pubkey")
        ciphertext_b64 = encrypted_payload.get("ciphertext")
        iv_b64 = encrypted_payload.get("iv")
        
        # Validate required fields
        if not (client_ephemeral_pub_b64 and ciphertext_b64 and iv_b64):
            print("DEBUG: [STEP 1] Missing required envelope fields.")
            raise ValueError("Missing required envelope fields.")
            
        # Validate base64 format and lengths
        try:
            ephemeral_der = base64.b64decode(client_ephemeral_pub_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            # Collect payload size metadata
            request.transaction_metadata['payload_size_bytes'] = len(ciphertext)
            
            # Validate lengths
            if len(iv) != 12:  # AES-GCM IV should be 12 bytes
                raise ValueError("Invalid IV length")
            if len(ephemeral_der) < 50 or len(ephemeral_der) > 200:  # Reasonable bounds for P-384
                raise ValueError("Invalid ephemeral key length")
                
        except Exception as e:
            print(f"DEBUG: [STEP 1] Base64 decode error: {e}")
            raise ValueError("Invalid base64 encoding in payload")

        # --- Step 2: Derive session key using ECDH ---
        request.current_step = "ecdh_derivation"
        print("DEBUG: [STEP 2] Deriving session key using ECDH...")
        try:
            middleware_key = get_or_create_active_key()
            print(f"DEBUG: [STEP 2] Middleware key loaded: {middleware_key}")
            
            middleware_private_key = serialization.load_pem_private_key(
                middleware_key.private_key_pem.encode(), password=None
            )
            
            client_ephemeral_pub_der = base64.b64decode(client_ephemeral_pub_b64)
            print(f"DEBUG: [STEP 2] Client ephemeral pubkey DER: {client_ephemeral_pub_der.hex()}")
            
            client_ephemeral_pub = serialization.load_der_public_key(client_ephemeral_pub_der)
            
            # Validate that it's the correct curve
            if not isinstance(client_ephemeral_pub.curve, ec.SECP384R1):
                raise ValueError("Invalid elliptic curve. Expected SECP384R1.")
                
            shared_key = middleware_private_key.exchange(ec.ECDH(), client_ephemeral_pub)
            print(f"DEBUG: [STEP 2] Shared key: {shared_key.hex()}")
            
            session_key = derive_session_key(shared_key)
            print(f"DEBUG: [STEP 2] Session key derived: {session_key.hex()}")
            
            # Store session key hash for metadata
            request.transaction_metadata['session_key_hash'] = hash_data(session_key)
            
        except Exception as e:
            print(f"DEBUG: [STEP 2] ECDH derivation failed: {e}")
            raise ValueError(f"Key exchange failed: {str(e)}")

        # --- Step 3: Decrypt AES-GCM payload ---
        request.current_step = "payload_decryption"
        print("DEBUG: [STEP 3] Decrypting AES-GCM payload...")
        try:
            client_envelope = {
                "iv": iv_b64,
                "ciphertext": ciphertext_b64
            }
            inner_payload = decrypt_payload(client_envelope, session_key)
            print(f"DEBUG: [STEP 3] Inner payload: {inner_payload}")
        except Exception as e:
            print(f"DEBUG: [STEP 3] Decryption failed: {e}")
            raise ValueError(f"Payload decryption failed: {str(e)}")

        # --- Step 4: Extract and validate inner payload fields ---
        request.current_step = "payload_validation"
        print("DEBUG: [STEP 4] Extracting and validating inner payload fields...")
        target_url = inner_payload.get("target")
        transaction_data = inner_payload.get("transaction_data")
        client_signature = inner_payload.get("client_signature")
        client_public_key_b64 = inner_payload.get("client_public_key")
        nonce = inner_payload.get("nonce")
        timestamp = inner_payload.get("timestamp")
        print(f"DEBUG: [STEP 4] target_url: {target_url}, nonce: {nonce}, timestamp: {timestamp}")

        # Store metadata from inner payload
        request.transaction_metadata.update({
            'nonce': nonce or '',
            'target_url': target_url or '',
            'payload_hash': hash_data(json.dumps(transaction_data, sort_keys=True) if transaction_data else ''),
            'client_public_key_hash': hash_data(client_public_key_b64 or '')
        })

        # Enhanced nonce validation
        if not nonce:
            print("DEBUG: [STEP 4] Nonce is missing!")
            raise ValueError("Nonce is required.")
        validate_timestamp(timestamp)
        validate_nonce(nonce)

        # --- Step 5: Verify client signature ---
        request.current_step = "signature_verification"
        print("DEBUG: [STEP 5] Verifying client signature...")
        sign_payload_dict = {
            "transaction_data": transaction_data,
        }
        signature_valid = verify_signature(sign_payload_dict, client_signature, client_public_key_b64)
        request.transaction_metadata['client_signature_verified'] = signature_valid
        
        if not signature_valid:
            print("DEBUG: [STEP 5] Client signature verification failed.")
            error_response = {"error": "Client signature verification failed"}
            encrypted_response = encrypt_payload(error_response, session_key)
            return Response(encrypted_response, status=400)
        
        
        print("DEBUG: [STEP 5] Client signature verified.")

        # --- Step 6: Add middleware signature/public key ---
        request.current_step = "middleware_signing"
        print("DEBUG: [STEP 6] Adding middleware signature and public key...")
        forwarded_payload = {
            "transaction_data": transaction_data,
            "client_signature": client_signature,
            "client_public_key": client_public_key_b64,
            "nonce": nonce
        }
        middleware_signature = sign_payload(forwarded_payload, middleware_key.private_key_pem)
        print(f"DEBUG: [STEP 6] Middleware signature: {middleware_signature}")
        
        # Store middleware signature in metadata
        request.transaction_metadata['middleware_signature'] = middleware_signature
        
        middleware_public_key_der = base64.b64encode(
            serialization.load_pem_public_key(middleware_key.public_key_pem.encode()).public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        print(f"DEBUG: [STEP 6] Middleware public key DER: {middleware_public_key_der}")

        forwarded_payload["middleware_signature"] = middleware_signature
        forwarded_payload["middleware_public_key"] = middleware_public_key_der

        # --- Step 7: Create downstream envelope ---
        request.current_step = "downstream_envelope"
        print("DEBUG: [STEP 7] Creating downstream envelope...")
        
        downstream_envelope, downstream_session_key = create_downstream_envelope(
            forwarded_payload, 
            get_bank_public_key()
        )
        
        print(f"DEBUG: [STEP 7] Downstream envelope created with keys: {list(downstream_envelope.keys())}")

        # --- Step 8: Route to downstream ---
        request.current_step = "downstream_routing"
        print("DEBUG: [STEP 8] Routing to downstream...")
        downstream_url = get_target_url(target_url)
        print(f"DEBUG: [STEP 8] Downstream URL: {downstream_url}")
        
        downstream_start_time = time.time()
        response_data, status_code = send_downstream_request(
            "POST", downstream_url, data=downstream_envelope
        )
        downstream_response_time = (time.time() - downstream_start_time) * 1000  # Convert to ms
        
        # Store downstream response metadata
        request.transaction_metadata.update({
            'status_code': status_code,
            'downstream_response_time_ms': downstream_response_time
        })
        
        print(f"DEBUG: [STEP 8] Downstream response status: {status_code}")

        # --- Step 9: Process banking API response ---
        request.current_step = "response_processing"
        print("DEBUG: [STEP 9] Processing banking API response...")
        
        business_data, final_status = process_downstream_response(
            response_data, 
            downstream_session_key, 
            status_code
        )
        
        # Re-encrypt business data for frontend
        frontend_response = encrypt_payload(business_data, session_key)
        
        # Update final metadata
        request.transaction_metadata.update({
            'status_code': final_status,
            'response_size_bytes': len(str(frontend_response)) if frontend_response else 0
        })
        
        print("DEBUG: [STEP 9] Business data re-encrypted for frontend")
        return Response(frontend_response, status=final_status)

    except Exception as error:
        print(f"DEBUG: [EXCEPTION] SecureCipher gateway exception: {error}")
        traceback.print_exc()
        
        if session_key:
            error_response = {"error": str(error)}
            encrypted_response = encrypt_payload(error_response, session_key)
            print("DEBUG: [EXCEPTION] Encrypted error response ready.")
            return Response(encrypted_response, status=500)
        else:
            print("DEBUG: [EXCEPTION] No session key, returning plain error.")
            return Response({"error": "An internal error occurred during decryption"}, status=500)
