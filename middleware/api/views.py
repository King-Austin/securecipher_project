# views.py
"""
Refactored SecureCipher middleware views (logger removed per request).
- Delegates cryptography to crypto_engine
- Key lifecycle to key_manager (DB-backed)
- Transaction processing to transaction_processor
- Audit persistence to audit_logs (DB-backed)
- Transaction metadata persisted via transaction_metadata
- Downstream HTTP handled by downstream_handler

This file intentionally includes verbose prints for debugging (can be switched back to logger later).
"""

import base64
import json
import time
import traceback
import uuid

from django.db import IntegrityError
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response

# App modules (these must exist in the same app package)
from modules import crypto_engine
from modules import key_manager
from modules import transaction_processor
from modules import transaction_metadata as tx_meta
from modules import audit_logs
from modules import tls_middleware
from modules.downstream_handler import send_downstream_request, get_bank_public_key, get_target_url

# DB models (persistent storage)
from .models import MiddlewareKey, UsedNonce, TransactionMetadata, AuditLog


def index_view(request):
    """Render the SecureCipher middleware landing page"""
    return render(request, 'index.html')


@api_view(["GET"])
def get_public_key(request):
    """
    Return middleware public key PEM (persistent via MiddlewareKey).
    """
    try:
        mk = key_manager.get_active_middleware_key()
        public_pem = mk.public_key_pem
        print("[GET_PUBLIC_KEY] Returning public key (truncated):", (public_pem[:80] + "...") if public_pem else "None")
        return Response({"public_key": public_pem})
    except Exception as e:
        # logger.exception replaced with print + traceback
        print("[GET_PUBLIC_KEY] ERROR retrieving middleware public key:", str(e))
        traceback.print_exc()
        return Response({"error": "Failed to retrieve public key"}, status=500)


@api_view(["POST"])
def secure_gateway(request):
    """
    Main SecureCipher gateway view.
    - Accepts outer AES-GCM envelope with client's ephemeral_pubkey (base64)
    - Derives per-request session key using server private key and client ephemeral pubkey
    - Decrypts inner payload, validates timestamp/nonce, verifies client signature
    - Signs forwarded payload with middleware key, sends to downstream bank (new ephemeral per-request)
    - Decrypts downstream response, optionally verifies server signature
    - Re-encrypts business payload for client and returns.
    """
    transaction_id = str(uuid.uuid4())
    start_time = time.time()
    client_ip = request.META.get("REMOTE_ADDR", "unknown")

    print(f"[SECURE_GATEWAY] NEW tx={transaction_id} from {client_ip}")
    audit_logs.log_event(transaction_id, "request_received", {"client_ip": client_ip})

    session_key = None  # ephemeral per-request; never persisted raw
    try:
        # --- Parse outer envelope ---
        encrypted_payload = request.data
        print("[STEP 1] Received envelope keys:", list(encrypted_payload.keys()) if isinstance(encrypted_payload, dict) else "invalid")
        audit_logs.log_event(transaction_id, "envelope_received", {"keys": list(encrypted_payload.keys()) if isinstance(encrypted_payload, dict) else []})

        if not isinstance(encrypted_payload, dict):
            raise ValueError("Invalid envelope format: expected JSON object")

        client_ephemeral_pub_b64 = encrypted_payload.get("ephemeral_pubkey")
        iv_b64 = encrypted_payload.get("iv")
        ciphertext_b64 = encrypted_payload.get("ciphertext")

        if not (client_ephemeral_pub_b64 and iv_b64 and ciphertext_b64):
            print("[STEP 1] ERROR: Missing required envelope fields")
            raise ValueError("Missing required envelope fields (ephemeral_pubkey/iv/ciphertext)")

        # decode and basic checks
        try:
            client_ephemeral_der = base64.b64decode(client_ephemeral_pub_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            print(f"[STEP 1] Decoded sizes - ephemeral_pub: {len(client_ephemeral_der)} bytes, iv: {len(iv)} bytes, ciphertext: {len(ciphertext)} bytes")
            audit_logs.log_event(transaction_id, "envelope_decoded", {"ephemeral_pub_len": len(client_ephemeral_der), "iv_len": len(iv), "ciphertext_len": len(ciphertext)})
            tx_meta.create_transaction_metadata(transaction_id, client_ip=client_ip, payload_size_bytes=len(ciphertext), start_time=start_time)
        except Exception as e:
            print("[STEP 1] Base64 decode error:", str(e))
            traceback.print_exc()
            raise ValueError("Invalid base64 encoding in envelope")

        # --- Derive session key (ECDH) using middleware private key ---
        mk = key_manager.get_active_middleware_key()
        print("[STEP 2] Loaded middleware key:", f"label={mk.label} v{mk.version} active={mk.active}")
        audit_logs.log_event(transaction_id, "middleware_key_loaded", {"label": mk.label, "version": mk.version})

        # derive session key: key_manager handles private key loading and ECDH
        session_key = key_manager.derive_session_key(client_ephemeral_der)
        session_key_hash = crypto_engine.hash_data(session_key)
        print("[STEP 2] Derived session key hash:", session_key_hash)
        audit_logs.log_event(transaction_id, "session_key_derived", {"session_key_hash": session_key_hash})
        tx_meta.update_transaction_metadata(transaction_id, session_key_hash=session_key_hash)

        # --- Decrypt inner payload ---
        inner_envelope = {"iv": iv_b64, "ciphertext": ciphertext_b64}
        try:
            inner_payload = crypto_engine.aes256gcm_decrypt(inner_envelope, session_key)
            print("[STEP 3] Inner payload decrypted. Keys:", list(inner_payload.keys()))
            audit_logs.log_event(transaction_id, "payload_decrypted", {"inner_keys": list(inner_payload.keys())})
            tx_meta.update_transaction_metadata(transaction_id, details={"inner_keys": list(inner_payload.keys())})
        except Exception as e:
            print("[STEP 3] Decryption failed:", str(e))
            traceback.print_exc()
            raise ValueError(f"Payload decryption failed: {e}")

        # --- Validate timestamp & nonce ---
        nonce = inner_payload.get("nonce")
        timestamp = inner_payload.get("timestamp")
        print(f"[STEP 4] Received nonce={nonce} timestamp={timestamp}")
        audit_logs.log_event(transaction_id, "timestamp_nonce_received", {"nonce": nonce, "timestamp": time.ctime(timestamp) if timestamp else "None"})
        # Validate timestamp (may raise)
        crypto_engine.validate_timestamp(timestamp)
        tx_meta.update_transaction_metadata(transaction_id, request_timestamp=timestamp)

        # Validate nonce using persistent UsedNonce model
        if nonce is None:
            raise ValueError("Nonce missing in inner payload")

        try:
            # Attempt create; unique constraint ensures replay protection
            UsedNonce.objects.create(nonce=nonce)
            print("[STEP 4] Nonce stored successfully.")
            audit_logs.log_event(transaction_id, "nonce_stored", {"nonce_trunc": nonce[:64]})
        except IntegrityError:
            print("[STEP 4] Nonce replay detected:", nonce)
            audit_logs.log_event(transaction_id, "nonce_replay_detected", {"nonce_trunc": nonce[:64]})
            raise ValueError("Nonce already used (replay detected)")

        # --- Verify client signature ---
        transaction_data = inner_payload.get("transaction_data")
        client_signature = inner_payload.get("client_signature")
        client_public_key = inner_payload.get("client_public_key")  # PEM or base64 DER allowed

        if not (transaction_data and client_signature and client_public_key):
            raise ValueError("Missing transaction_data / client_signature / client_public_key")

        print("[STEP 5] Verifying client signature...")
        verify_payload = {"transaction_data": transaction_data}
        client_sig_valid = crypto_engine.ecdsa_verify(verify_payload, client_signature, client_public_key)
        print("[STEP 5] Client signature verification result:", client_sig_valid)
        audit_logs.log_event(transaction_id, "client_signature_verified", {"valid": client_sig_valid})
        tx_meta.update_transaction_metadata(transaction_id, client_signature_verified=client_sig_valid)

        if not client_sig_valid:
            err = {"error": "Client signature verification failed"}
            encrypted_err = crypto_engine.aes256gcm_encrypt(err, session_key)
            print("[STEP 5] Invalid client signature; returning encrypted error")
            return Response(encrypted_err, status=400)

        # --- Middleware signs forwarded payload ---
        forwarded_payload = {
            "transaction_data": transaction_data,
            "client_signature": client_signature,
            "client_public_key": client_public_key,
            "nonce": nonce,
        }

        middleware_signature = crypto_engine.ecdsa_sign(forwarded_payload, mk.private_key_pem)
        print(f"[STEP 6] Middleware signature created: signature {middleware_signature} (len):", len(middleware_signature))
        audit_logs.log_event(transaction_id, "middleware_signed", {"signature_len": len(middleware_signature)})
        tx_meta.update_transaction_metadata(transaction_id, middleware_signature=middleware_signature)

        # Attach middleware public key PEM for downstream
        middleware_public_pem = mk.public_key_pem
        forwarded_payload["middleware_signature"] = middleware_signature
        forwarded_payload["middleware_public_key"] = middleware_public_pem

        # --- Encrypt and send to downstream bank ---
        target = inner_payload.get("target")
        if not target:
            raise ValueError("Missing target in inner payload")

        print(f"[STEP 7] Creating downstream envelope and sending to target='{target}'")
        print("[STEP 7] Forwarded payload keys:", list(forwarded_payload.keys()))
        audit_logs.log_event(transaction_id, "forwarding_to_downstream", {"target": target})

        response_data, status_code, downstream_session_key = transaction_processor.encrypt_and_send_to_bank(forwarded_payload, target)
        print("[STEP 7] Downstream response status:", status_code)
        audit_logs.log_event(transaction_id, "downstream_response_received", {"status_code": status_code})
        tx_meta.update_transaction_metadata(transaction_id, downstream_response_time_ms=(time.time() - start_time) * 1000)

        # --- Process downstream response ---
        business_payload = transaction_processor.handle_response_from_bank(response_data, downstream_session_key)
        if isinstance(business_payload, dict):
            print("[STEP 8] Business payload keys:", list(business_payload.keys()))
        else:
            print("[STEP 8] Business payload non-dict:", str(business_payload)[:200])
        audit_logs.log_event(transaction_id, "downstream_processed")

        # Optionally verify server signature if provided
        server_signature = business_payload.get("signature") if isinstance(business_payload, dict) else None
        server_pubkey = business_payload.get("server_pubkey") if isinstance(business_payload, dict) else None
        if server_signature and server_pubkey:
            try:
                sv = crypto_engine.ecdsa_verify(business_payload.get("payload", {}), server_signature, server_pubkey)
                print("[STEP 8] Server signature verification result:", sv)
                audit_logs.log_event(transaction_id, "server_signature_verified", {"verified": sv})
            except Exception as e:
                print("[STEP 8] Server signature verification error:", str(e))
                traceback.print_exc()
                audit_logs.log_event(transaction_id, "server_signature_verification_failed", {"error": str(e)})

        # --- Re-encrypt business payload for client using session_key ---
        payload_to_client = business_payload.get("payload", business_payload) if isinstance(business_payload, dict) else business_payload
        frontend_envelope = crypto_engine.aes256gcm_encrypt(payload_to_client, session_key)
        print("[STEP 9] Re-encrypted business payload for client, envelope keys:", list(frontend_envelope.keys()))
        audit_logs.log_event(transaction_id, "response_encrypted_for_client", {"envelope_keys": list(frontend_envelope.keys())})
        tx_meta.update_transaction_metadata(transaction_id, status_code=status_code, response_size_bytes=len(json.dumps(frontend_envelope)), processing_time_ms=(time.time() - start_time) * 1000)

        # Persist minimal TransactionMetadata info using tx_meta module (db-backed)
        try:
            tx_meta.update_transaction_metadata(
                transaction_id,
                client_ip=client_ip,
                processing_time_ms=(time.time() - start_time) * 1000,
                payload_size_bytes=len(ciphertext),
                client_signature_verified=client_sig_valid,
                status_code=status_code
            )
            print("[DB] TransactionMetadata updated for tx:", transaction_id)
        except Exception as e:
            print("[DB] Warning: could not persist TransactionMetadata:", str(e))
            traceback.print_exc()

        print(f"[SECURE_GATEWAY] Completed tx={transaction_id} in {int((time.time() - start_time) * 1000)}ms")
        return Response(frontend_envelope, status=status_code)

    except Exception as exc:
        print("[SECURE_GATEWAY] EXCEPTION:", str(exc))
        traceback.print_exc()
        audit_logs.log_event(transaction_id, "exception", {"error": str(exc)})

        # If session_key available, try to encrypt error response
        if session_key:
            try:
                err_payload = {"error": str(exc)}
                encrypted_err = crypto_engine.aes256gcm_encrypt(err_payload, session_key)
                print("[SECURE_GATEWAY] Returning encrypted error for tx:", transaction_id)
                return Response(encrypted_err, status=500)
            except Exception as e:
                print("[SECURE_GATEWAY] Failed to encrypt error response:", str(e))
                traceback.print_exc()

        return Response({"error": "An internal error occurred during processing"}, status=500)
