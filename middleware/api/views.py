"""
Refactored SecureCipher middleware views (logger removed per request).
- Delegates cryptography to crypto_engine
- Key lifecycle to key_manager (DB-backed)
- Transaction processing to transaction_processor
- Audit persistence to audit_logs (DB-backed)
- Transaction metadata persisted via transaction_metadata
- Downstream HTTP handled by tls_middleware

This file intentionally includes verbose prints for debugging 
(can be switched back to logger later).
"""

import base64
import json
import time
import traceback
import uuid
from django.db.models import Count, Avg, Q, F
from django.utils import timezone
from datetime import timedelta




from django.db import IntegrityError
from django.shortcuts import render
from django.contrib.auth import authenticate
#  DRF imports
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

#  DB models
from .models import (
    MiddlewareKey,
    KeyRotationLog,
    UsedNonce,
    TransactionMetadata,
    AuditLog,
)

#  Serializers
from .serializers import (
    MiddlewareKeySerializer,
    KeyRotationLogSerializer,
    UsedNonceSerializer,
    TransactionMetadataSerializer,
    AuditLogSerializer,
    AdminLoginSerializer
)

#  Internal modules (must exist in modules/ within the app)
from modules import crypto_engine
from modules import key_manager
from modules import transaction_processor
from modules import transaction_metadata as tx_meta
from modules import audit_logs

class RotateMiddlewareKeyView(APIView):
    def post(self, request):
        """
        Rotates the active middleware key:
        - Generates a new EC P-384 keypair
        - Deactivates previous active key (if any)
        - Writes KeyRotationLog
        - Returns: new active key + refreshed Admin dataset for instant UI refresh
        """
        reason = (request.data or {}).get("reason") or "admin-initiated rotation"
        key_manager.rotate_middleware_key(reason=reason)
        
        # Return the admin data directly instead of trying to call the class method
        admin_view = AdminDataCollectionView()
        return admin_view.get(request)


class AdminDataCollectionView(APIView):
    """
    Collects all data from serializers and returns them
    as a single response with computed statistics for dashboard.
    """

    def get(self, request):
        # Get base data
        keys = MiddlewareKeySerializer(MiddlewareKey.objects.all(), many=True).data
        nonces = UsedNonceSerializer(UsedNonce.objects.all(), many=True).data
        transactions = TransactionMetadataSerializer(TransactionMetadata.objects.all(), many=True).data
        audits = AuditLogSerializer(AuditLog.objects.all(), many=True).data

        # Compute statistics
        
        # Transaction stats
        recent_transactions = TransactionMetadata.objects.all()
        total_recent_tx = recent_transactions.count()
        successful_tx = recent_transactions.filter(status_code=200).count()
        failed_tx = total_recent_tx - successful_tx
        avg_processing_time = recent_transactions.aggregate(
            avg_time=Avg('processing_time_ms')
        )['avg_time'] or 0

        # Nonce stats
        recent_nonces = UsedNonce.objects.all()
        valid_nonces = recent_nonces.count()  # Assuming all stored nonces are valid

        # Key stats
        active_key = MiddlewareKey.objects.filter(active=True).first()
        key_rotation_count = KeyRotationLog.objects.count()

        # Build unified response with computed stats
        return Response({
            "middleware_keys": keys,
            "nonces": nonces,
            "transactions": transactions,
            "audit_logs": audits,
            "stats": {
                "total_transactions_24h": total_recent_tx,
                "successful_transactions_24h": successful_tx,
                "failed_transactions_24h": failed_tx,
                "success_rate_24h": (successful_tx / total_recent_tx * 100) if total_recent_tx > 0 else 0,
                "avg_processing_time_ms": avg_processing_time,
                "valid_nonces_24h": valid_nonces,
                "active_key_version": active_key.version if active_key else None,
                "total_key_rotations": key_rotation_count,
                "total_transactions_all_time": TransactionMetadata.objects.count(),
                "total_nonces_all_time": UsedNonce.objects.count(),
            }
        }, status=status.HTTP_200_OK)
    

class AdminLogin(APIView):
    """
    Validate user credentials using Django's built-in authentication.
    """

    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]

        user = authenticate(username=username, password=password)

        if user is not None:
            return Response({
                "authenticated": True,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_200_OK)
        #send authorise cookie to the user:
        

        return Response({"authenticated": False}, status=status.HTTP_401_UNAUTHORIZED)





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



from django.db import IntegrityError
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import base64, json, time, traceback, uuid

from .models import UsedNonce
from modules import crypto_engine, key_manager, transaction_processor
from modules import transaction_metadata as tx_meta
from modules import audit_logs
from .config import API_ENDPOINTS


def _enc_error(session_key, msg, http_status):
    """
    Always return an encrypted error if we already derived a session_key.
    Falls back to plaintext JSON if session_key is None.
    """
    payload = {"error": msg}
    if session_key:
        try:
            return Response(crypto_engine.aes256gcm_encrypt(payload, session_key), status=http_status)
        except Exception:
            # If encryption of the error fails, last resort: plaintext
            pass
    return Response(payload, status=http_status)


@api_view(["POST"])
def secure_gateway(request):
    """
    SecureCipher gateway (hardened):
    - Stricter input validation
    - Clear status codes
    - Encrypted errors after key derivation
    - Timing capture for decrypt/encrypt
    - Batch TransactionMetadata updates; stepwise AuditLog
    """
    TARGET_URLS = API_ENDPOINTS

    txn_id = str(uuid.uuid4())
    t0 = time.perf_counter()
    client_ip = request.META.get("REMOTE_ADDR", "unknown")
    session_key = None

    audit_logs.log_event(txn_id, "request_received", {"client_ip": client_ip})

    # --- validate outer envelope (plaintext) ---
    if not isinstance(request.data, dict):
        audit_logs.log_event(txn_id, "bad_request", {"reason": "non_json_payload"})
        return _enc_error(None, "Invalid envelope format: expected JSON object", status.HTTP_400_BAD_REQUEST)

    env = request.data
    required = ("ephemeral_pubkey", "iv", "ciphertext")
    if not all(k in env for k in required):
        audit_logs.log_event(txn_id, "bad_request", {"reason": "missing_fields"})
        return _enc_error(None, "Missing required envelope fields", status.HTTP_400_BAD_REQUEST)

    # Prepare TransactionMetadata (first light write)
    try:
        ciphertext_len = len(base64.b64decode(env["ciphertext"]))
    except Exception:
        audit_logs.log_event(txn_id, "bad_request", {"reason": "ciphertext_b64_decode"})
        return _enc_error(None, "Invalid base64 in ciphertext", status.HTTP_400_BAD_REQUEST)

    tx_meta.create_transaction_metadata(
        txn_id,
        client_ip=client_ip,
        payload_size_bytes=ciphertext_len,
        start_time=time.perf_counter(),  # you can store raw start as detail if you like
    )

    # --- derive session key ---
    try:
        client_ephemeral_der = base64.b64decode(env["ephemeral_pubkey"])
        iv = base64.b64decode(env["iv"])
        ciphertext = base64.b64decode(env["ciphertext"])
    except Exception as e:
        audit_logs.log_event(txn_id, "bad_request", {"reason": "b64_decode_fail"})
        return _enc_error(None, "Invalid base64 in envelope fields", status.HTTP_400_BAD_REQUEST)

    try:
        mk = key_manager.get_active_middleware_key()
        audit_logs.log_event(txn_id, "middleware_key_loaded", {"label": mk.label, "version": mk.version})

        session_key = key_manager.derive_session_key(client_ephemeral_der)
        session_key_hash = crypto_engine.hash_data(session_key)
        audit_logs.log_event(txn_id, "session_key_derived", {"session_key_hash": session_key_hash})
        tx_meta.update_transaction_metadata(txn_id, session_key_hash=session_key_hash)
    except Exception as e:
        audit_logs.log_event(txn_id, "key_derivation_error", {"error": str(e)})
        return _enc_error(None, "Failed to derive session key", status.HTTP_422_UNPROCESSABLE_ENTITY)

    # --- decrypt inner payload (measure time) ---
    try:
        t_dec0 = time.perf_counter()
        inner_payload = crypto_engine.aes256gcm_decrypt({"iv": env["iv"], "ciphertext": env["ciphertext"]}, session_key)
        dec_ms = (time.perf_counter() - t_dec0) * 1000
        audit_logs.log_event(txn_id, "payload_decrypted", {"t_ms": round(dec_ms, 2)})
        tx_meta.update_transaction_metadata(txn_id, decryption_time_ms=dec_ms)
    except Exception as e:
        audit_logs.log_event(txn_id, "decrypt_fail", {"error": str(e)})
        return _enc_error(session_key, f"Payload decryption failed", status.HTTP_400_BAD_REQUEST)

    # --- validate timestamp & nonce early ---
    try:
        nonce = inner_payload.get("nonce")
        timestamp = inner_payload.get("timestamp")
        if nonce is None or timestamp is None:
            audit_logs.log_event(txn_id, "bad_inner", {"reason": "nonce_or_timestamp_missing"})
            return _enc_error(session_key, "Missing nonce/timestamp", status.HTTP_400_BAD_REQUEST)

        crypto_engine.validate_timestamp(timestamp)
        tx_meta.update_transaction_metadata(txn_id, request_timestamp=timestamp)

        try:
            # atomic replay protection (fast path write)
            UsedNonce.objects.create(nonce=nonce)
            audit_logs.log_event(txn_id, "nonce_stored", {"nonce_trunc": str(nonce)[:64]})
        except IntegrityError:
            audit_logs.log_event(txn_id, "nonce_replay_detected", {"nonce_trunc": str(nonce)[:64]})
            return _enc_error(session_key, "Nonce already used (replay detected)", status.HTTP_409_CONFLICT)
    except Exception as e:
        audit_logs.log_event(txn_id, "timestamp_or_nonce_error", {"error": str(e)})
        return _enc_error(session_key, "Invalid timestamp/nonce", status.HTTP_400_BAD_REQUEST)

    # --- verify client signature ---
    try:
        tx_data = inner_payload.get("transaction_data")
        client_sig = inner_payload.get("client_signature")
        client_pub = inner_payload.get("client_public_key")
        if not (tx_data and client_sig and client_pub):
            audit_logs.log_event(txn_id, "bad_inner", {"reason": "missing_sig_fields"})
            return _enc_error(session_key, "Missing transaction/signature/public key", status.HTTP_400_BAD_REQUEST)

        v = crypto_engine.ecdsa_verify({"transaction_data": tx_data}, client_sig, client_pub)
        tx_meta.update_transaction_metadata(txn_id, client_signature_verified=bool(v))
        audit_logs.log_event(txn_id, "client_signature_verified", {"valid": bool(v)})

        if not v:
            return _enc_error(session_key, "Client signature verification failed", status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        audit_logs.log_event(txn_id, "client_sig_verify_error", {"error": str(e)})
        return _enc_error(session_key, "Signature verification error", status.HTTP_400_BAD_REQUEST)

    # --- sign payload for downstream ---
    try:
        fwd = {
            "transaction_data": tx_data,
            "client_signature": client_sig,
            "client_public_key": client_pub,
            "nonce": nonce,
        }
        mw_sig = crypto_engine.ecdsa_sign(fwd, mk.private_key_pem)
        fwd["middleware_signature"] = mw_sig
        fwd["middleware_public_key"] = mk.public_key_pem
        tx_meta.update_transaction_metadata(txn_id, middleware_signature=mw_sig)
        audit_logs.log_event(txn_id, "middleware_signed", {"signature_len": len(mw_sig)})
    except Exception as e:
        audit_logs.log_event(txn_id, "middleware_sign_error", {"error": str(e)})
        return _enc_error(session_key, "Middleware signing failed", status.HTTP_500_INTERNAL_SERVER_ERROR)

    # --- route & downstream call (with explicit mapping) ---
    try:
        target = inner_payload.get("target")
        if not target:
            return _enc_error(session_key, "Missing target", status.HTTP_400_BAD_REQUEST)

        target_url = TARGET_URLS.get(target)
        if not target_url:
            audit_logs.log_event(txn_id, "unknown_target", {"target": target})
            return _enc_error(session_key, "Unknown target", status.HTTP_400_BAD_REQUEST)

        audit_logs.log_event(txn_id, "forwarding_to_downstream", {"target": target, "target_url": target_url})

        # You can add per-call timeout in transaction_processor
        resp_data, downstream_status, downstream_sess = transaction_processor.encrypt_and_send_to_bank(
            fwd, target
        )
        audit_logs.log_event(txn_id, "downstream_response_received", {"status_code": downstream_status})
    except Exception as e:
        audit_logs.log_event(txn_id, "downstream_error", {"error": str(e)})
        # 502 because upstream dependency failed
        return _enc_error(session_key, "Downstream service error", status.HTTP_502_BAD_GATEWAY)

    # --- process downstream, verify optional server sig ---
    try:
        t_proc0 = time.perf_counter()
        business = transaction_processor.handle_response_from_bank(resp_data, downstream_sess)
        audit_logs.log_event(txn_id, "downstream_processed")
        # Optional: verify server signature if present
        if isinstance(business, dict) and "signature" in business and "server_pubkey" in business:
            try:
                verified = crypto_engine.ecdsa_verify(business.get("payload", {}), business["signature"], business["server_pubkey"])
                audit_logs.log_event(txn_id, "server_signature_verified", {"verified": bool(verified)})
            except Exception as e:
                audit_logs.log_event(txn_id, "server_signature_verification_failed", {"error": str(e)})
    except Exception as e:
        audit_logs.log_event(txn_id, "downstream_processing_error", {"error": str(e)})
        return _enc_error(session_key, "Malformed downstream response", status.HTTP_502_BAD_GATEWAY)

    # --- encrypt response for client (measure time) ---
    try:
        payload_for_client = business.get("payload", business) if isinstance(business, dict) else business
        t_enc0 = time.perf_counter()
        frontend_env = crypto_engine.aes256gcm_encrypt(payload_for_client, session_key)
        enc_ms = (time.perf_counter() - t_enc0) * 1000
        audit_logs.log_event(txn_id, "response_encrypted_for_client", {"t_ms": round(enc_ms, 2)})
    except Exception as e:
        audit_logs.log_event(txn_id, "encrypt_response_error", {"error": str(e)})
        return _enc_error(session_key, "Failed to encrypt response", status.HTTP_500_INTERNAL_SERVER_ERROR)

    # --- final TransactionMetadata batch update ---
    try:
        total_ms = (time.perf_counter() - t0) * 1000
        tx_meta.update_transaction_metadata(
            txn_id,
            status_code=int(downstream_status),
            encryption_time_ms=enc_ms,
            processing_time_ms=total_ms,
            response_size_bytes=len(json.dumps(frontend_env)),
            banking_route=target,
        )
    except Exception as e:
        # Non-fatal
        audit_logs.log_event(txn_id, "metadata_update_warning", {"error": str(e)})

    audit_logs.log_event(txn_id, "request_complete", {"t_ms": round(total_ms, 2)})
    
    return Response(frontend_env, status=downstream_status)
