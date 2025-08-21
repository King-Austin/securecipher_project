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

        # Build refreshed admin dataset so the frontend can overwrite local storage in a single pass.
        keys = MiddlewareKeySerializer(MiddlewareKey.objects.all(), many=True).data
        rotations = KeyRotationLogSerializer(KeyRotationLog.objects.all(), many=True).data
        nonces = UsedNonceSerializer(UsedNonce.objects.all(), many=True).data
        transactions = TransactionMetadataSerializer(TransactionMetadata.objects.all(), many=True).data
        audits = AuditLogSerializer(AuditLog.objects.all(), many=True).data

        # Build unified response
        return Response({
            "middleware_keys": keys,
            "key_rotations": rotations,
            "nonces": nonces,
            "transactions": transactions,
            "audit_logs": audits,
        }, status=status.HTTP_200_OK)

# class AdminDataCollectionView(APIView):
#     """
#     Collects all data from serializers and returns them
#     as a single response for the dashboard.
#     """

#     def get(self, request):
#         # Serialize each model
#         keys = MiddlewareKeySerializer(MiddlewareKey.objects.all(), many=True).data
#         rotations = KeyRotationLogSerializer(KeyRotationLog.objects.all(), many=True).data
#         nonces = UsedNonceSerializer(UsedNonce.objects.all(), many=True).data
#         transactions = TransactionMetadataSerializer(TransactionMetadata.objects.all(), many=True).data
#         audits = AuditLogSerializer(AuditLog.objects.all(), many=True).data

#         # Build unified response
#         return Response({
#             "middleware_keys": keys,
#             "key_rotations": rotations,
#             "nonces": nonces,
#             "transactions": transactions,
#             "audit_logs": audits,
#         }, status=status.HTTP_200_OK)
    

from django.db.models import Count, Avg, Q, F
from django.utils import timezone
from datetime import timedelta

class AdminDataCollectionView(APIView):
    """
    Collects all data from serializers and returns them
    as a single response with computed statistics for dashboard.
    """

    def get(self, request):
        # Get base data
        keys = MiddlewareKeySerializer(
            MiddlewareKey.objects.filter(active=True), 
            many=True
        ).data
        rotations = KeyRotationLogSerializer(KeyRotationLog.objects.all(), many=True).data
        nonces = UsedNonceSerializer(UsedNonce.objects.all(), many=True).data
        transactions = TransactionMetadataSerializer(TransactionMetadata.objects.all(), many=True).data
        audits = AuditLogSerializer(AuditLog.objects.all(), many=True).data

        # Compute statistics
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        
        # Transaction stats
        recent_transactions = TransactionMetadata.objects.filter(
            created_at__gte=twenty_four_hours_ago
        )
        total_recent_tx = recent_transactions.count()
        successful_tx = recent_transactions.filter(status_code=200).count()
        failed_tx = total_recent_tx - successful_tx
        avg_processing_time = recent_transactions.aggregate(
            avg_time=Avg('processing_time_ms')
        )['avg_time'] or 0

        # Nonce stats
        recent_nonces = UsedNonce.objects.filter(
            created_at__gte=twenty_four_hours_ago
        )
        valid_nonces = recent_nonces.count()  # Assuming all stored nonces are valid

        # Key stats
        active_key = MiddlewareKey.objects.filter(active=True).first()
        key_rotation_count = KeyRotationLog.objects.count()

        # Build unified response with computed stats
        return Response({
            "middleware_keys": keys,
            "key_rotations": rotations,
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
    # Pre-defined mapping of target → downstream URL for audit purposes
    TARGET_URLS = {
        "register": "https://bank.securecipher.com/api/register",
        "refresh": "https://bank.securecipher.com/api/refresh",
        "send_money": "https://bank.securecipher.com/api/transfer",
        "validate_account": "https://bank.securecipher.com/api/validate"
    }

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
            audit_logs.log_event(transaction_id, "payload_decrypted")
            tx_meta.update_transaction_metadata(transaction_id, banking_route=inner_payload.get("target"))
        except Exception as e:
            print("[STEP 3] Decryption failed:", str(e))
            traceback.print_exc()
            raise ValueError(f"Payload decryption failed: {e}")

        # --- Validate timestamp & nonce ---
        nonce = inner_payload.get("nonce")
        timestamp = inner_payload.get("timestamp")
        print(f"[STEP 4] Received nonce={nonce} timestamp={timestamp}")
        audit_logs.log_event(transaction_id, "timestamp_nonce_received", {"nonce": nonce, "timestamp": time.ctime(timestamp) if timestamp else "None"})
        crypto_engine.validate_timestamp(timestamp)
        tx_meta.update_transaction_metadata(transaction_id, request_timestamp=timestamp)

        if nonce is None:
            raise ValueError("Nonce missing in inner payload")

        try:
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
        client_public_key = inner_payload.get("client_public_key")  

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

        forwarded_payload["middleware_signature"] = middleware_signature
        forwarded_payload["middleware_public_key"] = mk.public_key_pem

        # --- Encrypt and send to downstream bank ---
        target = inner_payload.get("target")
        if not target:
            raise ValueError("Missing target in inner payload")

        target_url = TARGET_URLS.get(target, "unknown")  # <-- audit log compatible
        print(f"[STEP 7] Creating downstream envelope and sending to target='{target}' ({target_url})")
        print("[STEP 7] Forwarded payload keys:", list(forwarded_payload.keys()))
        audit_logs.log_event(transaction_id, "forwarding_to_downstream", {"target": target, "target_url": target_url})

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

        # Optional server signature verification
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

        payload_to_client = business_payload.get("payload", business_payload) if isinstance(business_payload, dict) else business_payload
        frontend_envelope = crypto_engine.aes256gcm_encrypt(payload_to_client, session_key)
        print("[STEP 9] Re-encrypted business payload for client, envelope keys:", list(frontend_envelope.keys()))
        audit_logs.log_event(transaction_id, "response_encrypted_for_client", {"envelope_keys": list(frontend_envelope.keys())})
        tx_meta.update_transaction_metadata(transaction_id, status_code=status_code, response_size_bytes=len(json.dumps(frontend_envelope)), processing_time_ms=(time.time() - start_time) * 1000)

        # Persist minimal TransactionMetadata info
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
