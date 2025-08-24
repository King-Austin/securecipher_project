import base64
import binascii
import json
import logging
import time
import traceback
import uuid
from cryptography.hazmat.primitives import serialization


from django.db import IntegrityError
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.db.models import Avg  




from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from cryptography.exceptions import InvalidSignature, InvalidTag

# DB models & serializers (unchanged)
from .models import (
    MiddlewareKey,
    KeyRotationLog,
    UsedNonce,
    TransactionMetadata,
    AuditLog,
)
from .serializers import (
    MiddlewareKeySerializer,
    UsedNonceSerializer,
    TransactionMetadataSerializer,
    AuditLogSerializer,
    AdminLoginSerializer,
)

# Internal modules
from modules import crypto_engine
from modules import key_manager
from modules import downstream_handler
from modules import transaction_metadata as tx_meta
from modules import audit_logs

logger = logging.getLogger("middleware_app")
EPHEMERAL_KEY_EXPIRY = getattr(settings, "EPHEMERAL_KEY_EXPIRY", 300)  # 5 min default


class RotateMiddlewareKeyView(APIView):
    def post(self, request):
        """
        Rotates the active middleware key and returns refreshed admin dataset.
        """
        reason = (request.data or {}).get("reason") or "admin-initiated rotation"
        logger.info("Key rotation requested. reason=%s", reason)
        try:
            key_manager.rotate_middleware_key(reason=reason)
            logger.info("Key rotation completed successfully.")
        except Exception as e:
            logger.error("Key rotation failed: %s", str(e), exc_info=True)
            return Response({"error": "Key rotation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Return the admin data directly for instant UI refresh
        admin_view = AdminDataCollectionView()
        return admin_view.get(request)


class AdminDataCollectionView(APIView):
    """
    Collects all data and returns them as a single response
    with computed statistics for dashboard.
    """

    def get(self, request):
        logger.debug("Admin data collection started.")
        # Base data
        keys = MiddlewareKeySerializer(MiddlewareKey.objects.all(), many=True).data
        nonces = UsedNonceSerializer(UsedNonce.objects.all(), many=True).data
        transactions = TransactionMetadataSerializer(TransactionMetadata.objects.all(), many=True).data
        audits = AuditLogSerializer(AuditLog.objects.all(), many=True).data

        # Stats (current implementation uses all-time aggregates)
        recent_transactions = TransactionMetadata.objects.all()
        total_recent_tx = recent_transactions.count()
        successful_tx = recent_transactions.count()
        failed_tx = total_recent_tx - successful_tx
        avg_processing_time = recent_transactions.aggregate(
            avg_time=Avg("processing_time_ms")
        )["avg_time"] or 0

        recent_nonces = UsedNonce.objects.all()
        valid_nonces = recent_nonces.count()

        active_key = MiddlewareKey.objects.filter(active=True).first()
        key_rotation_count = KeyRotationLog.objects.count()

        logger.debug(
            "Admin stats computed. total_tx=%s, success=%s, failed=%s, avg_ms=%.2f, nonces=%s, active_key=%s, rotations=%s",
            total_recent_tx, successful_tx, failed_tx, avg_processing_time, valid_nonces,
            getattr(active_key, "version", None), key_rotation_count
        )

        return Response(
            {
                "middleware_keys": keys,
                "nonces": nonces,
                "transactions": transactions,
                "audit_logs": audits,
                "stats": {
                    "total_transactions_24h": total_recent_tx,
                    "successful_transactions_24h": successful_tx,
                    "failed_transactions_24h": failed_tx,
                    "success_rate_24h": int((successful_tx / total_recent_tx * 100)) if total_recent_tx > 0 else 0,
                    "avg_processing_time_ms": avg_processing_time,
                    "valid_nonces_24h": valid_nonces,
                    "active_key_version": active_key.version if active_key else None,
                    "total_key_rotations": key_rotation_count,
                    "total_transactions_all_time": TransactionMetadata.objects.count(),
                    "total_nonces_all_time": UsedNonce.objects.count(),
                },
            },
            status=status.HTTP_200_OK,
        )


class AdminLogin(APIView):
    """
    Validate user credentials using Django's built-in authentication.
    """

    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data["username"]
        # Don't log raw password
        logger.info("Admin login attempt for user=%s", username)

        user = authenticate(username=username, password=serializer.validated_data["password"])

        if user is not None:
            logger.info("Admin login success for user_id=%s", user.id)
            return Response(
                {
                    "authenticated": True,
                    "user": {"id": user.id, "username": user.username, "email": user.email},
                },
                status=status.HTTP_200_OK,
            )

        logger.warning("Admin login failed for user=%s", username)
        return Response({"authenticated": False}, status=status.HTTP_401_UNAUTHORIZED)


def index_view(request):
    """Render the SecureCipher middleware landing page"""
    logger.debug("Rendering index page.")
    return render(request, "index.html")


@api_view(["GET"])
def get_public_key(request):
    """
    Generate and return an ephemeral public key for ECDH key exchange.
    Store the ephemeral private key in cache with session_id for later lookup.
    """

    try:
        # 1. Generate ephemeral key pair
        private_key, public_key = crypto_engine.perform_ecdh()



        # 3. Create session ID
        session_id = str(uuid.uuid4())

        cache.set(
            f"ephemeral_key_{session_id}",
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            timeout=300  # 5 minutes
)

        # 5. Return session ID + ephemeral public key (Base64/hex encoded)
        public_b64 = base64.b64encode(public_key).decode("utf-8")
        logger.info("Generated ephemeral keypair. session_id=%s", session_id)

        return Response({
            "session_id": session_id,
            "public_key": public_b64
        })

    except Exception as e:
        logger.error("Failed to generate ephemeral key: %s", str(e), exc_info=True)
        traceback.print_exc()
        return Response({"error": "Failed to generate key"}, status=500)
    
    

def _error_payload(code: str, message: str, txn_id: str = None):
    return {
        "status": "error",
        "error_code": code,
        "message": message,
        "txn_id": txn_id,
    }


def _enc_error(session_key, code: str, msg: str, http_status: int, txn_id: str = None):
    """
    Returns an encrypted error envelope if session_key exists and encryption succeeds.
    Otherwise returns plaintext error payload.  Always logs.
    """
    payload = _error_payload(code, msg, txn_id)
    if session_key:
        try:
            enc = crypto_engine.aes256gcm_encrypt(payload, session_key)
            logger.debug("Returning encrypted error. status=%s code=%s txn_id=%s", http_status, code, txn_id)
            return Response(enc, status=http_status)
        except Exception:
            logger.exception("Failed to encrypt error payload; falling back to plaintext. txn_id=%s", txn_id)
            # fall through to return plaintext

    logger.debug("Returning plaintext error. status=%s code=%s txn_id=%s", http_status, code, txn_id)
    return Response(payload, status=http_status)




class SecureGateway(APIView):
    """
    Hardened SecureGateway.
    Expects JSON envelope:
    {
      "ephemeral_pubkey": "<base64>",
      "iv": "<base64>",
      "ciphertext": "<base64>",
      "session_id": "<uuid>"
    }

    Inner payload (after decrypt) expected keys:
    {
      "transaction_data": {...},
      "client_signature": "<b64>",
      "client_public_key": "<pem-or-base64-der>",
      "nonce": "<str>",
      "timestamp": <int timestamp seconds>,
      "target": "<string>"
    }
    """
    def post(self, request):
        TARGET_URLS = getattr(settings, "ROUTING_TABLE", {})

        txn_id = str(uuid.uuid4())
        t0 = time.perf_counter()
        client_ip = get_client_ip(request)

        session_key = None
        downstream_status = status.HTTP_500_INTERNAL_SERVER_ERROR
        frontend_env = None
        enc_ms = 0.0
        target = None

        logger.info("Request received. txn_id=%s ip=%s", txn_id, client_ip)
        audit_logs.log_event(txn_id, "request_received", {"client_ip": client_ip})

        # Validate input is JSON dict
        if not isinstance(request.data, dict):
            logger.warning("Invalid envelope format (non-JSON). txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "non_json_payload"})
            return _enc_error(None, "INVALID_PAYLOAD", "Invalid envelope format: expected JSON object", status.HTTP_400_BAD_REQUEST, txn_id)

        env = request.data

        # Required envelope fields
        required = ("ephemeral_pubkey", "iv", "ciphertext", "session_id")
        missing = [k for k in required if k not in env]
        if missing:
            logger.warning("Missing envelope fields. txn_id=%s missing=%s", txn_id, missing)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "missing_fields", "missing": missing})
            return _enc_error(None, "MISSING_FIELDS", f"Missing required fields: {missing}", status.HTTP_400_BAD_REQUEST, txn_id)

        # Measure ciphertext size (validate base64)
        try:
            ciphertext_len = len(base64.b64decode(env["ciphertext"]))
        except (binascii.Error, TypeError) as e:
            logger.warning("Ciphertext base64 decode failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "ciphertext_b64_decode"})
            return _enc_error(None, "CIPHERTEXT_B64_DECODE_FAIL", "Invalid base64 in ciphertext", status.HTTP_400_BAD_REQUEST, txn_id)

        tx_meta.create_transaction_metadata(
            txn_id,
            client_ip=client_ip,
            payload_size_bytes=ciphertext_len,
            start_time=time.perf_counter(),
        )
        logger.debug("Transaction metadata created. txn_id=%s payload_bytes=%s", txn_id, ciphertext_len)


        session_id = env.get("session_id")
        ephemeral_pubkey = env.get("ephemeral_pubkey")
        iv_b64 = env.get("iv")
        ciphertext_b64 = env.get("ciphertext")


        # 1. Retrieve ephemeral private key from cache
        private_pem = cache.get(f"ephemeral_key_{session_id}")
        if not private_pem:
            return _enc_error({"error": "Session expired or invalid"}, status=400)

        private_key = serialization.load_pem_private_key(private_pem, password=None)

        # 2. Load client ephemeral public key
        client_ephemeral_pub_bytes = base64.b64decode(ephemeral_pubkey)
        client_public_key = serialization.load_der_public_key(client_ephemeral_pub_bytes)

        # 3. Deriving the session key
        try:
            # Convert the client public key back to DER bytes for the crypto engine
            client_public_key_der = client_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            session_key = crypto_engine.derive_session_key_from_peer(client_public_key_der, private_key)
            session_key_hash = crypto_engine.hash_data(session_key)
            logger.debug("Session key derived. txn_id=%s key_hash=%s", txn_id, session_key_hash[:16] + "...")
            audit_logs.log_event(txn_id, "session_key_derived", {"session_key_hash": session_key_hash})
            tx_meta.update_transaction_metadata(txn_id, session_key_hash=session_key_hash)
        except ValueError as e:
            logger.error("Session key derivation failed. txn_id=%s error=%s", txn_id, str(e), exc_info=True)
            audit_logs.log_event(txn_id, "key_derivation_error", {"error": str(e)})
            return _enc_error(None, "SESSION_KEY_DERIVATION_FAILED", "Failed to derive session key", status.HTTP_422_UNPROCESSABLE_ENTITY, txn_id)
        

        except Exception as e:
            logger.error("Unexpected session key derivation error. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "key_derivation_error", {"error": str(e)})
            return _enc_error(None, "SESSION_KEY_DERIVATION_FAILED", "Failed to derive session key", status.HTTP_422_UNPROCESSABLE_ENTITY, txn_id)


        # --- decrypt inner payload using session_key ---
        try:
            t_dec0 = time.perf_counter()
            inner_payload = crypto_engine.aes256gcm_decrypt({"iv": env["iv"], "ciphertext": env["ciphertext"]}, session_key)
            dec_ms = (time.perf_counter() - t_dec0) * 1000
            logger.debug("Payload decrypted. txn_id=%s t_ms=%.2f", txn_id, dec_ms)
            audit_logs.log_event(txn_id, "payload_decrypted", {"t_ms": round(dec_ms, 2)})
            tx_meta.update_transaction_metadata(txn_id, decryption_time_ms=dec_ms)
        except (InvalidTag, ValueError) as e:
            logger.warning("Payload decryption failed (invalid tag/format). txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "decrypt_fail", {"error": str(e)})
            return _enc_error(session_key, "DECRYPT_FAIL", "Payload decryption failed", status.HTTP_400_BAD_REQUEST, txn_id)
        except Exception as e:
            logger.exception("Unexpected error during decryption. txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "decrypt_fail", {"error": str(e)})
            return _enc_error(session_key, "DECRYPT_FAIL", "Payload decryption failed", status.HTTP_400_BAD_REQUEST, txn_id)

        # --- validate timestamp & nonce ---
        try:
            nonce = inner_payload.get("nonce")
            timestamp = inner_payload.get("timestamp")
            if nonce is None or timestamp is None:
                logger.warning("Missing nonce/timestamp in inner payload. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "bad_inner", {"reason": "nonce_or_timestamp_missing"})
                return _enc_error(session_key, "MISSING_INNER_FIELDS", "Missing nonce or timestamp", status.HTTP_400_BAD_REQUEST, txn_id)

            if not crypto_engine.validate_timestamp(timestamp):
                logger.warning("Stale/invalid timestamp. txn_id=%s ts=%s", txn_id, timestamp)
                audit_logs.log_event(txn_id, "timestamp_invalid", {"timestamp": timestamp})
                return _enc_error(session_key, "TIMESTAMP_INVALID", "Invalid or expired timestamp", status.HTTP_400_BAD_REQUEST, txn_id)

            tx_meta.update_transaction_metadata(txn_id, request_timestamp=timestamp)

            try:
                UsedNonce.objects.create(nonce=nonce)
                logger.debug("Nonce stored. txn_id=%s nonce_trunc=%s", txn_id, str(nonce)[:32] + "...")
                audit_logs.log_event(txn_id, "nonce_stored", {"nonce_trunc": str(nonce)[:64]})
            except IntegrityError:
                logger.warning("Replay detected (nonce already used). txn_id=%s nonce=%s", txn_id, str(nonce)[:32] + "...")
                audit_logs.log_event(txn_id, "nonce_replay_detected", {"nonce_trunc": str(nonce)[:64]})
                return _enc_error(session_key, "NONCE_REPLAY", "Nonce already used (replay detected)", status.HTTP_409_CONFLICT, txn_id)
        except Exception as e:
            logger.exception("Timestamp/nonce validation error. txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "timestamp_or_nonce_error", {"error": str(e)})
            return _enc_error(session_key, "TIMESTAMP_OR_NONCE_ERROR", "Invalid timestamp/nonce", status.HTTP_400_BAD_REQUEST, txn_id)

        # --- verify client signature ---
        try:
            tx_data = inner_payload.get("transaction_data")
            client_sig = inner_payload.get("client_signature")
            client_pub = inner_payload.get("client_public_key")
            if not (tx_data and client_sig and client_pub):
                logger.warning("Missing signature/public key fields. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "bad_inner", {"reason": "missing_sig_fields"})
                return _enc_error(session_key, "MISSING_SIG_FIELDS", "Missing transaction/signature/public key", status.HTTP_400_BAD_REQUEST, txn_id)

            try:
                v = crypto_engine.ecdsa_verify({"transaction_data": tx_data}, client_sig, client_pub)
            except Exception as e:
                logger.exception("Client signature verification error. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "client_sig_verify_error", {"error": str(e)})
                return _enc_error(session_key, "SIGNATURE_VERIFY_ERROR", "Signature verification error", status.HTTP_400_BAD_REQUEST, txn_id)

            tx_meta.update_transaction_metadata(txn_id, client_signature_verified=bool(v))
            audit_logs.log_event(txn_id, "client_signature_verified", {"valid": bool(v)})

            if not v:
                logger.warning("Client signature verification failed. txn_id=%s", txn_id)
                return _enc_error(session_key, "INVALID_SIGNATURE", "Client signature verification failed", status.HTTP_401_UNAUTHORIZED, txn_id)

            logger.info("Client signature verified. txn_id=%s", txn_id)
        except Exception as e:
            logger.exception("Unexpected client signature verification error. txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "client_sig_verify_error", {"error": str(e)})
            return _enc_error(session_key, "SIGNATURE_VERIFY_ERROR", "Signature verification error", status.HTTP_400_BAD_REQUEST, txn_id)

        if getattr(settings, "TEST_MODE", False):

            # --- sign payload for downstream with middleware signing key (ECDSA) ---
            try:

                # Get the active middleware key
                mk = key_manager.get_active_middleware_key()
                if not mk:
                    logger.error("No active middleware key found. txn_id=%s", txn_id)
                    audit_logs.log_event(txn_id, "no_active_middleware_key")
                    return _enc_error(session_key, "NO_ACTIVE_MW_KEY", "No active middleware key", status.HTTP_500_INTERNAL_SERVER_ERROR, txn_id)
            

                fwd = {
                    "transaction_data": tx_data,
                    "client_signature": client_sig,
                    "client_public_key": client_pub,
                    "nonce": nonce,
                }

                # Sign the forwarded data with the middleware key
                mw_sig = crypto_engine.ecdsa_sign(fwd, mk.private_key_pem)
                fwd["middleware_signature"] = mw_sig
                fwd["middleware_public_key"] = mk.public_key_pem
                tx_meta.update_transaction_metadata(txn_id, middleware_signature=mw_sig)
                audit_logs.log_event(txn_id, "middleware_signed", {"signature_len": len(mw_sig)})
                logger.info("Middleware signed payload. txn_id=%s sig_len=%s", txn_id, len(mw_sig))
            except Exception as e:
                logger.exception("Middleware signing failed. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "middleware_sign_error", {"error": str(e)})
                return _enc_error(session_key, "MW_SIGN_ERROR", "Middleware signing failed", status.HTTP_500_INTERNAL_SERVER_ERROR, txn_id)

            # --- route & downstream call (wrapped) ---
            try:
                target = inner_payload.get("target")
                if not target:
                    logger.warning("Missing target. txn_id=%s", txn_id)
                    return _enc_error(session_key, "MISSING_TARGET", "Missing target", status.HTTP_400_BAD_REQUEST, txn_id)

                target_url = TARGET_URLS.get(target)
                if not target_url:
                    logger.warning("Unknown target. txn_id=%s target=%s", txn_id, target)
                    audit_logs.log_event(txn_id, "unknown_target", {"target": target})
                    return _enc_error(session_key, "UNKNOWN_TARGET", "Unknown target", status.HTTP_400_BAD_REQUEST, txn_id)

                logger.info("Forwarding downstream. txn_id=%s target=%s url=%s", txn_id, target, target_url)
                audit_logs.log_event(txn_id, "forwarding_to_downstream", {"target": target, "target_url": target_url})

                # downstream_handler.encrypt_and_send_to_bank should be test-friendly (you can monkeypatch in tests)
                resp_data, downstream_status, downstream_session_key = downstream_handler.encrypt_and_send_to_bank(fwd, target)
                logger.info("Downstream response received. txn_id=%s status=%s", txn_id, downstream_status)
                audit_logs.log_event(txn_id, "downstream_response_received", {"status_code": downstream_status})
            except Exception as e:
                logger.exception("Downstream service error. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "downstream_error", {"error": str(e)})
                return _enc_error(session_key, "DOWNSTREAM_ERROR", "Downstream service error", status.HTTP_502_BAD_GATEWAY, txn_id)

            # --- process downstream response and verify server signature if present ---
            try:
                business = downstream_handler.handle_response_from_bank(resp_data, downstream_session_key)
                logger.debug("Downstream response processed. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "downstream_processed")

                if isinstance(business, dict) and "signature" in business and "server_pubkey" in business:
                    try:
                        verified = crypto_engine.ecdsa_verify(business.get("payload", {}), business["signature"], business["server_pubkey"])
                        logger.info("Server signature check. txn_id=%s verified=%s", txn_id, bool(verified))
                        audit_logs.log_event(txn_id, "server_signature_verified", {"verified": bool(verified)})
                    except Exception:
                        logger.exception("Server signature verification failed. txn_id=%s", txn_id)
                        audit_logs.log_event(txn_id, "server_signature_verification_failed", {"error": "server_signature_verification_failed"})
            except Exception as e:
                logger.exception("Downstream processing error. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "downstream_processing_error", {"error": str(e)})
                return _enc_error(session_key, "MALFORMED_DOWNSTREAM", "Malformed downstream response", status.HTTP_502_BAD_GATEWAY, txn_id)

            # --- encrypt response for client (only if session_key exists) ---
            try:
                payload_for_client = business.get("payload", business) if isinstance(business, dict) else business

                if session_key:
                    t_enc0 = time.perf_counter()
                    frontend_env = crypto_engine.aes256gcm_encrypt(payload_for_client, session_key)
                    enc_ms = (time.perf_counter() - t_enc0) * 1000
                    logger.debug("Response encrypted for client. txn_id=%s t_ms=%.2f", txn_id, enc_ms)
                    audit_logs.log_event(txn_id, "response_encrypted_for_client", {"t_ms": round(enc_ms, 2)})
                else:
                    # No session key -> return plaintext (as requested)
                    frontend_env = payload_for_client
                    logger.debug("No session key available; returning plaintext response. txn_id=%s", txn_id)
            except Exception as e:
                logger.exception("Encrypting response for client failed. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "encrypt_response_error", {"error": str(e)})
                # Try fallback: plaintext response (we do not leak private key, only plaintext payload)
                frontend_env = payload_for_client
                return _enc_error(None, "RESPONSE_ENCRYPT_FAIL", "Failed to encrypt response; returning plaintext", status.HTTP_500_INTERNAL_SERVER_ERROR, txn_id)

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
                logger.info("Transaction complete. txn_id=%s total_ms=%.2f status=%s", txn_id, total_ms, downstream_status)
            except Exception as e:
                logger.exception("Metadata update warning (non-fatal). txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "metadata_update_warning", {"error": str(e)})

            audit_logs.log_event(txn_id, "request_complete", {"t_ms": round((time.perf_counter() - t0) * 1000, 2)})
            return Response(frontend_env, status=downstream_status)
        

        else: #If the MIDDLEWARE is on test Mode: JUST RETURN A STATUS OF 200, ENCRYPTED WITHT THE SESSION KEY.
            payload = {"message": "The Request has proven legitimate upto the point of the session key derivation"}
            return Response(status=200, data=payload)

def get_client_ip(request):
    """
    Extract the client IP address from request, handling proxies and multiple IPs.
    Returns a single IP address string or 'unknown' if not available.
    """
    # Try X-Forwarded-For first (common in proxy setups)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        # Return the first (original client) IP
        return ips[0] if ips else 'unknown'
    
    # Fall back to REMOTE_ADDR
    return request.META.get('REMOTE_ADDR', 'unknown')
