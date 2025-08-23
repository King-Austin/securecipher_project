"""
SecureCipher middleware views with structured logging.

- Delegates cryptography to crypto_engine
- Key lifecycle to key_manager (DB-backed)
- Transaction processing to downstream_handler
- Audit persistence to audit_logs (DB-backed)
- Transaction metadata persisted via transaction_metadata
- Downstream HTTP handled by tls_middleware

Logging:
- Uses Python's logging; configure handlers/levels in Django settings.py.
- INFO for high-level milestones, DEBUG for timings/details, WARNING for client misuse,
  ERROR for unexpected failures.
"""

import base64
import json
import logging
import time
import traceback
import uuid
from datetime import timedelta

from django.contrib.auth import authenticate
from django.db import IntegrityError
from django.db.models import Count, Avg, Q, F
from django.shortcuts import render
from django.utils import timezone

# DRF
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from urllib3 import request

# DB models
from .models import (
    MiddlewareKey,
    KeyRotationLog,
    UsedNonce,
    TransactionMetadata,
    AuditLog,
)

# Serializers
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

# Configuration
from django.conf import settings

# Module logger
logger = logging.getLogger("middleware_app")


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
    Return middleware public key PEM (persistent via MiddlewareKey).
    """
    try:
        mk = key_manager.get_active_middleware_key()
        public_pem = mk.public_key_pem
        logger.info("Public key retrieved. version=%s", mk.version)
        return Response({"public_key": public_pem})
    except Exception as e:
        logger.error("Failed to retrieve middleware public key: %s", str(e), exc_info=True)
        traceback.print_exc()
        return Response({"error": "Failed to retrieve public key"}, status=500)


def _enc_error(session_key, msg, http_status):
    """
    Always return an encrypted error if we already derived a session_key.
    Falls back to plaintext JSON if session_key is None.
    """
    payload = {"error": msg}
    if session_key:
        try:
            logger.debug("Returning encrypted error. status=%s, msg=%s", http_status, msg)
            return Response(crypto_engine.aes256gcm_encrypt(payload, session_key), status=http_status)
        except Exception as e:
            logger.error("Encrypting error payload failed; falling back to plaintext: %s", str(e), exc_info=True)
    else:
        logger.debug("Returning plaintext error. status=%s, msg=%s", http_status, msg)
    return Response(payload, status=http_status)


class SecureGateway(APIView):
    """
    SecureCipher gateway (hardened):
        Expects JSON with base64-encoded fields:
        {
            "ephemeral_pubkey": "<base64-encoded client ephemeral public key PEM>",
            "iv": "<base64-encoded AES-GCM IV>",
            "ciphertext": "<base64-encoded AES-GCM ciphertext>"
        }
    """
    def post(self, request):
        """
        Expects JSON with base64-encoded fields:
    client_ip = request.META.get("REMOTE_ADDR", "unknown")
            "iv": "<base64-encoded AES-GCM IV>",
            "ciphertext": "<base64-encoded AES-GCM ciphertext>"
        }

        Inner payload (after decryption) must include:
        {
            "transaction_data": { ... },
            "client_signature": "<base64-encoded signature>",
            "client_public_key": "<base64-encoded client public key PEM>",
            "nonce": "<unique nonce string>",
            "timestamp": "<ISO 8601 UTC timestamp>",
            "target": "<string identifying downstream target>"
        }

        Returns encrypted response or error.
        """
        TARGET_URLS = settings.ROUTING_TABLE

        txn_id = str(uuid.uuid4())
        t0 = time.perf_counter()
        
        client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))
        session_key = None

        logger.info("Request received. txn_id=%s ip=%s", txn_id, client_ip)
        audit_logs.log_event(txn_id, "request_received", {"client_ip": client_ip})

        # --- validate outer envelope (plaintext) ---
        if not isinstance(request.data, dict):
            logger.warning("Invalid envelope format (non-JSON). txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "non_json_payload"})
            return _enc_error(None, "Invalid envelope format: expected JSON object", status.HTTP_400_BAD_REQUEST)

        env = request.data
        required = ("ephemeral_pubkey", "iv", "ciphertext")
        if not all(k in env for k in required):
            logger.warning("Missing envelope fields. txn_id=%s missing=%s", txn_id, [k for k in required if k not in env])
            audit_logs.log_event(txn_id, "bad_request", {"reason": "missing_fields"})
            return _enc_error(None, "Missing required envelope fields", status.HTTP_400_BAD_REQUEST)

        # Prepare TransactionMetadata (first light write)
        try:
            ciphertext_len = len(base64.b64decode(env["ciphertext"]))
        except Exception:
            logger.warning("Ciphertext base64 decode failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "ciphertext_b64_decode"})
            return _enc_error(None, "Invalid base64 in ciphertext", status.HTTP_400_BAD_REQUEST)

        tx_meta.create_transaction_metadata(
            txn_id,
            client_ip=client_ip,
            payload_size_bytes=ciphertext_len,
            start_time=time.perf_counter(),
        )
        logger.debug("Transaction metadata created. txn_id=%s payload_bytes=%s", txn_id, ciphertext_len)

        # --- derive session key ---
        try:
            client_ephemeral_der = base64.b64decode(env["ephemeral_pubkey"])
            _ = base64.b64decode(env["iv"])
            _ = base64.b64decode(env["ciphertext"])
        except Exception as e:
            logger.warning("Envelope fields base64 decode failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "bad_request", {"reason": "b64_decode_fail"})
            return _enc_error(None, "Invalid base64 in envelope fields", status.HTTP_400_BAD_REQUEST)

        try:
            mk = key_manager.get_active_middleware_key()
            logger.info("Active middleware key loaded. txn_id=%s label=%s version=%s", txn_id, mk.label, mk.version)
            audit_logs.log_event(txn_id, "middleware_key_loaded", {"label": mk.label, "version": mk.version})

            session_key = key_manager.derive_session_key(client_ephemeral_der)
            session_key_hash = crypto_engine.hash_data(session_key)
            logger.debug("Session key derived. txn_id=%s key_hash=%s", txn_id, session_key_hash[:16] + "...")
            audit_logs.log_event(txn_id, "session_key_derived", {"session_key_hash": session_key_hash})
            tx_meta.update_transaction_metadata(txn_id, session_key_hash=session_key_hash)
        except ValueError as e:
            if "Could not deserialize key data" in str(e):
                logger.error("Corrupted middleware private key detected. txn_id=%s", txn_id, exc_info=True)
                audit_logs.log_event(txn_id, "corrupted_private_key", {"error": str(e)})
                # Auto-rotate and retry
                key_manager.rotate_middleware_key("corrupted_key_auto_rotation")
                try:
                    session_key = key_manager.derive_session_key(client_ephemeral_der)
                    session_key_hash = crypto_engine.hash_data(session_key)
                    tx_meta.update_transaction_metadata(txn_id, session_key_hash=session_key_hash)
                except Exception as retry_error:
                    logger.error("Failed after key rotation. txn_id=%s", txn_id, exc_info=True)
                    return _enc_error(None, "Internal server error - key rotation failed", status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                logger.error("Session key derivation failed. txn_id=%s", txn_id, exc_info=True)
                audit_logs.log_event(txn_id, "key_derivation_error", {"error": str(e)})
                return _enc_error(None, "Failed to derive session key", status.HTTP_422_UNPROCESSABLE_ENTITY)
        except Exception as e:  
            logger.error("Session key derivation failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "key_derivation_error", {"error": str(e)})
            return _enc_error(None, "Failed to derive session key", status.HTTP_422_UNPROCESSABLE_ENTITY)


        # --- decrypt inner payload ---
        try:
            t_dec0 = time.perf_counter()
            inner_payload = crypto_engine.aes256gcm_decrypt(
                {"iv": env["iv"], "ciphertext": env["ciphertext"]}, session_key
            )
            dec_ms = (time.perf_counter() - t_dec0) * 1000
            logger.debug("Payload decrypted. txn_id=%s t_ms=%.2f", txn_id, dec_ms)
            audit_logs.log_event(txn_id, "payload_decrypted", {"t_ms": round(dec_ms, 2)})
            tx_meta.update_transaction_metadata(txn_id, decryption_time_ms=dec_ms)
        except Exception as e:
            logger.warning("Payload decryption failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "decrypt_fail", {"error": str(e)})
            return _enc_error(session_key, "Payload decryption failed", status.HTTP_400_BAD_REQUEST)

        # --- validate timestamp & nonce ---
        try:
            nonce = inner_payload.get("nonce")
            timestamp = inner_payload.get("timestamp")
            if nonce is None or timestamp is None:
                logger.warning("Missing nonce/timestamp. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "bad_inner", {"reason": "nonce_or_timestamp_missing"})
                return _enc_error(session_key, "Missing nonce/timestamp", status.HTTP_400_BAD_REQUEST)

            # validate_timestamp returns bool; enforce it
            if not crypto_engine.validate_timestamp(timestamp):
                logger.warning("Stale/invalid timestamp. txn_id=%s ts=%s", txn_id, timestamp)
                audit_logs.log_event(txn_id, "timestamp_invalid", {"timestamp": timestamp})
                return _enc_error(session_key, "Invalid or expired timestamp", status.HTTP_400_BAD_REQUEST)

            tx_meta.update_transaction_metadata(txn_id, request_timestamp=timestamp)

            try:
                UsedNonce.objects.create(nonce=nonce)
                logger.debug("Nonce stored. txn_id=%s nonce=%s", txn_id, str(nonce)[:32] + "...")
                audit_logs.log_event(txn_id, "nonce_stored", {"nonce_trunc": str(nonce)[:64]})
            except IntegrityError:
                logger.warning("Replay detected (nonce already used). txn_id=%s nonce=%s", txn_id, str(nonce)[:32] + "...")
                audit_logs.log_event(txn_id, "nonce_replay_detected", {"nonce_trunc": str(nonce)[:64]})
                return _enc_error(session_key, "Nonce already used (replay detected)", status.HTTP_409_CONFLICT)
        except Exception as e:
            logger.warning("Timestamp/nonce validation error. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "timestamp_or_nonce_error", {"error": str(e)})
            return _enc_error(session_key, "Invalid timestamp/nonce", status.HTTP_400_BAD_REQUEST)

        # --- verify client signature ---
        try:
            tx_data = inner_payload.get("transaction_data")
            client_sig = inner_payload.get("client_signature")
            client_pub = inner_payload.get("client_public_key")
            if not (tx_data and client_sig and client_pub):
                logger.warning("Missing signature/public key fields. txn_id=%s", txn_id)
                audit_logs.log_event(txn_id, "bad_inner", {"reason": "missing_sig_fields"})
                return _enc_error(session_key, "Missing transaction/signature/public key", status.HTTP_400_BAD_REQUEST)

            v = crypto_engine.ecdsa_verify({"transaction_data": tx_data}, client_sig, client_pub)
            tx_meta.update_transaction_metadata(txn_id, client_signature_verified=bool(v))
            audit_logs.log_event(txn_id, "client_signature_verified", {"valid": bool(v)})

            if not v:
                logger.warning("Client signature verification failed. txn_id=%s", txn_id)
                return _enc_error(session_key, "Client signature verification failed", status.HTTP_401_UNAUTHORIZED)
            logger.info("Client signature verified. txn_id=%s", txn_id)
        except Exception as e:
            logger.error("Client signature verification error. txn_id=%s", txn_id, exc_info=True)
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
            logger.info("Middleware signed payload. txn_id=%s sig_len=%s", txn_id, len(mw_sig))
        except Exception as e:
            logger.error("Middleware signing failed. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "middleware_sign_error", {"error": str(e)})
            return _enc_error(session_key, "Middleware signing failed", status.HTTP_500_INTERNAL_SERVER_ERROR)

        # --- route & downstream call ---
        try:
            target = inner_payload.get("target")
            if not target:
                logger.warning("Missing target. txn_id=%s", txn_id)
                return _enc_error(session_key, "Missing target", status.HTTP_400_BAD_REQUEST)

            target_url = TARGET_URLS.get(target)
            if not target_url:
                logger.warning("Unknown target. txn_id=%s target=%s", txn_id, target)
                audit_logs.log_event(txn_id, "unknown_target", {"target": target})
                return _enc_error(session_key, "Unknown target", status.HTTP_400_BAD_REQUEST)

            logger.info("Forwarding downstream. txn_id=%s target=%s url=%s", txn_id, target, target_url)
            audit_logs.log_event(txn_id, "forwarding_to_downstream", {"target": target, "target_url": target_url})

            resp_data, downstream_status, downstream_sess = downstream_handler.encrypt_and_send_to_bank(fwd, target)
            logger.info("Downstream response received. txn_id=%s status=%s", txn_id, downstream_status)
            audit_logs.log_event(txn_id, "downstream_response_received", {"status_code": downstream_status})
        except Exception as e:
            logger.error("Downstream service error. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "downstream_error", {"error": str(e)})
            return _enc_error(session_key, "Downstream service error", status.HTTP_502_BAD_GATEWAY)



        # --- process downstream, verify server sig ---
        try:
            business = downstream_handler.handle_response_from_bank(resp_data, downstream_sess)
            logger.debug("Downstream response processed. txn_id=%s", txn_id)
            audit_logs.log_event(txn_id, "downstream_processed")

            if isinstance(business, dict) and "signature" in business and "server_pubkey" in business:
                try:
                    verified = crypto_engine.ecdsa_verify(
                        business.get("payload", {}), business["signature"], business["server_pubkey"]
                    )
                    logger.info("Server signature check. txn_id=%s verified=%s", txn_id, bool(verified))
                    audit_logs.log_event(txn_id, "server_signature_verified", {"verified": bool(verified)})
                except Exception as e:
                    logger.warning("Server signature verification failed. txn_id=%s", txn_id, exc_info=True)
                    audit_logs.log_event(txn_id, "server_signature_verification_failed", {"error": str(e)})
        except Exception as e:
            logger.error("Downstream processing error. txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "downstream_processing_error", {"error": str(e)})
            return _enc_error(session_key, "Malformed downstream response", status.HTTP_502_BAD_GATEWAY)




        # --- encrypt response for client ---
        try:
            payload_for_client = business.get("payload", business) if isinstance(business, dict) else business
            t_enc0 = time.perf_counter()
            frontend_env = crypto_engine.aes256gcm_encrypt(payload_for_client, session_key)
            enc_ms = (time.perf_counter() - t_enc0) * 1000
            logger.debug("Response encrypted for client. txn_id=%s t_ms=%.2f", txn_id, enc_ms)
            audit_logs.log_event(txn_id, "response_encrypted_for_client", {"t_ms": round(enc_ms, 2)})
        except Exception as e:
            logger.error("Encrypting response for client failed. txn_id=%s", txn_id, exc_info=True)
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
            logger.info("Transaction complete. txn_id=%s total_ms=%.2f status=%s", txn_id, total_ms, downstream_status)
        except Exception as e:
            logger.warning("Metadata update warning (non-fatal). txn_id=%s", txn_id, exc_info=True)
            audit_logs.log_event(txn_id, "metadata_update_warning", {"error": str(e)})

        audit_logs.log_event(txn_id, "request_complete", {"t_ms": round(total_ms, 2)})
        return Response(frontend_env, status=downstream_status)
