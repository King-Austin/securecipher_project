from rest_framework import serializers
from .models import MiddlewareKey, KeyRotationLog, UsedNonce, TransactionMetadata, AuditLog


class AdminLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class MiddlewareKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = MiddlewareKey
        fields = [
            "id", "label", "public_key_pem", "version",
            "active", "created_at", "rotated_at"
        ]


class KeyRotationLogSerializer(serializers.ModelSerializer):
    old_key = serializers.StringRelatedField()
    new_key = serializers.StringRelatedField()

    class Meta:
        model = KeyRotationLog
        fields = ["id", "old_key", "new_key", "reason", "rotated_at"]


class UsedNonceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsedNonce
        fields = ["id", "nonce", "created_at", "note"]


class TransactionMetadataSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionMetadata
        fields = [
            "id", "transaction_id", "client_ip", "created_at",
            "processing_time_ms", "banking_route", "payload_size_bytes", "session_key_hash",
            "client_signature_verified", "middleware_signature",
            "status_code", "response_size_bytes", "downstream_response_time_ms", "decryption_time_ms", "encryption_time_ms"
        ]



class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = [
            "id", "transaction_id", "event_type", 
            "actor", "timestamp", "prev_hash", "record_hash"
        ]
        
