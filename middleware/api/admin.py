# admin.py
from django.contrib import admin
from .models import MiddlewareKey, KeyRotationLog, UsedNonce, TransactionMetadata, AuditLog

@admin.register(MiddlewareKey)
class MiddlewareKeyAdmin(admin.ModelAdmin):
    list_display = ("label", "version", "active", "created_at", "rotated_at")
    readonly_fields = ("created_at", "rotated_at")

@admin.register(KeyRotationLog)
class KeyRotationLogAdmin(admin.ModelAdmin):
    list_display = ("old_key", "new_key", "rotated_at", "reason")

@admin.register(UsedNonce)
class UsedNonceAdmin(admin.ModelAdmin):
    list_display = ("nonce", "created_at")


@admin.register(TransactionMetadata)
class TransactionMetadataAdmin(admin.ModelAdmin):
    list_display = (
        "transaction_id",
        "client_ip",
        "created_at",
        "processing_time_ms",
        "status_code",
        "client_signature_verified",
    )
    list_filter = ("created_at", "status_code", "client_signature_verified")
    search_fields = ("transaction_id", "client_ip")
    readonly_fields = ("id", "transaction_id", "created_at")
    ordering = ("-created_at",)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("transaction_id", "event_type", "actor", "timestamp")
    readonly_fields = ("prev_hash", "record_hash", "timestamp")
    search_fields = ("transaction_id", "event_type")
