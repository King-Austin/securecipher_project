# models.py
import uuid
from django.db import models
from django.utils import timezone

class MiddlewareKey(models.Model):
    """
    Stores server-side middleware keypair (PEM). For demo/research we store PEM,
    but in production use KMS/HSM or encrypted storage.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    label = models.CharField(max_length=64, default="active", db_index=True)
    private_key_pem = models.TextField(help_text="PEM encoded private key (encrypted at rest recommended)")
    public_key_pem = models.TextField(help_text="PEM encoded public key")
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-version"]
        indexes = [models.Index(fields=["label", "active"])]

    def __str__(self):
        return f"{self.label} v{self.version} (active={self.active})"


class KeyRotationLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    old_key = models.ForeignKey(MiddlewareKey, null=True, blank=True, on_delete=models.SET_NULL, related_name="old_key_logs")
    new_key = models.ForeignKey(MiddlewareKey, null=True, blank=True, on_delete=models.SET_NULL, related_name="new_key_logs")
    reason = models.TextField(null=True, blank=True)
    rotated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-rotated_at"]


class UsedNonce(models.Model):
    """
    Stores nonces to prevent replay. Unique constraint prevents reuse.
    Optionally you may add TTL cleanup job (cron) to delete old nonces.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nonce = models.CharField(max_length=256, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    note = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        indexes = [models.Index(fields=["nonce"])]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.nonce} @ {self.created_at.isoformat()}"


class TransactionMetadata(models.Model):
    """
    Per-transaction metadata (one row per transaction id).
    Keep fields minimal; store details as JSON for admin display.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction_id = models.CharField(max_length=128, unique=True, db_index=True)
    client_ip = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    processing_time_ms = models.FloatField(null=True, blank=True)
    payload_size_bytes = models.IntegerField(null=True, blank=True)
    session_key_hash = models.CharField(max_length=128, null=True, blank=True, help_text="SHA256 of session key (for audit only)")
    client_signature_verified = models.BooleanField(default=False)
    middleware_signature = models.TextField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    response_size_bytes = models.IntegerField(null=True, blank=True)
    downstream_response_time_ms = models.FloatField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    error_step = models.CharField(max_length=128, null=True, blank=True)
    details = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.transaction_id} ({self.created_at.isoformat()})"


class AuditLog(models.Model):
    """
    Tamper-evident audit logs grouped by transaction_id.
    Each record stores prev_hash and record_hash to form a chain.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction_id = models.CharField(max_length=128, db_index=True)
    event_type = models.CharField(max_length=100)
    details = models.JSONField(null=True, blank=True)
    actor = models.CharField(max_length=64, default="middleware")
    timestamp = models.DateTimeField(auto_now_add=True)
    prev_hash = models.CharField(max_length=128, null=True, blank=True)
    record_hash = models.CharField(max_length=128, null=True, blank=True)

    class Meta:
        ordering = ["transaction_id", "timestamp"]
        indexes = [
            models.Index(fields=["transaction_id", "-timestamp"]),
        ]

    def __str__(self):
        return f"{self.transaction_id} | {self.event_type} @ {self.timestamp.isoformat()}"
