from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid
from encrypted_model_fields.fields import EncryptedTextField


class MiddlewareKey(models.Model):
    label = models.CharField(max_length=50, unique=True)
    private_key_pem = models.TextField()
    public_key_pem = EncryptedTextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.label

class UsedNonce(models.Model):
    """Stores nonces that have been used to prevent replay attacks."""
    nonce = models.CharField(max_length=100, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'api_usednonce'
        indexes = [
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return self.nonce

    @classmethod
    def cleanup_expired_nonces(cls, hours=24):
        """Remove nonces older than specified hours to prevent table growth"""
        cutoff = timezone.now() - timedelta(hours=hours)
        deleted, _ = cls.objects.filter(timestamp__lt=cutoff).delete()
        return deleted

    @classmethod
    def is_nonce_valid(cls, nonce, max_age_seconds=300):
        """
        Check if nonce is valid:
        1. Not already used
        2. Within acceptable time window (default 5 minutes)
        """
        # Check if already used
        if cls.objects.filter(nonce=nonce).exists():
            return False, "Nonce already used"
            
        # For timestamp-based nonces, validate age
        try:
            # Assuming nonce format includes timestamp (implement based on your nonce format)
            # This is a placeholder - implement based on your nonce generation strategy
            return True, "Valid"
        except Exception:
            return True, "Valid"  # Fallback for non-timestamp nonces


class TransactionMetadata(models.Model):
    """Store metadata for each transaction passing through the middleware"""
    
    # Core identifiers
    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # Timing information
    timestamp = models.DateTimeField(auto_now_add=True)
    processing_time_ms = models.FloatField(null=True, blank=True, help_text="Processing time in milliseconds")
    
    # Client information
    client_ip = models.GenericIPAddressField(help_text="Client IP address")
    client_public_key_hash = models.CharField(max_length=64, help_text="SHA256 hash of client public key")
    
    # Request details
    nonce = models.CharField(max_length=255, db_index=True)
    target_url = models.CharField(max_length=500, help_text="Target downstream URL")
    payload_hash = models.CharField(max_length=64, help_text="SHA256 hash of transaction payload")
    payload_size_bytes = models.IntegerField(default=0, help_text="Size of encrypted payload in bytes")
    
    # Cryptographic details
    session_key_hash = models.CharField(max_length=64, help_text="SHA256 hash of session key")
    middleware_signature = models.TextField(help_text="Middleware signature for this transaction")
    client_signature_verified = models.BooleanField(default=False)
    
    # Response details  
    status_code = models.IntegerField(help_text="HTTP status code returned")
    downstream_response_time_ms = models.FloatField(null=True, blank=True, help_text="Downstream API response time")
    response_size_bytes = models.IntegerField(default=0, help_text="Size of response in bytes")
    
    # Error handling
    error_message = models.TextField(null=True, blank=True, help_text="Error message if transaction failed")
    error_step = models.CharField(max_length=50, null=True, blank=True, help_text="Step where error occurred")
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_transaction_metadata'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['client_ip']),
            models.Index(fields=['nonce']),
            models.Index(fields=['status_code']),
            models.Index(fields=['target_url']),
        ]
    
    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.status_code}"
    
    @classmethod
    def cleanup_old_metadata(cls, days=30):
        """Remove metadata older than specified days"""
        cutoff = timezone.now() - timedelta(days=days)
        deleted, _ = cls.objects.filter(timestamp__lt=cutoff).delete()
        return deleted
    
    @property
    def is_successful(self):
        return 200 <= self.status_code < 300
    
    @property
    def processing_time_seconds(self):
        if self.processing_time_ms:
            return self.processing_time_ms / 1000.0
        return None
    
# models.py (add these model definitions to the app that contains views.py)
import uuid
from django.db import models

class AuditLog(models.Model):
    """
    Persistent audit log entry keyed by transaction_id.
    Minimal but sufficient for admin display and tamper-evidence.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction_id = models.CharField(max_length=128, db_index=True, help_text="Middleware transaction UUID")
    event_type = models.CharField(max_length=100, help_text="Type of event (e.g., payload_decrypted)")
    details = models.JSONField(null=True, blank=True, help_text="Structured details for admin inspection")
    actor = models.CharField(max_length=100, blank=True, null=True, help_text="Optional actor (middleware, bank, client)")
    timestamp = models.DateTimeField(auto_now_add=True)
    prev_hash = models.CharField(max_length=128, blank=True, null=True, help_text="Previous record hash for chain")
    record_hash = models.CharField(max_length=128, blank=True, null=True, help_text="SHA256 hash of this record + prev_hash")

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["transaction_id", "-timestamp"]),
        ]

    def __str__(self):
        return f"{self.transaction_id} | {self.event_type} @ {self.timestamp.isoformat()}"

