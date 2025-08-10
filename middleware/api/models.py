from django.db import models
from django.utils import timezone
from datetime import timedelta

class MiddlewareKey(models.Model):
    label = models.CharField(max_length=50, unique=True)
    private_key_pem = models.TextField()
    public_key_pem = models.TextField()
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
