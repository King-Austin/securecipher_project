from django.contrib import admin
from django.contrib.auth.models import Group
from .models import MiddlewareKey, UsedNonce, TransactionMetadata

# Unregister the Group model since we're not using Django's built-in groups for middleware
admin.site.unregister(Group)

# Customize admin site for middleware
admin.site.site_header = "SecureCipher Middleware Administration"
admin.site.site_title = "SecureCipher Middleware Admin"
admin.site.index_title = "Welcome to SecureCipher Middleware Administration"

@admin.register(MiddlewareKey)
class MiddlewareKeyAdmin(admin.ModelAdmin):
    """
    Admin interface for managing the middleware's cryptographic keys.
    Displays key information and when it was created/updated.
    """
    list_display = ('label', 'created_at', 'updated_at')
    readonly_fields = ('public_key_pem', 'private_key_pem', 'created_at', 'updated_at')
    search_fields = ('label',)

@admin.register(UsedNonce)
class UsedNonceAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing nonces that have been used in transactions.
    This is critical for monitoring and detecting potential replay attacks.
    """
    list_display = ('nonce', 'timestamp')
    readonly_fields = ('nonce', 'timestamp')
    search_fields = ('nonce',)


@admin.register(TransactionMetadata)
class TransactionMetadataAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing transaction metadata and audit trails.
    Provides comprehensive monitoring of all transactions through the middleware.
    """
    list_display = (
        'transaction_id', 'timestamp', 'client_ip', 'target_url', 
        'status_code', 'processing_time_ms', 'is_successful'
    )
    list_filter = (
        'status_code', 'timestamp', 'target_url', 
        'client_signature_verified', 'created_at'
    )
    readonly_fields = (
        'transaction_id', 'timestamp', 'processing_time_ms', 'client_ip',
        'client_public_key_hash', 'nonce', 'target_url', 'payload_hash',
        'payload_size_bytes', 'session_key_hash', 'middleware_signature',
        'client_signature_verified', 'status_code', 'downstream_response_time_ms',
        'response_size_bytes', 'error_message', 'error_step', 'created_at'
    )
    search_fields = ('transaction_id', 'client_ip', 'nonce', 'target_url')
    date_hierarchy = 'timestamp'
    
    def is_successful(self, obj):
        return obj.is_successful
    is_successful.boolean = True
    is_successful.short_description = 'Success'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related()

