from django.contrib.admin import AdminSite
from django.contrib.admin.views.main import ChangeList
from django.contrib import admin
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from .models import MiddlewareKey, UsedNonce, TransactionMetadata
import os

class SecureCipherMiddlewareAdminSite(AdminSite):
    """
    Custom Admin Site for SecureCipher Middleware with enhanced dashboard
    """
    site_header = "SecureCipher Middleware Administration"
    site_title = "SecureCipher Middleware Admin"
    index_title = "Middleware Control Center"
    
    def index(self, request, extra_context=None):
        """
        Override the default admin index to include custom statistics
        """
        print("🔧 DEBUG: Custom middleware admin index method called")
        extra_context = extra_context or {}
        
        # Environment detection
        environment = os.getenv('DJANGO_ENV', 'development')
        extra_context['environment'] = environment
        print(f"🔧 DEBUG: Environment = {environment}")
        
        # Middleware-specific stats
        extra_context['show_middleware_stats'] = True
        extra_context['show_crypto_summary'] = True
        
        # Key statistics
        total_keys = MiddlewareKey.objects.count()
        active_keys = MiddlewareKey.objects.filter(
            public_key_pem__isnull=False, 
            private_key_pem__isnull=False
        ).count()
        
        extra_context.update({
            'total_keys': total_keys,
            'active_keys': active_keys,
        })
        print(f"🔧 DEBUG: Keys stats - Total: {total_keys}, Active: {active_keys}")
        
        # Nonce statistics
        today = timezone.now().date()
        used_nonces_today = UsedNonce.objects.filter(timestamp__date=today).count()
        total_used_nonces = UsedNonce.objects.count()
        
        extra_context.update({
            'used_nonces': total_used_nonces,
            'nonces_today': used_nonces_today,
        })
        print(f"🔧 DEBUG: Nonce stats - Total: {total_used_nonces}, Today: {used_nonces_today}")
        
        # Transaction statistics (if TransactionMetadata exists)
        try:
            transactions_today = TransactionMetadata.objects.filter(
                timestamp__date=today
            ).count()
            total_transactions = TransactionMetadata.objects.count()
            successful_transactions = TransactionMetadata.objects.filter(
                status_code__lt=400
            ).count()
            
            extra_context.update({
                'requests_today': transactions_today,
                'total_requests': total_transactions,
                'successful_requests': successful_transactions,
            })
            print(f"🔧 DEBUG: Transaction stats - Today: {transactions_today}, Total: {total_transactions}")
        except Exception as e:
            print(f"🔧 DEBUG: Transaction stats error: {e}")
            # If no transactions table exists
            extra_context.update({
                'requests_today': 0,
                'total_requests': 0,
                'successful_requests': 0,
            })
        
        print(f"🔧 DEBUG: Final context keys: {list(extra_context.keys())}")
        return super().index(request, extra_context)

# Create custom admin site instance
middleware_admin_site = SecureCipherMiddlewareAdminSite(name='middleware_admin')

# Import and register models with the custom admin site
from .admin import MiddlewareKeyAdmin, UsedNonceAdmin, TransactionMetadataAdmin

middleware_admin_site.register(MiddlewareKey, MiddlewareKeyAdmin)
middleware_admin_site.register(UsedNonce, UsedNonceAdmin)
middleware_admin_site.register(TransactionMetadata, TransactionMetadataAdmin)
