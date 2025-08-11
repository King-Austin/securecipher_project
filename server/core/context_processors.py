"""
Custom context processors for SecureCipher admin interface
"""
from django.conf import settings
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta


def admin_context(request):
    """
    Add SecureCipher-specific context to admin templates
    """
    context = {}
    
    # Only add context for admin pages
    if request.path.startswith('/admin/'):
        # Get dashboard widget settings
        widget_settings = getattr(settings, 'ADMIN_DASHBOARD_WIDGETS', {})
        
        # Add environment info
        context['environment'] = getattr(settings, 'ENVIRONMENT', 'development')
        context['bank_name'] = getattr(settings, 'BANK_NAME', 'SecureCipher Bank')
        context['bank_slogan'] = getattr(settings, 'BANK_SLOGAN', 'Secure. Encrypted. Trusted.')
        
        # Add widget visibility settings
        context['show_recent_actions'] = widget_settings.get('show_recent_actions', True)
        context['show_user_stats'] = widget_settings.get('show_user_stats', True)
        context['show_transaction_summary'] = widget_settings.get('show_transaction_summary', True)
        context['show_security_alerts'] = widget_settings.get('show_security_alerts', True)
        
        # Add statistics if user is staff
        if request.user.is_authenticated and request.user.is_staff:
            try:
                from core.models import User, Transaction
                
                # User statistics
                if widget_settings.get('show_user_stats', True):
                    context['total_users'] = User.objects.count()
                    context['active_users'] = User.objects.filter(is_active=True).count()
                    context['verified_users'] = User.objects.filter(is_verified=True).count()
                
                # Transaction statistics  
                if widget_settings.get('show_transaction_summary', True):
                    today = timezone.now().date()
                    context['transactions_today'] = Transaction.objects.filter(
                        created_at__date=today
                    ).count()
                    context['total_transactions'] = Transaction.objects.count()
                    context['failed_transactions'] = Transaction.objects.filter(
                        status='failed'
                    ).count()
                    
            except ImportError:
                # Core models not available (middleware admin)
                pass
    
    return context
