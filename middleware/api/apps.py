from django.apps import AppConfig
from django.contrib import admin


class CryptoEngineConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    verbose_name = 'SecureCipher Middleware API'

    def ready(self):
        # Import admin configurations
        from django.conf import settings
        
        # Apply custom admin site configuration
        admin.site.site_header = getattr(settings, 'ADMIN_SITE_HEADER', 'SecureCipher Middleware Administration')
        admin.site.site_title = getattr(settings, 'ADMIN_SITE_TITLE', 'SecureCipher Middleware Admin')
        admin.site.index_title = getattr(settings, 'ADMIN_INDEX_TITLE', 'Welcome to SecureCipher Middleware Administration')
        
        # Custom admin styling for middleware
        admin.site.site_url = None  # Remove "View site" link
        admin.site.enable_nav_sidebar = True
