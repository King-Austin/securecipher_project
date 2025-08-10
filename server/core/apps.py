from django.apps import AppConfig
from django.contrib import admin


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    verbose_name = 'SecureCipher Banking Core'

    def ready(self):
        # Import admin configurations
        from django.conf import settings
        
        # Apply custom admin site configuration
        admin.site.site_header = getattr(settings, 'ADMIN_SITE_HEADER', 'SecureCipher Banking Administration')
        admin.site.site_title = getattr(settings, 'ADMIN_SITE_TITLE', 'SecureCipher Banking Admin')
        admin.site.index_title = getattr(settings, 'ADMIN_INDEX_TITLE', 'Welcome to SecureCipher Banking Administration')
        
        # Custom admin styling
        admin.site.site_url = None  # Remove "View site" link
        admin.site.enable_nav_sidebar = True
