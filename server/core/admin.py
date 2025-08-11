from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.utils.html import format_html
from django import forms
from .models import (
    User, Transaction, ApiKeyPair
)

# Unregister the Group model since we're not using Django's built-in groups
admin.site.unregister(Group)

# Customize admin site
admin.site.site_header = "SecureCipher Banking Administration"
admin.site.site_title = "SecureCipher Banking Admin"
admin.site.index_title = "Welcome to SecureCipher Banking Administration"




@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = (
        'username', 'email', 'first_name', 'last_name', 'account_number', 
        'balance', 'status', 'is_verified', 'has_nin', 'has_bvn', 'created_at'
    )
    list_filter = ('status', 'account_type', 'is_verified', 'is_active', 'date_joined')
    search_fields = (
        'username', 'email', 'first_name', 'last_name', 
        'account_number', 'phone_number'
    )
    readonly_fields = (
        'account_number', 'created_at', 'updated_at', 'date_joined', 
        'last_login', 'nin_hash', 'bvn_hash', 'public_key'
    )
    date_hierarchy = 'created_at'
    
    def has_nin(self, obj):
        """Show if user has NIN without revealing it"""
        return bool(obj.nin_hash)
    has_nin.boolean = True
    has_nin.short_description = 'Has NIN'
    
    def has_bvn(self, obj):
        """Show if user has BVN without revealing it"""
        return bool(obj.bvn_hash)
    has_bvn.boolean = True
    has_bvn.short_description = 'Has BVN'
    
    fieldsets = (
        ('User Information', {
            'fields': ('username', 'email', 'first_name', 'last_name', 'is_active')
        }),
        ('Account Details', {
            'fields': (
                'account_number', 'balance', 'account_type', 'status', 
                'is_primary', 'is_verified'
            )
        }),
        ('Personal Information', {
            'fields': (
                'phone_number', 'date_of_birth', 'address', 'occupation'
            ),
            'classes': ('collapse',)
        }),
        ('Security & Verification', {
            'fields': ('nin_hash', 'bvn_hash', 'public_key'),
            'classes': ('collapse',),
            'description': 'Sensitive information - NIN and BVN are encrypted. Only hashes shown for verification.'
        }),
        ('Permissions', {
            'fields': ('is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('date_joined', 'last_login', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_form(self, request, obj=None, **kwargs):
        """Customize form based on user permissions"""
        form = super().get_form(request, obj, **kwargs)
        
        # Only superusers can modify balance directly
        if not request.user.is_superuser:
            if 'balance' in form.base_fields:
                form.base_fields['balance'].disabled = True
                
        # Prevent modification of account numbers and hashes
        readonly_fields = ['account_number', 'nin_hash', 'bvn_hash', 'public_key']
        for field in readonly_fields:
            if field in form.base_fields:
                form.base_fields[field].disabled = True
                
        return form
    

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        'reference_number', 'account', 'transaction_type', 'amount', 
        'status', 'sender_name', 'recipient_name', 'created_at'
    )
    list_filter = ('transaction_type', 'status', 'created_at', 'ip_address')
    search_fields = (
        'reference_number', 'account__account_number', 'description', 
        'recipient_account_number', 'sender_account_number', 
        'recipient_name', 'sender_name'
    )
    readonly_fields = (
        'id', 'reference_number', 'balance_before', 'balance_after',
        'ip_address', 'user_agent', 'location', 'created_at', 'updated_at'
    )
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Transaction Information', {
            'fields': (
                'account', 'transaction_type', 'amount', 'description', 
                'status', 'reference_number'
            )
        }),
        ('Balance Information', {
            'fields': ('balance_before', 'balance_after'),
            'classes': ('collapse',)
        }),
        ('Transfer Details', {
            'fields': (
                'sender_name', 'sender_account_number',
                'recipient_name', 'recipient_account_number'
            ),
            'classes': ('collapse',)
        }),
        ('Security & Tracking', {
            'fields': ('ip_address', 'user_agent', 'location'),
            'classes': ('collapse',),
            'description': 'Security tracking information for fraud detection and audit purposes.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of transaction records for audit compliance"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Restrict modification of completed transactions"""
        if obj and obj.status == 'COMPLETED':
            return False
        return super().has_change_permission(request, obj)


@admin.register(ApiKeyPair)
class ApiKeyPairAdmin(admin.ModelAdmin):
    list_display = ('label', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('label',)
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Key Information', {
            'fields': ('label',)
        }),
        ('Keys', {
            'fields': ('public_key', 'private_key'),
            'classes': ('collapse',),
            'description': 'Warning: Handle these keys with extreme care. Never share private keys.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
