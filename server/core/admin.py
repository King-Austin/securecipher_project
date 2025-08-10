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
    list_display = ('username', 'email', 'first_name', 'last_name', 'account_number', 'balance', 'nin', 'bvn', 'is_verified', 'created_at')
    list_filter = ('status', 'is_verified', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'account_number', 'phone_number')
    readonly_fields = (
        'account_number', 'created_at', 'updated_at', 'date_joined', 'last_login',
        'nin_hash', 'bvn_hash'
    )
    date_hierarchy = 'created_at'
    

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('reference_number', 'account', 'transaction_type', 'amount', 'status', 'created_at')
    list_filter = ('transaction_type', 'status', 'created_at')
    search_fields = ('reference_number', 'account__account_number', 'description', 'recipient_account_number')
    readonly_fields = ('id', 'reference_number', 'created_at', 'updated_at')
    date_hierarchy = 'created_at'


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
