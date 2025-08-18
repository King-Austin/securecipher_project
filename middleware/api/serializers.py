from rest_framework import serializers
from .models import CryptoKey, CryptoLog, Transaction, MiddlewareKey

class CryptoKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoKey
        fields = '__all__'

class CryptoLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoLog
        fields = '__all__'

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = '__all__'

class MiddlewareKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = MiddlewareKey
        fields = '__all__'
