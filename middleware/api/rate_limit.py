"""

Rate limiting middleware for SecureCipher API endpoints
"""
import time
from django.core.cache import cache
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger('securecipher.security')

class RateLimitMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware for API endpoints
    """
    
    RATE_LIMITS = {
        '/api/secure/gateway/': {'requests': 10, 'window': 60},  # 10 requests per minute
        '/api/public-key/': {'requests': 20, 'window': 60},      # 20 requests per minute
    }
    
    def process_request(self, request):
        if not self.should_rate_limit(request):
            return None
            
        client_ip = self.get_client_ip(request)
        path = request.path
        
        # Get rate limit for this endpoint
        limit_config = self.RATE_LIMITS.get(path, {'requests': 100, 'window': 60})
        
        # Check current usage
        cache_key = f"rate_limit:{client_ip}:{path}"
        current_requests = cache.get(cache_key, 0)
        
        if current_requests >= limit_config['requests']:
            logger.warning(f"Rate limit exceeded for IP {client_ip} on {path}")
            return JsonResponse({
                'error': 'Rate limit exceeded. Please try again later.',
                'retry_after': limit_config['window']
            }, status=429)
        
        # Increment counter
        cache.set(cache_key, current_requests + 1, limit_config['window'])
        return None
    
    def should_rate_limit(self, request):
        """Determine if this request should be rate limited"""
        return request.path in self.RATE_LIMITS
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityEventLogger:
    """Log security-related events"""
    
    @staticmethod
    def log_failed_signature(client_ip, error_details):
        logger.warning(f"Signature verification failed from {client_ip}: {error_details}")
    
    @staticmethod
    def log_replay_attack(client_ip, nonce):
        logger.error(f"Replay attack detected from {client_ip} with nonce: {nonce}")
    
    @staticmethod
    def log_crypto_error(client_ip, error_details):
        logger.error(f"Cryptographic error from {client_ip}: {error_details}")
    
    @staticmethod
    def log_successful_transaction(client_ip, target, transaction_id=None):
        logger.info(f"Successful transaction from {client_ip} to {target}, ID: {transaction_id}")
