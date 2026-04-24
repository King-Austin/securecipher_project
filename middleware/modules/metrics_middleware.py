"""
Middleware to track HTTP requests for Prometheus metrics.
"""
from modules.metrics import REQUEST_COUNT, ACTIVE_REQUESTS
from django.utils.deprecation import MiddlewareMixin

class MetricsMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """Track incoming requests."""
        ACTIVE_REQUESTS.inc()

    def process_response(self, request, response):
        """Track outgoing responses and update metrics."""
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.path,
            http_status=response.status_code
        ).inc()
        ACTIVE_REQUESTS.dec()
        return response