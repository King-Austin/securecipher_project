"""
Prometheus metrics endpoint for middleware service.
"""
from prometheus_client import make_wsgi_app, Counter, Gauge, generate_latest
from django.http import HttpResponse

# Define custom metrics
REQUEST_COUNT = Counter(
    'middleware_request_count',
    'Total number of HTTP requests received.',
    ['method', 'endpoint', 'http_status']
)

ACTIVE_REQUESTS = Gauge(
    'middleware_active_requests',
    'Number of active requests in the system.'
)

# Prometheus metrics endpoint
def metrics(request):
    """Expose Prometheus metrics."""
    return HttpResponse(generate_latest(), content_type='text/plain; version=0.0.4; charset=utf-8')