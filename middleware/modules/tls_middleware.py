# tls_middleware.py
from django.utils.deprecation import MiddlewareMixin

def enforce_tls13_only(request) -> bool:
    proto = request.META.get("SSL_PROTOCOL") or request.META.get("HTTP_X_FORWARDED_PROTO", "")
    return "TLSv1.3" in str(proto) or proto.lower() == "https"

def inject_security_headers(response):
    response["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response["X-Content-Type-Options"] = "nosniff"
    response["X-Frame-Options"] = "DENY"
    response["Referrer-Policy"] = "no-referrer"
    return response

class EnforceTLS13Middleware(MiddlewareMixin):
    def process_request(self, request):
        request.tls_enforced = enforce_tls13_only(request)
    def process_response(self, request, response):
        return inject_security_headers(response)
