# --- TLS enforcement ---
def enforce_tls13_only(request):
    # Demo: assume request has protocol attribute
    return getattr(request, "protocol", "HTTP/1.1") == "TLS1.3"

def inject_security_headers(response):
    # Add security headers
    response["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response["X-Content-Type-Options"] = "nosniff"
    response["X-Frame-Options"] = "DENY"
    return response

def validate_tls_handshake(request):
    # Demo: just return True for handshake validation
    return True
