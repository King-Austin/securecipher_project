from django.http import JsonResponse

class TLSEnforcerMiddleware:
    """
    Middleware to enforce TLS 1.3 on all incoming requests.
    Rejects requests using older TLS versions.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check TLS version from request.META
        tls_version = request.META.get("SSL_PROTOCOL", "")

        if tls_version != "TLSv1.3":
            return JsonResponse(
                {"error": "Only TLS 1.3 is supported"},
                status=403
            )

        return self.get_response(request)
