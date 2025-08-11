# API Configuration for SecureCipher Server
# Centralized API endpoints configuration

# Base URLs - change these for different environments
MIDDLEWARE_BASE_URL = 'http://localhost:8000'

# API Endpoints
API_ENDPOINTS = {
    'middleware_gateway': f'{MIDDLEWARE_BASE_URL}/api/secure/gateway/',
    'middleware_public_key': f'{MIDDLEWARE_BASE_URL}/api/middleware/public-key/',
}

# Server API endpoints (internal)
SERVER_ENDPOINTS = {
    'register': '/register/',
    'validate_account': '/validate_account/',
    'transfer': '/transfer/',
    'public_key': '/public-key/',
    'profile': '/profile/',
}
