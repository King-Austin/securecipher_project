# API Configuration for SecureCipher Middleware
# Centralized API endpoints configuration

# Base URL for banking API - change this for different environments
BANKING_API_BASE_URL = 'http://localhost:8001'

# API Endpoints
API_ENDPOINTS = {
    'register': f'{BANKING_API_BASE_URL}/register/',
    'validate_account': f'{BANKING_API_BASE_URL}/validate_account/',
    'transfer': f'{BANKING_API_BASE_URL}/transfer/',
    'public_key': f'{BANKING_API_BASE_URL}/public-key/',
    'profile': f'{BANKING_API_BASE_URL}/profile/',
}

# Middleware API endpoints
MIDDLEWARE_ENDPOINTS = {
    'public_key': '/api/middleware/public-key/',
    'secure_gateway': '/api/secure/gateway/',
}

# Default routing table for downstream services
DEFAULT_ROUTING_TABLE = API_ENDPOINTS
