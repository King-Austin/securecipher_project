# API Configuration for SecureCipher Middleware
# Centralized API endpoints configuration

# Base URL for banking API - change this for different environments
BANKING_API_BASE_URL = 'https://securecipher-server.onrender.com' #uncomment this for production
# BANKING_API_BASE_URL = 'http://localhost:8001'  # Use localhost for development

# API Endpoints
API_ENDPOINTS = {
    'register': f'{BANKING_API_BASE_URL}/register/',
    'validate_account': f'{BANKING_API_BASE_URL}/validate_account/',
    'transfer': f'{BANKING_API_BASE_URL}/transfer/',
    'public_key': f'{BANKING_API_BASE_URL}/public-key/',
    'refresh': f'{BANKING_API_BASE_URL}/refresh/',
}

# Middleware API endpoints
MIDDLEWARE_ENDPOINTS = {
    'public_key': '/api/middleware/public-key/',
    'secure_gateway': '/api/secure/gateway/',
}

# Default routing table for downstream services
DEFAULT_ROUTING_TABLE = API_ENDPOINTS
