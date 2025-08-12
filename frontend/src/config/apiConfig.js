// API Configuration for SecureCipher
// Centralized API endpoints configuration

// Base URL for middleware API - change this for different environments
export const MIDDLEWARE_BASE_URL = 'https://securecipher-middleware.onrender.com';

// API Endpoints
export const API_ENDPOINTS = {
  MIDDLEWARE_GATEWAY: `${MIDDLEWARE_BASE_URL}/api/secure/gateway/`,
  MIDDLEWARE_PUBLIC_KEY: `${MIDDLEWARE_BASE_URL}/api/middleware/public-key/`,
};

// Validation
if (!MIDDLEWARE_BASE_URL.startsWith('http')) {
  throw new Error('MIDDLEWARE_BASE_URL must start with http:// or https://');
}

export default {
  MIDDLEWARE_BASE_URL,
  API_ENDPOINTS
};
