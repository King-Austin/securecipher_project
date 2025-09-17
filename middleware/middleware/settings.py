"""
Django settings for SecureCipher Middleware project.
Organized for readability and maintainability.
"""

# =============================================================================
# IMPORTS
# =============================================================================

import os
from pathlib import Path
from dotenv import load_dotenv

# =============================================================================
# BASIC SETUP
# =============================================================================

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
load_dotenv()

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', '')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')

# Environment flags
LOCAL_DEV = False
TEST_MODE = False  # Default: production mode

# Host configuration
ALLOWED_HOSTS = ["*"]

# =============================================================================
# APPLICATION DEFINITION
# =============================================================================

INSTALLED_APPS = [
    # Django core apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'corsheaders',
    'rest_framework',
    'encrypted_model_fields',

    # Local apps
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# =============================================================================
# URL AND TEMPLATES CONFIGURATION
# =============================================================================

ROOT_URLCONF = 'middleware.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'middleware.wsgi.application'

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

if LOCAL_DEV:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('LOCAL_DB_NAME'),
            'USER': os.getenv('LOCAL_DB_USER'),
            'PASSWORD': os.getenv('LOCAL_DB_PASSWORD'),
            'HOST': os.getenv('LOCAL_DB_HOST'),
            'PORT': os.getenv('LOCAL_DB_PORT'),
            'CONN_MAX_AGE': 0,
            'OPTIONS': {
                'sslmode': os.getenv('LOCAL_DB_SSLMODE', 'require'),
            },
        }
    }
    BANKING_API_BASE_URL = 'http://localhost:8001'  # Development URL
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER'),
            'PASSWORD': os.getenv('DB_PASSWORD'),
            'HOST': os.getenv('DB_HOST'),
            'PORT': os.getenv('DB_PORT'),
            'CONN_MAX_AGE': 600,
            'OPTIONS': {
                'sslmode': os.getenv('DB_SSLMODE', 'require'),
            },
        }
    }
    BANKING_API_BASE_URL = 'https://bankingapi.securecipher.app'  # Production URL

# =============================================================================
# PASSWORD VALIDATION
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# =============================================================================
# INTERNATIONALIZATION
# =============================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Lagos'
USE_I18N = True
USE_TZ = True

# =============================================================================
# STATIC AND MEDIA FILES
# =============================================================================

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# DJANGO REST FRAMEWORK CONFIGURATION
# =============================================================================

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}

# =============================================================================
# CACHING CONFIGURATION
# =============================================================================

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "ephemeral-sessions",
    }
}

# =============================================================================
# CORS CONFIGURATION
# =============================================================================

# CORS Settings for React Frontend - Very permissive for development
CORS_ALLOW_ALL_ORIGINS = True  # Only for development!

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# =============================================================================
# AUTHENTICATION AND USER MODEL
# =============================================================================

# Use the default Django auth model
AUTH_USER_MODEL = 'auth.User'

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================

# Email Configuration - Console backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "middleware_app": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

# =============================================================================
# API ENDPOINTS AND ROUTING
# =============================================================================

ROUTING_TABLE = {
    'register': f'{BANKING_API_BASE_URL}/register',
    'validate_account': f'{BANKING_API_BASE_URL}/validate_account/',
    'transfer': f'{BANKING_API_BASE_URL}/transfer/',
    'public_key': f'{BANKING_API_BASE_URL}/public-key/',
    'refresh': f'{BANKING_API_BASE_URL}/refresh/',
}

# =============================================================================
# ADMIN SITE CONFIGURATION
# =============================================================================

ADMIN_SITE_HEADER = 'SecureCipher Middleware Administration'
ADMIN_SITE_TITLE = 'SecureCipher Middleware Admin'
ADMIN_INDEX_TITLE = 'Welcome to SecureCipher Middleware Administration'

# =============================================================================
# SECURECIPHER MIDDLEWARE CONFIGURATION
# =============================================================================

BANK_NAME = 'SecureCipher Middleware'
BANK_CODE = 'SCM'
BANK_SLOGAN = 'Secure. Encrypted. Trusted.'

# Encryption settings
FIELD_KEY = os.getenv('SECRET_KEY').encode('utf-8')
FIELD_ENCRYPTION_KEY = FIELD_KEY
EPHEMERAL_KEY_EXPIRY = 300  # 5 minutes