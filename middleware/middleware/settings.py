"""
Simplified Django settings for development.
This removes dependency on python-decouple and external services.
"""

import os
from pathlib import Path
from urllib.parse import urlparse, parse_qsl


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()



# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', '')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True #os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')
LOCAL_DEV = False
TEST_MODE = False   # Default: production mode




ALLOWED_HOSTS = [
    "*"
    ]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'corsheaders',

    'rest_framework',
    'encrypted_model_fields',
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',   # <— insert here
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',

]


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

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'

# The absolute path to the directory where collectstatic will collect static files for deployment.
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Additional locations of static files
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# The file storage engine to use when collecting static files with the collectstatic management command.
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Database

# Replace the DATABASES section of your settings.py with this

if LOCAL_DEV:
        
        

        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': BASE_DIR / 'db.sqlite3',
                }
            }
        BANKING_API_BASE_URL = 'http://localhost:8001'  # Use localhost for development


else:
        

        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': os.getenv('DB_NAME'),
                'USER': os.getenv('DB_USER'),
                'PASSWORD': os.getenv('DB_PASSWORD'),
                'HOST': os.getenv('DB_HOST'),
                'PORT': os.getenv('DB_PORT'),
                'CONN_MAX_AGE': 0,  # Let Supabase pooler manage connections
                'OPTIONS': {
                    'sslmode': os.getenv('DB_SSLMODE', 'require'),
                },
            }
        }

        BANKING_API_BASE_URL = 'https://securecipher-server.onrender.com' #uncomment this for production



# Password validation
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



# Internationalization
LANGUAGE_CODE = 'en-us'
USE_I18N = True
USE_TZ = True
TIME_ZONE = 'Africa/Lagos'
# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Django REST Framework Configuration
REST_FRAMEWORK = {

    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",  # dev
        "LOCATION": "ephemeral-sessions",
    }
}



# Banking App Specific Settings
TRANSACTION_DAILY_LIMIT = 50000.00
MINIMUM_BALANCE = 100.00
ACCOUNT_NUMBER_LENGTH = 10
DEMO_ACCOUNT_BALANCE = 50000.00
DEFAULT_CURRENCY = 'NGN'

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

# SECURE_SSL_REDIRECT = False

#use the default django auth model
AUTH_USER_MODEL = 'auth.User'

# Email Configuration - Console backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Simple logging for development
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
        "level": "INFO",  # set root level to INFO so it won't spam debug
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",  # default framework logs
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["console"],
            "level": "WARNING",  # suppress SQL unless it errors
            "propagate": False,
        },
        "middleware_app": {  # <--- your custom app/module
            "handlers": ["console"],
            "level": "DEBUG",  # keep detailed logs for your code
            "propagate": False,
        },
    },
}



# API Endpoints
ROUTING_TABLE = {
    'register': f'{BANKING_API_BASE_URL}/register',
    'validate_account': f'{BANKING_API_BASE_URL}/validate_account/',
    'transfer': f'{BANKING_API_BASE_URL}/transfer/',
    'public_key': f'{BANKING_API_BASE_URL}/public-key/',
    'refresh': f'{BANKING_API_BASE_URL}/refresh/',
}


# Admin Site Configuration for SecureCipher Middleware
ADMIN_SITE_HEADER = 'SecureCipher Middleware Administration'
ADMIN_SITE_TITLE = 'SecureCipher Middleware Admin'
ADMIN_INDEX_TITLE = 'Welcome to SecureCipher Middleware Administration'

# SecureCipher Middleware Configuration
BANK_NAME = 'SecureCipher Middleware'
BANK_CODE = 'SCM'
BANK_SLOGAN = 'Secure. Encrypted. Trusted.'

from cryptography.fernet import Fernet
#Fernet key must be 32 url-safe base64-encoded bytes.
FIELD_KEY = os.getenv('SECRET_KEY').encode('utf-8')
FIELD_ENCRYPTION_KEY = FIELD_KEY

EPHEMERAL_KEY_EXPIRY = 300  # 5 minutes