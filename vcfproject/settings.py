# ============================================
# Django Settings — Hardened & Complete
# Safe for development, production-ready
# ============================================

from pathlib import Path
import os
import logging
from dotenv import load_dotenv
from decouple import config, Csv
import dj_database_url

# --------------------------------------------
# Load env & base dir
# --------------------------------------------
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------
# Deployment Mode & Debug
# --------------------------------------------
# New: Deployment mode (development, staging, production)
DEPLOYMENT_MODE = config('DEPLOYMENT_MODE', default='development')
DEBUG = config('DEBUG', default=(DEPLOYMENT_MODE == 'development'), cast=bool)

# Safety check for production mode
if DEPLOYMENT_MODE == 'production' and DEBUG:
    raise ValueError("DEBUG must be False in production mode!")

# --------------------------------------------
# Secret Key
# --------------------------------------------
SECRET_KEY = config('SECRET_KEY')  # must be set in .env

if DEPLOYMENT_MODE != 'development' and (not SECRET_KEY or SECRET_KEY.strip() == ""):
    raise ValueError("SECRET_KEY is missing! Set it in your .env file.")

# --------------------------------------------
# Allowed Hosts & CSRF Trusted Origins
# --------------------------------------------
ALLOWED_HOSTS = [
    "localhost",  # Local development
    "127.0.0.1",  # Local development
] + config("ALLOWED_HOSTS", cast=Csv())

if DEPLOYMENT_MODE == 'production' and "*" in ALLOWED_HOSTS:
    raise ValueError("Wildcard '*' in ALLOWED_HOSTS is not allowed in production.")

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",  # Local development
    "http://127.0.0.1:8000",  # Local development
#    "https://58d57bd5-0670-4922-8fd3-58042be67f50-00-2huud3ci0678c.spock.replit.dev",
#    "https://fastgain.publicmail.repl.co",
] + config("CSRF_EXTRA_TRUSTED", default="", cast=Csv())

# --------------------------------------------
# Custom App Config / Business Settings
# --------------------------------------------
# Paystack
PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY')
PAYSTACK_SUCCESS_URL = config('PAYSTACK_SUCCESS_URL')
TEST_MODE = config('TEST_MODE', default=False, cast=bool)

# Admin Credentials (Custom Admin Login)
ADMIN_USERNAME = config('ADMIN_USERNAME')
ADMIN_PASSWORD = config('ADMIN_PASSWORD')
ADMIN_EMAIL = config('ADMIN_EMAIL')

# Superuser Credentials (For Django Admin bootstrap tasks, if you use them)
SUPERUSER_USERNAME = config('SUPERUSER_USERNAME')
SUPERUSER_PASSWORD = config('SUPERUSER_PASSWORD')
SUPERUSER_EMAIL = config('SUPERUSER_EMAIL')

# Time interval for member auth email change
AUTH_EMAIL_CHANGE_INTERVAL = int(os.getenv('AUTH_EMAIL_CHANGE_INTERVAL', 30))

# --------------------------------------------
# Email (secure defaults)
# --------------------------------------------
# Check if we're in development mode and email vars aren't configured
try:
    EMAIL_HOST_USER = config('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
    EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
    EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
    DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)
    
    # Basic header injection guard
    if EMAIL_HOST_USER and ("\n" in EMAIL_HOST_USER or "\r" in EMAIL_HOST_USER):
        raise ValueError("Invalid characters in EMAIL_HOST_USER")
        
except:
    # Fallback to console backend for development if email config is missing
    import warnings
    warnings.warn("Email configuration missing, using console backend for development")
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'noreply@vcfmanager.com'

# --------------------------------------------
# Installed Applications
# --------------------------------------------
INSTALLED_APPS = [
    # Django
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party / Dev
    'django_extensions',

    # Project apps
    'paystackapi',
    'vcfviewer',
    'customadmin',
    'members',
    'public',  # Public pages app
]

# --------------------------------------------
# Middleware
# --------------------------------------------
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # static optimization
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'vcfproject.middleware.AuthMiddleware',  # your access checks
]

# Add HTTPS redirect middleware for non-development environments
if DEPLOYMENT_MODE != 'development':
    MIDDLEWARE.insert(0, 'django.middleware.security.SecurityMiddleware')
else:
    # Add development-only middleware for HTTP redirect
    MIDDLEWARE.append('vcfproject.middleware.DevelopmentSSLRedirectMiddleware')

# --------------------------------------------
# URL / WSGI
# --------------------------------------------
ROOT_URLCONF = 'vcfproject.urls'
WSGI_APPLICATION = 'vcfproject.wsgi.application'

# --------------------------------------------
# Templates
# --------------------------------------------
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# --------------------------------------------
# Database (SSL only in prod, pooled connections)
# --------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,          # persistent connections
            ssl_require=(DEPLOYMENT_MODE == 'production')  # require SSL only in prod
        )
    }
else:
    DATABASES = {
        'default': dj_database_url.config(
            default=(
                f"postgres://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
                f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
            ),
            conn_max_age=600,
            ssl_require=(DEPLOYMENT_MODE == 'production')
        )
    }

# If behind a proxy/load balancer that sets X-Forwarded-Proto (Heroku, etc.)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# --------------------------------------------
# Passwords & Authentication
# --------------------------------------------
AUTH_USER_MODEL = 'members.MemberAccount'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Optional: faster hashing in pure dev to speed logins
if DEBUG:
    PASSWORD_HASHERS = [
        'django.contrib.auth.hashers.MD5PasswordHasher',
        'django.contrib.auth.hashers.PBKDF2PasswordHasher',
        'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
        'django.contrib.auth.hashers.Argon2PasswordHasher',
        'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    ]

# --------------------------------------------
# Redirects
# --------------------------------------------
LOGIN_URL = 'members:login'
ADMIN_LOGIN_URL = 'customadmin:login'
LOGIN_REDIRECT_URL = 'members:dashboard'
ADMIN_LOGIN_REDIRECT_URL = 'customadmin:dashboard'

# --------------------------------------------
# I18N / TZ
# --------------------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# --------------------------------------------
# Static Files
# --------------------------------------------
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --------------------------------------------
# Cache (dev: LocMem, prod: Redis if REDIS_URL provided)
# --------------------------------------------
REDIS_URL = config('REDIS_URL', default='')
if REDIS_URL and DEPLOYMENT_MODE != 'development':
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': REDIS_URL,
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    }

# --------------------------------------------
# Security — Different settings per environment
# --------------------------------------------
# HTTPS / Cookies - only enforced in production
SECURE_SSL_REDIRECT = (DEPLOYMENT_MODE == 'production')
SESSION_COOKIE_SECURE = (DEPLOYMENT_MODE == 'production')
CSRF_COOKIE_SECURE = (DEPLOYMENT_MODE == 'production')
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to read CSRF cookie for AJAX requests

# SameSite protections
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SAMESITE = 'Strict'

# CSRF settings for better AJAX compatibility
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'

# HSTS - only in production
SECURE_HSTS_SECONDS = 31536000 if DEPLOYMENT_MODE == 'production' else 0  # 1 year in prod
SECURE_HSTS_INCLUDE_SUBDOMAINS = (DEPLOYMENT_MODE == 'production')
SECURE_HSTS_PRELOAD = (DEPLOYMENT_MODE == 'production')

# Headers
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True

# Referrer policy
SECURE_REFERRER_POLICY = 'strict-origin'

# Request/Upload size limits (mitigate DoS via large payloads)
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024     # 5 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024     # 5 MB

# --------------------------------------------
# Logging — merged, rotating files + console
# --------------------------------------------
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {name} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },

    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple' if DEBUG else 'verbose',
        },
        'file_django': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOG_DIR / 'django.log'),
            'maxBytes': 5 * 1024 * 1024,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'file_security': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOG_DIR / 'security.log'),
            'maxBytes': 2 * 1024 * 1024,  # 2 MB
            'backupCount': 3,
            'formatter': 'verbose',
        },
        'file_requests': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOG_DIR / 'requests.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
        },
        'file_db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOG_DIR / 'db.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
        },
    },

    'loggers': {
        # Core Django logs
        'django': {
            'handlers': ['console', 'file_django'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        # HTTP request logging
        'django.request': {
            'handlers': ['console', 'file_requests'],
            'level': 'DEBUG' if DEBUG else 'WARNING',
            'propagate': False,
        },
        # Security events
        'django.security': {
            'handlers': ['console', 'file_security'],
            'level': 'WARNING',
            'propagate': False,
        },
        # Database queries (verbose in dev only)
        'django.db.backends': {
            'handlers': ['console', 'file_db'] if DEBUG else ['file_db'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # Your apps
        'members': {
            'handlers': ['console', 'file_django'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        'customadmin': {
            'handlers': ['console', 'file_django'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        'public': {
            'handlers': ['console', 'file_django'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        # PostgreSQL warnings
        'psycopg': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },

    # Root logger (fallback)
    'root': {
        'handlers': ['console', 'file_django'],
        'level': 'DEBUG' if DEBUG else 'INFO',
    },
}

# --------------------------------------------
# Celery Configuration (Async Tasks)
# --------------------------------------------
# Celery settings
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379/0')

# Celery task settings
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# Task routing
CELERY_TASK_ROUTES = {
    'members.tasks.verify_paystack_payment_async': {'queue': 'payments'},
    'members.tasks.cleanup_unverified_purchases': {'queue': 'cleanup'},
    'members.tasks.invalidate_user_cache': {'queue': 'cache'},
}

# Task retry settings
CELERY_TASK_ALWAYS_EAGER = config('CELERY_ALWAYS_EAGER', default=DEBUG, cast=bool)
CELERY_TASK_EAGER_PROPAGATES = True

# Periodic tasks (if using celery beat)
CELERY_BEAT_SCHEDULE = {
    'cleanup-unverified-purchases': {
        'task': 'members.tasks.cleanup_unverified_purchases',
        'schedule': 3600.0,  # Every hour
    },
}

# --------------------------------------------
# Development Mode Specific Settings
# --------------------------------------------
if DEPLOYMENT_MODE == 'development':
    # Disable security features that cause HTTPS issues
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    
    # Add localhost to allowed hosts
    ALLOWED_HOSTS += ['localhost', '127.0.0.1']
    
    # Print deployment mode for confirmation
    print(f"Running in DEVELOPMENT MODE - HTTPS security disabled")