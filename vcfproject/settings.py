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
# Debug & Secret Key
# --------------------------------------------
SECRET_KEY = config('SECRET_KEY')  # must be set in .env
DEBUG = config('DEBUG', default=False, cast=bool)

if not DEBUG:
    if not SECRET_KEY or SECRET_KEY.strip() == "":
        raise ValueError("SECRET_KEY is missing! Set it in your .env file.")

# --------------------------------------------
# Allowed Hosts & CSRF Trusted Origins
# --------------------------------------------
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())

if not DEBUG and "*" in ALLOWED_HOSTS:
    raise ValueError("Wildcard '*' in ALLOWED_HOSTS is not allowed in production.")

CSRF_TRUSTED_ORIGINS = [
    "https://58d57bd5-0670-4922-8fd3-58042be67f50-00-2huud3ci0678c.spock.replit.dev",
    "https://fastgain.publicmail.repl.co",
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
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)

# Basic header injection guard
if EMAIL_HOST_USER and ("\n" in EMAIL_HOST_USER or "\r" in EMAIL_HOST_USER):
    raise ValueError("Invalid characters in EMAIL_HOST_USER")

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
            ssl_require=not DEBUG      # require SSL only in prod
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
            ssl_require=not DEBUG
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

# Optional: faster hashing in pure dev to speed logins (uncomment if you want)
# if DEBUG:
#     PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

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
if REDIS_URL and not DEBUG:
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
# Security — ONE canonical place (prod strict)
# --------------------------------------------
# HTTPS / Cookies
SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# SameSite protections
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SAMESITE = 'Strict'

# HSTS
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0  # 1 year in prod
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

# Headers
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True
# SECURE_BROWSER_XSS_FILTER is deprecated but harmless; omit for cleanliness

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
    },

    # Root logger (fallback)
    'root': {
        'handlers': ['console', 'file_django'],
        'level': 'DEBUG' if DEBUG else 'INFO',
    },
}
