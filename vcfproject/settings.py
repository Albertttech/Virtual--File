# =============================
# Core Django Imports
# =============================
from pathlib import Path
import os
import logging
from dotenv import load_dotenv
from decouple import config, Csv
import dj_database_url

# =============================
# Load environment variables
# =============================
load_dotenv()

# =============================
# Base Directory
# =============================
BASE_DIR = Path(__file__).resolve().parent.parent

# =============================
# Debug & Secret Key Settings
# =============================
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)

# =============================
# Logging Configuration
# =============================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.server': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# =============================
# Allowed Hosts and CSRF Origins
# =============================
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())

CSRF_TRUSTED_ORIGINS = [
    "https://58d57bd5-0670-4922-8fd3-58042be67f50-00-2huud3ci0678c.spock.replit.dev",
    "https://fastgain.publicmail.repl.co",
]

# =============================
# Paystack Configuration
# =============================
PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY')
PAYSTACK_SUCCESS_URL = config('PAYSTACK_SUCCESS_URL')
TEST_MODE = config('TEST_MODE', default=False, cast=bool)

# =============================
# Admin Credentials (Custom Admin Login)
# =============================
ADMIN_USERNAME = config('ADMIN_USERNAME')
ADMIN_PASSWORD = config('ADMIN_PASSWORD')
ADMIN_EMAIL = config('ADMIN_EMAIL')

# =============================
# Email Configuration
# =============================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)

# =============================
# Superuser Credentials (For Django Admin)
# =============================
SUPERUSER_USERNAME = config('SUPERUSER_USERNAME')
SUPERUSER_PASSWORD = config('SUPERUSER_PASSWORD')
SUPERUSER_EMAIL = config('SUPERUSER_EMAIL')

# =============================
# Installed Applications
# =============================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'django_extensions',
    'paystackapi',
    'vcfviewer',
    'customadmin',
    'members',
]

# =============================
# Middleware Stack
# =============================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'vcfproject.middleware.AuthMiddleware',
    # 'vcfproject.middleware.AuthEmailMiddleware',
    'members.middleware.MembersAuthEmailMiddleware',
]

# =============================
# URL Configuration
# =============================
ROOT_URLCONF = 'vcfproject.urls'

# =============================
# Templates Configuration
# =============================
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

# =============================
# WSGI Application
# =============================
WSGI_APPLICATION = 'vcfproject.wsgi.application'

# =============================
# Database Configuration
# =============================
DATABASES = {
    'default': dj_database_url.config(
        default=f"postgres://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}",
        conn_max_age=600,
        ssl_require=True
    )
}

# =============================
# Password Validators
# =============================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# =============================
# Internationalization
# =============================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# =============================
# Static Files Configuration
# =============================
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "vcfviewer" / "static"]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# =============================
# Custom User Model
# =============================
AUTH_USER_MODEL = 'members.MemberAccount'

# =============================
# Authentication Redirects
# =============================
LOGIN_URL = 'members:login'
ADMIN_LOGIN_URL = 'customadmin:login'
LOGIN_REDIRECT_URL = 'members:dashboard'
ADMIN_LOGIN_REDIRECT_URL = 'customadmin:dashboard'

# =============================
# Logging Configuration
# =============================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'customadmin': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'members': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
}
