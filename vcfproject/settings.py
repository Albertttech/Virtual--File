from pathlib import Path
import os
from decouple import config, Csv
import logging

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# =============================
# Environment Variables (from .env)
# =============================
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())

PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY')
PAYSTACK_SUCCESS_URL = config('PAYSTACK_SUCCESS_URL')
TEST_MODE = config('TEST_MODE', default=False, cast=bool)

# =============================
# Admin credentials
ADMIN_USERNAME = config('ADMIN_USERNAME')
ADMIN_PASSWORD = config('ADMIN_PASSWORD')
ADMIN_EMAIL = config('ADMIN_EMAIL')
# =============================
# Superuser credentials (for initial setup)
SUPERUSER_USERNAME = config('SUPERUSER_USERNAME')
SUPERUSER_PASSWORD = config('SUPERUSER_PASSWORD')
SUPERUSER_EMAIL = config('SUPERUSER_EMAIL')

# =============================
# Application Definition
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
]

ROOT_URLCONF = 'vcfproject.urls'

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

WSGI_APPLICATION = 'vcfproject.wsgi.application'

# =============================
# Database
# =============================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'adb.sqlite3',
    }
}

# =============================
# Password Validation
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
# Static Files
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
# Authentication URLs
# =============================
LOGIN_URL = 'members:login'
ADMIN_LOGIN_URL = 'customadmin:login'
LOGIN_REDIRECT_URL = 'members:dashboard'
ADMIN_LOGIN_REDIRECT_URL = 'customadmin:dashboard'

# =============================
# Logging
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
