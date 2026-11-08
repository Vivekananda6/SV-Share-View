"""
Django settings for the SV API.
"""

import base64
import binascii
import os
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


IS_RENDER = os.environ.get("RENDER", "").strip().lower() == "true"
DEBUG = env_bool("DJANGO_DEBUG", not IS_RENDER)
if IS_RENDER and DEBUG:
    raise ImproperlyConfigured("DJANGO_DEBUG must be false when running on Render.")

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be configured when DJANGO_DEBUG is false.")
    SECRET_KEY = "development-only-not-for-production"

if not DEBUG and not os.environ.get("FILE_ENCRYPTION_KEY"):
    raise ImproperlyConfigured("FILE_ENCRYPTION_KEY must be configured when DJANGO_DEBUG is false.")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "api",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "api.middleware.AuditDeniedMediaRequestsMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
if not DEBUG:
    MIDDLEWARE.insert(2, "whitenoise.middleware.WhiteNoiseMiddleware")

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"
ASGI_APPLICATION = "core.asgi.application"

DATABASE_ENGINE = os.environ.get("DATABASE_ENGINE", "django.db.backends.sqlite3")
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            ssl_require=not DEBUG,
        )
    }
elif DATABASE_ENGINE == "django.db.backends.sqlite3":
    DATABASES = {
        "default": {
            "ENGINE": DATABASE_ENGINE,
            "NAME": os.environ.get("DATABASE_NAME", str(BASE_DIR / "db.sqlite3")),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": DATABASE_ENGINE,
            "NAME": os.environ.get("DATABASE_NAME", "trustify"),
            "USER": os.environ.get("DATABASE_USER", ""),
            "PASSWORD": os.environ.get("DATABASE_PASSWORD", ""),
            "HOST": os.environ.get("DATABASE_HOST", "localhost"),
            "PORT": os.environ.get("DATABASE_PORT", "5432"),
            "CONN_MAX_AGE": 60,
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
DEFAULT_MEDIA_ROOT = BASE_DIR / "media"
MEDIA_ROOT = Path(os.environ.get("MEDIA_ROOT", str(DEFAULT_MEDIA_ROOT)))
FILE_ENCRYPTION_KEY = os.environ.get("FILE_ENCRYPTION_KEY", "")
if FILE_ENCRYPTION_KEY:
    try:
        encryption_key_bytes = base64.b64decode(
            FILE_ENCRYPTION_KEY.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ImproperlyConfigured(
            "FILE_ENCRYPTION_KEY must be a URL-safe base64-encoded 32-byte key."
        ) from exc
    if len(encryption_key_bytes) != 32:
        raise ImproperlyConfigured("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes.")
MAX_FILE_UPLOAD_SIZE = int(os.environ.get("MAX_FILE_UPLOAD_SIZE", 104_857_600))
FILE_UPLOAD_MAX_MEMORY_SIZE = 2_621_440
DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_FILE_UPLOAD_SIZE + 1_048_576

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS",
    ["https://sv-share-view-fe.onrender.com"]
    + (
        ["http://localhost:5173", "http://127.0.0.1:5173"]
        if DEBUG
        else []
    ),
)

CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOW_CREDENTIALS = False
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", [])

REST_FRAMEWORK = {
    "EXCEPTION_HANDLER": "api.views.audit_api_exception",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "login": "5/min",
        "register": "5/hour",
    },
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "api.authentication.VersionedJWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "CHECK_REVOKE_TOKEN": True,
}
AUDIT_LOG_HMAC_KEY = os.environ.get("AUDIT_LOG_HMAC_KEY") or SECRET_KEY
DEFAULT_AUDIT_CHECKPOINT_PATH = BASE_DIR / "audit_checkpoint" / "events.jsonl"
AUDIT_CHECKPOINT_PATH = os.environ.get(
    "AUDIT_CHECKPOINT_PATH",
    str(DEFAULT_AUDIT_CHECKPOINT_PATH),
)
if not DEBUG and not os.environ.get("AUDIT_LOG_HMAC_KEY"):
    raise ImproperlyConfigured(
        "AUDIT_LOG_HMAC_KEY must be configured when DJANGO_DEBUG is false."
    )
if not DEBUG and len(AUDIT_LOG_HMAC_KEY) < 32:
    raise ImproperlyConfigured(
        "AUDIT_LOG_HMAC_KEY must contain at least 32 characters in production."
    )
if not DEBUG and AUDIT_LOG_HMAC_KEY == SECRET_KEY:
    raise ImproperlyConfigured(
        "AUDIT_LOG_HMAC_KEY must be distinct from DJANGO_SECRET_KEY."
    )

SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", not DEBUG)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "31536000" if not DEBUG else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", False)
