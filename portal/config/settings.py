"""Isolated sandbox only. Production is deliberately not an accepted mode yet."""
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
if os.environ.get("PORTAL_SANDBOX") != "1":
    raise ImproperlyConfigured("This build only supports PORTAL_SANDBOX=1; production is not enabled")
SECRET_KEY = os.environ["PORTAL_SECRET_KEY"]
if len(SECRET_KEY) < 32:
    raise ImproperlyConfigured("PORTAL_SECRET_KEY must contain at least 32 characters")
ROLE = os.environ.get("PORTAL_ROLE", "web")
if ROLE not in {"web", "worker", "hooks", "owner"}:
    raise ImproperlyConfigured("Invalid portal role")
DEBUG = False
ALLOWED_HOSTS = os.environ.get("PORTAL_HOSTS", "localhost,127.0.0.1,testserver").split(",")
DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": os.environ.get("PORTAL_DB_NAME", "xportal_sandbox"),
    "USER": os.environ.get("PORTAL_DB_USER", "xportal_web"),
    "PASSWORD": os.environ.get("PORTAL_DB_PASSWORD", ""),
    "HOST": os.environ.get("PORTAL_DB_HOST", "/var/run/postgresql"),
    "PORT": os.environ.get("PORTAL_DB_PORT", "5432"),
    "CONN_MAX_AGE": 0,
    "OPTIONS": {"options": "-c statement_timeout=10000 -c lock_timeout=5000"},
}}
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions", "django.contrib.staticfiles", "commerce"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "commerce.middleware.SandboxHeaders",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
ROOT_URLCONF = "config.urls" if ROLE != "hooks" else "config.hooks_urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [], "APP_DIRS": True,
              "OPTIONS": {"context_processors": ["django.template.context_processors.request", "django.contrib.auth.context_processors.auth"]}}]
WSGI_APPLICATION = "config.wsgi.application"
AUTH_USER_MODEL = "commerce.Account"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "UTC"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "build-static"
SESSION_COOKIE_NAME = "xportal_session"
CSRF_COOKIE_NAME = "xportal_csrf"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_AGE = 8 * 3600
CSRF_COOKIE_SAMESITE = "Strict"
SECURE_CONTENT_TYPE_NOSNIFF = True
# HTML form navigation needs a same-origin source for CSRF validation.
# Cross-origin navigation still sends no referrer.
SECURE_REFERRER_POLICY = "same-origin"
DATA_UPLOAD_MAX_MEMORY_SIZE = 16384
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/account/"
LOGOUT_REDIRECT_URL = "/"
PROVISION_SOCKET = os.environ.get("PORTAL_PROVISION_SOCKET", "/run/xportal-bridge/provision.sock")
SANDBOX_MERCHANT = "xcli-local-sandbox"
SANDBOX_SIGNING_KEY = os.environ.get("PORTAL_SANDBOX_SIGNING_KEY", "") if ROLE in {"worker", "hooks", "owner"} else ""
SANDBOX_HOOK_URL = os.environ.get("PORTAL_SANDBOX_HOOK_URL", "http://127.0.0.1:8089/webhooks/sandbox/")
LOGGING = {"version": 1, "disable_existing_loggers": False,
           "handlers": {"console": {"class": "logging.StreamHandler"}},
           "loggers": {"django.security.csrf": {"handlers": ["console"], "level": "WARNING", "propagate": False}}}
