"""Ajustes de Django. Interfaz LOCAL de un solo analista: sin base de datos (la verdad es el ledger y las carpetas del caso) y sin
cuentas. Por eso solo escucha en localhost por defecto; si la publicas en otra interfaz, protégela tú (proxy con autenticación)."""
import os
import secrets
from pathlib import Path

from dfir_copilot.projects import data_root

BASE_DIR = Path(__file__).resolve().parent


def _secret_key() -> str:
    env = os.environ.get("DFIR_WEB_SECRET")
    if env:
        return env
    path = data_root() / ".web_secret"
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(50)
        path.write_text(key, encoding="utf-8")
        path.chmod(0o600)
        return key
    except OSError:
        return secrets.token_urlsafe(50)  # sin disco escribible: una clave por proceso (las sesiones no se usan)


SECRET_KEY = _secret_key()
DEBUG = os.environ.get("DFIR_WEB_DEBUG") == "1"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DFIR_WEB_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",") if h.strip()]
INSTALLED_APPS = ["django.contrib.staticfiles", "dfir_copilot.web"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "dfir_copilot.web.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True,
              "OPTIONS": {"context_processors": ["django.template.context_processors.request"]}}]
DATABASES: dict = {}
STATIC_URL = "/static/"
LANGUAGE_CODE = "es"
USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
